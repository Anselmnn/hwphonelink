/*
 * dfile_conn.h - DFile transfer connection engine
 *
 * One engine per TCP connection. Runs a dedicated GMainLoop thread that
 * owns the socket (reads + writes + timers all happen on that thread, so
 * no locking is needed for engine state).
 *
 * Wire-level behaviour (spec §7, RE'd from libnstackx_dfile.so):
 *   - SETTING exchange on connect (both sides send immediately over TCP;
 *     mtu_inuse = min, block size = peer's dataFrameSize or 1472).
 *   - One transfer per direction, multiplexed by transId (1 = first).
 *   - Sender: FILE_HEADER → wait FILE_HEADER_CONFIRM + FILE_TRANSFER_REQ
 *     (the binary's receiver-initiated "pull" gate) → stream FILE_DATA
 *     (block = negotiated data frame size, flags START/CONTINUE/END,
 *     RETRAN on retransmission) → batched cumulative FILE_DATA_ACK (V1)
 *     from the receiver → wait FILE_TRANSFER_DONE (sent by the receiver
 *     after all data is written) → reply FILE_TRANSFER_DONE_ACK.
 *   - Receiver: accumulate header → FILE_HEADER_CONFIRM + FILE_TRANSFER_REQ
 *     → write blocks (sparse, pwrite at seq*block_size) → batched V1 ACKs
 *     → FILE_TRANSFER_DONE → wait FILE_TRANSFER_DONE_ACK.
 *   - Any error → RST frame (code 200..210), transfer failed.
 *
 * Replay-stand conventions: no dfile encryption (cipherCapability = 0),
 * no backpressure (capsCheck = 0), V1 acks only. File names follow
 * "ft-<sha256hex>.bin" (ft_testfile.h) so the receiver verifies content.
 *
 * Threading: callbacks fire on the engine thread — keep them short; use
 * g_main_context_invoke() to touch app state on another thread. The
 * engine holds an internal ref until its thread exits, so dropping your
 * ref from a callback is safe.
 */

#pragma once

#include <gio/gio.h>
#include "dfile_frame.h"

G_BEGIN_DECLS

typedef struct _DFileConn DFileConn;

/* One file to send (sender side). */
typedef struct {
  gchar *path;   /* on-disk file */
  gchar *name;   /* wire name (use ft-<sha>.bin for self-verification) */
  guint64 size;  /* 0 = take from stat */
} DFileSendItem;

/* Fired after the SETTING exchange completes (engine thread). */
typedef void (*DFileConnNegotiatedCb)(DFileConn *conn, gpointer user_data);

/* Fired when the peer's FILE_HEADER is complete (engine thread).
 * @entries is owned by the engine for the lifetime of the transfer. */
typedef void (*DFileConnFileListCb)(DFileConn *conn,
                                    const DFileHeaderEntry *entries, gsize n,
                                    gpointer user_data);

/*
 * Fired when a transfer finishes in either direction (engine thread).
 * ok = TRUE when the transfer completed (DONE/DONEACK for the receiver,
 * all data acked + DONE + DONEACK sent for the sender). @message carries
 * details (per-file sha256 verification on the receiver side).
 */
typedef void (*DFileConnResultCb)(DFileConn *conn, gboolean is_sender,
                                  gboolean ok, const gchar *message,
                                  gpointer user_data);

/* Fired once, on connection teardown (engine thread). */
typedef void (*DFileConnClosedCb)(DFileConn *conn, gpointer user_data);

/*
 * Client side: connect (synchronously, 5 s timeout) to @host:@port and
 * start the engine. Returns NULL + @error on failure.
 */
DFileConn* dfile_conn_new_client(const gchar *host, guint port,
                                 GError **error);

/*
 * Server side: wrap an already-accepted @conn (e.g. from a GSocketService
 * on another loop) and start the engine. The engine takes its own ref on
 * @conn.
 */
DFileConn* dfile_conn_new_server(GSocketConnection *conn);

DFileConn* dfile_conn_ref(DFileConn *conn);
void dfile_conn_unref(DFileConn *conn);

void dfile_conn_set_callbacks(DFileConn *conn,
                              DFileConnNegotiatedCb on_negotiated,
                              DFileConnFileListCb on_file_list,
                              DFileConnResultCb on_result,
                              DFileConnClosedCb on_closed,
                              gpointer user_data);

/*
 * Directory received files are written into (receiver side). Must be set
 * before the peer's FILE_HEADER arrives.
 */
void dfile_conn_set_recv_dir(DFileConn *conn, const gchar *dir);

/*
 * Start a transfer as the sender. MUST be called on the engine thread
 * (i.e. from a DFileConn callback) — all engine state is unlocked. One
 * active send transfer per connection. Returns FALSE with @error if the
 * connection is not ready or a transfer is already active.
 */
gboolean dfile_conn_send_files(DFileConn *conn, const DFileSendItem *items,
                               gsize n, GError **error);

/*
 * Orderly shutdown (any thread, idempotent). Fails pending transfers,
 * fires on_result for them and then on_closed (engine thread), closes the
 * socket. The engine's thread self-joins: the last unref after the thread
 * exits frees the structure.
 */
void dfile_conn_close(DFileConn *conn);

/* Human-readable state (for logs). */
const gchar* dfile_conn_state_name(DFileConn *conn);

/* Negotiated block size (0 until negotiated). */
guint dfile_conn_block_size(DFileConn *conn);

G_END_DECLS
