/*
 * stream_file.h - VTP file session over a fillp peer
 *
 * One StreamFile runs on one fillp peer and is bidirectional: the app
 * may start_send() one file (the first VTP frame in that direction is
 * metadata [u64 total][u16 name_len][name], the rest are data chunks)
 * and simultaneously receive the peer's file into the recv dir.
 *
 * Wire: every VTP frame is one GCM-sealed message (vtp_frame.h), and
 * fillp delivers an opaque byte stream, so this module reassembles
 * frames across fillp deliveries (4-byte length prefix, then N bytes).
 *
 * Threading: StreamFile state is touched only on the fillp engine
 * thread (on_data / on_tx_complete / on_closed callbacks and the
 * fill func all run there). stream_file_new() and the setters must be
 * called before traffic starts; stream_file_start_send() from the
 * on_established callback; stream_file_close() from on_closed (the
 * peer is already finalized, so no engine call is made on it).
 */

#pragma once

#include <glib.h>
#include <gio/gio.h>
#include "fillp_conn.h"
#include "vtp_frame.h"

G_BEGIN_DECLS

typedef struct _StreamFile StreamFile;

/*
 * Received the metadata frame of the peer's file (engine thread).
 * The file will be written to <recv_dir>/<name>.
 */
typedef void (*StreamFileOnRxMetaCb)(StreamFile *sf, const gchar *name,
                                     guint64 size, gpointer user_data);

/*
 * One direction finished (engine thread). @is_send = sender side
 * (ok always means "all bytes sent and acked"); @is_send = FALSE =
 * receiver side (ok means content verified: sha256 vs wire name, plus
 * H.264 structure checks for .h264 files). @message is a short,
 * g_malloc'ed summary (caller frees).
 */
typedef void (*StreamFileDoneCb)(StreamFile *sf, gboolean is_send,
                                 gboolean ok, const gchar *message,
                                 gpointer user_data);

/*
 * Create a session bound to @peer (non-owning) with the 32-byte VTP
 * key (vtp_derive_key()). The app owns the StreamFile; free it with
 * stream_file_close().
 */
StreamFile* stream_file_new(FillpPeer *peer, const guint8 key[VTP_KEY_LEN]);

/* Directory for received files (any thread, before traffic). */
void stream_file_set_recv_dir(StreamFile *sf, const gchar *dir);

/* Callbacks (any thread, before traffic). */
void stream_file_set_callbacks(StreamFile *sf, StreamFileOnRxMetaCb on_rx_meta,
                               StreamFileDoneCb on_done, gpointer user_data);

/*
 * Start sending @path to the peer under @wire_name (engine thread,
 * e.g. from on_established). The wire name follows the
 * "hs-<sha>.h264" / "ft-<sha>.bin" convention so the receiver can
 * verify content; the actual byte count is carried in the metadata
 * frame. Also attaches the session to the peer's byte stream.
 */
gboolean stream_file_start_send(StreamFile *sf, const gchar *path,
                                const gchar *wire_name, GError **error);

/*
 * Attach the session to the peer's byte stream without sending (rx
 * only; engine thread, e.g. from on_established). stream_file_start_send()
 * attaches as well; calling both is harmless.
 */
void stream_file_attach(StreamFile *sf);

/*
 * Abort the session and free it (engine thread, e.g. from on_closed;
 * or after the engine has fully stopped).
 */
void stream_file_close(StreamFile *sf);

const gchar* stream_file_rx_state_name(StreamFile *sf);
const gchar* stream_file_tx_state_name(StreamFile *sf);

G_END_DECLS
