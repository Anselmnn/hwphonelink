/*
 * fillp_conn.h - fillp (Dstream) UDP reliable-stream engine
 *
 * One engine = one bound UDP socket + one GMainLoop thread. The engine
 * is role-agnostic: it can accept CONN_REQs (server peers) and/or
 * connect out (client peers) on the same socket; peers are keyed by
 * "ip:port".
 *
 * Wire behaviour (spec §8, from the public fillp source):
 *   - 4-way cookie handshake:
 *       client CONN_REQ → server CONN_REQ_ACK (cookie) →
 *       client CONN_CONFIRM (cookie echo) → server CONN_CONFIRM_ACK
 *     The cookie HMAC key is a per-engine local 32-byte MAC key, never
 *     sent (DTLS-style).
 *   - DATA: sender pktNum is 1-based and increments per packet;
 *     seqNum is the cumulative byte offset INCLUDING the packet.
 *     Receiver: dup (seqNum <= recv.seqNum) / out-of-window dropped,
 *     out-of-order buffered (OFO), in-order bytes delivered to the app.
 *   - NACK: receiver NACKs on the first gap (stand convention: exactly
 *     the first missing packet); sender retransmits the gap. A stall
 *     valve retransmits the oldest inflight packet after 1 s (the real
 *     stack does this via RTT-based RTO).
 *   - PACK: cumulative ack (head.pktNum / head.seqNum); sender frees
 *     inflight packets up to the ack point.
 *   - FIN: graceful close (sent when the app has drained its send
 *     queue); the peer finalizes on FIN.
 *
 * The delivered byte stream is opaque to fillp: the VTP layer
 * (stream_file.c) frames it (length prefix + GCM) and reassembles
 * frames across fillp deliveries.
 *
 * Threading: all engine/peer state is touched on the engine thread
 * except the peers table (locked) and refcount (atomic). Callbacks
 * fire on the engine thread. fillp_engine_connect() is safe from any
 * thread: it registers a fresh peer under the engine lock and sends
 * the CONN_REQ (a single sendto); no peer datagram can exist before
 * that.
 *
 * Lifetime mirrors dfile_conn: refs start at 2 (creator +
 * engine-internal); the internal ref is dropped as the last step of
 * the engine thread.
 */

#pragma once

#include <glib.h>

G_BEGIN_DECLS

typedef struct _FillpEngine FillpEngine;
typedef struct _FillpPeer FillpPeer;

/* Fired on ESTABLISHED (engine thread), after the handshake completes. */
typedef void (*FillpOnEstablishedCb)(FillpEngine *engine, FillpPeer *peer,
                                     gpointer user_data);

/*
 * Opaque byte delivery from the peer's fillp stream (engine thread).
 * Data is contiguous stream bytes — NOT message boundaries; the
 * consumer (VTP) reassembles frames.
 */
typedef void (*FillpOnDataCb)(FillpEngine *engine, FillpPeer *peer,
                              const guint8 *data, gsize len,
                              gpointer user_data);

/*
 * Fired when the app's send queue has fully drained AND every sent
 * packet is acked (engine thread). Fired at most once per peer, and
 * only if the app queued data.
 */
typedef void (*FillpOnTxCompleteCb)(FillpEngine *engine, FillpPeer *peer,
                                    gpointer user_data);

/* Fired once per peer on teardown (engine thread); the peer is valid
 * during the callback and dead after it returns. */
typedef void (*FillpOnClosedCb)(FillpEngine *engine, FillpPeer *peer,
                                const gchar *reason, gpointer user_data);

/*
 * Send data provider (engine thread): the engine calls it from its 1 ms
 * tick while the peer's send queue is below the high-water mark. The
 * app appends bytes via fillp_peer_send() and returns the bytes queued
 * this round, 0 when "nothing right now", or -1 exactly once when the
 * app has queued its final byte (drains → on_tx_complete).
 */
typedef gssize (*FillpPeerFillFunc)(FillpPeer *peer, gpointer app_data);

/*
 * Bind UDP @port and start the engine thread. Returns NULL + @error on
 * bind failure. The engine accepts CONN_REQs from any peer and can also
 * connect out (fillp_engine_connect).
 */
FillpEngine* fillp_engine_new(guint port, GError **error);

void fillp_engine_set_callbacks(FillpEngine *engine,
                                FillpOnEstablishedCb on_established,
                                FillpOnDataCb on_data,
                                FillpOnTxCompleteCb on_tx_complete,
                                FillpOnClosedCb on_closed,
                                gpointer user_data);

/*
 * Start a client handshake to @host:@port (any thread). Returns the
 * peer (owned by the engine until its on_closed). The peer is live
 * from the call until its on_closed fires — which also happens if the
 * handshake times out (5 s); the app then retries with a fresh
 * connect.
 */
FillpPeer* fillp_engine_connect(FillpEngine *engine, const gchar *host,
                                guint port, GError **error);

/* Orderly shutdown (any thread, idempotent): finalizes all peers,
 * stops the loop. The thread self-joins on the last unref. */
void fillp_engine_close(FillpEngine *engine);

FillpEngine* fillp_engine_ref(FillpEngine *engine);
void fillp_engine_unref(FillpEngine *engine);

guint fillp_engine_port(FillpEngine *engine);

/* Append bytes to the peer's send queue (engine thread only; dropped
 * unless the peer is ESTABLISHED). */
void fillp_peer_send(FillpPeer *peer, const guint8 *data, gsize len);

/* App glue (engine thread): opaque pointer + send-data provider. */
void fillp_peer_set_app_data(FillpPeer *peer, gpointer app_data);
void fillp_peer_set_fill_func(FillpPeer *peer, FillpPeerFillFunc fn);

/*
 * Per-peer stream callbacks (engine thread): when set, they take
 * precedence over the engine-level on_data/on_tx_complete for this
 * peer; @user_data is the per-peer one. The stream layer (stream_file)
 * registers these when it attaches to the peer.
 */
void fillp_peer_set_stream_cbs(FillpPeer *peer, FillpOnDataCb on_data,
                               FillpOnTxCompleteCb on_tx_complete,
                               gpointer user_data);

/* Graceful close (any thread, idempotent): sends FIN when
 * established, then finalizes on the peer's FIN / 2 s timeout. */
void fillp_peer_close(FillpPeer *peer);

gboolean fillp_peer_is_established(FillpPeer *peer);
const gchar* fillp_peer_state_name(FillpPeer *peer);
guint fillp_peer_port(FillpPeer *peer);

G_END_DECLS
