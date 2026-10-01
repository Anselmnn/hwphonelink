/*
 * fillp_conn.c - fillp (Dstream) UDP reliable-stream engine
 *
 * See fillp_conn.h for the wire flow and threading model. All engine and
 * peer state is touched only from the engine thread; the only
 * cross-thread contacts are the peers table (e->lock) and the refcount
 * (atomic).
 *
 * Lifetime: refs start at 2 (creator + engine-internal). The internal
 * ref is dropped as the last step of the engine thread (same pattern as
 * dfile_conn.c).
 */

#include "proto/fillp_conn.h"
#include "proto/fillp_frame.h"
#include "proto/softbus_crypto.h"

#include <gio/gio.h>
#include <string.h>

/* ============================ Tuning ============================ */

#define FP_PKT_DATA_MAX 1400 /* DATA payload (12+1400+28 < 1500 MTU)  */
#define FP_SEND_CACHE (256 * 1024)  /* in-flight window, bytes        */
#define FP_RECV_CACHE (1024 * 1024) /* advertised, not enforced       */
#define FP_OFO_MAX_BYTES (2 * 1024 * 1024)
#define FP_TXQ_WATERMARK (64 * 1024) /* app fill below this level      */
#define FP_HANDSHAKE_TIMEOUT_MS 5000
#define FP_HS_RETRANS_MS 500 /* client handshake msg retransmit       */
#define FP_CLOSE_TIMEOUT_MS 2000 /* CLOSING → finalize                 */
#define FP_STALL_TIMEOUT_MS 1000 /* oldest-inflight retransmit valve   */
#define FP_NACK_INTERVAL_MS 20
#define FP_PACK_INTERVAL_MS 10
#define FP_PACK_FLUSH_BYTES 65536
#define FP_TICK_MS 1
#define FP_SEND_BUDGET 32 /* max DATA packets per tick                */
#define FP_COOKIE_LIFETIME_US (10 * 1000 * 1000)
#define FP_PRESERVE_MAX_US (20 * 1000 * 1000)
#define FP_CLIENT_PRESERVE_US (10 * 1000 * 1000)

/* ============================ Errors ============================ */

typedef enum {
  FP_E_INVALID = 1,
  FP_E_BIND,
  FP_E_CLOSED,
} FpErr;

static GQuark fp_quark(void) {
  return g_quark_from_static_string("hwphonelink-fillp-error-quark");
}

/* ============================ State ============================ */

typedef enum {
  FP_ST_PENDING,
  FP_ST_ESTABLISHED,
  FP_ST_CLOSING,
  FP_ST_CLOSED,
} FpState;

/* One DATA packet: payload copy + counters. Lives in the sender's
 * inflight list and/or the receiver's OFO table. */
typedef struct {
  guint32 pkt_num;
  guint32 seq_num;
  guint16 len;
  guint64 t_sent_ms;
  guint8 *data;
} FpPkt;

struct _FillpPeer {
  FillpEngine *engine;
  gboolean is_client;
  volatile gint state; /* FpState; engine thread (reads best-effort) */

  guint16 port;
  GSocketAddress *sock_addr;
  gchar *key; /* "ip:port" */

  /* handshake */
  guint8 cookie[FILLP_COOKIE_LEN];
  guint64 t_stage_ms;
  /* Client-side handshake retransmit: while PENDING the client
   * resends its last sent message every FP_HS_RETRANS_MS (CONN_REQ
   * until the ACK arrives, then CONN_CONFIRM); the server answers
   * duplicates by resending its own message. @cookie holds the
   * server's cookie on the client (echoed in CONN_CONFIRM). */
  guint32 req_preserve_us;
  guint32 req_send_cache;
  guint32 req_recv_cache;
  guint64 req_ts;
  guint16 hs_tag; /* tagCookie from the CONN_REQ_ACK */
  gboolean hs_confirm_sent;
  guint64 t_hs_retrans_ms;

  /* send */
  guint32 send_pkt_num;
  guint32 send_seq_num;
  GByteArray *txq;
  GList *inflight; /* FpPkt*, oldest first */
  guint64 inflight_bytes;
  gboolean fill_done;
  gboolean tx_notified;

  /* receive */
  guint32 recv_pkt_num;
  guint32 recv_seq_num;
  GHashTable *ofo; /* guint32 pktNum (boxed ptr) → FpPkt* */
  guint64 ofo_bytes;
  guint64 delivered_since_pack;
  guint64 t_last_pack_ms;
  guint64 t_last_nack_ms;

  FillpPeerFillFunc fill_fn;
  gpointer app_data;

  /* per-peer stream callbacks (take precedence over the engine-level
   * on_data/on_tx_complete; user_data is per-peer) */
  FillpOnDataCb on_data;
  FillpOnTxCompleteCb on_tx_complete;
  gpointer stream_ud;

  /* close coordination (see FP_PKT_FIN in fp_handle_datagram) */
  gboolean peer_fin;    /* received a FIN from the peer */
  gboolean pending_fin; /* reply-FIN owed once our tx has drained */
};

struct _FillpEngine {
  volatile gint refs;         /* external + engine-internal */
  volatile gint thread_alive;

  GMutex lock;                /* guards the 3 flags + peers table */
  gboolean thread_started;
  gboolean thread_done;
  gboolean close_requested;
  gboolean close_in_progress;

  GSocket *socket;
  guint port;
  guint8 mac_key[32];  /* local cookie HMAC key, never sent */
  guint8 local_addr[FILLP_ADDR_LEN];

  GMainContext *ctx;
  GMainLoop *loop;
  GThread *thread;
  GSource *io_source;
  GSource *tick_source;
  GHashTable *peers;

  FillpOnEstablishedCb on_established;
  FillpOnDataCb on_data;
  FillpOnTxCompleteCb on_tx_complete;
  FillpOnClosedCb on_closed;
  gpointer user_data;
};

/* ============================ Helpers ============================ */

static guint64 fp_now_ms(void) {
  return (guint64)(g_get_monotonic_time() / 1000);
}

static void fp_pkt_free(FpPkt *pkt) {
  g_free(pkt->data);
  g_free(pkt);
}

static void fp_sendto(FillpPeer *p, const guint8 *buf, gsize len) {
  FillpEngine *e = p->engine;
  GError *err = NULL;
  gssize sent = g_socket_send_to(e->socket, p->sock_addr, (gchar *)buf, len,
                                 NULL, &err);
  if (sent != (gssize)len) {
    /* UDP is best-effort; NACK + stall valve recover. */
    g_print("fillp[%s]: sendto: %s\n", p->key,
            err ? err->message : "unknown");
    g_clear_error(&err);
  }
}

static FillpPeer *fp_peer_new(FillpEngine *e, GInetAddress *addr, guint16 port,
                              gboolean is_client) {
  FillpPeer *p = g_new0(FillpPeer, 1);
  p->engine = e;
  p->is_client = is_client;
  p->state = FP_ST_PENDING;
  p->port = port;
  p->sock_addr = g_inet_socket_address_new(addr, port);
  p->key = g_strdup_printf("%s:%u", g_inet_address_to_string(addr), port);
  p->txq = g_byte_array_new();
  p->ofo = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
                                 (GDestroyNotify)fp_pkt_free);
  p->t_stage_ms = fp_now_ms();
  p->t_hs_retrans_ms = fp_now_ms();
  return p;
}

static void fp_free_tx(FillpPeer *p) {
  if (p->txq) {
    g_byte_array_free(p->txq, TRUE);
    p->txq = NULL;
  }
  g_list_free_full(p->inflight, (GDestroyNotify)fp_pkt_free);
  p->inflight = NULL;
  p->inflight_bytes = 0;
}

static void fp_free_rx(FillpPeer *p) {
  if (p->ofo) {
    g_hash_table_destroy(p->ofo);
    p->ofo = NULL;
  }
  p->ofo_bytes = 0;
}

static void fp_peer_established(FillpPeer *p) {
  p->state = FP_ST_ESTABLISHED;
  p->t_stage_ms = fp_now_ms();
  g_print("fillp[%s]: established\n", p->key);
  FillpEngine *e = p->engine;
  if (e->on_established) e->on_established(e, p, e->user_data);
}

/* ============================ Peer teardown ============================ */

/*
 * Engine thread only. Frees the peer and fires on_closed (the peer is
 * valid during the callback, dead after it returns). Idempotent via
 * the state guard.
 */
static void fp_peer_finalize(FillpPeer *p, const gchar *reason) {
  if (p->state == FP_ST_CLOSED) return;
  g_print("fillp[%s]: closing: %s\n", p->key, reason);
  p->state = FP_ST_CLOSED;
  FillpEngine *e = p->engine;
  fp_free_tx(p);
  fp_free_rx(p);
  if (e->on_closed) e->on_closed(e, p, reason, e->user_data);
  gchar *key = p->key;
  p->key = NULL;
  g_object_unref(p->sock_addr);
  g_mutex_lock(&e->lock);
  /* The table holds p->key itself; remove() destroys it via the key
   * destroy function (g_free) — do not free it a second time. */
  g_hash_table_remove(e->peers, key);
  g_mutex_unlock(&e->lock);
  g_free(p);
}

/*
 * Engine thread only. PENDING/ESTABLISHED → CLOSING (FIN when
 * established). The peer stays alive in CLOSING: the pump keeps
 * retransmitting and flushing acks, rx keeps accepting, and the tick
 * finalizes once the close drains (peer FIN + our tx drained + our acks
 * flushed) or after FP_CLOSE_TIMEOUT_MS.
 */
static void fp_peer_request_close(FillpPeer *p, const gchar *why) {
  if (p->state == FP_ST_CLOSED || p->state == FP_ST_CLOSING) return;
  g_print("fillp[%s]: close requested: %s\n", p->key, why);
  if (p->state == FP_ST_ESTABLISHED) {
    guint8 buf[FILLP_HLEN + FILLP_FIN_LEN];
    gsize total = fillp_encode_fin(buf, sizeof(buf), 0);
    fp_sendto(p, buf, total);
  }
  p->state = FP_ST_CLOSING;
  p->t_stage_ms = fp_now_ms();
}

static int fp_peer_close_cb(gpointer p_) {
  fp_peer_request_close((FillpPeer *)p_, "app close");
  return 0;
}

void fillp_peer_close(FillpPeer *p) {
  if (p == NULL) return;
  FillpEngine *e = p->engine;
  g_mutex_lock(&e->lock);
  if (p->state == FP_ST_CLOSED || p->state == FP_ST_CLOSING ||
      e->thread_done) {
    g_mutex_unlock(&e->lock);
    return;
  }
  if (e->thread_started)
    g_main_context_invoke_full(e->ctx, G_PRIORITY_DEFAULT, fp_peer_close_cb,
                               p, NULL);
  else
    fp_peer_request_close(p, "app close"); /* pre-loop: we are the only writer */
  g_mutex_unlock(&e->lock);
}

/* ============================ Handshake ============================ */

static void fp_send_conn_req_ack(FillpPeer *p) {
  guint8 buf[FILLP_HLEN + FILLP_CONN_REQ_ACK_LEN];
  gsize total = fillp_encode_conn_req_ack(
      buf, sizeof(buf), 1, p->cookie, (guint64)g_get_monotonic_time());
  fp_sendto(p, buf, total);
}

/* Client handshake retransmits (idempotent server-side: a duplicate
 * CONN_REQ makes the server resend its CONN_REQ_ACK, a duplicate
 * CONN_CONFIRM makes it resend the CONN_CONFIRM_ACK). */
static void fp_resend_conn_req(FillpPeer *p) {
  guint8 buf[FILLP_HLEN + FILLP_CONN_REQ_LEN];
  gsize total = fillp_encode_conn_req(buf, sizeof(buf), p->req_preserve_us,
                                      p->req_send_cache, p->req_recv_cache,
                                      p->req_ts);
  fp_sendto(p, buf, total);
}

static void fp_resend_conn_confirm(FillpPeer *p) {
  guint8 buf[FILLP_HLEN + FILLP_CONN_CONFIRM_LEN];
  gsize total = fillp_encode_conn_confirm(buf, sizeof(buf), p->hs_tag,
                                          p->cookie, p->engine->local_addr);
  fp_sendto(p, buf, total);
}

static void fp_handle_conn_req(FillpEngine *e, FillpPeer *p, GInetAddress *from,
                               guint16 from_port, const guint8 *buf,
                               gsize len) {
  guint32 pres = 0, sc = 0, rc = 0;
  guint64 ts = 0;
  if (!fillp_decode_conn_req(buf, len, &pres, &sc, &rc, &ts)) return;

  if (p != NULL) {
    /* Known peer: resend the ACK if we are still waiting (the client
     * may have missed it); ignore once established. */
    if (p->state == FP_ST_PENDING) fp_send_conn_req_ack(p);
    return;
  }

  FillpPeer *np = fp_peer_new(e, from, from_port, FALSE);
  g_mutex_lock(&e->lock);
  g_hash_table_insert(e->peers, np->key, np);
  g_mutex_unlock(&e->lock);

  guint32 life = FP_COOKIE_LIFETIME_US +
                 (pres > FP_PRESERVE_MAX_US ? FP_PRESERVE_MAX_US : pres);
  guint8 remote_addr[FILLP_ADDR_LEN];
  const guint8 *ip4 = g_inet_address_to_bytes(from);
  fillp_addr_fill_ipv4(remote_addr, from_port, ip4);
  fillp_cookie_fill(np->cookie, e->mac_key, (guint64)g_get_monotonic_time(),
                    life, (guint32)g_random_int(), (guint32)g_random_int(),
                    0, 0, sc, rc, e->port, 2 /* AF_INET */, remote_addr,
                    e->local_addr);
  fp_send_conn_req_ack(np);
}

static void fp_handle_conn_req_ack(FillpPeer *p, const guint8 *buf, gsize len) {
  if (p == NULL || p->state != FP_ST_PENDING || !p->is_client) return;
  guint16 tag = 0;
  guint64 ts = 0;
  if (!fillp_decode_conn_req_ack(buf, len, &tag, p->cookie, &ts)) return;
  p->hs_tag = tag;
  p->hs_confirm_sent = TRUE; /* retransmit target is now CONN_CONFIRM */
  guint8 buf2[FILLP_HLEN + FILLP_CONN_CONFIRM_LEN];
  gsize total = fillp_encode_conn_confirm(buf2, sizeof(buf2), tag, p->cookie,
                                          p->engine->local_addr);
  fp_sendto(p, buf2, total);
  p->t_stage_ms = fp_now_ms();
}

static void fp_handle_conn_confirm(FillpEngine *e, FillpPeer *p,
                                   const guint8 *buf, gsize len) {
  if (p == NULL || p->is_client) return;
  /* The client retransmits CONN_CONFIRM until its CONFIRM_ACK
   * arrives; a duplicate after ESTABLISHED means ours was lost —
   * resend it so the client can finish the handshake. */
  if (p->state != FP_ST_PENDING && p->state != FP_ST_ESTABLISHED) return;
  guint16 tag = 0;
  guint8 cookie[FILLP_COOKIE_LEN];
  guint8 laddr[FILLP_ADDR_LEN];
  if (!fillp_decode_conn_confirm(buf, len, &tag, cookie, laddr)) return;
  if (!fillp_cookie_verify(cookie, e->mac_key, e->local_addr)) {
    fp_peer_request_close(p, "cookie verify failed");
    return;
  }
  guint8 buf2[FILLP_HLEN + FILLP_CONN_CONFIRM_ACK_LEN];
  gsize total = fillp_encode_conn_confirm_ack(
      buf2, sizeof(buf2), FP_SEND_CACHE, FP_RECV_CACHE, FP_PKT_DATA_MAX,
      e->local_addr);
  fp_sendto(p, buf2, total);
  if (p->state == FP_ST_PENDING)
    fp_peer_established(p);
}

static void fp_handle_conn_confirm_ack(FillpPeer *p, const guint8 *buf,
                                       gsize len) {
  if (p == NULL || p->state != FP_ST_PENDING || !p->is_client) return;
  guint32 sc = 0, rc = 0, pkt_size = 0;
  guint8 laddr[FILLP_ADDR_LEN];
  if (!fillp_decode_conn_confirm_ack(buf, len, &sc, &rc, &pkt_size, laddr))
    return;
  fp_peer_established(p);
}

/* ============================ Data plane ============================ */

static void fp_deliver(FillpPeer *p, const guint8 *data, gsize len) {
  FillpEngine *e = p->engine;
  if (p->on_data)
    p->on_data(e, p, data, len, p->stream_ud);
  else if (e->on_data) e->on_data(e, p, data, len, e->user_data);
}

static void fp_send_pack(FillpPeer *p) {
  guint8 buf[FILLP_HLEN + FILLP_PACK_LEN];
  gsize total = fillp_encode_pack(buf, sizeof(buf), p->recv_seq_num,
                                  p->recv_pkt_num, p->recv_seq_num,
                                  (guint32)p->ofo_bytes);
  fp_sendto(p, buf, total);
  p->delivered_since_pack = 0;
  p->t_last_pack_ms = fp_now_ms();
}

static void fp_maybe_pack(FillpPeer *p) {
  guint64 now = fp_now_ms();
  if (p->delivered_since_pack == 0) return;
  if (p->delivered_since_pack < FP_PACK_FLUSH_BYTES &&
      now - p->t_last_pack_ms < FP_PACK_INTERVAL_MS)
    return;
  fp_send_pack(p);
}

static void fp_maybe_nack(FillpPeer *p) {
  guint64 now = fp_now_ms();
  if (now - p->t_last_nack_ms < FP_NACK_INTERVAL_MS) return;
  p->t_last_nack_ms = now;
  guint8 buf[FILLP_HLEN + FILLP_NACK_LEN];
  /* Stand convention (spec §8.7): retransmit exactly the first missing
   * packet: (begin, end) = (last in-order, last in-order + 2). */
  gsize total = fillp_encode_nack(buf, sizeof(buf), FP_PKT_NACK,
                                  p->recv_pkt_num, p->recv_pkt_num + 2,
                                  p->recv_seq_num,
                                  ((guint64)g_random_int() << 32) |
                                      (guint64)g_random_int());
  fp_sendto(p, buf, total);
}

static void fp_on_data(FillpPeer *p, const guint8 *buf, gsize len) {
  FpPktType type;
  guint16 flags = 0, data_len = 0;
  guint32 pkt_num = 0, seq_num = 0;
  if (!fillp_decode_head(buf, len, &type, &flags, &data_len, &pkt_num,
                         &seq_num))
    return;
  if (len < (gsize)FILLP_HLEN + (gsize)data_len) return;
  if (data_len > FP_PKT_DATA_MAX) return;
  const guint8 *payload = buf + FILLP_HLEN;

  /* Not ahead of the last in-order packet = duplicate (retransmit of an
   * already-delivered packet); the real fillp drops on
   * seqNum <= recv.seqNum, which is equivalent here. Re-ack anyway:
   * our PACK may have been lost, and the peer's stall valve is
   * retransmitting because it never saw it. */
  if (!fp_num_isbigger(pkt_num, p->recv_pkt_num)) {
    if (fp_now_ms() - p->t_last_pack_ms >= FP_NACK_INTERVAL_MS)
      fp_send_pack(p);
    return;
  }

  if (pkt_num == p->recv_pkt_num + 1) {
    p->recv_pkt_num = pkt_num;
    p->recv_seq_num = seq_num;
    p->delivered_since_pack += data_len;
    fp_deliver(p, payload, data_len);
    /* Flush buffered out-of-order packets that are now in order. */
    for (;;) {
      FpPkt *next =
          g_hash_table_lookup(p->ofo, GUINT_TO_POINTER(p->recv_pkt_num + 1));
      if (next == NULL) break;
      g_hash_table_remove(p->ofo, GUINT_TO_POINTER(p->recv_pkt_num + 1));
      p->recv_pkt_num = next->pkt_num;
      p->recv_seq_num = next->seq_num;
      p->delivered_since_pack += next->len;
      p->ofo_bytes -= next->len;
      fp_deliver(p, next->data, next->len);
      fp_pkt_free(next);
    }
    fp_maybe_pack(p);
  } else {
    /* Gap: buffer out-of-order (up to the OFO cap). */
    if (p->ofo_bytes + data_len <= FP_OFO_MAX_BYTES) {
      FpPkt *pkt = g_new0(FpPkt, 1);
      pkt->pkt_num = pkt_num;
      pkt->seq_num = seq_num;
      pkt->len = data_len;
      pkt->data = g_memdup2(payload, data_len);
      g_hash_table_replace(p->ofo, GUINT_TO_POINTER(pkt_num), pkt);
      p->ofo_bytes += data_len;
    }
    fp_maybe_nack(p);
  }
}

static void fp_on_nack(FillpPeer *p, const guint8 *buf, gsize len) {
  guint32 begin = 0, end = 0, seq = 0;
  if (!fillp_decode_nack(buf, len, &begin, &end, &seq)) return;
  guint8 pkt_buf[FILLP_HLEN + FP_PKT_DATA_MAX];
  for (GList *l = p->inflight; l; l = l->next) {
    FpPkt *pkt = l->data;
    if (fp_num_isbigger(pkt->pkt_num, begin) &&
        fp_num_isbigger(end, pkt->pkt_num)) {
      gsize total = fillp_encode_head(pkt_buf, FP_PKT_DATA, 0, pkt->len,
                                      pkt->pkt_num, pkt->seq_num);
      memcpy(pkt_buf + FILLP_HLEN, pkt->data, pkt->len);
      fp_sendto(p, pkt_buf, total + pkt->len);
      pkt->t_sent_ms = fp_now_ms();
    }
  }
}

static void fp_on_pack(FillpPeer *p, const guint8 *buf, gsize len) {
  guint32 ack_seq = 0, ack_pkt = 0, lost = 0, rl = 0;
  if (!fillp_decode_pack(buf, len, &ack_seq, &ack_pkt, &lost, &rl)) return;
  GList *l = p->inflight;
  while (l != NULL) {
    FpPkt *pkt = l->data;
    if (fp_num_isbigger(pkt->pkt_num, ack_pkt)) break; /* ascending list */
    GList *next = l->next;
    p->inflight = g_list_delete_link(p->inflight, l);
    p->inflight_bytes -= pkt->len;
    fp_pkt_free(pkt);
    l = next;
  }
}

/* ============================ Sender pump ============================ */

static void fp_pump(FillpPeer *p, guint64 now) {
  FillpEngine *e = p->engine;

  /* 1. Ask the app for more data while the queue has room. */
  if (p->fill_fn != NULL && !p->fill_done &&
      p->txq->len < FP_TXQ_WATERMARK) {
    gssize r = p->fill_fn(p, p->app_data);
    if (r < 0) p->fill_done = TRUE;
  }

  /* 2. Stall valve: the receiver NACKs on the first gap; if the NACK is
   * lost, retransmit the oldest inflight packet after 1 s (the real
   * stack does this via RTT-based RTO). */
  if (p->inflight != NULL) {
    FpPkt *oldest = p->inflight->data;
    if (now - oldest->t_sent_ms >= FP_STALL_TIMEOUT_MS) {
      guint8 pkt_buf[FILLP_HLEN + FP_PKT_DATA_MAX];
      gsize total = fillp_encode_head(pkt_buf, FP_PKT_DATA, 0, oldest->len,
                                      oldest->pkt_num, oldest->seq_num);
      memcpy(pkt_buf + FILLP_HLEN, oldest->data, oldest->len);
      fp_sendto(p, pkt_buf, total + oldest->len);
      oldest->t_sent_ms = now;
    }
  }

  /* 3. Packetize the queue into DATA packets (in-flight window cap). */
  guint budget = FP_SEND_BUDGET;
  while (budget-- > 0 && p->txq->len > 0 &&
         p->inflight_bytes < FP_SEND_CACHE) {
    gsize n = p->txq->len;
    if (n > FP_PKT_DATA_MAX) n = FP_PKT_DATA_MAX;
    p->send_pkt_num++;
    p->send_seq_num += (guint32)n;
    FpPkt *pkt = g_new0(FpPkt, 1);
    pkt->pkt_num = p->send_pkt_num;
    pkt->seq_num = p->send_seq_num;
    pkt->len = (guint16)n;
    pkt->t_sent_ms = now;
    pkt->data = g_memdup2(p->txq->data, n);
    g_byte_array_remove_range(p->txq, 0, n);
    p->inflight = g_list_append(p->inflight, pkt);
    p->inflight_bytes += n;

    guint8 pkt_buf[FILLP_HLEN + FP_PKT_DATA_MAX];
    gsize total = fillp_encode_head(pkt_buf, FP_PKT_DATA, 0, (guint16)n,
                                    pkt->pkt_num, pkt->seq_num);
    memcpy(pkt_buf + FILLP_HLEN, pkt->data, n);
    fp_sendto(p, pkt_buf, total + n);
  }

  /* 4. TX complete: the app queued its final byte and everything is
   * acked. */
  if (p->fill_done && p->txq->len == 0 && p->inflight == NULL &&
      !p->tx_notified) {
    p->tx_notified = TRUE;
    g_print("fillp[%s]: send complete (all %u bytes acked)\n", p->key,
            p->send_seq_num);
    if (p->on_tx_complete)
      p->on_tx_complete(e, p, p->stream_ud);
    else if (e->on_tx_complete) e->on_tx_complete(e, p, e->user_data);
  }

  /* 5. Periodic PACK: flush pending acks even when no new data arrives
   * (the peer's stream may have just ended; the tail ack would
   * otherwise never go out). */
  fp_maybe_pack(p);

  /* 6. Reply FIN: the peer sent a FIN and our tx has drained — hand it
   * a FIN (FIN/FIN exchange) so it knows our side is done; the tick
   * finalizes on the same condition. */
  if (p->pending_fin && p->fill_done && p->txq->len == 0 &&
      p->inflight == NULL) {
    p->pending_fin = FALSE;
    guint8 buf[FILLP_HLEN + FILLP_FIN_LEN];
    gsize total = fillp_encode_fin(buf, sizeof(buf), 0);
    fp_sendto(p, buf, total);
    g_print("fillp[%s]: FIN sent (reply, tx drained)\n", p->key);
  }
}

/* ============================ Datagram dispatch ============================ */

static void fp_handle_datagram(FillpEngine *e, GInetAddress *from,
                               guint16 from_port, const guint8 *buf,
                               gsize len) {
  if (len < FILLP_HLEN) return;
  FpPktType type;
  if (!fillp_decode_head(buf, len, &type, NULL, NULL, NULL, NULL)) return;
  gchar *key = g_strdup_printf("%s:%u", g_inet_address_to_string(from),
                               from_port);
  g_mutex_lock(&e->lock);
  FillpPeer *p = (FillpPeer *)g_hash_table_lookup(e->peers, key);
  g_mutex_unlock(&e->lock);

  switch (type) {
  case FP_PKT_CONN_REQ:
    fp_handle_conn_req(e, p, from, from_port, buf, len);
    break;
  case FP_PKT_CONN_REQ_ACK:
    fp_handle_conn_req_ack(p, buf, len);
    break;
  case FP_PKT_CONN_CONFIRM:
    fp_handle_conn_confirm(e, p, buf, len);
    break;
  case FP_PKT_CONN_CONFIRM_ACK:
    fp_handle_conn_confirm_ack(p, buf, len);
    break;
  case FP_PKT_DATA:
    if (p != NULL &&
        (p->state == FP_ST_ESTABLISHED || p->state == FP_ST_CLOSING))
      fp_on_data(p, buf, len);
    break;
  case FP_PKT_NACK:
    if (p != NULL && p->state == FP_ST_ESTABLISHED) fp_on_nack(p, buf, len);
    break;
  case FP_PKT_PACK:
    if (p != NULL &&
        (p->state == FP_ST_ESTABLISHED || p->state == FP_ST_CLOSING))
      fp_on_pack(p, buf, len);
    break;
  case FP_PKT_FIN:
    if (p != NULL && p->state != FP_ST_CLOSED) {
      /* Never finalize immediately: we may still owe the peer acks for
       * its last bytes (PACK throttle), and the peer may still owe us
       * acks for ours. Enter/stay in CLOSING; the tick finalizes once
       * the close drains or on timeout. */
      p->peer_fin = TRUE;
      p->pending_fin = TRUE;
      if (p->state != FP_ST_CLOSING) {
        p->state = FP_ST_CLOSING;
        p->t_stage_ms = fp_now_ms();
        g_print("fillp[%s]: peer sent FIN; draining close\n", p->key);
      }
    }
    break;
  default: /* HISTORY_NACK and unknowns: stand ignores */
    break;
  }
  g_free(key);
}

/* ============================ I/O ============================ */

static void fp_drain(FillpEngine *e) {
  guint8 buf[2048];
  for (;;) {
    GSocketAddress *from_sa = NULL;
    GError *err = NULL;
    gssize n = g_socket_receive_from(e->socket, &from_sa, (gchar *)buf,
                                     sizeof(buf), NULL, &err);
    if (n > 0) {
      GInetAddress *from = NULL;
      guint16 from_port = 0;
      if (from_sa != NULL && G_IS_INET_SOCKET_ADDRESS(from_sa)) {
        from = g_inet_socket_address_get_address(
            (GInetSocketAddress *)from_sa);
        from_port = g_inet_socket_address_get_port(
            (GInetSocketAddress *)from_sa);
      }
      if (from_sa != NULL) g_object_unref(from_sa);
      if (from != NULL) fp_handle_datagram(e, from, from_port, buf, (gsize)n);
      continue;
    }
    if (from_sa != NULL) g_object_unref(from_sa);
    if (g_error_matches(err, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
      g_clear_error(&err);
      break;
    }
    g_clear_error(&err); /* e.g. ICMP-port-unreachable: ignore */
    break;
  }
}

/*
 * Non-deprecated socket I/O: a GSource polling the socket fd (same
 * pattern as dfile_conn.c; g_io_channel_unix_new() is deprecated).
 */
typedef struct {
  GSource  source;
  GPollFD  poll;
} FpIoSource;

static gboolean fp_io_prepare(GSource *src, gint *timeout) {
  (void)src;
  *timeout = -1;
  return FALSE;
}

static gboolean fp_io_check(GSource *src) {
  FpIoSource *s = (FpIoSource *)src;
  return s->poll.revents != 0;
}

static gboolean fp_io_dispatch(GSource *src, GSourceFunc callback,
                               gpointer user_data) {
  FpIoSource *s = (FpIoSource *)src;
  s->poll.revents = 0;
  return callback(user_data);
}

static GSourceFuncs fp_io_funcs = {
    .prepare = fp_io_prepare,
    .check = fp_io_check,
    .dispatch = fp_io_dispatch,
    .finalize = NULL,
};

static gboolean on_io_source(gpointer p) {
  fp_drain((FillpEngine *)p);
  return TRUE;
}

static GSource *fp_add_io_watch(FillpEngine *e) {
  GSource *src = g_source_new(&fp_io_funcs, sizeof(FpIoSource));
  FpIoSource *s = (FpIoSource *)src;
  s->poll.fd = (int)g_socket_get_fd(e->socket);
  s->poll.events = G_IO_IN | G_IO_HUP | G_IO_ERR;
  s->poll.revents = 0;
  g_source_add_poll(src, &s->poll);
  g_source_set_priority(src, G_PRIORITY_DEFAULT);
  g_source_set_callback(src, on_io_source, e, NULL);
  /* g_source_attach() takes a ref in this GLib; the context owns the
   * source until teardown destroys it. The returned pointer is a
   * non-owning handle. */
  g_source_attach(src, e->ctx);
  g_source_unref(src);
  return src;
}

/* ============================ Tick ============================ */

static gboolean fp_on_tick(gpointer p) {
  FillpEngine *e = (FillpEngine *)p;
  guint64 now = fp_now_ms();

  g_mutex_lock(&e->lock);
  GList *snapshot = g_hash_table_get_values(e->peers);
  g_mutex_unlock(&e->lock);

  GList *to_finalize = NULL;
  for (GList *l = snapshot; l != NULL; l = l->next) {
    FillpPeer *p = (FillpPeer *)l->data;
    gint st = p->state;
    if (st == FP_ST_PENDING) {
      if (now - p->t_stage_ms >= FP_HANDSHAKE_TIMEOUT_MS) {
        fp_peer_request_close(p, "handshake timeout");
      } else if (p->is_client &&
                 now - p->t_hs_retrans_ms >= FP_HS_RETRANS_MS) {
        p->t_hs_retrans_ms = now;
        if (p->hs_confirm_sent)
          fp_resend_conn_confirm(p);
        else
          fp_resend_conn_req(p);
      }
    } else if (st == FP_ST_ESTABLISHED || st == FP_ST_CLOSING) {
      /* The pump runs in CLOSING too: stall-valve retransmits, tx
       * completion, pending PACKs and the reply FIN must keep flowing
       * until the close drains. */
      fp_pump(p, now);
      if (p->state == FP_ST_CLOSING &&
          ((p->peer_fin && p->fill_done && p->txq->len == 0 &&
            p->inflight == NULL && p->delivered_since_pack == 0) ||
           now - p->t_stage_ms >= FP_CLOSE_TIMEOUT_MS))
        to_finalize = g_list_prepend(to_finalize, p);
    }
  }
  for (GList *l = to_finalize; l != NULL; l = l->next) {
    FillpPeer *p = (FillpPeer *)l->data;
    gboolean drained = p->peer_fin && p->fill_done && p->txq->len == 0 &&
                       p->inflight == NULL && p->delivered_since_pack == 0;
    fp_peer_finalize(p, drained ? "close drained" : "close timeout");
  }
  g_list_free(to_finalize);
  g_list_free(snapshot);
  return TRUE;
}

/* ============================ Thread / lifecycle ============================ */

static void fp_engine_free(FillpEngine *e) {
  if (e->thread) g_thread_unref(e->thread);
  g_mutex_clear(&e->lock);
  g_free(e);
}

/*
 * Engine thread, after the loop exits. Frees everything, marks the
 * thread done (under e->lock, BEFORE the context is unrefed — close()
 * relies on that ordering), drops the internal ref, frees if we were
 * the last one. (Same pattern as dfile_conn.c.)
 */
static void fp_engine_teardown(FillpEngine *e) {
  if (e->io_source) {
    g_source_destroy(e->io_source);
    e->io_source = NULL;
  }
  if (e->tick_source) {
    g_source_destroy(e->tick_source);
    e->tick_source = NULL;
  }
  g_object_unref(e->socket);
  e->socket = NULL;
  if (e->peers != NULL) {
    g_hash_table_destroy(e->peers);
    e->peers = NULL;
  }
  /* user_data belongs to the app; never freed here. */

  g_mutex_lock(&e->lock);
  e->thread_done = TRUE;
  e->thread_started = FALSE;
  g_mutex_unlock(&e->lock);

  g_main_loop_unref(e->loop);
  e->loop = NULL;
  g_main_context_unref(e->ctx);
  e->ctx = NULL;

  g_atomic_int_set(&e->thread_alive, 0);
  if (g_atomic_int_dec_and_test(&e->refs)) fp_engine_free(e);
}

static gpointer fp_engine_thread(gpointer p) {
  FillpEngine *e = (FillpEngine *)p;
  g_atomic_int_set(&e->thread_alive, 1);

  gboolean pre_closed = FALSE;
  g_mutex_lock(&e->lock);
  if (e->close_requested)
    pre_closed = TRUE;
  else
    e->thread_started = TRUE;
  g_mutex_unlock(&e->lock);

  if (pre_closed) {
    /* Close was requested before the thread ran: no sources, no loop —
     * the single teardown below does all the cleanup (incl. socket). */
  } else {
    e->io_source = fp_add_io_watch(e);
    GSource *tick = g_timeout_source_new(FP_TICK_MS);
    g_source_set_priority(tick, G_PRIORITY_DEFAULT);
    g_source_set_callback(tick, fp_on_tick, e, NULL);
    g_source_attach(tick, e->ctx);
    g_source_unref(tick);
    e->tick_source = tick; /* non-owning handle */
    g_main_loop_run(e->loop);
  }

  fp_engine_teardown(e);
  return NULL;
}

static void fp_engine_abort(FillpEngine *e) {
  if (e->loop) g_main_loop_unref(e->loop);
  if (e->ctx) g_main_context_unref(e->ctx);
  g_mutex_clear(&e->lock);
  g_free(e);
}

/*
 * Engine thread only. Finalizes all peers (firing on_closed for each),
 * stops the I/O and quits the loop. Idempotent via close_in_progress.
 */
static void fp_engine_shutdown(FillpEngine *e, const gchar *reason) {
  if (e->close_in_progress) return;
  e->close_in_progress = TRUE;
  g_print("fillp[engine:%u]: closing: %s\n", e->port, reason);

  g_mutex_lock(&e->lock);
  GList *snapshot = g_hash_table_get_values(e->peers);
  g_mutex_unlock(&e->lock);
  for (GList *l = snapshot; l != NULL; l = l->next)
    fp_peer_finalize((FillpPeer *)l->data, reason);
  g_list_free(snapshot);

  /* Sources live on e->ctx, not the default context — plain
   * g_source_remove() would look in the wrong context. This GLib's
   * g_source_attach() takes a ref, so the context owns the source
   * until we destroy it; g_source_destroy() is safe from within
   * dispatch. */
  if (e->io_source) {
    g_source_destroy(e->io_source);
    e->io_source = NULL;
  }
  if (e->tick_source) {
    g_source_destroy(e->tick_source);
    e->tick_source = NULL;
  }
  g_main_loop_quit(e->loop);
}

static int fp_engine_close_impl(gpointer p) {
  fp_engine_shutdown((FillpEngine *)p, "closed by application");
  return 0;
}

void fillp_engine_close(FillpEngine *e) {
  if (e == NULL) return;
  g_mutex_lock(&e->lock);
  if (e->close_requested || e->thread_done) {
    g_mutex_unlock(&e->lock);
    return;
  }
  e->close_requested = TRUE;
  if (e->thread_started)
    g_main_context_invoke_full(e->ctx, G_PRIORITY_DEFAULT,
                               fp_engine_close_impl, e, NULL);
  g_mutex_unlock(&e->lock);
  /* !thread_started: the engine thread tears down before loop start */
}

/* ============================ Public API ============================ */

FillpEngine* fillp_engine_new(guint port, GError **error) {
  FillpEngine *e = g_new0(FillpEngine, 1);
  e->refs = 2; /* creator + engine-internal */
  g_mutex_init(&e->lock);
  e->port = port;
  e->ctx = g_main_context_new();
  e->loop = g_main_loop_new(e->ctx, FALSE);
  e->peers =
      g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
  softbus_random_bytes(e->mac_key, 32);
  /* Wildcard-bound engine: the local address field is cosmetic (only
   * used inside the server-side cookie HMAC; identical at generation
   * and verification time). */
  fillp_addr_fill_ipv4(e->local_addr, port, (const guint8[]){0, 0, 0, 0});

  e->socket = g_socket_new(G_SOCKET_FAMILY_IPV4, G_SOCKET_TYPE_DATAGRAM,
                           G_SOCKET_PROTOCOL_UDP, error);
  if (e->socket == NULL) {
    g_prefix_error(error, "fillp engine: ");
    fp_engine_abort(e);
    return NULL;
  }
  g_socket_set_blocking(e->socket, FALSE);
  GSocketAddress *la =
      g_inet_socket_address_new(g_inet_address_new_any(G_SOCKET_FAMILY_IPV4),
                                port);
  gboolean bound = g_socket_bind(e->socket, la, TRUE, error);
  g_object_unref(la);
  if (!bound) {
    g_prefix_error(error, "fillp engine: bind port %u: ", port);
    g_object_unref(e->socket);
    fp_engine_abort(e);
    return NULL;
  }
  e->thread = g_thread_new("fillp-engine", fp_engine_thread, e);
  return e;
}

void fillp_engine_set_callbacks(FillpEngine *e,
                                FillpOnEstablishedCb on_established,
                                FillpOnDataCb on_data,
                                FillpOnTxCompleteCb on_tx_complete,
                                FillpOnClosedCb on_closed,
                                gpointer user_data) {
  if (e == NULL) return;
  /* Plain field writes: set immediately after construction, long before
   * any peer traffic can arrive (a full RTT). Callbacks are NULL-checked
   * before every call, so an early fire is simply skipped. */
  e->on_established = on_established;
  e->on_data = on_data;
  e->on_tx_complete = on_tx_complete;
  e->on_closed = on_closed;
  e->user_data = user_data;
}

FillpPeer* fillp_engine_connect(FillpEngine *e, const gchar *host, guint port,
                                GError **error) {
  if (e == NULL) {
    g_set_error_literal(error, fp_quark(), FP_E_INVALID, "null engine");
    return NULL;
  }
  GInetAddress *addr = g_inet_address_new_from_string(host);
  if (addr == NULL ||
      g_inet_address_get_family(addr) != G_SOCKET_FAMILY_IPV4) {
    g_clear_object(&addr);
    g_set_error(error, fp_quark(), FP_E_INVALID, "invalid IPv4 host: %s",
                host);
    return NULL;
  }

  g_mutex_lock(&e->lock);
  if (e->close_requested || e->thread_done) {
    g_mutex_unlock(&e->lock);
    g_object_unref(addr);
    g_set_error_literal(error, fp_quark(), FP_E_CLOSED, "engine closed");
    return NULL;
  }
  FillpPeer *p = fp_peer_new(e, addr, port, TRUE);
  /* Retransmit state: the client re-sends this exact CONN_REQ while
   * PENDING (idempotent server-side), so keep the original params.
   * Written before the table insert, i.e. before the engine thread
   * can observe the peer. */
  p->req_preserve_us = FP_CLIENT_PRESERVE_US;
  p->req_send_cache = FP_SEND_CACHE;
  p->req_recv_cache = FP_RECV_CACHE;
  p->req_ts = (guint64)g_get_monotonic_time();
  g_hash_table_insert(e->peers, p->key, p);
  g_mutex_unlock(&e->lock);
  g_object_unref(addr);

  /* Single sendto of the CONN_REQ — the peer cannot receive anything
   * before this, so no peer state is touched outside the engine thread
   * beyond the table registration above. */
  guint8 buf[FILLP_HLEN + FILLP_CONN_REQ_LEN];
  gsize total = fillp_encode_conn_req(buf, sizeof(buf), p->req_preserve_us,
                                      p->req_send_cache, p->req_recv_cache,
                                      p->req_ts);
  GError *serr = NULL;
  gssize sent = g_socket_send_to(e->socket, p->sock_addr, (gchar *)buf, total,
                                 NULL, &serr);
  if (sent != (gssize)total) {
    gchar *msg = g_strdup_printf("CONN_REQ send failed: %s",
                                 serr ? serr->message : "unknown");
    g_clear_error(&serr);
    fillp_peer_close(p); /* the app gets on_closed */
    g_set_error(error, fp_quark(), FP_E_CLOSED, "%s", msg);
    g_free(msg);
    return p;
  }
  return p;
}

FillpEngine* fillp_engine_ref(FillpEngine *e) {
  if (e == NULL) return NULL;
  g_atomic_int_inc(&e->refs);
  return e;
}

void fillp_engine_unref(FillpEngine *e) {
  if (e == NULL) return;
  if (g_atomic_int_dec_and_test(&e->refs)) fp_engine_free(e);
}

guint fillp_engine_port(FillpEngine *e) {
  return e ? e->port : 0;
}

void fillp_peer_send(FillpPeer *p, const guint8 *data, gsize len) {
  if (p == NULL || len == 0) return;
  if (p->state != FP_ST_ESTABLISHED) return; /* dropped */
  g_byte_array_append(p->txq, data, len);
}

void fillp_peer_set_app_data(FillpPeer *p, gpointer app_data) {
  if (p != NULL) p->app_data = app_data;
}

void fillp_peer_set_fill_func(FillpPeer *p, FillpPeerFillFunc fn) {
  if (p != NULL) p->fill_fn = fn;
}

void fillp_peer_set_stream_cbs(FillpPeer *p, FillpOnDataCb on_data,
                               FillpOnTxCompleteCb on_tx_complete,
                               gpointer user_data) {
  if (p == NULL) return;
  p->on_data = on_data;
  p->on_tx_complete = on_tx_complete;
  p->stream_ud = user_data;
}

gboolean fillp_peer_is_established(FillpPeer *p) {
  return p != NULL && p->state == FP_ST_ESTABLISHED;
}

const gchar* fillp_peer_state_name(FillpPeer *p) {
  if (p == NULL) return "null";
  switch (p->state) {
  case FP_ST_PENDING:
    return "pending";
  case FP_ST_ESTABLISHED:
    return "established";
  case FP_ST_CLOSING:
    return "closing";
  case FP_ST_CLOSED:
    return "closed";
  }
  return "?";
}

guint fillp_peer_port(FillpPeer *p) {
  return p ? p->port : 0;
}
