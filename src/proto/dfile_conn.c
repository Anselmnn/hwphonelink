/*
 * dfile_conn.c - DFile transfer connection engine
 *
 * See dfile_conn.h for the wire flow. All engine state is touched only
 * from the engine thread; the only cross-thread handshake is the
 * close request (guarded by c->lock) and the refcount (atomic).
 *
 * Lifetime: refs start at 2 (creator + engine-internal). The internal
 * ref is dropped as the last step of the engine thread, so the
 * structure can never be freed while the thread is alive, and it is
 * safe to drop the external ref from a callback (e.g. on_closed).
 */

#include "proto/dfile_conn.h"
#include "proto/dfile_frame.h"
#include "proto/ft_testfile.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ============================ Tuning ============================ */

#define DC_NEGOTIATE_TIMEOUT_MS 5000   /* setting exchange budget        */
#define DC_TRANSFER_TIMEOUT_MS 30000   /* per-direction transfer budget  */
#define DC_CTRL_RETRY_INTERVAL_MS 3000 /* FILE_HEADER retransmit period  */
#define DC_CTRL_MAX_RETRIES 3          /* before giving up               */
#define DC_RETRAN_INTERVAL_MS 500      /* data retransmit pace           */
#define DC_TICK_MS 1
#define DC_SEND_BUDGET 64              /* max data frames per tick       */
#define DC_READ_CHUNK 8192

/* ============================ State ============================ */

typedef enum {
  DC_ST_NEGOTIATING,
  DC_ST_READY,
  DC_ST_CLOSING,
} DCState;

typedef enum {
  DC_PH_IDLE = 0,
  DC_PH_TX_WAIT_CONFIRM_REQ,  /* header sent, awaiting confirm + req */
  DC_PH_TX_SENDING,           /* streaming data */
  DC_PH_TX_WAIT_DONE,         /* all data sent, awaiting DONE + acks */
  DC_PH_TX_DONE,
  DC_PH_RX_WAIT_DATA,         /* header complete, confirm+req sent   */
  DC_PH_RX_WAIT_DONEACK,      /* all written, DONE sent              */
  DC_PH_RX_DONE,
  DC_PH_FAILED,
} DCPhase;

typedef struct {
  guint16 file_id;
  guint64 size;
  gchar  *name;

  gint    fd;
  guint32 total_blocks;

  /* sender */
  guint32 next_seq;
  GArray  *retrans;       /* guint32 seqs, oldest first */
  guint32 last_acked;     /* contiguous; G_MAXUINT32 = none yet */
  gboolean acked_all;
  gboolean confirmed;

  /* receiver */
  gchar   *dst_path;
  guint32  expected_seq;
  gboolean write_complete;
  GChecksum *sha;
  gchar     *expected_sha; /* from wire name, NULL if not ft-<sha>.bin */
} DCFile;

typedef struct {
  gboolean is_sender;
  guint16 trans_id;
  DCPhase  phase;
  GPtrArray *files;       /* DCFile* */

  /* rx: FILE_HEADER accumulation */
  guint16 node_number;
  DFileHeaderEntry *hdr;
  gsize   hdr_n;

  guint64 t0_ms;
  guint64 last_ctrl_ms;
  guint32 ctrl_retries;
  guint64 last_ack_ms;
  guint64 last_retran_ms;

  /* tx */
  gboolean req_received;
  gboolean all_confirmed;
  gboolean done_received;
  gboolean doneack_sent;

  /* rx */
  gboolean ack_pending;
  gboolean done_sent;

  gchar *result_msg;
} DCTrans;

struct _DFileConn {
  volatile gint refs;         /* external + engine-internal */
  volatile gint thread_alive;

  GMutex lock;                /* guards the 3 flags below */
  gboolean thread_started;    /* loop is (or will be) running */
  gboolean thread_done;       /* teardown finished */
  gboolean close_requested;

  GSocketConnection *conn;
  GSocket *socket;
  GMainContext *ctx;
  GMainLoop *loop;
  GThread *thread;

  GSource *io_source;
  GSource *tick_source;
  GByteArray *rxbuf;

  DCState state;
  guint64 t_connect_ms;

  gboolean local_setting_sent;
  DFileSetting peer_setting;
  gboolean negotiated;
  guint block_size;

  DCTrans *tx;
  DCTrans *rx;
  guint16 next_trans_id;
  gchar *recv_dir;

  DFileConnNegotiatedCb on_negotiated;
  DFileConnFileListCb on_file_list;
  DFileConnResultCb on_result;
  DFileConnClosedCb on_closed;
  gpointer user_data;

  gchar *log_name;
};

/* ============================ Helpers ============================ */

static guint64 dc_now_ms(void) {
  return (guint64)(g_get_monotonic_time() / 1000);
}

static GQuark dc_quark(void) {
  return g_quark_from_static_string("hwphonelink-dfile");
}

static gboolean dc_on_engine_thread(const DFileConn *c) {
  return c->thread != NULL && c->thread == g_thread_self();
}

static void dcfile_free(DCFile *f) {
  if (f == NULL) return;
  if (f->fd >= 0) close(f->fd);
  g_free(f->name);
  g_free(f->dst_path);
  if (f->retrans) g_array_free(f->retrans, TRUE);
  if (f->sha) g_checksum_free(f->sha);
  g_free(f->expected_sha);
  g_free(f);
}

static void trans_free(DCTrans *t) {
  if (t == NULL) return;
  if (t->files) g_ptr_array_free(t->files, TRUE);
  dfile_header_entries_free(t->hdr, t->hdr_n);
  g_free(t->result_msg);
  g_free(t);
}

static DCTrans *trans_new(gboolean is_sender, guint16 trans_id) {
  DCTrans *t = g_new0(DCTrans, 1);
  t->is_sender = is_sender;
  t->trans_id = trans_id;
  t->phase = DC_PH_IDLE;
  t->files = g_ptr_array_new_with_free_func((GDestroyNotify)dcfile_free);
  t->t0_ms = dc_now_ms();
  t->last_ctrl_ms = t->t0_ms;
  t->last_ack_ms = t->t0_ms;
  return t;
}

/*
 * Complete write on the non-blocking socket: loop g_socket_send(),
 * polling for writability on WOULD_BLOCK (the engine thread is free to
 * block on its own fd — nothing else can interleave).
 */
static gboolean dc_send(DFileConn *c, const guint8 *frame, gsize len,
                        GError **error) {
  gsize sent = 0;
  while (sent < len) {
    GError *err = NULL;
    gssize w = g_socket_send(c->socket, (const gchar *)frame + sent,
                             len - sent, NULL, &err);
    if (w > 0) {
      sent += (gsize)w;
      continue;
    }
    if (err && g_error_matches(err, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
      g_clear_error(&err);
      GPollFD pfd = {
          .fd = (int)g_socket_get_fd(c->socket),
          .events = G_IO_OUT,
          .revents = 0,
      };
      if (g_poll(&pfd, 1, -1) <= 0) {
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_CANCELLED,
                            "poll interrupted during send");
        return FALSE;
      }
      continue;
    }
    if (err) *error = g_error_copy(err);
    return FALSE;
  }
  return TRUE;
}

static const gchar *rst_code_str(guint16 code) {
  switch (code) {
    case DFILE_RST_NO_ERROR:          return "no error";
    case DFILE_RST_WITHOUT_SETTING:   return "without setting";
    case DFILE_RST_FILE_WRITE_ERROR:  return "file write error";
    case DFILE_RST_FILE_READ_ERROR:   return "file read error";
    case DFILE_RST_NO_ENOUGH_STORAGE: return "not enough storage";
    case DFILE_RST_INTERNAL_ERROR:    return "internal error";
    case DFILE_RST_CANCEL:            return "cancel";
    default:                          return "unknown rst code";
  }
}

static gboolean dc_send_rst(DFileConn *c, guint16 trans_id, guint16 code,
                            const guint16 *ids, gsize n) {
  guint8 buf[DFILE_FRAME_HEADER_LEN + 2 + 2 * DFILE_MAX_FILE_NUM];
  gssize sz = dfile_encode_rst(buf, sizeof(buf), trans_id, code, ids, n);
  if (sz < 0) return FALSE;
  return dc_send(c, buf, (gsize)sz, NULL);
}

static DCFile *find_file(DCTrans *t, guint16 file_id) {
  for (guint i = 0; i < t->files->len; i++) {
    DCFile *f = (DCFile *)g_ptr_array_index(t->files, i);
    if (f->file_id == file_id) return f;
  }
  return NULL;
}

static void trans_fail(DFileConn *c, DCTrans *t, const gchar *reason,
                       gboolean send_rst) {
  if (t == NULL) return;
  if (t->phase == DC_PH_FAILED || t->phase == DC_PH_TX_DONE ||
      t->phase == DC_PH_RX_DONE)
    return;
  g_print("dfile[%s]: transfer %u %s failed: %s\n", c->log_name,
          t->trans_id, t->is_sender ? "send" : "recv", reason);
  t->phase = DC_PH_FAILED;
  if (send_rst) dc_send_rst(c, t->trans_id, DFILE_RST_CANCEL, NULL, 0);
  if (c->on_result)
    c->on_result(c, t->is_sender, FALSE, reason, c->user_data);
}

static void shutdown_common(DFileConn *c, const gchar *reason);

static void dc_teardown(DFileConn *c);

/*
 * Engine thread only. Idempotent via the state guard: on_closed fires
 * exactly once per connection.
 */
static void shutdown_common(DFileConn *c, const gchar *reason) {
  if (c->state == DC_ST_CLOSING) return;
  g_print("dfile[%s]: closing: %s\n", c->log_name, reason);
  c->state = DC_ST_CLOSING;
  trans_fail(c, c->tx, reason, FALSE);
  trans_fail(c, c->rx, reason, FALSE);
  /* Sources live on c->ctx, not the default context — plain
   * g_source_remove() would look in the wrong context.  This GLib's
   * g_source_attach() takes a ref, so the context owns the source until
   * we destroy it; g_source_destroy() is safe from within dispatch. */
  if (c->io_source) {
    g_source_destroy(c->io_source);
    c->io_source = NULL;
  }
  if (c->tick_source) {
    g_source_destroy(c->tick_source);
    c->tick_source = NULL;
  }
  g_socket_shutdown(c->socket, TRUE, TRUE, NULL);
  if (c->on_closed) c->on_closed(c, c->user_data);
  g_main_loop_quit(c->loop);
}

static int close_impl(gpointer p) {
  DFileConn *c = (DFileConn *)p;
  shutdown_common(c, "closed by application");
  return 0;
}

/* ============================ Sender: pump ============================ */

static gboolean tx_all_sent(DCTrans *t) {
  for (guint i = 0; i < t->files->len; i++) {
    DCFile *f = (DCFile *)g_ptr_array_index(t->files, i);
    if (f->next_seq < f->total_blocks || f->retrans->len > 0) return FALSE;
  }
  return TRUE;
}

static gboolean tx_all_acked(DCTrans *t) {
  for (guint i = 0; i < t->files->len; i++) {
    DCFile *f = (DCFile *)g_ptr_array_index(t->files, i);
    if (!f->acked_all) return FALSE;
  }
  return TRUE;
}

/*
 * Encode the (possibly multi-frame) FILE_HEADER list and send every frame.
 * Returns FALSE on encode/send error.
 */
static gboolean tx_send_header(DFileConn *c, DCTrans *t) {
  gsize n = t->files->len;
  DFileHeaderEntry *ents = g_new(DFileHeaderEntry, n);
  for (gsize i = 0; i < n; i++) {
    DCFile *f = (DCFile *)g_ptr_array_index(t->files, i);
    ents[i].file_id = f->file_id;
    ents[i].file_size = f->size;
    ents[i].name = f->name;
  }
  gboolean ok = TRUE;
  guint8 buf[DFILE_FRAME_MAX_SIZE + 16];
  gsize start = 0;
  while (start < n) {
    gsize written = 0;
    gssize sz = dfile_encode_file_header(buf, sizeof(buf), t->trans_id,
                                         (guint16)n, ents, start, n - start,
                                         &written);
    if (sz < 0 || written == 0 ||
        !dc_send(c, buf, (gsize)sz, NULL)) {
      ok = FALSE;
      break;
    }
    start += written;
  }
  g_free(ents);
  return ok;
}

/*
 * Engine thread only. See dfile_conn_send_files().
 */
static gboolean send_files_impl(DFileConn *c, const DFileSendItem *items,
                                gsize n, GError **error) {
  if (c->state != DC_ST_READY) {
    g_set_error_literal(error, dc_quark(), 0,
                        "connection not negotiated yet");
    return FALSE;
  }
  if (c->tx != NULL) {
    g_set_error_literal(error, dc_quark(), 0,
                        "a send transfer is already active");
    return FALSE;
  }
  if (n == 0 || n > DFILE_MAX_FILE_NUM) {
    g_set_error_literal(error, dc_quark(), 0, "file count out of range");
    return FALSE;
  }

  DCTrans *t = trans_new(TRUE, c->next_trans_id++);
  for (gsize i = 0; i < n; i++) {
    DCFile *f = g_new0(DCFile, 1);
    f->fd = -1;
    f->file_id = (guint16)(i + 1);
    f->name = g_strdup(items[i].name ? items[i].name : "unnamed");
    f->last_acked = G_MAXUINT32;
    f->retrans = g_array_new(FALSE, FALSE, sizeof(guint32));

    f->fd = open(items[i].path, O_RDONLY);
    if (f->fd < 0) {
      gchar *msg = g_strdup_printf("cannot open %s: %s", items[i].path,
                                   g_strerror(errno));
      g_ptr_array_add(t->files, f); /* let trans_free clean up */
      trans_free(t);
      g_set_error(error, dc_quark(), 0, "%s", msg);
      g_free(msg);
      return FALSE;
    }
    struct stat st;
    if (fstat(f->fd, &st) < 0 || !S_ISREG(st.st_mode)) {
      gchar *msg = g_strdup_printf("fstat failed for %s", items[i].path);
      g_ptr_array_add(t->files, f);
      trans_free(t);
      g_set_error(error, dc_quark(), 0, "%s", msg);
      g_free(msg);
      return FALSE;
    }
    f->size = (guint64)st.st_size;
    if (items[i].size != 0 && items[i].size != f->size) {
      gchar *msg = g_strdup_printf("size mismatch for %s", items[i].path);
      g_ptr_array_add(t->files, f);
      trans_free(t);
      g_set_error(error, dc_quark(), 0, "%s", msg);
      g_free(msg);
      return FALSE;
    }
    if (f->size > DFILE_MAX_FILE_SIZE) {
      gchar *msg = g_strdup_printf("%s exceeds 512GB limit", items[i].path);
      g_ptr_array_add(t->files, f);
      trans_free(t);
      g_set_error(error, dc_quark(), 0, "%s", msg);
      g_free(msg);
      return FALSE;
    }
    f->total_blocks =
        (guint32)((f->size + c->block_size - 1) / c->block_size);
    f->acked_all = (f->total_blocks == 0);
    g_ptr_array_add(t->files, f);
  }

  c->tx = t;
  if (!tx_send_header(c, t)) {
    c->tx = NULL;
    trans_free(t);
    g_set_error_literal(error, dc_quark(), 0, "file header send failed");
    return FALSE;
  }
  t->phase = DC_PH_TX_WAIT_CONFIRM_REQ;
  t->t0_ms = dc_now_ms();
  t->last_ctrl_ms = t->t0_ms;
  g_print("dfile[%s]: sending %u file(s) (transfer %u)\n", c->log_name,
          (unsigned)n, t->trans_id);
  return TRUE;
}

static void tx_pump(DFileConn *c) {
  DCTrans *t = c->tx;
  guint64 now = dc_now_ms();
  guint budget = DC_SEND_BUDGET;
  guint8 block[DFILE_FRAME_MAX_SIZE];
  guint8 frame[DFILE_FRAME_MAX_SIZE + 16];

  for (guint fi = 0; fi < t->files->len && budget > 0; fi++) {
    DCFile *f = (DCFile *)g_ptr_array_index(t->files, fi);
    if (f->next_seq >= f->total_blocks && f->retrans->len == 0) continue;

    /* New blocks, in order. */
    while (f->next_seq < f->total_blocks && budget > 0) {
      gsize off = (gsize)f->next_seq * c->block_size;
      gsize want = (gsize)(f->size - off);
      if (want > c->block_size) want = c->block_size;
      gssize r = pread(f->fd, block, want, (off_t)off);
      if (r != (gssize)want) {
        gchar *why = g_strdup_printf("read error: %s", g_strerror(errno));
        trans_fail(c, t, why, TRUE);
        g_free(why);
        return;
      }
      guint8 flag = 0;
      if (f->next_seq != 0) flag |= DFILE_FLAG_DATA_CONTINUE;
      if ((guint32)f->next_seq + 1 == f->total_blocks)
        flag |= DFILE_FLAG_DATA_END;
      gssize s = dfile_encode_data(frame, sizeof(frame), t->trans_id, flag,
                                   f->file_id, f->next_seq, block, want);
      if (s < 0 || !dc_send(c, frame, (gsize)s, NULL)) {
        trans_fail(c, t, "data send failed", FALSE);
        return;
      }
      g_array_append_val(f->retrans, f->next_seq);
      f->next_seq++;
      budget--;
    }

    /* Retransmissions: oldest pending first, paced per transfer. */
    if (f->retrans->len > 0 && budget > 0 &&
        (t->last_retran_ms == 0 ||
         now - t->last_retran_ms >= DC_RETRAN_INTERVAL_MS)) {
      guint32 seq = g_array_index(f->retrans, guint32, 0);
      gsize off = (gsize)seq * c->block_size;
      gsize want = (gsize)(f->size - off);
      if (want > c->block_size) want = c->block_size;
      gssize r = pread(f->fd, block, want, (off_t)off);
      if (r != (gssize)want) {
        trans_fail(c, t, "retransmit read error", TRUE);
        return;
      }
      guint8 flag = DFILE_FLAG_DATA_RETRAN | DFILE_FLAG_DATA_CONTINUE;
      gssize s = dfile_encode_data(frame, sizeof(frame), t->trans_id, flag,
                                   f->file_id, seq, block, want);
      if (s < 0 || !dc_send(c, frame, (gsize)s, NULL)) {
        trans_fail(c, t, "retransmit send failed", FALSE);
        return;
      }
      g_array_remove_index(f->retrans, 0);
      t->last_retran_ms = now;
      budget--;
    }
  }
}

/* ============================ Sender: ctrl frames ============================ */

static void tx_finish(DFileConn *c, DCTrans *t) {
  if (t->doneack_sent || t->phase == DC_PH_TX_DONE ||
      t->phase == DC_PH_FAILED)
    return;
  guint16 *ids = g_new(guint16, t->files->len);
  for (gsize i = 0; i < t->files->len; i++)
    ids[i] = ((DCFile *)g_ptr_array_index(t->files, i))->file_id;
  guint8 buf[DFILE_FRAME_HEADER_LEN + 2 * DFILE_MAX_FILE_NUM];
  gssize s = dfile_encode_idlist(buf, sizeof(buf),
                                 DFILE_FRAME_FILE_TRANSFER_DONE_ACK, 0,
                                 t->trans_id, ids, t->files->len);
  g_free(ids);
  if (s < 0 || !dc_send(c, buf, (gsize)s, NULL)) {
    trans_fail(c, t, "DONE_ACK send failed", FALSE);
    return;
  }
  t->doneack_sent = TRUE;
  t->phase = DC_PH_TX_DONE;
  guint64 bytes = 0;
  for (gsize i = 0; i < t->files->len; i++)
    bytes += ((DCFile *)g_ptr_array_index(t->files, i))->size;
  gchar *msg = g_strdup_printf(
      "sent %u file(s), %" G_GUINT64_FORMAT " bytes (all acked, done+ack)",
      (unsigned)t->files->len, bytes);
  g_print("dfile[%s]: %s\n", c->log_name, msg);
  if (c->on_result)
    c->on_result(c, TRUE, TRUE, msg, c->user_data);
  g_free(msg);
}

/*
 * FILE_HEADER_CONFIRM / FILE_TRANSFER_REQ from the receiver (the
 * receiver-initiated "pull" gate).
 */
static void handle_tx_ctrl(DFileConn *c, DFileFrameType type,
                           const guint8 *frame, gsize len) {
  DCTrans *t = c->tx;
  if (t == NULL || t->phase != DC_PH_TX_WAIT_CONFIRM_REQ) return;

  guint16 trans_id = 0;
  guint8 flag = 0;
  guint16 *ids = NULL;
  gsize n = 0;
  if (!dfile_decode_idlist(frame, len, type, &trans_id, &flag, &ids, &n)) {
    shutdown_common(c, "bad id-list frame");
    return;
  }
  if (trans_id != t->trans_id) {
    g_free(ids);
    shutdown_common(c, "id-list transfer mismatch");
    return;
  }
  if (type == DFILE_FRAME_FILE_HEADER_CONFIRM) {
    for (gsize i = 0; i < n; i++) {
      DCFile *f = find_file(t, ids[i]);
      if (f) f->confirmed = TRUE;
    }
    t->all_confirmed = TRUE;
    for (guint i = 0; i < t->files->len; i++) {
      if (!((DCFile *)g_ptr_array_index(t->files, i))->confirmed) {
        t->all_confirmed = FALSE;
        break;
      }
    }
  } else {
    t->req_received = TRUE;
  }
  t->last_ctrl_ms = dc_now_ms();
  g_free(ids);

  if (t->all_confirmed && t->req_received) {
    t->phase = DC_PH_TX_SENDING;
    g_print("dfile[%s]: transfer %u armed (confirm + req received)\n",
            c->log_name, t->trans_id);
  }
}

static void handle_ack(DFileConn *c, const guint8 *frame, gsize len) {
  DCTrans *t = c->tx;
  if (t == NULL || (t->phase != DC_PH_TX_SENDING &&
                    t->phase != DC_PH_TX_WAIT_DONE))
    return;

  guint16 trans_id = 0;
  guint8 flag = 0;
  gboolean v2 = FALSE;
  DFileAckEntry *ents = NULL;
  gsize n = 0;
  if (!dfile_decode_ack(frame, len, &trans_id, &flag, &v2, &ents, &n)) {
    shutdown_common(c, "bad FILE_DATA_ACK frame");
    return;
  }
  if (trans_id != t->trans_id) {
    g_free(ents);
    shutdown_common(c, "ACK transfer mismatch");
    return;
  }
  t->last_ack_ms = dc_now_ms();
  for (gsize i = 0; i < n; i++) {
    const DFileAckEntry *e = &ents[i];
    DCFile *f = find_file(t, e->file_id);
    if (f == NULL || e->last_seq == G_MAXUINT32) continue;
    if (f->last_acked == G_MAXUINT32 || e->last_seq > f->last_acked) {
      f->last_acked = e->last_seq;
      while (f->retrans->len > 0 &&
             g_array_index(f->retrans, guint32, 0) <= e->last_seq)
        g_array_remove_index(f->retrans, 0);
      if (f->total_blocks == 0 || e->last_seq + 1 >= f->total_blocks)
        f->acked_all = TRUE;
    }
  }
  g_free(ents);
  if (t->done_received && tx_all_acked(t)) tx_finish(c, t);
}

static void handle_done(DFileConn *c, const guint8 *frame, gsize len) {
  DCTrans *t = c->tx;
  if (t == NULL || t->phase == DC_PH_FAILED || t->phase == DC_PH_TX_DONE)
    return;
  guint16 trans_id = 0;
  guint8 flag = 0;
  guint16 *ids = NULL;
  gsize n = 0;
  if (!dfile_decode_idlist(frame, len, DFILE_FRAME_FILE_TRANSFER_DONE,
                           &trans_id, &flag, &ids, &n)) {
    shutdown_common(c, "bad FILE_TRANSFER_DONE frame");
    return;
  }
  g_free(ids);
  if (trans_id != t->trans_id) {
    shutdown_common(c, "DONE transfer mismatch");
    return;
  }
  t->done_received = TRUE;
  if (t->phase == DC_PH_TX_SENDING) t->phase = DC_PH_TX_WAIT_DONE;
  if (tx_all_acked(t)) tx_finish(c, t);
}

/* ============================ Receiver ============================ */

static void rx_flush_ack(DFileConn *c) {
  DCTrans *t = c->rx;
  t->ack_pending = FALSE;
  DFileAckEntry *ents = g_new0(DFileAckEntry,
                               t->files->len > 0 ? t->files->len : 1);
  gsize n = 0;
  for (guint i = 0; i < t->files->len; i++) {
    DCFile *f = (DCFile *)g_ptr_array_index(t->files, i);
    if (f->expected_seq > 0 && n < DFILE_MAX_ACK_ENTRIES) {
      ents[n].file_id = f->file_id;
      ents[n].last_seq = f->expected_seq - 1;
      n++;
    }
  }
  if (n == 0) {
    g_free(ents);
    return;
  }
  guint8 buf[DFILE_FRAME_HEADER_LEN + 12 + 37 * DFILE_MAX_ACK_ENTRIES];
  gssize s = dfile_encode_ack(buf, sizeof(buf), FALSE, t->trans_id, 0,
                              ents, n);
  g_free(ents);
  if (s < 0 || !dc_send(c, buf, (gsize)s, NULL))
    trans_fail(c, t, "ACK send failed", FALSE);
}

static void rx_send_done(DFileConn *c) {
  DCTrans *t = c->rx;
  if (t->done_sent) return;

  GString *msg = g_string_new("received:");
  for (guint i = 0; i < t->files->len; i++) {
    DCFile *f = (DCFile *)g_ptr_array_index(t->files, i);
    gchar *hex = g_strdup(g_checksum_get_string(f->sha));
    if (f->expected_sha != NULL) {
      if (g_ascii_strcasecmp(hex, f->expected_sha) != 0) {
        g_string_append_printf(msg, " %s: SHA256 MISMATCH (got %s, want %s)",
                               f->name, hex, f->expected_sha);
        g_free(hex);
        g_free(t->result_msg);
        t->result_msg = g_string_free(msg, FALSE);
        dc_send_rst(c, t->trans_id, DFILE_RST_INTERNAL_ERROR, NULL, 0);
        trans_fail(c, t, "sha256 mismatch", FALSE);
        return;
      }
      g_string_append_printf(msg, " %s sha256=%s OK", f->name, hex);
    } else {
      g_string_append_printf(msg, " %s sha256=%s (unverified)", f->name, hex);
    }
    g_free(hex);
  }
  g_free(t->result_msg);
  t->result_msg = g_string_free(msg, FALSE);

  guint16 *ids = g_new(guint16, t->files->len);
  for (gsize i = 0; i < t->files->len; i++)
    ids[i] = ((DCFile *)g_ptr_array_index(t->files, i))->file_id;
  guint8 buf[DFILE_FRAME_HEADER_LEN + 2 * DFILE_MAX_FILE_NUM];
  gssize s = dfile_encode_idlist(buf, sizeof(buf),
                                 DFILE_FRAME_FILE_TRANSFER_DONE, 0,
                                 t->trans_id, ids, t->files->len);
  g_free(ids);
  if (s < 0 || !dc_send(c, buf, (gsize)s, NULL)) {
    trans_fail(c, t, "DONE send failed", FALSE);
    return;
  }
  t->done_sent = TRUE;
  t->phase = DC_PH_RX_WAIT_DONEACK;
  g_print("dfile[%s]: all data written, sent DONE: %s\n", c->log_name,
          t->result_msg);
}

static void handle_doneack(DFileConn *c, const guint8 *frame, gsize len) {
  DCTrans *t = c->rx;
  if (t == NULL || t->phase != DC_PH_RX_WAIT_DONEACK) return;
  guint16 trans_id = 0;
  guint8 flag = 0;
  guint16 *ids = NULL;
  gsize n = 0;
  if (!dfile_decode_idlist(frame, len, DFILE_FRAME_FILE_TRANSFER_DONE_ACK,
                           &trans_id, &flag, &ids, &n)) {
    shutdown_common(c, "bad DONE_ACK frame");
    return;
  }
  g_free(ids);
  if (trans_id != t->trans_id) {
    shutdown_common(c, "DONE_ACK transfer mismatch");
    return;
  }
  t->phase = DC_PH_RX_DONE;
  const gchar *msg = t->result_msg ? t->result_msg : "received";
  g_print("dfile[%s]: %s\n", c->log_name, msg);
  if (c->on_result)
    c->on_result(c, FALSE, TRUE, msg, c->user_data);
}

/* Open + pre-size one destination file. Heap DCFile on success (fd open,
 * checksum started); NULL + @why on failure. */
static DCFile *rx_open_file(DFileConn *c, const DFileHeaderEntry *he,
                            gchar **why) {
  DCFile *f = g_new0(DCFile, 1);
  f->fd = -1;
  f->file_id = he->file_id;
  f->size = he->file_size;
  f->name = g_strdup(he->name);
  f->dst_path = g_build_filename(c->recv_dir, he->name, NULL);
  f->expected_sha = ft_testfile_name_sha(he->name);

  if (he->file_size > DFILE_MAX_FILE_SIZE) {
    *why = g_strdup("file size exceeds 512GB limit");
    goto fail;
  }
  f->fd = open(f->dst_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (f->fd < 0) {
    *why = g_strdup_printf("cannot create %s: %s", f->dst_path,
                           g_strerror(errno));
    goto fail;
  }
  if (ftruncate(f->fd, (off_t)f->size) < 0) {
    *why = g_strdup_printf("cannot pre-size %s: %s", f->dst_path,
                           g_strerror(errno));
    goto fail;
  }
  f->sha = g_checksum_new(G_CHECKSUM_SHA256);
  f->total_blocks =
      (guint32)((f->size + c->block_size - 1) / c->block_size);
  if (f->total_blocks == 0) f->write_complete = TRUE;
  return f;

fail:
  if (f->fd >= 0) close(f->fd);
  dcfile_free(f);
  return NULL;
}

static void rx_header_complete(DFileConn *c) {
  DCTrans *t = c->rx;
  if (t->phase != DC_PH_IDLE) return;
  if (c->recv_dir == NULL) {
    trans_fail(c, t, "no receive directory set", FALSE);
    return;
  }

  for (gsize i = 0; i < t->hdr_n; i++) {
    gchar *why = NULL;
    DCFile *f = rx_open_file(c, &t->hdr[i], &why);
    if (f == NULL) {
      dc_send_rst(c, t->trans_id, DFILE_RST_NO_ENOUGH_STORAGE, NULL, 0);
      trans_fail(c, t, why ? why : "cannot open destination file", FALSE);
      g_free(why);
      return;
    }
    g_ptr_array_add(t->files, f);
  }

  if (c->on_file_list)
    c->on_file_list(c, t->hdr, t->hdr_n, c->user_data);

  /* Confirm + transfer request (the stand's pull gate, all ids at once).
   * Encode AND send each frame before encoding the next — both frames
   * would otherwise clobber each other in the shared buffer. */
  guint16 *ids = g_new(guint16, t->hdr_n);
  for (gsize i = 0; i < t->hdr_n; i++) ids[i] = t->hdr[i].file_id;
  guint8 buf[DFILE_FRAME_HEADER_LEN + 2 * DFILE_MAX_FILE_NUM];
  gssize s1 = dfile_encode_idlist(
      buf, sizeof(buf), DFILE_FRAME_FILE_HEADER_CONFIRM, 0, t->trans_id,
      ids, t->hdr_n);
  gboolean sent1 = s1 >= 0 && dc_send(c, buf, (gsize)s1, NULL);
  gssize s2 = dfile_encode_idlist(
      buf, sizeof(buf), DFILE_FRAME_FILE_TRANSFER_REQ, 0, t->trans_id,
      ids, t->hdr_n);
  g_free(ids);
  if (!sent1 || s2 < 0 || !dc_send(c, buf, (gsize)s2, NULL)) {
    trans_fail(c, t, "confirm/req send failed", FALSE);
    return;
  }
  t->phase = DC_PH_RX_WAIT_DATA;
  g_print("dfile[%s]: receive ready: %u file(s) (transfer %u)\n",
          c->log_name, (unsigned)t->hdr_n, t->trans_id);
}

static void handle_file_header(DFileConn *c, const guint8 *frame, gsize len) {
  if (c->rx != NULL && (c->rx->phase == DC_PH_FAILED ||
                        c->rx->phase == DC_PH_RX_DONE)) {
    g_print("dfile[%s]: ignoring FILE_HEADER after receive finished\n",
            c->log_name);
    return;
  }
  guint16 trans_id = 0;
  guint16 node = 0;
  DFileHeaderEntry *ents = NULL;
  gsize n = 0;
  if (!dfile_decode_file_header(frame, len, &trans_id, &node, &ents, &n)) {
    shutdown_common(c, "bad FILE_HEADER frame");
    return;
  }
  if (node == 0) {
    dfile_header_entries_free(ents, n);
    shutdown_common(c, "FILE_HEADER with nodeNumber 0");
    return;
  }
  if (c->rx == NULL) {
    c->rx = trans_new(FALSE, trans_id);
    c->rx->node_number = node;
  } else if (c->rx->trans_id != trans_id ||
             c->rx->node_number != node) {
    dfile_header_entries_free(ents, n);
    shutdown_common(c, "FILE_HEADER transfer/node mismatch");
    return;
  }
  DCTrans *t = c->rx;
  /* Accumulate with per-entry dedup: the sender retransmits the whole
   * FILE_HEADER while waiting for confirm, so re-sent entries are
   * dropped instead of failing the transfer. */
  for (gsize i = 0; i < n; i++) {
    gboolean dup = FALSE;
    for (gsize j = 0; j < t->hdr_n; j++) {
      if (t->hdr[j].file_id == ents[i].file_id) {
        dup = TRUE;
        break;
      }
    }
    if (dup) {
      g_free(ents[i].name);
      continue;
    }
    if (t->hdr_n + 1 > node) {
      for (gsize k = i; k < n; k++) g_free(ents[k].name);
      g_free(ents);
      shutdown_common(c, "FILE_HEADER entries overflow nodeNumber");
      return;
    }
    t->hdr = (DFileHeaderEntry *)g_realloc(t->hdr,
                                           sizeof(*t->hdr) * (t->hdr_n + 1));
    t->hdr[t->hdr_n++] = ents[i]; /* take ownership of the entry */
  }
  g_free(ents); /* container only; accepted entries are owned by t->hdr */
  g_print("dfile[%s]: FILE_HEADER +1 frame (%u/%u files)\n", c->log_name,
          (unsigned)t->hdr_n, (unsigned)node);
  if (t->hdr_n >= node) rx_header_complete(c);
}

static void handle_data(DFileConn *c, const guint8 *frame, gsize len) {
  DCTrans *t = c->rx;
  guint16 trans_id = 0;
  guint8 flag = 0;
  guint16 file_id = 0;
  guint32 seq = 0;
  const guint8 *pay = NULL;
  gsize paylen = 0;
  if (!dfile_decode_data(frame, len, &trans_id, &flag, &file_id, &seq,
                         &pay, &paylen)) {
    shutdown_common(c, "bad FILE_DATA frame");
    return;
  }
  if (t == NULL || t->phase != DC_PH_RX_WAIT_DATA ||
      trans_id != t->trans_id) {
    dc_send_rst(c, trans_id, DFILE_RST_INTERNAL_ERROR, NULL, 0);
    shutdown_common(c, "FILE_DATA with no active receive");
    return;
  }
  DCFile *f = find_file(t, file_id);
  if (f == NULL) {
    dc_send_rst(c, t->trans_id, DFILE_RST_INTERNAL_ERROR, NULL, 0);
    shutdown_common(c, "FILE_DATA unknown file id");
    return;
  }
  if (seq >= f->total_blocks) {
    dc_send_rst(c, t->trans_id, DFILE_RST_INTERNAL_ERROR, NULL, 0);
    shutdown_common(c, "FILE_DATA sequence out of range");
    return;
  }
  if (seq < f->expected_seq) return; /* duplicate (retransmit) */
  if (seq > f->expected_seq) {
    /* TCP delivers in order; a gap means a corrupt stream. */
    dc_send_rst(c, t->trans_id, DFILE_RST_INTERNAL_ERROR, NULL, 0);
    shutdown_common(c, "FILE_DATA gap (unexpected over TCP)");
    return;
  }
  gsize off = (gsize)seq * c->block_size;
  gsize want = (gsize)(f->size - off);
  if (want > c->block_size) want = c->block_size;
  if (paylen != want) {
    dc_send_rst(c, t->trans_id, DFILE_RST_INTERNAL_ERROR, NULL, 0);
    shutdown_common(c, "FILE_DATA payload size mismatch");
    return;
  }
  gssize w = pwrite(f->fd, pay, paylen, (off_t)off);
  if (w != (gssize)paylen) {
    dc_send_rst(c, t->trans_id, DFILE_RST_FILE_WRITE_ERROR, NULL, 0);
    gchar *why = g_strdup_printf("write error: %s", g_strerror(errno));
    shutdown_common(c, why);
    g_free(why);
    return;
  }
  g_checksum_update(f->sha, pay, (gssize)paylen);
  f->expected_seq = seq + 1;
  if (f->expected_seq >= f->total_blocks) {
    f->write_complete = TRUE;
    close(f->fd);
    f->fd = -1;
  }
  t->ack_pending = TRUE;
}

/* ============================ Setting / RST ============================ */

static void dc_send_local_setting(DFileConn *c) {
  if (c->local_setting_sent) return;
  DFileSetting s;
  memset(&s, 0, sizeof(s));
  s.mtu = DFILE_DEFAULT_FRAME_SIZE;
  s.conn_type = 1; /* TCP; value unvalidated on the stand (TBD vs M4) */
  s.dfile_version = DFILE_VERSION;
  s.capability = 0;
  s.data_frame_size = 0; /* let the peer pick */
  s.caps_check = 0;      /* no V2 feedback, no backpressure */
  s.cipher_capability = 0;
  g_strlcpy(s.product_version, "hwphonelink 0.1.0", sizeof(s.product_version));

  guint8 buf[DFILE_FRAME_HEADER_LEN + DFILE_SETTING_PAYLOAD_LEN];
  gssize n = dfile_encode_setting(buf, sizeof(buf), &s);
  GError *err = NULL;
  if (n > 0 && dc_send(c, buf, (gsize)n, &err)) {
    c->local_setting_sent = TRUE;
    g_print("dfile[%s]: SETTING sent (mtu %u, dfile v%u)\n", c->log_name,
            s.mtu, s.dfile_version);
    return;
  }
  gchar *why = g_strdup_printf("setting send failed: %s",
                               err ? err->message : "encode error");
  g_clear_error(&err);
  shutdown_common(c, why);
  g_free(why);
}

static void handle_setting(DFileConn *c, const guint8 *frame, gsize len) {
  if (c->negotiated) return; /* duplicate: ignore */
  DFileSetting s;
  if (!dfile_decode_setting(frame, len, &s)) {
    shutdown_common(c, "bad SETTING frame");
    return;
  }
  if (s.mtu == 0) {
    dc_send_rst(c, 0, DFILE_RST_WITHOUT_SETTING, NULL, 0);
    shutdown_common(c, "peer SETTING has mtu 0");
    return;
  }
  c->peer_setting = s;
  /* A data frame is 8 (hdr) + 6 (meta) + payload and must fit in
   * DFILE_FRAME_MAX_SIZE, so the block (payload) is capped below that. */
  const guint32 max_block =
      DFILE_FRAME_MAX_SIZE - DFILE_FRAME_HEADER_LEN - 6;
  c->block_size =
      (s.data_frame_size >= DFILE_MIN_MTU_SIZE &&
       s.data_frame_size <= max_block)
          ? (guint)s.data_frame_size
          : DFILE_DEFAULT_FRAME_SIZE;
  c->negotiated = TRUE;
  c->state = DC_ST_READY;
  g_print("dfile[%s]: negotiated (peer mtu %u, block %u, dfile v%u)\n",
          c->log_name, s.mtu, c->block_size, s.dfile_version);
  if (c->on_negotiated) c->on_negotiated(c, c->user_data);
}

static void handle_rst(DFileConn *c, const guint8 *frame, gsize len) {
  guint16 trans_id = 0;
  guint16 code = 0;
  guint16 *ids = NULL;
  gsize n = 0;
  if (!dfile_decode_rst(frame, len, &trans_id, &code, &ids, &n)) {
    shutdown_common(c, "bad RST frame");
    return;
  }
  DCTrans *t = NULL;
  if (c->tx && c->tx->trans_id == trans_id)
    t = c->tx;
  else if (c->rx && c->rx->trans_id == trans_id)
    t = c->rx;
  gchar *why = g_strdup_printf("RST code %u (%s)", code, rst_code_str(code));
  if (t) trans_fail(c, t, why, FALSE);
  g_print("dfile[%s]: %s (trans %u)\n", c->log_name, why, trans_id);
  g_free(why);
  g_free(ids);
}

/* ============================ Frame dispatch ============================ */

static void handle_frame(DFileConn *c, const guint8 *frame, gsize len) {
  DFileFrameHeader h;
  if (dfile_frame_header_unpack(frame, len, &h) != 0) {
    shutdown_common(c, "corrupt frame header");
    return;
  }
  switch ((DFileFrameType)h.type) {
    case DFILE_FRAME_SETTING:
      handle_setting(c, frame, len);
      break;
    case DFILE_FRAME_FILE_HEADER:
      handle_file_header(c, frame, len);
      break;
    case DFILE_FRAME_FILE_HEADER_CONFIRM:
    case DFILE_FRAME_FILE_TRANSFER_REQ:
      handle_tx_ctrl(c, (DFileFrameType)h.type, frame, len);
      break;
    case DFILE_FRAME_FILE_DATA:
      handle_data(c, frame, len);
      break;
    case DFILE_FRAME_FILE_DATA_ACK:
      handle_ack(c, frame, len);
      break;
    case DFILE_FRAME_FILE_TRANSFER_DONE:
      handle_done(c, frame, len);
      break;
    case DFILE_FRAME_FILE_TRANSFER_DONE_ACK:
      handle_doneack(c, frame, len);
      break;
    case DFILE_FRAME_RST:
      handle_rst(c, frame, len);
      break;
    default:
      /* FLOW_CONTROL / CONGESTION_CONTROL / PEER_DOWN / BACK_PRESSURE:
       * not used by the stand — accept and ignore. */
      break;
  }
}

/* ============================ Tick ============================ */

static gboolean on_tick(gpointer p) {
  DFileConn *c = (DFileConn *)p;
  if (c->state == DC_ST_CLOSING) return G_SOURCE_REMOVE;
  guint64 now = dc_now_ms();

  if (!c->negotiated && now - c->t_connect_ms > DC_NEGOTIATE_TIMEOUT_MS) {
    shutdown_common(c, "setting negotiation timeout");
    return G_SOURCE_REMOVE;
  }

  if (c->tx && c->tx->phase != DC_PH_TX_DONE &&
      c->tx->phase != DC_PH_FAILED &&
      now - c->tx->t0_ms > DC_TRANSFER_TIMEOUT_MS)
    trans_fail(c, c->tx, "transfer timeout", TRUE);
  if (c->rx && c->rx->phase != DC_PH_RX_DONE &&
      c->rx->phase != DC_PH_FAILED &&
      now - c->rx->t0_ms > DC_TRANSFER_TIMEOUT_MS)
    trans_fail(c, c->rx, "transfer timeout", TRUE);
  if (c->state == DC_ST_CLOSING) return G_SOURCE_REMOVE;

  /* Receiver: flush pending ACKs, then check for write completion. */
  if (c->rx && c->rx->phase == DC_PH_RX_WAIT_DATA) {
    if (c->rx->ack_pending) rx_flush_ack(c);
    if (c->state == DC_ST_CLOSING) return G_SOURCE_REMOVE;
    if (!c->rx->done_sent && c->rx->files->len > 0) {
      gboolean all = TRUE;
      for (guint i = 0; i < c->rx->files->len; i++) {
        if (!((DCFile *)g_ptr_array_index(c->rx->files, i))
                 ->write_complete) {
          all = FALSE;
          break;
        }
      }
      if (all) {
        rx_send_done(c);
        if (c->state == DC_ST_CLOSING) return G_SOURCE_REMOVE;
      }
    }
  }

  /* Sender: pump data, then check the finish condition. */
  if (c->tx && (c->tx->phase == DC_PH_TX_SENDING ||
                c->tx->phase == DC_PH_TX_WAIT_DONE)) {
    tx_pump(c);
    if (c->state == DC_ST_CLOSING) return G_SOURCE_REMOVE;
    if (c->tx->phase == DC_PH_TX_SENDING && tx_all_sent(c->tx))
      c->tx->phase = DC_PH_TX_WAIT_DONE;
    if (c->tx->done_received && tx_all_acked(c->tx)) tx_finish(c, c->tx);
  }

  /* Sender: retransmit the FILE_HEADER while awaiting confirm/req. */
  if (c->tx && c->tx->phase == DC_PH_TX_WAIT_CONFIRM_REQ &&
      now - c->tx->last_ctrl_ms > DC_CTRL_RETRY_INTERVAL_MS) {
    if (++c->tx->ctrl_retries > DC_CTRL_MAX_RETRIES) {
      trans_fail(c, c->tx, "header confirm timeout", TRUE);
    } else if (tx_send_header(c, c->tx)) {
      c->tx->last_ctrl_ms = now;
      g_print("dfile[%s]: FILE_HEADER retransmit (%u)\n", c->log_name,
              c->tx->ctrl_retries);
    } else {
      trans_fail(c, c->tx, "header retransmit failed", FALSE);
    }
  }

  return G_SOURCE_CONTINUE;
}

/* ============================ I/O ============================ */

/*
 * Read all currently available data and process complete frames.
 * Engine thread only. Leaves the connection closed on fatal errors.
 */
static void dc_drain(DFileConn *c) {
  guint8 tmp[DC_READ_CHUNK];
  for (;;) {
    GError *err = NULL;
    gssize n = g_socket_receive(c->socket, (gchar *)tmp, sizeof(tmp), NULL,
                                &err);
    if (n > 0) {
      g_byte_array_append(c->rxbuf, tmp, (gsize)n);
      for (;;) {
        DFileFrameHeader h;
        int rc = dfile_frame_header_unpack(c->rxbuf->data, c->rxbuf->len,
                                           &h);
        if (rc == -1) break; /* incomplete header */
        if (rc != 0) {
          shutdown_common(c, "corrupt frame header");
          return;
        }
        gsize total = DFILE_FRAME_HEADER_LEN + h.length;
        if (c->rxbuf->len < total) break; /* incomplete payload */
        handle_frame(c, c->rxbuf->data, total);
        if (c->state == DC_ST_CLOSING) return;
        g_byte_array_remove_range(c->rxbuf, 0, total);
      }
      continue;
    }
    if (n == 0) {
      shutdown_common(c, "peer closed connection");
      return;
    }
    if (g_error_matches(err, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
      g_clear_error(&err);
      break;
    }
    gchar *why = g_strdup_printf("socket error: %s",
                                 err ? err->message : "unknown");
    g_clear_error(&err);
    shutdown_common(c, why);
    g_free(why);
    return;
  }
}

/*
 * Non-deprecated socket I/O: a GSource polling the socket fd
 * (g_io_channel_unix_new() is deprecated; GIOChannel is off the table).
 * The struct starts with GSource, per the g_source_new() convention.
 */
typedef struct {
  GSource  source;
  GPollFD  poll;
} DcIoSource;

static gboolean dc_io_prepare(GSource *src, gint *timeout) {
  (void)src;
  *timeout = -1; /* readiness comes from the poll fd only */
  return FALSE;
}

static gboolean dc_io_check(GSource *src) {
  DcIoSource *s = (DcIoSource *)src;
  return s->poll.revents != 0;
}

static gboolean dc_io_dispatch(GSource *src, GSourceFunc callback,
                               gpointer user_data) {
  DcIoSource *s = (DcIoSource *)src;
  s->poll.revents = 0;
  return callback(user_data);
}

static GSourceFuncs dc_io_funcs = {
    .prepare = dc_io_prepare,
    .check = dc_io_check,
    .dispatch = dc_io_dispatch,
    .finalize = NULL,
};

static gboolean on_io_source(gpointer p) {
  DFileConn *c = (DFileConn *)p;
  dc_drain(c);
  return c->state != DC_ST_CLOSING;
}

static GSource *add_io_watch(DFileConn *c) {
  GSource *src = g_source_new(&dc_io_funcs, sizeof(DcIoSource));
  DcIoSource *s = (DcIoSource *)src;
  s->poll.fd = (int)g_socket_get_fd(c->socket);
  s->poll.events = G_IO_IN | G_IO_HUP | G_IO_ERR;
  s->poll.revents = 0;
  g_source_add_poll(src, &s->poll);
  g_source_set_priority(src, G_PRIORITY_DEFAULT);
  g_source_set_callback(src, on_io_source, c, NULL);
  /* g_source_attach() takes a ref in this GLib; the context owns the
   * source until teardown destroys it.  The returned pointer is a
   * non-owning handle. */
  g_source_attach(src, c->ctx);
  g_source_unref(src);
  return src;
}

/* ============================ Thread / lifecycle ============================ */

static void dc_free(DFileConn *c) {
  if (c->thread) g_thread_unref(c->thread);
  g_mutex_clear(&c->lock);
  g_free(c);
}

/*
 * Engine thread, after the loop exits. Frees everything, marks the thread
 * done (under c->lock, BEFORE the context is unrefed — close() relies on
 * that ordering), drops the internal ref, frees if we were the last one.
 */
static void dc_teardown(DFileConn *c) {
  /* Normally already destroyed in shutdown_common; defensive cleanup
   * for paths that skipped it. */
  if (c->io_source) {
    g_source_destroy(c->io_source);
    c->io_source = NULL;
  }
  if (c->tick_source) {
    g_source_destroy(c->tick_source);
    c->tick_source = NULL;
  }
  trans_free(c->tx);
  c->tx = NULL;
  trans_free(c->rx);
  c->rx = NULL;
  g_free(c->recv_dir);
  g_free(c->log_name);
  if (c->rxbuf) {
    g_byte_array_free(c->rxbuf, TRUE);
    c->rxbuf = NULL;
  }
  g_socket_close(c->socket, NULL);
  if (c->conn) {
    g_object_unref(c->conn);
    c->conn = NULL;
  }

  g_mutex_lock(&c->lock);
  c->thread_done = TRUE;
  c->thread_started = FALSE;
  g_mutex_unlock(&c->lock);

  g_main_loop_unref(c->loop);
  c->loop = NULL;
  g_main_context_unref(c->ctx);
  c->ctx = NULL;

  g_atomic_int_set(&c->thread_alive, 0);
  if (g_atomic_int_dec_and_test(&c->refs)) dc_free(c);
}

static gpointer engine_thread(gpointer p) {
  DFileConn *c = (DFileConn *)p;
  g_atomic_int_set(&c->thread_alive, 1);

  gboolean pre_closed = FALSE;
  g_mutex_lock(&c->lock);
  if (c->close_requested)
    pre_closed = TRUE;
  else
    c->thread_started = TRUE;
  g_mutex_unlock(&c->lock);

  if (pre_closed) {
    close_impl(c);
  } else {
    c->io_source = add_io_watch(c);
    GSource *tick = g_timeout_source_new(DC_TICK_MS);
    g_source_set_priority(tick, G_PRIORITY_DEFAULT);
    g_source_set_callback(tick, on_tick, c, NULL);
    g_source_attach(tick, c->ctx);
    g_source_unref(tick);
    c->tick_source = tick; /* non-owning handle */
    dc_send_local_setting(c);
    if (c->state != DC_ST_CLOSING) g_main_loop_run(c->loop);
  }

  dc_teardown(c);
  return NULL;
}

static DFileConn *dc_alloc(void) {
  DFileConn *c = g_new0(DFileConn, 1);
  c->refs = 2; /* creator + engine-internal */
  g_mutex_init(&c->lock);
  c->ctx = g_main_context_new();
  c->loop = g_main_loop_new(c->ctx, FALSE);
  c->rxbuf = g_byte_array_new();
  c->state = DC_ST_NEGOTIATING;
  c->t_connect_ms = dc_now_ms();
  c->next_trans_id = 1;
  return c;
}

static void dc_abort(DFileConn *c) {
  g_free(c->log_name);
  g_free(c->recv_dir);
  if (c->rxbuf) g_byte_array_free(c->rxbuf, TRUE);
  if (c->loop) g_main_loop_unref(c->loop);
  if (c->ctx) g_main_context_unref(c->ctx);
  g_mutex_clear(&c->lock);
  g_free(c);
}

/* ============================ Public API ============================ */

DFileConn* dfile_conn_new_client(const gchar *host, guint port,
                                 GError **error) {
  DFileConn *c = dc_alloc();
  c->log_name = g_strdup_printf("client:%s:%u", host, port);

  GSocketClient *sc = g_socket_client_new();
  g_socket_client_set_timeout(sc, 5);
  c->conn = g_socket_client_connect_to_host(sc, host, (gint)port, NULL,
                                            error);
  g_object_unref(sc);
  if (c->conn == NULL) {
    dc_abort(c);
    return NULL;
  }
  c->socket = g_socket_connection_get_socket(c->conn);
  g_socket_set_blocking(c->socket, FALSE);
  c->thread = g_thread_new("dfile-engine", engine_thread, c);
  return c;
}

DFileConn* dfile_conn_new_server(GSocketConnection *conn) {
  if (conn == NULL) return NULL;
  DFileConn *c = dc_alloc();
  c->log_name = g_strdup("server");
  c->conn = g_object_ref(conn);
  c->socket = g_socket_connection_get_socket(conn);
  g_socket_set_blocking(c->socket, FALSE);
  c->thread = g_thread_new("dfile-engine", engine_thread, c);
  return c;
}

DFileConn* dfile_conn_ref(DFileConn *c) {
  if (c == NULL) return NULL;
  g_atomic_int_inc(&c->refs);
  return c;
}

void dfile_conn_unref(DFileConn *c) {
  if (c == NULL) return;
  if (g_atomic_int_dec_and_test(&c->refs)) dc_free(c);
}

void dfile_conn_set_callbacks(DFileConn *c, DFileConnNegotiatedCb on_negotiated,
                              DFileConnFileListCb on_file_list,
                              DFileConnResultCb on_result,
                              DFileConnClosedCb on_closed,
                              gpointer user_data) {
  if (c == NULL) return;
  /*
   * Plain field writes: set immediately after construction, long before
   * any peer traffic can arrive (a full RTT). Callbacks are NULL-checked
   * before every call, so an early fire is simply skipped.
   */
  c->on_negotiated = on_negotiated;
  c->on_file_list = on_file_list;
  c->on_result = on_result;
  c->on_closed = on_closed;
  c->user_data = user_data;
}

void dfile_conn_set_recv_dir(DFileConn *c, const gchar *dir) {
  if (c == NULL) return;
  g_free(c->recv_dir);
  c->recv_dir = g_strdup(dir);
}

gboolean dfile_conn_send_files(DFileConn *c, const DFileSendItem *items,
                               gsize n, GError **error) {
  if (c == NULL || items == NULL) {
    g_set_error_literal(error, dc_quark(), 0, "invalid arguments");
    return FALSE;
  }
  if (!dc_on_engine_thread(c)) {
    g_set_error_literal(error, dc_quark(), 0,
                        "must be called on the engine thread (from a "
                        "DFileConn callback)");
    return FALSE;
  }
  return send_files_impl(c, items, n, error);
}

void dfile_conn_close(DFileConn *c) {
  if (c == NULL) return;
  /*
   * The invoke happens while holding c->lock: teardown sets thread_done
   * under the same lock and only unrefs the context after that, so the
   * context cannot die out from under us. close_impl's argument is c
   * itself (kept alive by the internal ref), so no wrapper is needed; if
   * the context is gone first, the state guard in shutdown_common makes
   * a late call a no-op.
   */
  g_mutex_lock(&c->lock);
  if (c->close_requested || c->thread_done) {
    g_mutex_unlock(&c->lock);
    return;
  }
  c->close_requested = TRUE;
  if (c->thread_started)
    g_main_context_invoke_full(c->ctx, G_PRIORITY_DEFAULT, close_impl, c,
                               NULL);
  g_mutex_unlock(&c->lock);
  /* !thread_started: the engine thread runs close_impl() before loop start */
}

const gchar* dfile_conn_state_name(DFileConn *c) {
  if (c == NULL) return "null";
  switch (c->state) {
    case DC_ST_NEGOTIATING: return "negotiating";
    case DC_ST_READY:       return "ready";
    case DC_ST_CLOSING:     return "closing";
  }
  return "?";
}

guint dfile_conn_block_size(DFileConn *c) {
  return c ? c->block_size : 0;
}
