/*
 * softbus_session.c - Logical session over a connected socket
 */

#include "softbus_session.h"
#include "softbus_crypto.h"

#include <string.h>

struct _SoftbusSession {
  GObject parent_instance;
};

typedef struct {
  GSocketConnection *conn;       /* ref held */
  SoftbusFrameBuf *frame_buf;

  GThread *pump_thread;
  GCancellable *cancel;
  gint running;                  /* atomic: 1 while pump is live */
  gint closed_emitted;           /* atomic: closed cb fired once */

  GMutex write_mutex;
  guint8 session_id[SOFTBUS_FRAME_SESSION_ID_SIZE];
  SoftbusSessionType session_type;
  gint seq;                      /* frame sequence (write_mutex) */

  SoftbusSessionDataCb data_cb;
  gpointer data_user;
  GDestroyNotify data_user_free;
  SoftbusSessionClosedCb closed_cb;
  gpointer closed_user;
} SoftbusSessionPrivate;

G_DEFINE_TYPE_WITH_PRIVATE(SoftbusSession, softbus_session, G_TYPE_OBJECT)

#define SOFTBUS_SESSION_GET_PRIVATE(o) \
  (softbus_session_get_instance_private(SOFTBUS_SESSION(o)))

static SoftbusSessionPrivate* _priv(SoftbusSession *s) {
  return SOFTBUS_SESSION_GET_PRIVATE(s);
}

/* Wire buffer: min frame + max payload + slack. */
#define SESSION_WIRE_CAP (SOFTBUS_FRAME_MIN_SIZE + SOFTBUS_FRAME_MAX_PAYLOAD + 64)

/* ============================ Pump ============================ */

static void _on_frame(SoftbusSession *s, const guint8 *data, gsize len) {
  SoftbusSessionPrivate *priv = _priv(s);
  if (priv->data_cb) {
    priv->data_cb(s, data, len, priv->data_user);
  }
}

static void _emit_closed(SoftbusSession *s) {
  SoftbusSessionPrivate *priv = _priv(s);
  if (!g_atomic_int_compare_and_exchange(&priv->closed_emitted, 0, 1)) return;
  SoftbusSessionClosedCb cb = priv->closed_cb;
  gpointer user = priv->closed_user;
  if (cb == NULL) return;
  /* Keep the object alive across the callback (the caller may unref it). */
  g_object_ref(s);
  cb(s, user);
  g_object_unref(s);
}

static void* _pump_thread(gpointer data) {
  SoftbusSession *s = SOFTBUS_SESSION(data);
  SoftbusSessionPrivate *priv = _priv(s);

  /*
   * Pump with the single-recv primitive: g_input_stream_read_all() would not
   * return until *all* sizeof(chunk) bytes are gathered or EOF, which on a
   * streaming socket only happens when the peer closes — the first frame
   * would sit in the buffer forever. g_socket_receive_with_blocking() does
   * one recv() per call: it blocks only while the peer sends nothing and
   * returns as soon as any data (up to chunk size) is available.
   */
  GSocket *sock = g_socket_connection_get_socket(priv->conn);
  if (sock == NULL) {
    g_warning("softbus-session: connection has no GSocket, pump exits");
    _emit_closed(s);
    return NULL;
  }

  guint8 chunk[4096];

  while (g_atomic_int_get(&priv->running)) {
    GError *err = NULL;
    gssize n = g_socket_receive_with_blocking(sock, (gchar *)chunk, sizeof(chunk),
                                              TRUE, priv->cancel, &err);
    if (n < 0) {
      if (!g_error_matches(err, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
        g_warning("softbus-session: read error: %s", err ? err->message : "unknown");
      }
      g_clear_error(&err);
      break;
    }
    if (n == 0) break;  /* EOF — peer closed */

    softbus_frame_buf_append(priv->frame_buf, chunk, (gsize)n, NULL);

    SoftbusFrame frame;
    GError *perr = NULL;
    while (softbus_frame_buf_pop(priv->frame_buf, &frame, &perr)) {
      /*
       * pop() hands us an owned copy of the payload (NULL when empty).
       * The data callback must not retain the pointer, so release it as
       * soon as the callback returns.
       */
      if (frame.payload_len > 0 && frame.payload != NULL) {
        _on_frame(s, frame.payload, frame.payload_len);
      } else {
        _on_frame(s, NULL, 0);
      }
      g_free(frame.payload);
    }
    g_clear_error(&perr);
  }

  /*
   * Claim shutdown before emitting closed: the closed callback may drop
   * this session's last reference, which would run finalize() on this
   * very thread — and finalize() must never join the pump (joining from
   * inside the pump is a self-join, an EDEADLK abort). Whoever wins this
   * CAS owns the GThread reference: a stop()/finalize() on another thread
   * joins it, we drop it here instead — the thread's own reference keeps
   * the GThread object alive until we return.
   */
  if (g_atomic_int_compare_and_exchange(&priv->running, 1, 0)) {
    g_thread_unref(priv->pump_thread);
    priv->pump_thread = NULL;
  }

  _emit_closed(s);
  return NULL;
}

/* ============================ Lifecycle ============================ */

static void softbus_session_finalize(GObject *object) {
  SoftbusSession *s = SOFTBUS_SESSION(object);
  SoftbusSessionPrivate *priv = _priv(s);

  /*
   * Only the CAS winner joins the pump. The pump clears @running with the
   * same CAS before emitting closed, so a pump-driven finalize (the closed
   * callback dropped our last reference) always sees running == 0 and must
   * not join itself. If we win, the pump is still alive and we are on a
   * different thread; g_thread_join() consumes the GThread reference.
   */
  if (g_atomic_int_compare_and_exchange(&priv->running, 1, 0)) {
    GThread *t = priv->pump_thread;
    priv->pump_thread = NULL;
    if (priv->cancel) g_cancellable_cancel(priv->cancel);
    if (t) g_thread_join(t);
  }
  if (priv->cancel) {
    g_object_unref(priv->cancel);
    priv->cancel = NULL;
  }
  if (priv->conn) {
    g_object_unref(priv->conn);
    priv->conn = NULL;
  }
  softbus_frame_buf_free(priv->frame_buf);
  priv->frame_buf = NULL;
  if (priv->data_user_free) {
    priv->data_user_free(priv->data_user);
    priv->data_user_free = NULL;
  }
  g_mutex_clear(&priv->write_mutex);

  G_OBJECT_CLASS(softbus_session_parent_class)->finalize(object);
}

static void softbus_session_class_init(SoftbusSessionClass *klass) {
  G_OBJECT_CLASS(klass)->finalize = softbus_session_finalize;
}

static void softbus_session_init(SoftbusSession *self) {
  SoftbusSessionPrivate *priv = _priv(self);
  g_mutex_init(&priv->write_mutex);
}

SoftbusSession* softbus_session_new(GSocketConnection *conn,
                                    SoftbusSessionType session_type) {
  if (conn == NULL) return NULL;
  SoftbusSession *s = g_object_new(SOFTBUS_TYPE_SESSION, NULL);
  SoftbusSessionPrivate *priv = _priv(s);

  priv->conn = g_object_ref(conn);
  priv->session_type = session_type;
  priv->frame_buf = softbus_frame_buf_new();
  priv->cancel = g_cancellable_new();
  softbus_random_bytes(priv->session_id, SOFTBUS_FRAME_SESSION_ID_SIZE);

  g_atomic_int_set(&priv->running, 1);
  priv->pump_thread = g_thread_new("softbus-session", _pump_thread, s);
  if (priv->pump_thread == NULL) {
    g_atomic_int_set(&priv->running, 0);
    g_object_unref(s);
    return NULL;
  }
  return s;
}

void softbus_session_stop(SoftbusSession *session) {
  if (session == NULL) return;
  SoftbusSessionPrivate *priv = _priv(session);
  if (!g_atomic_int_compare_and_exchange(&priv->running, 1, 0)) return;
  if (priv->cancel) g_cancellable_cancel(priv->cancel);
  /* We won the CAS, so the pump will not release its own GThread ref;
   * the join consumes it and guarantees the closed callback has fired
   * before stop() returns. */
  if (priv->pump_thread) {
    g_thread_join(priv->pump_thread);
    priv->pump_thread = NULL;
  }
}

gboolean softbus_session_is_active(const SoftbusSession *session) {
  if (session == NULL) return FALSE;
  return g_atomic_int_get(&_priv((SoftbusSession *)session)->running) != 0;
}

/* ============================ Send ============================ */

gboolean softbus_session_send(SoftbusSession *session, const guint8 *data,
                              gsize len, GError **error) {
  if (session == NULL) {
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "session is NULL");
    return FALSE;
  }
  if (data == NULL && len > 0) {
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "NULL data with len>0");
    return FALSE;
  }
  SoftbusSessionPrivate *priv = _priv(session);
  if (!g_atomic_int_get(&priv->running)) {
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_CLOSED, "session stopped");
    return FALSE;
  }

  SoftbusFrame frame;
  memset(&frame, 0, sizeof(frame));
  memcpy(frame.session_id, priv->session_id, SOFTBUS_FRAME_SESSION_ID_SIZE);
  frame.type = (guint8)priv->session_type;
  frame.flags = SOFTBUS_FRAME_FLAG_FIN;
  frame.payload = (guint8 *)data;
  frame.payload_len = len;

  GOutputStream *out = g_io_stream_get_output_stream(G_IO_STREAM(priv->conn));
  guint8 wire[SESSION_WIRE_CAP];
  gsize written = 0;
  /* seq is serialized by the write mutex (GLib's g_atomic_int_inc returns
   * void since 2.76). */
  g_mutex_lock(&priv->write_mutex);
  frame.seq = (guint32)++priv->seq;
  gsize total = softbus_frame_pack(&frame, wire, sizeof(wire));
  gboolean ok = FALSE;
  if (total > 0) {
    ok = g_output_stream_write_all(out, wire, total, &written, priv->cancel, error);
  } else if (error != NULL) {
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "failed to pack frame");
  }
  g_mutex_unlock(&priv->write_mutex);
  return ok;
}

gboolean softbus_session_send_json(SoftbusSession *session, const gchar *json,
                                   GError **error) {
  if (json == NULL) {
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "json is NULL");
    return FALSE;
  }
  return softbus_session_send(session, (const guint8 *)json, strlen(json), error);
}

/* ============================ Callbacks / accessors ============================ */

void softbus_session_set_data_cb(SoftbusSession *session,
                                 SoftbusSessionDataCb cb,
                                 gpointer user_data,
                                 GDestroyNotify user_data_free) {
  if (session == NULL) return;
  SoftbusSessionPrivate *priv = _priv(session);
  priv->data_cb = cb;
  priv->data_user = user_data;
  priv->data_user_free = user_data_free;
}

void softbus_session_set_closed_cb(SoftbusSession *session,
                                   SoftbusSessionClosedCb cb,
                                   gpointer user_data) {
  if (session == NULL) return;
  SoftbusSessionPrivate *priv = _priv(session);
  priv->closed_cb = cb;
  priv->closed_user = user_data;
}

const guint8* softbus_session_get_session_id(const SoftbusSession *session) {
  if (session == NULL) return NULL;
  return _priv((SoftbusSession *)session)->session_id;
}

SoftbusSessionType softbus_session_get_session_type(const SoftbusSession *session) {
  if (session == NULL) return SOFTBUS_SESSION_MESSAGE;
  return _priv((SoftbusSession *)session)->session_type;
}

GSocketConnection* softbus_session_get_connection(const SoftbusSession *session) {
  if (session == NULL) return NULL;
  return _priv((SoftbusSession *)session)->conn;
}
