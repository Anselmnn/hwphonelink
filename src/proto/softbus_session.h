/*
 * softbus_session.h - Logical session over a connected socket
 *
 * Wraps a GSocketConnection with:
 *   - a read pump thread that deframes the byte stream into SoftbusFrames
 *   - a serialized write path (pack frame → write_all)
 *   - a per-session 8-byte session id and sequence counter
 *
 * The data callback is invoked from the pump thread (NOT the main loop).
 * Keep it short; use g_main_context_invoke() if you must touch the main
 * loop. The closed callback is invoked once, from the pump thread, after
 * the pump has fully stopped — it is safe to unref the session inside it
 * (the pump holds a temporary ref across the call).
 */

#pragma once

#include <glib.h>
#include <gio/gio.h>
#include "softbus_defs.h"
#include "softbus_frame.h"

G_BEGIN_DECLS

#define SOFTBUS_TYPE_SESSION (softbus_session_get_type())
G_DECLARE_FINAL_TYPE(SoftbusSession, softbus_session, SOFTBUS, SESSION, GObject)

typedef void (*SoftbusSessionDataCb)(SoftbusSession *session,
                                     const guint8 *data, gsize len,
                                     gpointer user_data);
typedef void (*SoftbusSessionClosedCb)(SoftbusSession *session,
                                       gpointer user_data);

/*
 * Create a session on a connected socket. The session takes its own ref on
 * @conn; the caller keeps its ref (or drops it) independently.
 * The read pump starts immediately.
 */
SoftbusSession* softbus_session_new(GSocketConnection *conn,
                                    SoftbusSessionType session_type);

/* Stop the read pump and block further writes. Idempotent. The peer
 * connection itself is not closed by this call. */
void softbus_session_stop(SoftbusSession *session);

/*
 * Send one logical message (framed: session id + seq + type + FIN).
 * @data may be NULL only when @len == 0.
 */
gboolean softbus_session_send(SoftbusSession *session, const guint8 *data,
                              gsize len, GError **error);
gboolean softbus_session_send_json(SoftbusSession *session, const gchar *json,
                                   GError **error);

void softbus_session_set_data_cb(SoftbusSession *session,
                                 SoftbusSessionDataCb cb,
                                 gpointer user_data,
                                 GDestroyNotify user_data_free);
void softbus_session_set_closed_cb(SoftbusSession *session,
                                   SoftbusSessionClosedCb cb,
                                   gpointer user_data);

const guint8* softbus_session_get_session_id(const SoftbusSession *session);
SoftbusSessionType softbus_session_get_session_type(const SoftbusSession *session);
GSocketConnection* softbus_session_get_connection(const SoftbusSession *session);
gboolean softbus_session_is_active(const SoftbusSession *session);

G_END_DECLS
