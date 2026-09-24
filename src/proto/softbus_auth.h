/*
 * softbus_auth.h - HiChain authentication FSM (4 states) + PSK mode
 *
 * FSM from auth_session_fsm.c (spec §4.1):
 *
 *   IDLE → SYNC_NEGOTIATION → SYNC_DEVICE_ID → DEVICE_AUTH → SYNC_DEVICE_INFO → DONE
 *          (proto version)    (device IDs)     (auth+keys)    (info + confirm)
 *
 * The real device uses HiChain V1 / Identity Service V2 (cloud-assisted,
 * Huawei ID trust, spec §10.1). That cloud adapter is M5. For the replay
 * stand and mock phone (no live phone until M4) this FSM runs in PSK mode
 * (SOFTBUS_AUTH_TYPE_PSK): the shared secret is a pre-provisioned PSK and
 * DEVICE_AUTH is an HMAC-SHA256 challenge. The state machine, message
 * shapes, timing and key-derivation (HKDF) match the production flow.
 *
 * The FSM is synchronous and event-driven; the owner (session layer) feeds
 * received JSON and sends the returned response. No internal timers.
 */

#pragma once

#include <glib.h>
#include "softbus_defs.h"
#include "softbus_device.h"

typedef struct _SoftbusAuth SoftbusAuth;

/* Result of feeding a message / starting auth. */
typedef enum {
  SOFTBUS_AUTH_RESULT_NOOP = 0,    /* no action, state unchanged */
  SOFTBUS_AUTH_RESULT_SEND,        /* @out_json holds a message to send */
  SOFTBUS_AUTH_RESULT_COMPLETE,    /* reached DONE, keys available */
  SOFTBUS_AUTH_RESULT_FAILED,      /* auth failed (bad sig, timeout, ...) */
} SoftbusAuthResult;

/*
 * Create an auth context.
 * @local  our device record
 * @peer   the discovered peer (may be refined during the exchange)
 * @psk    shared secret for PSK mode (NULL → HiChain/cloud mode, M5)
 */
SoftbusAuth* softbus_auth_new(const SoftbusDevice *local,
                              SoftbusDevice *peer,
                              const guint8 *psk, gsize psk_len);
void softbus_auth_free(SoftbusAuth *auth);

/* Local / peer device access. */
const SoftbusDevice* softbus_auth_get_local(const SoftbusAuth *auth);
SoftbusDevice* softbus_auth_get_peer(SoftbusAuth *auth);

/* Current FSM state. */
SoftbusAuthState softbus_auth_get_state(const SoftbusAuth *auth);

/*
 * Begin as the ACTIVE side (we initiate). Returns the first message
 * (SYNC_NEGOTIATION) in @out_json (newly allocated) on SEND.
 */
SoftbusAuthResult softbus_auth_begin_active(SoftbusAuth *auth, gchar **out_json,
                                            GError **error);

/*
 * Receive a JSON message from the peer. Advances the FSM.
 * On SEND, @out_json is set to the reply (newly allocated, may be NULL for
 * messages needing no reply). On COMPLETE, session keys are derived.
 * @out_json is left NULL/unchanged when no reply is required.
 */
SoftbusAuthResult softbus_auth_feed(SoftbusAuth *auth, const gchar *json,
                                    gsize len, gchar **out_json, GError **error);

/*
 * Retry support (spec §4.1: 30s per state, 3 retries @ 300ms).
 * The owner calls this periodically (e.g. from a g_timeout) after sending a
 * message that expects a reply. Returns TRUE if a retry is due (and consumes
 * one retry budget). When retries are exhausted, state → FAILED.
 * @now_ms monotonic milliseconds.
 */
gboolean softbus_auth_retry_due(SoftbusAuth *auth, guint64 now_ms);

/* Session keys (valid once state == DONE). */
const guint8* softbus_auth_get_control_key(const SoftbusAuth *auth);
const guint8* softbus_auth_get_data_key(const SoftbusAuth *auth);
gsize softbus_auth_get_key_len(const SoftbusAuth *auth);

/* AuthId (correlates messages of one exchange). */
guint64 softbus_auth_get_id(const SoftbusAuth *auth);
