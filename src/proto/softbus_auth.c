/*
 * softbus_auth.c - HiChain authentication FSM (4 states) + PSK mode
 *
 * Message flow (active = the side that calls softbus_auth_begin_active):
 *
 *   active  --[negotiation:  authState=0, protoVersion]-->  passive
 *   active  <--[device-id:   authState=1, deviceId]--------  passive
 *   active  --[auth-request: authState=2, authType, nonce, deviceId]-->  passive
 *   active  <--[auth-response: authState=2, authType, nonce, signature]--  passive
 *   active  --[device-info:  authState=3, deviceName, capabilities, sessionKeyLen]-->  passive
 *
 * active  → DONE after sending device-info (verified signature)
 * passive → DONE after receiving device-info
 *
 * PSK-mode signature (replay stand; real HiChain V1/V2 is a cloud adapter, M5):
 *   signature = HMAC-SHA256(psk, nonce_active || nonce_passive || id_active || id_passive)
 * Session keys: HKDF-SHA256(psk, salt=sorted(id_a,id_b), info=control|data).
 */

#include "softbus_auth.h"
#include "softbus_crypto.h"

#include <json-glib/json-glib.h>
#include <string.h>

#define AUTH_NONCE_LEN 16

struct _SoftbusAuth {
  SoftbusDevice *local;      /* borrowed ref (caller keeps alive) */
  SoftbusDevice *peer;       /* owned ref (we hold a ref) */

  const guint8 *psk;         /* borrowed (caller keeps alive) */
  gsize psk_len;

  SoftbusAuthState state;
  gboolean is_active;
  gboolean awaiting_reply;   /* last sent message expects a response */
  guint64 auth_id;
  gint retry_count;
  guint64 state_entered_ms;

  gchar *peer_device_id;     /* learned from peer during exchange */
  guint8 active_nonce[AUTH_NONCE_LEN];

  /* Derived on success */
  guint8 control_key[SOFTBUS_SESSION_KEY_LEN];
  guint8 data_key[SOFTBUS_SESSION_KEY_LEN];
  gboolean keys_ready;
};

/* ============================ Lifecycle ============================ */

SoftbusAuth* softbus_auth_new(const SoftbusDevice *local, SoftbusDevice *peer,
                              const guint8 *psk, gsize psk_len) {
  if (local == NULL) return NULL;
  SoftbusAuth *a = g_new0(SoftbusAuth, 1);
  a->local = (SoftbusDevice *)local;
  a->peer = peer ? softbus_device_ref(peer) : NULL;
  a->psk = psk;
  a->psk_len = psk_len;
  a->state = SOFTBUS_AUTH_STATE_IDLE;
  a->auth_id = (guint64)(g_random_int() & 0x7fffffff) | 1;  /* nonzero */
  softbus_random_bytes(a->active_nonce, AUTH_NONCE_LEN);
  return a;
}

void softbus_auth_free(SoftbusAuth *a) {
  if (a == NULL) return;
  if (a->peer) softbus_device_unref(a->peer);
  g_free(a->peer_device_id);
  memset(a->control_key, 0, sizeof(a->control_key));
  memset(a->data_key, 0, sizeof(a->data_key));
  g_free(a);
}

const SoftbusDevice* softbus_auth_get_local(const SoftbusAuth *a) { return a ? a->local : NULL; }
SoftbusDevice* softbus_auth_get_peer(SoftbusAuth *a) { return a ? a->peer : NULL; }
SoftbusAuthState softbus_auth_get_state(const SoftbusAuth *a) { return a ? a->state : SOFTBUS_AUTH_STATE_IDLE; }
guint64 softbus_auth_get_id(const SoftbusAuth *a) { return a ? a->auth_id : 0; }
const guint8* softbus_auth_get_control_key(const SoftbusAuth *a) { return (a && a->keys_ready) ? a->control_key : NULL; }
const guint8* softbus_auth_get_data_key(const SoftbusAuth *a) { return (a && a->keys_ready) ? a->data_key : NULL; }
gsize softbus_auth_get_key_len(const SoftbusAuth *a) { return (a && a->keys_ready) ? SOFTBUS_SESSION_KEY_LEN : 0; }

/* ============================ Helpers ============================ */

static void _enter_state(SoftbusAuth *a, SoftbusAuthState s) {
  a->state = s;
  a->retry_count = 0;
  a->state_entered_ms = (guint64)(g_get_monotonic_time() / 1000);
}

/* Create a JsonObject with the common header members. */
static JsonObject* _new_msg(SoftbusAuth *a, gint auth_state) {
  JsonObject *o = json_object_new();
  json_object_set_int_member(o, SOFTBUS_JSON_AUTH_STATE, (gint64)auth_state);
  json_object_set_int_member(o, SOFTBUS_JSON_AUTH_ID, (gint64)a->auth_id);
  return o;
}

/* json-glib 1.x removed json_to_data() — serialize via JsonGenerator. */
static gchar* _node_to_data(JsonNode *root, gboolean pretty) {
  JsonGenerator *gen = json_generator_new();
  json_generator_set_pretty(gen, pretty);
  json_generator_set_root(gen, root);
  gchar *out = json_generator_to_data(gen, NULL);
  g_object_unref(gen);
  return out;
}

/* Finalize a message object into a compact JSON string. */
static gchar* _finish_msg(JsonObject *o) {
  JsonNode *root = json_node_new(JSON_NODE_OBJECT);
  json_node_take_object(root, o);
  gchar *out = _node_to_data(root, FALSE);
  json_node_free(root);
  return out;
}

/*
 * Extract the message header. The parsed document is detached from the
 * parser (json_parser_steal_root) so the object outlives it: the caller
 * owns @out_root (free with json_node_free) and @out_obj borrows from it,
 * valid until the node is freed.
 */
static gboolean _parse_header(const gchar *json, gsize len, JsonNode **out_root,
                              JsonObject **out_obj,
                              gint *out_state, guint64 *out_auth_id, GError **error) {
  JsonParser *p = json_parser_new();
  if (!json_parser_load_from_data(p, json, (gssize)len, error)) {
    g_object_unref(p);  /* json-glib 1.x: parser is a GObject */
    return FALSE;
  }
  JsonNode *root = json_parser_steal_root(p);
  g_object_unref(p);
  if (root == NULL || !JSON_NODE_HOLDS_OBJECT(root)) {
    json_node_free(root);
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "auth msg is not a JSON object");
    return FALSE;
  }
  JsonObject *obj = json_node_get_object(root);
  *out_root = root;
  *out_obj = obj;
  *out_state = (int)json_object_get_int_member(obj, SOFTBUS_JSON_AUTH_STATE);
  *out_auth_id = (guint64)json_object_get_int_member(obj, SOFTBUS_JSON_AUTH_ID);
  return TRUE;
}

/*
 * PSK-mode signature:
 *   HMAC-SHA256(psk, nonce_active || nonce_passive || id_active || id_passive)
 * Both sides compute the same value (fields concatenated in a fixed order).
 */
static gboolean _compute_sig(const SoftbusAuth *a,
                             const guint8 *nonce_a, const guint8 *nonce_p,
                             const gchar *id_a, const gchar *id_p,
                             guint8 out[32]) {
  if (a->psk == NULL || id_a == NULL || id_p == NULL) return FALSE;
  gsize la = strlen(id_a), lp = strlen(id_p);
  guint8 *buf = g_malloc((gsize)(AUTH_NONCE_LEN * 2 + la + lp));
  guint8 *q = buf;
  memcpy(q, nonce_a, AUTH_NONCE_LEN); q += AUTH_NONCE_LEN;
  memcpy(q, nonce_p, AUTH_NONCE_LEN); q += AUTH_NONCE_LEN;
  memcpy(q, id_a, la); q += la;
  memcpy(q, id_p, lp); q += lp;
  gboolean ok = softbus_hmac_sha256(a->psk, a->psk_len, buf, (gsize)(q - buf), out);
  g_free(buf);
  return ok;
}

/* Constant-time comparison (no early exit). */
static gboolean _const_time_eq(const guint8 *x, const guint8 *y, gsize n) {
  volatile guint8 diff = 0;
  for (gsize i = 0; i < n; i++) diff |= (guint8)(x[i] ^ y[i]);
  return diff == 0;
}

static void _derive_keys(SoftbusAuth *a) {
  if (a->psk == NULL || a->peer_device_id == NULL) return;
  const gchar *local_id = softbus_device_get_id(a->local);
  if (local_id == NULL) return;
  if (softbus_hkdf_session_keys(local_id,
                                a->peer_device_id,
                                a->psk, a->psk_len,
                                a->control_key, a->data_key)) {
    a->keys_ready = TRUE;
  }
}

static void _fail(SoftbusAuth *a) {
  a->state = SOFTBUS_AUTH_STATE_FAILED;
  a->awaiting_reply = FALSE;
}

/* ============================ Active start ============================ */

SoftbusAuthResult softbus_auth_begin_active(SoftbusAuth *a, gchar **out_json,
                                            GError **error) {
  if (a == NULL) return SOFTBUS_AUTH_RESULT_NOOP;
  if (a->state != SOFTBUS_AUTH_STATE_IDLE) {
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "auth already started");
    return SOFTBUS_AUTH_RESULT_NOOP;
  }
  a->is_active = TRUE;
  a->awaiting_reply = TRUE;
  _enter_state(a, SOFTBUS_AUTH_STATE_SYNC_NEGOTIATION);

  if (out_json) {
    JsonObject *o = _new_msg(a, SOFTBUS_AUTH_STATE_SYNC_NEGOTIATION);
    json_object_set_int_member(o, SOFTBUS_JSON_PROTO_VERSION, (gint64)SOFTBUS_PROTO_VERSION);
    *out_json = _finish_msg(o);
    return SOFTBUS_AUTH_RESULT_SEND;
  }
  return SOFTBUS_AUTH_RESULT_NOOP;
}

/* ============================ Feed (receive) ============================ */

SoftbusAuthResult softbus_auth_feed(SoftbusAuth *a, const gchar *json, gsize len,
                                    gchar **out_json, GError **error) {
  if (out_json) *out_json = NULL;

  if (a == NULL) {
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "auth is NULL");
    return SOFTBUS_AUTH_RESULT_NOOP;
  }
  if (json == NULL || len == 0) {
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "empty message");
    return SOFTBUS_AUTH_RESULT_NOOP;
  }
  if (a->is_active && a->state == SOFTBUS_AUTH_STATE_IDLE) {
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                "auth not started (call softbus_auth_begin_active first)");
    return SOFTBUS_AUTH_RESULT_NOOP;
  }
  if (a->state == SOFTBUS_AUTH_STATE_DONE || a->state == SOFTBUS_AUTH_STATE_FAILED) {
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                "auth already %s", a->state == SOFTBUS_AUTH_STATE_DONE ? "complete" : "failed");
    return SOFTBUS_AUTH_RESULT_NOOP;
  }

  JsonNode *root = NULL;
  JsonObject *obj = NULL;
  gint rstate = 0;
  guint64 rauth_id = 0;
  if (!_parse_header(json, len, &root, &obj, &rstate, &rauth_id, error)) {
    return SOFTBUS_AUTH_RESULT_NOOP;
  }

  if (!a->is_active && a->state == SOFTBUS_AUTH_STATE_IDLE) {
    /* First message received (passive side): the sender's auth id names
     * this exchange — adopt it so later messages match on both sides. */
    a->auth_id = rauth_id;
  } else if (rauth_id != a->auth_id) {
    _fail(a);
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "authId mismatch");
    json_node_free(root);
    return SOFTBUS_AUTH_RESULT_FAILED;
  }

  const gchar *local_id = softbus_device_get_id(a->local);
  SoftbusAuthResult result = SOFTBUS_AUTH_RESULT_NOOP;

  switch (a->state) {
    /* ---------- Passive: receive negotiation (state 0) ---------- */
    case SOFTBUS_AUTH_STATE_IDLE: {
      if (a->is_active || rstate != SOFTBUS_AUTH_STATE_SYNC_NEGOTIATION) {
        _fail(a);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                    "unexpected negotiation (state=%d)", rstate);
        result = SOFTBUS_AUTH_RESULT_FAILED;
        break;
      }
      if (json_object_has_member(obj, SOFTBUS_JSON_PROTO_VERSION)) {
        gint64 pv = json_object_get_int_member(obj, SOFTBUS_JSON_PROTO_VERSION);
        if (pv != SOFTBUS_PROTO_VERSION) {
          _fail(a);
          g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                      "unsupported proto version %lld", (long long)pv);
          result = SOFTBUS_AUTH_RESULT_FAILED;
          break;
        }
      }
      a->is_active = FALSE;
      a->awaiting_reply = TRUE;
      _enter_state(a, SOFTBUS_AUTH_STATE_SYNC_DEVICE_ID);

      if (out_json) {
        JsonObject *o = _new_msg(a, SOFTBUS_AUTH_STATE_SYNC_DEVICE_ID);
        if (local_id) json_object_set_string_member(o, SOFTBUS_JSON_DEVICE_ID_SHORT, local_id);
        *out_json = _finish_msg(o);
        result = SOFTBUS_AUTH_RESULT_SEND;
      }
      break;
    }

    /* ---------- Active: receive device id (state 1) ---------- */
    case SOFTBUS_AUTH_STATE_SYNC_NEGOTIATION: {
      if (!a->is_active || rstate != SOFTBUS_AUTH_STATE_SYNC_DEVICE_ID) {
        _fail(a);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                    "expected device-id, got state=%d", rstate);
        result = SOFTBUS_AUTH_RESULT_FAILED;
        break;
      }
      const gchar *peer_id = json_object_get_string_member(obj, SOFTBUS_JSON_DEVICE_ID_SHORT);
      if (peer_id == NULL) {
        _fail(a);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "missing deviceId");
        result = SOFTBUS_AUTH_RESULT_FAILED;
        break;
      }
      g_free(a->peer_device_id);
      a->peer_device_id = g_strdup(peer_id);

      a->awaiting_reply = TRUE;
      _enter_state(a, SOFTBUS_AUTH_STATE_DEVICE_AUTH);

      if (out_json) {
        JsonObject *o = _new_msg(a, SOFTBUS_AUTH_STATE_DEVICE_AUTH);
        json_object_set_int_member(o, SOFTBUS_JSON_AUTH_TYPE, (gint64)SOFTBUS_AUTH_TYPE_PSK);
        gchar *nhex = softbus_to_hex(a->active_nonce, AUTH_NONCE_LEN);
        json_object_set_string_member(o, SOFTBUS_JSON_NONCE, nhex);
        g_free(nhex);
        if (local_id) json_object_set_string_member(o, SOFTBUS_JSON_DEVICE_ID_SHORT, local_id);
        *out_json = _finish_msg(o);
        result = SOFTBUS_AUTH_RESULT_SEND;
      }
      break;
    }

    /* ---------- Passive: receive auth request (state 2, nonce) ---------- */
    case SOFTBUS_AUTH_STATE_SYNC_DEVICE_ID: {
      if (a->is_active || rstate != SOFTBUS_AUTH_STATE_DEVICE_AUTH) {
        _fail(a);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                    "expected auth-request, got state=%d", rstate);
        result = SOFTBUS_AUTH_RESULT_FAILED;
        break;
      }
      if (local_id == NULL) {
        _fail(a);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "local device has no id");
        result = SOFTBUS_AUTH_RESULT_FAILED;
        break;
      }
      const gchar *nonce_hex = json_object_get_string_member(obj, SOFTBUS_JSON_NONCE);
      const gchar *req_id = json_object_get_string_member(obj, SOFTBUS_JSON_DEVICE_ID_SHORT);
      if (nonce_hex == NULL) {
        _fail(a);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "missing nonce");
        result = SOFTBUS_AUTH_RESULT_FAILED;
        break;
      }
      guint8 nonce_a[AUTH_NONCE_LEN];
      gsize nl = 0;
      if (!softbus_from_hex(nonce_hex, nonce_a, sizeof(nonce_a), &nl) || nl != AUTH_NONCE_LEN) {
        _fail(a);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "bad nonce encoding");
        result = SOFTBUS_AUTH_RESULT_FAILED;
        break;
      }
      if (req_id) {
        g_free(a->peer_device_id);
        a->peer_device_id = g_strdup(req_id);
      }
      if (a->peer_device_id == NULL) {
        _fail(a);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "missing peer deviceId");
        result = SOFTBUS_AUTH_RESULT_FAILED;
        break;
      }

      /* Generate our nonce + signature, then respond.
       * Spec order: nonce_active || nonce_passive || id_active || id_passive.
       * From the passive side's view the active device is the peer. */
      guint8 nonce_p[AUTH_NONCE_LEN];
      softbus_random_bytes(nonce_p, AUTH_NONCE_LEN);
      guint8 sig[32];
      if (!_compute_sig(a, nonce_a, nonce_p, a->peer_device_id, local_id, sig)) {
        _fail(a);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "signature compute failed");
        result = SOFTBUS_AUTH_RESULT_FAILED;
        break;
      }
      _derive_keys(a);
      a->awaiting_reply = TRUE;
      _enter_state(a, SOFTBUS_AUTH_STATE_SYNC_DEVICE_INFO);

      if (out_json) {
        JsonObject *o = _new_msg(a, SOFTBUS_AUTH_STATE_DEVICE_AUTH);
        json_object_set_int_member(o, SOFTBUS_JSON_AUTH_TYPE, (gint64)SOFTBUS_AUTH_TYPE_PSK);
        gchar *nhex = softbus_to_hex(nonce_p, AUTH_NONCE_LEN);
        json_object_set_string_member(o, SOFTBUS_JSON_NONCE, nhex);
        g_free(nhex);
        gchar *shex = softbus_to_hex(sig, sizeof(sig));
        json_object_set_string_member(o, SOFTBUS_JSON_SIG, shex);
        g_free(shex);
        *out_json = _finish_msg(o);
        result = SOFTBUS_AUTH_RESULT_SEND;
      }
      break;
    }

    /* ---------- Active: receive auth response (state 2, signature) ---------- */
    case SOFTBUS_AUTH_STATE_DEVICE_AUTH: {
      if (!a->is_active || rstate != SOFTBUS_AUTH_STATE_DEVICE_AUTH) {
        _fail(a);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                    "expected auth-response, got state=%d", rstate);
        result = SOFTBUS_AUTH_RESULT_FAILED;
        break;
      }
      if (local_id == NULL || a->peer_device_id == NULL) {
        _fail(a);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "device ids unknown");
        result = SOFTBUS_AUTH_RESULT_FAILED;
        break;
      }
      const gchar *nonce_hex = json_object_get_string_member(obj, SOFTBUS_JSON_NONCE);
      const gchar *sig_hex = json_object_get_string_member(obj, SOFTBUS_JSON_SIG);
      if (nonce_hex == NULL || sig_hex == NULL) {
        _fail(a);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "missing nonce/signature");
        result = SOFTBUS_AUTH_RESULT_FAILED;
        break;
      }
      guint8 nonce_p[AUTH_NONCE_LEN];
      gsize nl = 0;
      if (!softbus_from_hex(nonce_hex, nonce_p, sizeof(nonce_p), &nl) || nl != AUTH_NONCE_LEN) {
        _fail(a);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "bad peer nonce");
        result = SOFTBUS_AUTH_RESULT_FAILED;
        break;
      }
      guint8 rx_sig[32];
      if (!softbus_from_hex(sig_hex, rx_sig, sizeof(rx_sig), NULL)) {
        _fail(a);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "bad signature encoding");
        result = SOFTBUS_AUTH_RESULT_FAILED;
        break;
      }
      guint8 exp_sig[32];
      if (!_compute_sig(a, a->active_nonce, nonce_p, local_id, a->peer_device_id, exp_sig) ||
          !_const_time_eq(rx_sig, exp_sig, sizeof(exp_sig))) {
        _fail(a);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "signature mismatch (auth failed)");
        result = SOFTBUS_AUTH_RESULT_FAILED;
        break;
      }
      _derive_keys(a);
      if (!a->keys_ready) {
        _fail(a);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "key derivation failed");
        result = SOFTBUS_AUTH_RESULT_FAILED;
        break;
      }
      a->awaiting_reply = FALSE;

      /* Send device info and complete. */
      if (out_json) {
        JsonObject *o = _new_msg(a, SOFTBUS_AUTH_STATE_SYNC_DEVICE_INFO);
        const gchar *nm = softbus_device_get_name(a->local);
        if (nm) json_object_set_string_member(o, SOFTBUS_JSON_DEVICE_NAME, nm);
        json_object_set_int_member(o, SOFTBUS_JSON_CAPABILITIES,
                                   (gint64)softbus_device_get_capabilities(a->local));
        json_object_set_int_member(o, SOFTBUS_JSON_SESSION_KEY_LEN,
                                   (gint64)SOFTBUS_SESSION_KEY_LEN);
        *out_json = _finish_msg(o);
      }
      a->state = SOFTBUS_AUTH_STATE_DONE;
      result = SOFTBUS_AUTH_RESULT_COMPLETE;
      break;
    }

    /* ---------- Passive: receive device info (state 3) → DONE ---------- */
    case SOFTBUS_AUTH_STATE_SYNC_DEVICE_INFO: {
      if (a->is_active || rstate != SOFTBUS_AUTH_STATE_SYNC_DEVICE_INFO) {
        _fail(a);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                    "expected device-info, got state=%d", rstate);
        result = SOFTBUS_AUTH_RESULT_FAILED;
        break;
      }
      if (!a->keys_ready) {
        _fail(a);
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "keys not derived");
        result = SOFTBUS_AUTH_RESULT_FAILED;
        break;
      }
      a->awaiting_reply = FALSE;
      _enter_state(a, SOFTBUS_AUTH_STATE_DONE);
      result = SOFTBUS_AUTH_RESULT_COMPLETE;
      break;
    }

    case SOFTBUS_AUTH_STATE_DONE:
    case SOFTBUS_AUTH_STATE_FAILED:
    default:
      g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "unexpected state %d",
                  (int)a->state);
      break;
  }

  json_node_free(root);
  return result;
}

/* ============================ Retry ============================ */

gboolean softbus_auth_retry_due(SoftbusAuth *a, guint64 now_ms) {
  if (a == NULL) return FALSE;
  if (a->state == SOFTBUS_AUTH_STATE_FAILED || a->state == SOFTBUS_AUTH_STATE_DONE)
    return FALSE;
  if (!a->awaiting_reply) return FALSE;

  if (now_ms < a->state_entered_ms) return FALSE;
  guint64 elapsed = now_ms - a->state_entered_ms;
  if (elapsed < SOFTBUS_AUTH_STATE_TIMEOUT_MS) return FALSE;

  if (a->retry_count >= SOFTBUS_AUTH_RETRIES) {
    _fail(a);
    return FALSE;
  }
  a->retry_count++;
  a->state_entered_ms = now_ms;
  return TRUE;
}
