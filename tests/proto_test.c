/*
 * proto_test.c - Unit tests for the dsoftbus protocol core
 *
 *   - TLV frame codec (pack/unpack round-trip, incremental stream buffer,
 *     corrupt-stream handling)
 *   - Discovery beacon JSON (pack/parse round-trip)
 *   - Crypto primitives (HKDF determinism + symmetry, AES-256-GCM
 *     round-trip + tamper detection, HMAC determinism)
 *   - Auth FSM (full PSK exchange in-process, wrong-PSK rejection,
 *     retry budget exhaustion)
 *   - Session layer (frame pump over a real socketpair)
 *   - DFile frame codec (RE'd wire format: setting, file header,
 *     id-list, data, ACK V1/V2 count-encoding, RST) + ft test-file helper
 *   - fillp (Dstream) codec: 12B head + 8 management payloads, cookie
 *     HMAC make/verify (incl. tamper + wrong-address rejection), 28-byte
 *     compat address layout, wraparound-safe counter comparison
 *   - VTP frame layer: AES-256-GCM COMMON framing round-trip, key
 *     derivation, wrong-key / tamper / truncation / ext-bit rejection
 *   - H.264 replay test-file generator: Annex-B invariants, sha-in-name,
 *     determinism, corruption detection
 *   - RemoteCtrl input encoder (RE'd builders: touch/key/zoom/scroll/
 *     mouse/input7/wheel/vkey/message; exact byte vectors, pad rule,
 *     hdr[0] flag remap, dead types 4/5)
 *   - DMSDP control text (builder byte-exact stand vectors, 3-byte
 *     NoCrypto frame, parser incl. soft-ignored keys / parse_integer
 *     degeneracies / trigger-method body, minimal client FSM)
 *
 * No network required; runs in CI.
 */

#include <glib.h>
#include <gio/gio.h>
#include <sys/socket.h>
#include <string.h>

#include "proto/softbus_defs.h"
#include "proto/softbus_frame.h"
#include "proto/softbus_device.h"
#include "proto/softbus_crypto.h"
#include "proto/softbus_auth.h"
#include "proto/softbus_session.h"
#include "proto/dfile_frame.h"
#include "proto/ft_testfile.h"
#include "proto/fillp_frame.h"
#include "proto/vtp_frame.h"
#include "proto/h264_testfile.h"
#include "proto/remote_input.h"
#include "proto/dmsdp.h"

static int failures = 0;

#define CHECK(cond) \
  do { \
    if (cond) { \
      g_print("  ok   %s\n", #cond); \
    } else { \
      g_print("  FAIL %s (%s:%d)\n", #cond, __FILE__, __LINE__); \
      failures++; \
    } \
  } while (0)

/* ============================ Frame codec ============================ */

static void test_frame_roundtrip(void) {
  g_print("frame round-trip\n");
  gchar payload[] = "hello softbus";

  SoftbusFrame f;
  memset(&f, 0, sizeof(f));
  for (int i = 0; i < SOFTBUS_FRAME_SESSION_ID_SIZE; i++)
    f.session_id[i] = (guint8)(i + 1);
  f.seq = 0x12345678u;
  f.type = SOFTBUS_SESSION_FILE;
  f.flags = SOFTBUS_FRAME_FLAG_FIN;
  f.pkt_flags = SOFTBUS_PKT_FLAG_NONE;
  f.ext_len = 0;
  f.payload = (guint8 *)payload;
  f.payload_len = sizeof(payload) - 1;

  guint8 wire[SOFTBUS_FRAME_MIN_SIZE + 128];
  gsize n = softbus_frame_pack(&f, wire, sizeof(wire));
  CHECK(n == SOFTBUS_FRAME_MIN_SIZE + sizeof(payload) - 1);
  CHECK(wire[0] == SOFTBUS_FRAME_MAGIC_0 && wire[1] == SOFTBUS_FRAME_MAGIC_1);
  CHECK(wire[2] == SOFTBUS_FRAME_VERSION);
  CHECK(wire[3] == SOFTBUS_FRAME_FLAG_FIN);
  /* Length field (offset 4, BE) = total incl. header */
  guint32 len_be;
  memcpy(&len_be, wire + 4, 4);
  CHECK(GUINT32_FROM_BE(len_be) == n);

  SoftbusFrame r;
  gssize rn = softbus_frame_unpack(wire, n, &r);
  CHECK(rn == (gssize)n);
  CHECK(memcmp(r.session_id, f.session_id, SOFTBUS_FRAME_SESSION_ID_SIZE) == 0);
  CHECK(r.seq == f.seq);
  CHECK(r.type == f.type);
  CHECK(r.flags == f.flags);
  CHECK(r.pkt_flags == f.pkt_flags);
  CHECK(r.ext_len == 0);
  CHECK(r.payload_len == f.payload_len);
  CHECK(r.payload != NULL && memcmp(r.payload, payload, r.payload_len) == 0);
}

static void test_frame_buf_incremental(void) {
  g_print("frame buffer (incremental feed)\n");
  gchar payload[] = "incremental";

  SoftbusFrame f;
  memset(&f, 0, sizeof(f));
  memset(f.session_id, 0xa5, SOFTBUS_FRAME_SESSION_ID_SIZE);
  f.seq = 7;
  f.type = SOFTBUS_SESSION_MESSAGE;
  f.flags = SOFTBUS_FRAME_FLAG_FIN;
  f.payload = (guint8 *)payload;
  f.payload_len = sizeof(payload) - 1;

  guint8 wire[SOFTBUS_FRAME_MIN_SIZE + 128];
  gsize total = softbus_frame_pack(&f, wire, sizeof(wire));
  CHECK(total > 0);

  SoftbusFrameBuf *buf = softbus_frame_buf_new();
  SoftbusFrame got;
  GError *err = NULL;
  gboolean popped = FALSE;

  /* Feed one byte at a time; the frame only completes on the last byte. */
  for (gsize i = 0; i < total; i++) {
    CHECK(softbus_frame_buf_append(buf, wire + i, 1, NULL));
    if (i + 1 < total) {
      if (softbus_frame_buf_pop(buf, &got, &err)) {
        CHECK(FALSE && "premature pop");
        g_free(got.payload);  /* pop() hands us an owned copy */
        g_clear_error(&err);
      }
    } else {
      popped = softbus_frame_buf_pop(buf, &got, &err);
      if (err) { g_print("  pop error: %s\n", err->message); g_clear_error(&err); }
    }
  }
  CHECK(popped);
  CHECK(got.seq == 7);
  CHECK(got.type == SOFTBUS_SESSION_MESSAGE);
  CHECK(got.payload_len == sizeof(payload) - 1);
  CHECK(got.payload != NULL && memcmp(got.payload, payload, got.payload_len) == 0);
  g_free(got.payload);  /* pop() hands us an owned copy */

  /* Second frame appended right after the first — both pop in order. */
  SoftbusFrame f2 = f;
  f2.seq = 8;
  memcpy(f2.payload, "second", 6);
  f2.payload_len = 6;
  guint8 wire2[SOFTBUS_FRAME_MIN_SIZE + 128];
  gsize total2 = softbus_frame_pack(&f2, wire2, sizeof(wire2));
  softbus_frame_buf_append(buf, wire2, total2, NULL);
  CHECK(softbus_frame_buf_pop(buf, &got, &err));
  CHECK(got.seq == 8 && got.payload_len == 6 && memcmp(got.payload, "second", 6) == 0);
  g_free(got.payload);  /* pop() hands us an owned copy */

  softbus_frame_buf_free(buf);
}

static void test_frame_bad_magic(void) {
  g_print("frame corrupt-stream handling\n");
  gchar payload[] = "badmagic";
  SoftbusFrame f;
  memset(&f, 0, sizeof(f));
  f.type = SOFTBUS_SESSION_MESSAGE;
  f.payload = (guint8 *)payload;
  f.payload_len = sizeof(payload) - 1;

  guint8 wire[SOFTBUS_FRAME_MIN_SIZE + 128];
  gsize total = softbus_frame_pack(&f, wire, sizeof(wire));
  wire[0] = 0xde;  /* corrupt magic */

  SoftbusFrame r;
  CHECK(softbus_frame_unpack(wire, total, &r) == -1);

  SoftbusFrameBuf *buf = softbus_frame_buf_new();
  SoftbusFrame got;
  GError *err = NULL;
  softbus_frame_buf_append(buf, wire, total, NULL);
  CHECK(!softbus_frame_buf_pop(buf, &got, &err));
  CHECK(err != NULL);  /* bad magic sets an error */
  if (err) g_clear_error(&err);
  CHECK(softbus_frame_buf_pending(buf) == 0);  /* buffer reset after resync */

  /* A valid frame after garbage is still parsed. */
  wire[0] = SOFTBUS_FRAME_MAGIC_0;
  softbus_frame_buf_append(buf, wire, total, NULL);
  CHECK(softbus_frame_buf_pop(buf, &got, &err));
  CHECK(got.payload_len == sizeof(payload) - 1);
  g_free(got.payload);  /* pop() hands us an owned copy */
  softbus_frame_buf_free(buf);
}

/* ============================ Beacon ============================ */

static void test_beacon_roundtrip(void) {
  g_print("beacon JSON round-trip\n");
  SoftbusDevice *dev = softbus_device_new();
  dev->device_id = g_strdup("mock-phone-001");
  dev->device_name = g_strdup("HUAWEI P40 Pro");
  dev->device_type = SOFTBUS_DEVTYPE_PHONE;
  dev->capabilities = 15;
  dev->auth_port = 45678;
  dev->session_port = 45679;
  dev->proxy_port = 45680;
  dev->ble_mac = g_strdup("aa:bb:cc:dd:ee:ff");

  GError *err = NULL;
  gchar *beacon = softbus_device_pack_beacon(dev, &err);
  CHECK(beacon != NULL);
  if (!beacon) { g_print("  pack error: %s\n", err->message); g_clear_error(&err); softbus_device_unref(dev); return; }

  SoftbusDevice *parsed = softbus_device_parse_beacon(beacon, strlen(beacon), &err);
  CHECK(parsed != NULL);
  if (parsed) {
    CHECK(strcmp(softbus_device_get_id(parsed), "mock-phone-001") == 0);
    CHECK(strcmp(softbus_device_get_name(parsed), "HUAWEI P40 Pro") == 0);
    CHECK(softbus_device_get_type(parsed) == SOFTBUS_DEVTYPE_PHONE);
    CHECK(softbus_device_get_capabilities(parsed) == 15);
    CHECK(softbus_device_get_auth_port(parsed) == 45678);
    CHECK(softbus_device_get_session_port(parsed) == 45679);
    CHECK(softbus_device_get_proxy_port(parsed) == 45680);
    CHECK(strcmp(softbus_device_get_ble_mac(parsed), "aa:bb:cc:dd:ee:ff") == 0);
    softbus_device_unref(parsed);
  }

  /* A beacon without deviceId must be rejected. */
  GError *err2 = NULL;
  SoftbusDevice *bad = softbus_device_parse_beacon(
      "{\"deviceName\":\"nope\"}", 19, &err2);
  CHECK(bad == NULL);
  if (err2) g_clear_error(&err2);

  g_free(beacon);
  softbus_device_unref(dev);
}

/* ============================ Crypto ============================ */

static void test_hkdf(void) {
  g_print("HKDF determinism + symmetry\n");
  const gchar *ikm = "test-psk-material";
  guint8 salt[] = {0x00, 0x01, 0x02, 0x03};
  guint8 out1[32], out2[32], out3[32];

  CHECK(softbus_hkdf_sha256((guint8 *)ikm, strlen(ikm), salt, sizeof(salt),
                            "info-a", out1, sizeof(out1)));
  CHECK(softbus_hkdf_sha256((guint8 *)ikm, strlen(ikm), salt, sizeof(salt),
                            "info-a", out2, sizeof(out2)));
  CHECK(memcmp(out1, out2, 32) == 0);          /* deterministic */
  CHECK(softbus_hkdf_sha256((guint8 *)ikm, strlen(ikm), salt, sizeof(salt),
                            "info-b", out3, sizeof(out3)));
  CHECK(memcmp(out1, out3, 32) != 0);          /* info distinguishes keys */

  /* Session keys: symmetric in (id_a, id_b) — same keys both directions. */
  guint8 ca1[SOFTBUS_SESSION_KEY_LEN], da1[SOFTBUS_SESSION_KEY_LEN];
  guint8 ca2[SOFTBUS_SESSION_KEY_LEN], da2[SOFTBUS_SESSION_KEY_LEN];
  CHECK(softbus_hkdf_session_keys("device-b", "device-a",
                                  (guint8 *)ikm, strlen(ikm), ca1, da1));
  CHECK(softbus_hkdf_session_keys("device-a", "device-b",
                                  (guint8 *)ikm, strlen(ikm), ca2, da2));
  CHECK(memcmp(ca1, ca2, SOFTBUS_SESSION_KEY_LEN) == 0);
  CHECK(memcmp(da1, da2, SOFTBUS_SESSION_KEY_LEN) == 0);
  CHECK(memcmp(ca1, da1, SOFTBUS_SESSION_KEY_LEN) != 0);  /* control != data */
}

static void test_aes_gcm(void) {
  g_print("AES-256-GCM round-trip + tamper detection\n");
  guint8 key[32], iv[SOFTBUS_GCM_IV_LEN];
  CHECK(softbus_random_bytes(key, sizeof(key)));
  CHECK(softbus_random_bytes(iv, sizeof(iv)));

  const gchar *pt = "sensitive multiscreen payload";
  guint8 ct[128], pt_out[128], tag[SOFTBUS_GCM_TAG_LEN];
  const guint8 aad[] = "aad";

  CHECK(softbus_aes_gcm_encrypt(key, sizeof(key), iv, sizeof(iv),
                                aad, sizeof(aad) - 1,
                                (guint8 *)pt, strlen(pt), ct, tag));
  CHECK(softbus_aes_gcm_decrypt(key, sizeof(key), iv, sizeof(iv),
                                aad, sizeof(aad) - 1,
                                ct, strlen(pt), tag, pt_out));
  CHECK(memcmp(pt_out, pt, strlen(pt)) == 0);

  /* Tamper with the ciphertext → tag check must fail. */
  ct[3] ^= 0x01;
  CHECK(!softbus_aes_gcm_decrypt(key, sizeof(key), iv, sizeof(iv),
                                 aad, sizeof(aad) - 1,
                                 ct, strlen(pt), tag, pt_out));

  /* Wrong key → fail. */
  ct[3] ^= 0x01;
  guint8 bad_key[32];
  memcpy(bad_key, key, sizeof(bad_key));
  bad_key[0] ^= 0xff;
  CHECK(!softbus_aes_gcm_decrypt(bad_key, sizeof(bad_key), iv, sizeof(iv),
                                 aad, sizeof(aad) - 1,
                                 ct, strlen(pt), tag, pt_out));
}

static void test_hmac(void) {
  g_print("HMAC-SHA256 determinism\n");
  const gchar *key = "hmac-key";
  const gchar *data = "the quick brown fox";
  guint8 h1[32], h2[32], h3[32];

  CHECK(softbus_hmac_sha256((guint8 *)key, strlen(key),
                            (guint8 *)data, strlen(data), h1));
  CHECK(softbus_hmac_sha256((guint8 *)key, strlen(key),
                            (guint8 *)data, strlen(data), h2));
  CHECK(memcmp(h1, h2, 32) == 0);
  CHECK(softbus_hmac_sha256((guint8 *)key, strlen(key),
                            (guint8 *)"other data", 10, h3));
  CHECK(memcmp(h1, h3, 32) != 0);
}

/* ============================ Auth FSM ============================ */

static SoftbusDevice* make_device(const gchar *id) {
  SoftbusDevice *d = softbus_device_new();
  d->device_id = g_strdup(id);
  d->device_name = g_strdup(id);
  d->device_type = SOFTBUS_DEVTYPE_PHONE;
  d->capabilities = 15;
  return d;
}

/* Feed *in to @dst, replacing *in with the reply (NULL when none). */
static SoftbusAuthResult _relay(SoftbusAuth *dst, gchar **in, GError **err) {
  if (in == NULL || *in == NULL) return SOFTBUS_AUTH_RESULT_NOOP;
  gchar *out = NULL;
  SoftbusAuthResult r = softbus_auth_feed(dst, *in, strlen(*in), &out, err);
  g_free(*in);
  *in = out;
  return r;
}

static void test_auth_fsm_psk(void) {
  g_print("auth FSM: full PSK exchange (in-process)\n");
  const gchar *psk = "shared-unit-psk";

  SoftbusDevice *dev_a = make_device("pc-unit-001");
  SoftbusDevice *dev_b = make_device("phone-unit-001");

  SoftbusAuth *a = softbus_auth_new(dev_a, NULL, (guint8 *)psk, strlen(psk));
  SoftbusAuth *b = softbus_auth_new(dev_b, NULL, (guint8 *)psk, strlen(psk));

  gchar *in = NULL;
  GError *err = NULL;

  /* 0: active sends negotiation (authState=0) */
  CHECK(softbus_auth_begin_active(a, &in, &err) == SOFTBUS_AUTH_RESULT_SEND);
  CHECK(in != NULL);
  /* 1: passive replies with device id (authState=1) */
  CHECK(_relay(b, &in, &err) == SOFTBUS_AUTH_RESULT_SEND);
  CHECK(in != NULL);
  /* 2: active sends auth request with nonce (authState=2) */
  CHECK(_relay(a, &in, &err) == SOFTBUS_AUTH_RESULT_SEND);
  CHECK(in != NULL);
  /* 3: passive replies with its nonce + signature (authState=2) */
  CHECK(_relay(b, &in, &err) == SOFTBUS_AUTH_RESULT_SEND);
  CHECK(in != NULL);
  /* 4: active verifies signature, produces device info (authState=3) → DONE */
  CHECK(_relay(a, &in, &err) == SOFTBUS_AUTH_RESULT_COMPLETE);
  CHECK(softbus_auth_get_state(a) == SOFTBUS_AUTH_STATE_DONE);
  CHECK(in != NULL);  /* the device-info frame to deliver */
  /* 5: passive receives device info → DONE */
  CHECK(_relay(b, &in, &err) == SOFTBUS_AUTH_RESULT_COMPLETE);
  CHECK(softbus_auth_get_state(b) == SOFTBUS_AUTH_STATE_DONE);
  g_free(in);

  /* Both sides must have derived identical keys. */
  const guint8 *cka = softbus_auth_get_control_key(a);
  const guint8 *dka = softbus_auth_get_data_key(a);
  const guint8 *ckb = softbus_auth_get_control_key(b);
  const guint8 *dkb = softbus_auth_get_data_key(b);
  CHECK(cka != NULL && dka != NULL && ckb != NULL && dkb != NULL);
  CHECK(cka && ckb && memcmp(cka, ckb, SOFTBUS_SESSION_KEY_LEN) == 0);
  CHECK(dka && dkb && memcmp(dka, dkb, SOFTBUS_SESSION_KEY_LEN) == 0);
  CHECK(cka && dka && memcmp(cka, dka, SOFTBUS_SESSION_KEY_LEN) != 0);

  g_clear_error(&err);
  softbus_auth_free(a);
  softbus_auth_free(b);
  softbus_device_unref(dev_a);
  softbus_device_unref(dev_b);
}

static void test_auth_wrong_psk(void) {
  g_print("auth FSM: wrong PSK is rejected\n");
  SoftbusDevice *dev_a = make_device("pc-unit-101");
  SoftbusDevice *dev_b = make_device("phone-unit-101");

  SoftbusAuth *a = softbus_auth_new(dev_a, NULL, (guint8 *)"psk-one", 7);
  SoftbusAuth *b = softbus_auth_new(dev_b, NULL, (guint8 *)"psk-two", 7);

  gchar *in = NULL;
  GError *err = NULL;

  CHECK(softbus_auth_begin_active(a, &in, &err) == SOFTBUS_AUTH_RESULT_SEND);
  CHECK(in != NULL);
  CHECK(_relay(b, &in, &err) == SOFTBUS_AUTH_RESULT_SEND);
  CHECK(in != NULL);
  CHECK(_relay(a, &in, &err) == SOFTBUS_AUTH_RESULT_SEND);
  CHECK(in != NULL);
  CHECK(_relay(b, &in, &err) == SOFTBUS_AUTH_RESULT_SEND);
  CHECK(in != NULL);
  /* Active verifies the signature — mismatch with the wrong PSK. */
  CHECK(_relay(a, &in, &err) == SOFTBUS_AUTH_RESULT_FAILED);
  CHECK(softbus_auth_get_state(a) == SOFTBUS_AUTH_STATE_FAILED);
  CHECK(softbus_auth_get_control_key(a) == NULL);

  g_free(in);
  g_clear_error(&err);  /* the mismatch error was left in @err */
  softbus_auth_free(a);
  softbus_auth_free(b);
  softbus_device_unref(dev_a);
  softbus_device_unref(dev_b);
}

static void test_auth_retry_exhaustion(void) {
  g_print("auth FSM: retry budget exhaustion\n");
  SoftbusDevice *dev_a = make_device("pc-unit-201");
  SoftbusAuth *a = softbus_auth_new(dev_a, NULL, (guint8 *)"psk", 3);

  gchar *msg = NULL;
  GError *err = NULL;
  CHECK(softbus_auth_begin_active(a, &msg, &err) == SOFTBUS_AUTH_RESULT_SEND);
  g_free(msg);

  guint64 now = (guint64)(g_get_monotonic_time() / 1000) + SOFTBUS_AUTH_STATE_TIMEOUT_MS + 1;
  CHECK(softbus_auth_retry_due(a, now));            /* retry 1 */
  now += SOFTBUS_AUTH_STATE_TIMEOUT_MS + 1;
  CHECK(softbus_auth_retry_due(a, now));            /* retry 2 */
  now += SOFTBUS_AUTH_STATE_TIMEOUT_MS + 1;
  CHECK(softbus_auth_retry_due(a, now));            /* retry 3 */
  now += SOFTBUS_AUTH_STATE_TIMEOUT_MS + 1;
  CHECK(!softbus_auth_retry_due(a, now));           /* exhausted → FAILED */
  CHECK(softbus_auth_get_state(a) == SOFTBUS_AUTH_STATE_FAILED);
  CHECK(!softbus_auth_retry_due(a, now + 1000));    /* FAILED: no more retries */

  g_clear_error(&err);
  softbus_auth_free(a);
  softbus_device_unref(dev_a);
}

/* ============================ Session (socketpair) ============================ */

static GMutex test_lock;
static GCond test_cond;
static guint8 test_payload[128];
static gsize test_payload_len = 0;
static gboolean test_got_data = FALSE;
static int test_frames_seen = 0;

static void test_session_cb(SoftbusSession *session, const guint8 *data,
                            gsize len, gpointer user_data) {
  (void)session;
  (void)user_data;
  g_mutex_lock(&test_lock);
  test_frames_seen++;
  if (data != NULL && len > 0 && len <= sizeof(test_payload)) {
    memcpy(test_payload, data, len);
    test_payload_len = len;
  }
  test_got_data = TRUE;
  g_cond_signal(&test_cond);
  g_mutex_unlock(&test_lock);
}

static void test_session_socketpair(void) {
  g_print("session: frame pump over socketpair\n");
  int sv[2];
  CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

  GSocket *sock_a = g_socket_new_from_fd(sv[0], NULL);
  GSocket *sock_b = g_socket_new_from_fd(sv[1], NULL);
  CHECK(sock_a != NULL && sock_b != NULL);
  if (!sock_a || !sock_b) return;

  GSocketConnection *conn_a = g_socket_connection_factory_create_connection(sock_a);
  GSocketConnection *conn_b = g_socket_connection_factory_create_connection(sock_b);
  CHECK(conn_a != NULL && conn_b != NULL);
  if (!conn_a || !conn_b) { g_object_unref(sock_a); g_object_unref(sock_b); return; }

  SoftbusSession *sess_a = softbus_session_new(conn_a, SOFTBUS_SESSION_MESSAGE);
  SoftbusSession *sess_b = softbus_session_new(conn_b, SOFTBUS_SESSION_MESSAGE);
  CHECK(sess_a != NULL && sess_b != NULL);
  if (!sess_a || !sess_b) {
    g_object_unref(conn_a); g_object_unref(conn_b);
    g_object_unref(sock_a); g_object_unref(sock_b);
    return;
  }

  softbus_session_set_data_cb(sess_b, test_session_cb, NULL, NULL);

  GError *err = NULL;
  CHECK(softbus_session_send_json(sess_a, "{\"test\":1}", &err));
  CHECK(softbus_session_send(sess_a, (guint8 *)"raw-bytes", 9, &err));
  if (err) { g_print("  send error: %s\n", err->message); g_clear_error(&err); }

  /*
   * Wait for both frames (up to 2s). g_cond_wait_until() takes the deadline
   * in the same units as g_get_monotonic_time() — microseconds (per the GLib
   * docs and both its wait implementations), NOT milliseconds. A ms value is
   * always "in the past" and the call returns immediately every iteration,
   * spinning this thread and starving the pump's callback on the mutex.
   */
  g_mutex_lock(&test_lock);
  gint64 deadline = g_get_monotonic_time() + 2 * G_TIME_SPAN_SECOND;
  while (test_frames_seen < 2) {
    if (g_get_monotonic_time() >= deadline) break;
    g_cond_wait_until(&test_cond, &test_lock, deadline);
  }
  CHECK(test_frames_seen == 2);
  /* Second frame received last */
  CHECK(test_payload_len == 9 && memcmp(test_payload, "raw-bytes", 9) == 0);
  g_mutex_unlock(&test_lock);

  softbus_session_stop(sess_a);
  softbus_session_stop(sess_b);
  g_object_unref(sess_a);
  g_object_unref(sess_b);
  g_object_unref(conn_a);
  g_object_unref(conn_b);
  g_object_unref(sock_a);
  g_object_unref(sock_b);
}

/* ============================ DFile codec ============================ */

static void put16_test(guint8 *p, guint16 v) {
  p[0] = (guint8)(v >> 8);
  p[1] = (guint8)(v & 0xff);
}

static void put32_test(guint8 *p, guint32 v) {
  p[0] = (guint8)(v >> 24);
  p[1] = (guint8)((v >> 16) & 0xff);
  p[2] = (guint8)((v >> 8) & 0xff);
  p[3] = (guint8)(v & 0xff);
}

static void test_dfile_header_unpack(void) {
  g_print("dfile header unpack\n");
  guint8 buf[8] = {0};
  put16_test(buf + 4, 7);
  put16_test(buf + 6, 100);
  DFileFrameHeader h;
  CHECK(dfile_frame_header_unpack(buf, 8, &h) == 0);
  CHECK(h.type == 0 && h.flag == 0 && h.session_id == 0);
  CHECK(h.trans_id == 7 && h.length == 100);
  /* fewer than 8 bytes -> -1 */
  CHECK(dfile_frame_header_unpack(buf, 5, &h) == -1);
  /* zero payload -> -2 */
  buf[6] = 0;
  buf[7] = 0;
  CHECK(dfile_frame_header_unpack(buf, 8, &h) == -2);
  /* length above the main-loop sanity cap -> -2 */
  put16_test(buf + 6, DFILE_FRAME_MAX_LEN + 1);
  CHECK(dfile_frame_header_unpack(buf, 8, &h) == -2);
}

static void test_dfile_setting_roundtrip(void) {
  g_print("dfile setting round-trip\n");
  DFileSetting s;
  memset(&s, 0, sizeof(s));
  s.mtu = DFILE_DEFAULT_FRAME_SIZE;
  s.conn_type = 1;
  s.dfile_version = DFILE_VERSION;
  s.capability = DFILE_CAPS_LINK_SEQUENCE;
  g_strlcpy(s.product_version, "hwphonelink 0.1.0",
            sizeof(s.product_version));
  s.is_support_160m = 1;

  guint8 frame[256];
  gssize n = dfile_encode_setting(frame, sizeof(frame), &s);
  CHECK(n == (gssize)(DFILE_FRAME_HEADER_LEN + DFILE_SETTING_PAYLOAD_LEN));
  CHECK(frame[0] == DFILE_FRAME_SETTING);
  CHECK(frame[7] == DFILE_SETTING_PAYLOAD_LEN);
  CHECK(frame[8] == 0x05 && frame[9] == 0xC0); /* mtu 1472 BE */

  DFileSetting t;
  memset(&t, 0, sizeof(t));
  CHECK(dfile_decode_setting(frame, (gsize)n, &t));
  CHECK(t.mtu == s.mtu && t.conn_type == s.conn_type);
  CHECK(t.dfile_version == s.dfile_version);
  CHECK(t.capability == s.capability && t.is_support_160m == 1);
  CHECK(strcmp(t.product_version, "hwphonelink 0.1.0") == 0);
  /* wrong frame type -> reject */
  frame[0] = DFILE_FRAME_RST;
  CHECK(!dfile_decode_setting(frame, (gsize)n, &t));
}

static void test_dfile_file_header_roundtrip(void) {
  g_print("dfile file-header round-trip\n");
  DFileHeaderEntry ents[3] = {
      {1, 100, "a.txt"},
      {2, 200, "b.txt"},
      {3, 300, "c.txt"},
  };
  guint8 frame[DFILE_DEFAULT_FRAME_SIZE];
  gsize written = 0;
  gssize n = dfile_encode_file_header(frame, sizeof(frame), 4, 3, ents, 0, 3,
                                      &written);
  CHECK(n == (gssize)(DFILE_FRAME_HEADER_LEN + 2 + 3 * 17));
  CHECK(written == 3);
  /* raw layout: node @0, entry 0 @2 (fid, u64 size, nameLen, name) */
  CHECK(frame[8 + 0] == 0 && frame[8 + 1] == 3);  /* node = 3 */
  CHECK(frame[8 + 2] == 0 && frame[8 + 3] == 1);  /* fileId 1 */
  CHECK(frame[8 + 12] == 0 && frame[8 + 13] == 5); /* nameLen 5 */
  CHECK(memcmp(frame + 8 + 14, "a.txt", 5) == 0);

  guint16 trans = 0, node = 0;
  DFileHeaderEntry *dec = NULL;
  gsize dn = 0;
  CHECK(dfile_decode_file_header(frame, (gsize)n, &trans, &node, &dec, &dn));
  CHECK(trans == 4 && node == 3 && dn == 3);
  CHECK(dec[0].file_id == 1 && dec[0].file_size == 100);
  CHECK(strcmp(dec[0].name, "a.txt") == 0);
  CHECK(dec[1].file_id == 2 && dec[1].file_size == 200);
  CHECK(strcmp(dec[1].name, "b.txt") == 0);
  CHECK(dec[2].file_id == 3 && dec[2].file_size == 300);
  CHECK(strcmp(dec[2].name, "c.txt") == 0);
  dfile_header_entries_free(dec, dn);

  /* size budget: a 44-byte frame fits node + 2 entries (8+2+17+17) */
  written = 0;
  n = dfile_encode_file_header(frame, 44, 4, 3, ents, 0, 3, &written);
  CHECK(n == (gssize)(DFILE_FRAME_HEADER_LEN + 2 + 2 * 17));
  CHECK(written == 2);
  dec = NULL;
  dn = 0;
  CHECK(dfile_decode_file_header(frame, (gsize)n, &trans, &node, &dec, &dn));
  CHECK(node == 3 && dn == 2);
  dfile_header_entries_free(dec, dn);

  /* bad: nameLen claims 3 bytes but only 1 is present */
  guint8 bad[32];
  memset(bad, 0, sizeof(bad));
  bad[0] = DFILE_FRAME_FILE_HEADER;
  put16_test(bad + 6, 15); /* 2 node + 2 fid + 8 size + 2 nameLen + 1 */
  put16_test(bad + 8, 1);  /* node */
  put16_test(bad + 10, 1); /* fileId */
  put32_test(bad + 16, 1); /* size low word */
  put16_test(bad + 20, 3); /* nameLen = 3 */
  bad[22] = 'x';
  dec = NULL;
  dn = 0;
  CHECK(!dfile_decode_file_header(bad, 23, &trans, &node, &dec, &dn));

  /* bad: nameLen 0 */
  put16_test(bad + 6, 14);
  put16_test(bad + 20, 0);
  CHECK(!dfile_decode_file_header(bad, 22, &trans, &node, &dec, &dn));
}

static void test_dfile_idlist_roundtrip(void) {
  g_print("dfile id-list round-trip\n");
  const guint16 ids[4] = {7, 8, 9, 10};
  guint8 frame[64];
  gssize n = dfile_encode_idlist(frame, sizeof(frame),
                                 DFILE_FRAME_FILE_HEADER_CONFIRM, 0, 3, ids,
                                 4);
  CHECK(n == (gssize)(DFILE_FRAME_HEADER_LEN + 8));
  CHECK(frame[0] == DFILE_FRAME_FILE_HEADER_CONFIRM);
  CHECK(frame[5] == 3); /* transId low */
  CHECK(frame[7] == 8); /* length = 2N */
  CHECK(frame[8] == 0 && frame[9] == 7);
  CHECK(frame[14] == 0 && frame[15] == 10);

  guint16 trans = 0;
  guint8 flag = 0;
  guint16 *dec = NULL;
  gsize dn = 0;
  CHECK(dfile_decode_idlist(frame, (gsize)n, DFILE_FRAME_FILE_HEADER_CONFIRM,
                            &trans, &flag, &dec, &dn));
  CHECK(trans == 3 && flag == 0 && dn == 4);
  CHECK(dec[0] == 7 && dec[1] == 8 && dec[2] == 9 && dec[3] == 10);
  g_free(dec);
  /* wrong expected type -> reject */
  dec = NULL;
  dn = 0;
  CHECK(!dfile_decode_idlist(frame, (gsize)n, DFILE_FRAME_FILE_TRANSFER_REQ,
                             &trans, &flag, &dec, &dn));
}

static void test_dfile_data_roundtrip(void) {
  g_print("dfile data round-trip\n");
  /* Max payload that fits in a DFILE_FRAME_MAX_SIZE frame:
   * total = 8 (header) + 6 (fileId + seq) + payload. */
  const gsize max_payload = DFILE_FRAME_MAX_SIZE - DFILE_FRAME_HEADER_LEN - 6;
  guint8 *payload = g_malloc(max_payload);
  for (gsize i = 0; i < max_payload; i++)
    payload[i] = (guint8)(i * 31 + 7);

  guint8 frame[DFILE_FRAME_MAX_SIZE];
  gssize n = dfile_encode_data(frame, sizeof(frame), 2, 0, 1, 0, payload,
                               max_payload);
  CHECK(n == (gssize)DFILE_FRAME_MAX_SIZE);
  CHECK(frame[0] == DFILE_FRAME_FILE_DATA);
  CHECK(frame[1] == 0); /* START: no continue/end bits */

  guint16 trans = 0, fid = 0;
  guint8 flag = 0;
  guint32 seq = 0;
  const guint8 *pl = NULL;
  gsize pln = 0;
  CHECK(dfile_decode_data(frame, (gsize)n, &trans, &flag, &fid, &seq, &pl,
                          &pln));
  CHECK(trans == 2 && flag == 0 && fid == 1 && seq == 0);
  CHECK(pln == max_payload && memcmp(pl, payload, pln) == 0);
  CHECK(pl == frame + DFILE_FRAME_HEADER_LEN + 6);

  /* one byte over the max payload -> reject */
  n = dfile_encode_data(frame, sizeof(frame), 2, 0, 1, 0, payload,
                        max_payload + 1);
  CHECK(n == -1);

  /* last partial block: CONTINUE|END */
  guint8 tail[512];
  memset(tail, 0x5A, sizeof(tail));
  n = dfile_encode_data(frame, sizeof(frame), 2,
                        DFILE_FLAG_DATA_CONTINUE | DFILE_FLAG_DATA_END, 1,
                        712, tail, sizeof(tail));
  CHECK(n == (gssize)(DFILE_FRAME_HEADER_LEN + 6 + 512));
  trans = 0;
  flag = 0;
  seq = 0;
  CHECK(dfile_decode_data(frame, (gsize)n, &trans, &flag, &fid, &seq, &pl,
                          &pln));
  CHECK(flag == (DFILE_FLAG_DATA_CONTINUE | DFILE_FLAG_DATA_END));
  CHECK(seq == 712 && pln == 512 && memcmp(pl, tail, 512) == 0);
  g_free(payload);
}

static void test_dfile_ack_v1(void) {
  g_print("dfile ack V1\n");
  DFileAckEntry ents[3] = {
      {1, 5, 0, 0},
      {2, 0, 0, 0},
      {3, 9, 0, 0},
  };
  guint8 frame[256];
  gssize n = dfile_encode_ack(frame, sizeof(frame), FALSE, 4, 0, ents, 3);
  CHECK(n == (gssize)(DFILE_FRAME_HEADER_LEN + 6 + 37 * 3));
  CHECK(frame[0] == DFILE_FRAME_FILE_DATA_ACK);
  CHECK(frame[6] == 0 && frame[7] == (guint8)(6 + 37 * 3));
  /* entries packed at payload 6*i (count-encoding is length-only) */
  CHECK(frame[8 + 0] == 0 && frame[8 + 1] == 1);   /* e0 fid 1 */
  CHECK(frame[8 + 5] == 5);                        /* e0 seq 5 */
  CHECK(frame[8 + 6] == 0 && frame[8 + 7] == 2);   /* e1 fid 2 */
  CHECK(frame[8 + 12] == 0 && frame[8 + 13] == 3); /* e2 fid 3 */
  /* reserved tail (after last entry) stays zero */
  CHECK(frame[8 + 18] == 0 && frame[8 + 6 + 37 * 3 - 1] == 0);

  guint16 trans = 0;
  guint8 flag = 0;
  gboolean v2 = TRUE;
  DFileAckEntry *dec = NULL;
  gsize dn = 99;
  CHECK(dfile_decode_ack(frame, (gsize)n, &trans, &flag, &v2, &dec, &dn));
  CHECK(trans == 4 && flag == 0 && !v2 && dn == 3);
  CHECK(dec[0].file_id == 1 && dec[0].last_seq == 5);
  CHECK(dec[1].file_id == 2 && dec[1].last_seq == 0);
  CHECK(dec[2].file_id == 3 && dec[2].last_seq == 9);
  g_free(dec);

  /* hand-built raw frame (RE layout): trans 7, flag ACK_RETRAN */
  guint8 raw[8 + 6 + 37 * 3];
  memset(raw, 0, sizeof(raw));
  raw[0] = DFILE_FRAME_FILE_DATA_ACK;
  raw[1] = DFILE_FLAG_ACK_RETRAN;
  put16_test(raw + 4, 7);
  put16_test(raw + 6, 6 + 37 * 3);
  put16_test(raw + 8 + 0, 2);
  put32_test(raw + 8 + 2, 3);
  put16_test(raw + 8 + 6, 5);
  put32_test(raw + 8 + 8, 255);
  put16_test(raw + 8 + 12, 9);
  put32_test(raw + 8 + 14, 256);
  trans = 0;
  flag = 0;
  v2 = TRUE;
  dec = NULL;
  dn = 99;
  CHECK(dfile_decode_ack(raw, sizeof(raw), &trans, &flag, &v2, &dec, &dn));
  CHECK(trans == 7 && flag == DFILE_FLAG_ACK_RETRAN && !v2 && dn == 3);
  CHECK(dec[0].file_id == 2 && dec[0].last_seq == 3);
  CHECK(dec[1].file_id == 5 && dec[1].last_seq == 255);
  CHECK(dec[2].file_id == 9 && dec[2].last_seq == 256);
  g_free(dec);

  /* N = 0: V1 length field 6 */
  n = dfile_encode_ack(frame, sizeof(frame), FALSE, 4, 0, NULL, 0);
  CHECK(n == (gssize)(DFILE_FRAME_HEADER_LEN + 6));
  dec = NULL;
  dn = 0;
  CHECK(dfile_decode_ack(frame, (gsize)n, &trans, &flag, &v2, &dec, &dn));
  CHECK(!v2 && dn == 0 && dec == NULL);
}

static void test_dfile_ack_v2(void) {
  g_print("dfile ack V2\n");
  DFileAckEntry ents[3] = {
      {1, 4, 0x1234, 0x5678},
      {2, 0, 0, 0},
      {3, 9, 0, 0},
  };
  guint8 frame[256];
  gssize n = dfile_encode_ack(frame, sizeof(frame), TRUE, 4, 0, ents, 3);
  CHECK(n == (gssize)(DFILE_FRAME_HEADER_LEN + 12 + 37 * 3));
  CHECK(frame[6] == 0 && frame[7] == (guint8)(12 + 37 * 3));
  /* entry 0: fid @0, seq @2, c @6, d @8 */
  CHECK(frame[8 + 1] == 1);
  CHECK(frame[8 + 5] == 4); /* seq low byte */
  CHECK(frame[8 + 6] == 0x12 && frame[8 + 7] == 0x34);
  CHECK(frame[8 + 8] == 0x56 && frame[8 + 9] == 0x78);
  /* 2-byte gap @10-11, entries 1..N-1 packed at 12 + 6(i-1) */
  CHECK(frame[8 + 10] == 0 && frame[8 + 11] == 0);
  CHECK(frame[8 + 12] == 0 && frame[8 + 13] == 2);
  CHECK(frame[8 + 18] == 0 && frame[8 + 19] == 3);
  /* reserved tail stays zero */
  CHECK(frame[8 + 24] == 0 && frame[8 + 12 + 37 * 3 - 1] == 0);

  guint16 trans = 0;
  guint8 flag = 0;
  gboolean v2 = FALSE;
  DFileAckEntry *dec = NULL;
  gsize dn = 0;
  CHECK(dfile_decode_ack(frame, (gsize)n, &trans, &flag, &v2, &dec, &dn));
  CHECK(v2 && dn == 3);
  CHECK(dec[0].file_id == 1 && dec[0].last_seq == 4);
  CHECK(dec[0].c == 0x1234 && dec[0].d == 0x5678);
  CHECK(dec[1].file_id == 2 && dec[1].last_seq == 0);
  CHECK(dec[2].file_id == 3 && dec[2].last_seq == 9);
  g_free(dec);

  /* N = 0 V2: length field 12 is valid (12 % 37 == 12) */
  n = dfile_encode_ack(frame, sizeof(frame), TRUE, 4, 0, NULL, 0);
  CHECK(n == (gssize)(DFILE_FRAME_HEADER_LEN + 12));
  dec = NULL;
  dn = 0;
  CHECK(dfile_decode_ack(frame, (gsize)n, &trans, &flag, &v2, &dec, &dn));
  CHECK(v2 && dn == 0 && dec == NULL);
}

static void test_dfile_ack_bad(void) {
  g_print("dfile ack invalid count encoding\n");
  guint8 raw[8 + 0x5c1];
  const guint16 bad_lengths[] = {7, 42, 0x5c1};
  for (gsize i = 0; i < G_N_ELEMENTS(bad_lengths); i++) {
    memset(raw, 0, sizeof(raw));
    raw[0] = DFILE_FRAME_FILE_DATA_ACK;
    put16_test(raw + 6, bad_lengths[i]);
    guint16 trans = 0;
    guint8 flag = 0;
    gboolean v2 = FALSE;
    DFileAckEntry *dec = NULL;
    gsize dn = 0;
    CHECK(!dfile_decode_ack(raw, (gsize)(8 + bad_lengths[i]), &trans, &flag,
                            &v2, &dec, &dn));
  }
}

static void test_dfile_rst_roundtrip(void) {
  g_print("dfile rst round-trip\n");
  guint8 frame[64];
  const guint16 ids[2] = {3, 7};
  gssize n = dfile_encode_rst(frame, sizeof(frame), 2,
                              DFILE_RST_INTERNAL_ERROR, ids, 2);
  CHECK(n == (gssize)(DFILE_FRAME_HEADER_LEN + 2 + 4));
  CHECK(frame[0] == DFILE_FRAME_RST);
  CHECK(frame[8] == 0 && frame[9] == 209);
  CHECK(frame[10] == 0 && frame[11] == 3);

  guint16 trans = 0, code = 0;
  guint16 *dec = NULL;
  gsize dn = 0;
  CHECK(dfile_decode_rst(frame, (gsize)n, &trans, &code, &dec, &dn));
  CHECK(trans == 2 && code == DFILE_RST_INTERNAL_ERROR && dn == 2);
  CHECK(dec[0] == 3 && dec[1] == 7);
  g_free(dec);

  /* no ids: payload is the code only */
  n = dfile_encode_rst(frame, sizeof(frame), 1, DFILE_RST_CANCEL, NULL, 0);
  CHECK(n == (gssize)(DFILE_FRAME_HEADER_LEN + 2));
  trans = 0;
  code = 0;
  dec = NULL;
  dn = 0;
  CHECK(dfile_decode_rst(frame, (gsize)n, &trans, &code, &dec, &dn));
  CHECK(code == DFILE_RST_CANCEL && dn == 0 && dec == NULL);
}

static void test_ft_testfile(void) {
  g_print("ft testfile helper\n");
  const gchar *sha64 =
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  gchar *good = g_strdup_printf("ft-%s.bin", sha64);
  gchar *sha = ft_testfile_name_sha(good);
  CHECK(sha != NULL && strcmp(sha, sha64) == 0);
  g_free(sha);
  g_free(good);
  CHECK(ft_testfile_name_sha("ft-xyz.bin") == NULL);
  CHECK(ft_testfile_name_sha("x" "ft-0123456789abcdef0123456789abcdef"
                              "0123456789abcdef0123456789abcdef.bin") == NULL);
  CHECK(ft_testfile_name_sha(NULL) == NULL);

  /* generator: name carries the sha256 of the content; deterministic */
  gchar *dir = g_build_filename(g_get_tmp_dir(), "hwphonelink-ft-test", NULL);
  g_mkdir_with_parents(dir, 0755);
  gchar *path = NULL;
  gchar *wire = NULL;
  CHECK(ft_testfile_generate(dir, 42, 7000, &path, &wire));
  CHECK(path != NULL && wire != NULL);
  if (path != NULL && wire != NULL) {
    gchar *data = NULL;
    gsize len = 0;
    gboolean ok = g_file_get_contents(path, &data, &len, NULL) && len == 7000;
    CHECK(ok);
    if (ok) {
      GChecksum *c = g_checksum_new(G_CHECKSUM_SHA256);
      g_checksum_update(c, (const guchar *)data, (gssize)len);
      gchar *expected = g_strdup_printf("ft-%s.bin",
                                        g_checksum_get_string(c));
      CHECK(strcmp(wire, expected) == 0);
      g_free(expected);
      g_checksum_free(c);
    }
    g_free(data);
    gchar *path2 = NULL;
    gchar *wire2 = NULL;
    CHECK(ft_testfile_generate(dir, 42, 7000, &path2, &wire2));
    CHECK(wire2 != NULL && strcmp(wire2, wire) == 0);
    g_free(path2);
    g_free(wire2);
  }
  g_free(path);
  g_free(wire);
  g_free(dir);
}

/* ============================ fillp codec ============================ */

static void test_fillp_head(void) {
  guint8 buf[FILLP_HLEN];
  gsize n = fillp_encode_head(buf, FP_PKT_DATA,
                              FILLP_FLAG_DATA_FIRST | FILLP_FLAG_DATA_LAST,
                              1400, 42, 10000);
  CHECK(n == FILLP_HLEN);
  /* raw BE layout: u16 flag, u16 len, u32 pkt, u32 seq */
  CHECK(buf[0] == (guint8)FP_PKT_DATA); /* version nibble 0, type nibble */
  CHECK(buf[1] == (guint8)(FILLP_FLAG_DATA_FIRST | FILLP_FLAG_DATA_LAST));
  CHECK(buf[2] == 0x05 && buf[3] == 0x78); /* 1400 */
  CHECK(buf[4] == 0 && buf[5] == 0 && buf[6] == 0 && buf[7] == 42); /* pktNum */
  CHECK(buf[8] == 0 && buf[9] == 0 && buf[10] == 0x27 && buf[11] == 0x10); /* seqNum 10000 */

  FpPktType type;
  guint16 flags, dlen;
  guint32 pkt, seq;
  CHECK(fillp_decode_head(buf, n, &type, &flags, &dlen, &pkt, &seq));
  CHECK(type == FP_PKT_DATA);
  CHECK(flags == (guint16)(FILLP_FLAG_DATA_FIRST | FILLP_FLAG_DATA_LAST));
  CHECK(dlen == 1400 && pkt == 42 && seq == 10000);

  /* version nibble must be 0 */
  buf[0] = (guint8)((1 << 4) | FP_PKT_DATA);
  CHECK(!fillp_decode_head(buf, n, &type, &flags, &dlen, &pkt, &seq));
  buf[0] = (guint8)FP_PKT_DATA;
  /* short buffer */
  CHECK(!fillp_decode_head(buf, FILLP_HLEN - 1, &type, &flags, &dlen, &pkt,
                           &seq));
  /* all-NULL out params are fine */
  CHECK(fillp_decode_head(buf, n, NULL, NULL, NULL, NULL, NULL));

  /* wraparound-safe "ahead of" comparison */
  CHECK(fp_num_isbigger(1, 0xFFFFFFFF));
  CHECK(fp_num_isbigger(0, 0xFFFFFFFF));
  CHECK(!fp_num_isbigger(0xFFFFFFFF, 0));
  CHECK(!fp_num_isbigger(5, 5));
  CHECK(fp_num_isbigger(7, 5));
  CHECK(!fp_num_isbigger(5, 7));
}

static void test_fillp_mgmt_roundtrip(void) {
  guint8 buf[256];
  gsize n;

  /* CONN_REQ */
  n = fillp_encode_conn_req(buf, sizeof(buf), 5000000, 819200, 819200,
                            123456789ULL);
  CHECK(n == FILLP_HLEN + FILLP_CONN_REQ_LEN);
  FpPktType type;
  CHECK(fillp_decode_head(buf, n, &type, NULL, NULL, NULL, NULL) &&
        type == FP_PKT_CONN_REQ);
  guint32 pres = 0, sc = 0, rc = 0;
  guint64 ts = 0;
  CHECK(fillp_decode_conn_req(buf, n, &pres, &sc, &rc, &ts));
  CHECK(pres == 5000000 && sc == 819200 && rc == 819200 &&
        ts == 123456789ULL);
  CHECK(!fillp_decode_conn_req(buf, n + 1, &pres, &sc, &rc, &ts));

  /* CONN_REQ_ACK / CONN_CONFIRM / CONN_CONFIRM_ACK */
  guint8 mac_key[32];
  memset(mac_key, 0x5a, sizeof(mac_key));
  guint8 cookie[FILLP_COOKIE_LEN];
  guint8 laddr[FILLP_ADDR_LEN], raddr[FILLP_ADDR_LEN];
  fillp_addr_fill_ipv4(raddr, 40000, (const guint8[]){172, 50, 20, 54});
  memset(laddr, 0, sizeof(laddr));
  fillp_cookie_fill(cookie, mac_key, 999, 30000000, 111, 222, 333, 444,
                    819200, 819200, 54323, 2, raddr, laddr);

  n = fillp_encode_conn_req_ack(buf, sizeof(buf), 0x0102, cookie, 424242);
  CHECK(n == FILLP_HLEN + FILLP_CONN_REQ_ACK_LEN);
  guint16 tag = 0;
  guint8 cookie2[FILLP_COOKIE_LEN];
  CHECK(fillp_decode_conn_req_ack(buf, n, &tag, cookie2, &ts));
  CHECK(tag == 0x0102 && ts == 424242);
  CHECK(memcmp(cookie, cookie2, FILLP_COOKIE_LEN) == 0);

  n = fillp_encode_conn_confirm(buf, sizeof(buf), 0x0102, cookie, raddr);
  CHECK(n == FILLP_HLEN + FILLP_CONN_CONFIRM_LEN);
  guint8 laddr2[FILLP_ADDR_LEN];
  CHECK(fillp_decode_conn_confirm(buf, n, &tag, cookie2, laddr2));
  CHECK(tag == 0x0102 && memcmp(cookie, cookie2, FILLP_COOKIE_LEN) == 0 &&
        memcmp(raddr, laddr2, FILLP_ADDR_LEN) == 0);

  n = fillp_encode_conn_confirm_ack(buf, sizeof(buf), 262144, 1048576, 1400,
                                    laddr);
  CHECK(n == FILLP_HLEN + FILLP_CONN_CONFIRM_ACK_LEN);
  guint32 pkt_size = 0;
  CHECK(fillp_decode_conn_confirm_ack(buf, n, &sc, &rc, &pkt_size, laddr2));
  CHECK(sc == 262144 && rc == 1048576 && pkt_size == 1400 &&
        memcmp(laddr, laddr2, FILLP_ADDR_LEN) == 0);

  /* NACK: head.pktNum = begin, head.seqNum = recv offset,
   * payload lastPktNum = end - 1 */
  n = fillp_encode_nack(buf, sizeof(buf), FP_PKT_NACK, 100, 102, 5000,
                        0xDEADBEEFCAFEBABEULL);
  CHECK(n == FILLP_HLEN + FILLP_NACK_LEN);
  guint32 begin = 0, end = 0, seqn = 0;
  CHECK(fillp_decode_nack(buf, n, &begin, &end, &seqn));
  CHECK(begin == 100 && end == 102 && seqn == 5000);
  n = fillp_encode_nack(buf, sizeof(buf), FP_PKT_HISTORY_NACK, 7, 9, 100, 1);
  CHECK(fillp_decode_nack(buf, n, &begin, &end, &seqn) && begin == 7 &&
        end == 9 && seqn == 100);

  /* PACK: cumulative ack in the head, lostSeq in the payload */
  n = fillp_encode_pack(buf, sizeof(buf), 5000, 101, 5000, 1234);
  CHECK(n == FILLP_HLEN + FILLP_PACK_LEN);
  guint32 ack_seq = 0, ack_pkt = 0, lost = 0, rcv = 0;
  CHECK(fillp_decode_pack(buf, n, &ack_seq, &ack_pkt, &lost, &rcv));
  CHECK(ack_seq == 5000 && ack_pkt == 101 && lost == 5000 && rcv == 1234);

  /* FIN */
  n = fillp_encode_fin(buf, sizeof(buf), 0x0001);
  CHECK(n == FILLP_HLEN + FILLP_FIN_LEN);
  guint16 fflag = 0;
  CHECK(fillp_decode_fin(buf, n, &fflag) && fflag == 1);
  CHECK(fillp_decode_head(buf, n, &type, NULL, NULL, NULL, NULL) &&
        type == FP_PKT_FIN);

  /* undersized buffers are rejected */
  CHECK(fillp_encode_conn_req(buf, FILLP_HLEN + FILLP_CONN_REQ_LEN - 1, 0, 0,
                              0, 0) == (gssize)-1);
  CHECK(fillp_encode_pack(buf, 10, 0, 0, 0, 0) == (gssize)-1);
}

static void test_fillp_cookie(void) {
  guint8 mac_key[32], other_key[32];
  memset(mac_key, 0x11, sizeof(mac_key));
  memset(other_key, 0x22, sizeof(other_key));
  guint8 laddr[FILLP_ADDR_LEN], laddr2[FILLP_ADDR_LEN], raddr[FILLP_ADDR_LEN];
  fillp_addr_fill_ipv4(laddr, 54324, (const guint8[]){0, 0, 0, 0});
  fillp_addr_fill_ipv4(laddr2, 54324, (const guint8[]){1, 2, 3, 4});
  fillp_addr_fill_ipv4(raddr, 40000, (const guint8[]){172, 50, 20, 54});

  guint8 cookie[FILLP_COOKIE_LEN];
  fillp_cookie_fill(cookie, mac_key, 123456, 30000000, 1, 2, 3, 4, 819200,
                    819200, 54323, 2, raddr, laddr);

  CHECK(fillp_cookie_verify(cookie, mac_key, laddr));
  CHECK(!fillp_cookie_verify(cookie, other_key, laddr)); /* wrong key */
  CHECK(!fillp_cookie_verify(cookie, mac_key, laddr2));   /* wrong local addr */

  /* every digested field is covered */
  guint8 tampered[FILLP_COOKIE_LEN];
  memcpy(tampered, cookie, sizeof(tampered));
  tampered[36] ^= 0x01; /* genTime */
  CHECK(!fillp_cookie_verify(tampered, mac_key, laddr));
  memcpy(tampered, cookie, sizeof(tampered));
  tampered[48] ^= 0x80; /* lifeTime */
  CHECK(!fillp_cookie_verify(tampered, mac_key, laddr));
  memcpy(tampered, cookie, sizeof(tampered));
  tampered[70] ^= 0x01; /* remoteSock */
  CHECK(!fillp_cookie_verify(tampered, mac_key, laddr));
  memcpy(tampered, cookie, sizeof(tampered));
  tampered[0] ^= 0xff; /* the digest itself */
  CHECK(!fillp_cookie_verify(tampered, mac_key, laddr));

  /* layout spot checks (all BE; computed, not hand-rolled hex) */
  guint64 gen = 123456;
  guint32 life = 30000000;
  guint16 sport = 54323;
  CHECK(cookie[32] == 0 && cookie[36] == 0 &&
        cookie[37] == (guint8)(gen >> 16) && cookie[38] == (guint8)(gen >> 8) &&
        cookie[39] == (guint8)gen);
  CHECK(cookie[48] == (guint8)(life >> 24) &&
        cookie[49] == (guint8)(life >> 16) &&
        cookie[50] == (guint8)(life >> 8) && cookie[51] == (guint8)life);
  CHECK(cookie[52] == 0 && cookie[55] == 1);  /* localPktSeq  @52 */
  CHECK(cookie[56] == 0 && cookie[59] == 3);  /* remotePktSeq @56 */
  CHECK(cookie[60] == 0 && cookie[63] == 2);  /* localMsgSeq  @60 */
  CHECK(cookie[64] == 0 && cookie[67] == 4);  /* remoteMsgSeq @64 */
  CHECK(cookie[68] == 0x00 && cookie[71] == 0x00); /* remoteSendCache 819200 @68 */
  CHECK(cookie[72] == 0x00 && cookie[75] == 0x00); /* remoteRecvCache 819200 @72 */
  CHECK(cookie[76] == (guint8)(sport >> 8) &&
        cookie[77] == (guint8)sport && cookie[78] == 0 && cookie[79] == 2);
  CHECK(memcmp(cookie + 80, raddr, FILLP_ADDR_LEN) == 0);

  /* 28-byte compat address: sockaddr_in layout, zero-extended */
  guint8 addr[FILLP_ADDR_LEN];
  fillp_addr_fill_ipv4(addr, 0x1234, (const guint8[]){10, 20, 30, 40});
  CHECK(addr[0] == 0 && addr[1] == 2);
  CHECK(addr[2] == 0x12 && addr[3] == 0x34);
  CHECK(addr[4] == 10 && addr[5] == 20 && addr[6] == 30 && addr[7] == 40);
  gboolean zero = TRUE;
  for (guint i = 8; i < FILLP_ADDR_LEN; i++)
    zero = zero && addr[i] == 0;
  CHECK(zero);
}

/* ============================ VTP frame ============================ */

static void test_vtp_frame(void) {
  const gchar *psk = "hwphonelink-test-psk";
  guint8 key[VTP_KEY_LEN], key_b[VTP_KEY_LEN], key_c[VTP_KEY_LEN];
  vtp_derive_key((const guint8 *)psk, strlen(psk), key);
  vtp_derive_key((const guint8 *)psk, strlen(psk), key_b);
  vtp_derive_key((const guint8 *)"different-psk", 13, key_c);
  CHECK(memcmp(key, key_b, VTP_KEY_LEN) == 0);
  CHECK(memcmp(key, key_c, VTP_KEY_LEN) != 0);

  guint8 data[100];
  for (guint i = 0; i < sizeof(data); i++) data[i] = (guint8)(i * 7 + 1);
  guint8 frame[512];
  gsize total = vtp_build_common_frame(frame, sizeof(frame), key,
                                       VTP_MODE_COMMON, 0, 0, 123456789u,
                                       data, sizeof(data));
  CHECK(total == vtp_common_frame_size(100));
  CHECK(total == 4 + VTP_NONCE_LEN + VTP_HEADER_LEN + 100 + VTP_TAG_LEN);
  /* 4-byte BE length prefix = total - 4 */
  CHECK(frame[0] == 0 && frame[1] == 0 &&
        frame[2] == (guint8)((total - 4) >> 8) &&
        frame[3] == (guint8)((total - 4) & 0xff));

  guint8 out[256];
  gsize out_len = 0;
  guint16 mode = 0, st = 0, scene = 0;
  guint32 ts = 0;
  CHECK(vtp_parse_common_frame(frame, total, key, &mode, &st, &scene, &ts,
                               out, sizeof(out), &out_len));
  CHECK(mode == VTP_MODE_COMMON && st == 0 && scene == 0);
  CHECK(ts == 123456789u);
  CHECK(out_len == 100 && memcmp(out, data, 100) == 0);

  /* wrong key → GCM tag failure */
  CHECK(!vtp_parse_common_frame(frame, total, key_c, &mode, &st, &scene, &ts,
                                out, sizeof(out), &out_len));
  /* tampered ciphertext → GCM tag failure */
  guint8 bad[512];
  memcpy(bad, frame, total);
  bad[4 + VTP_NONCE_LEN + 5] ^= 0x42;
  CHECK(!vtp_parse_common_frame(bad, total, key, NULL, NULL, NULL, NULL, out,
                                sizeof(out), &out_len));
  /* truncated frame */
  CHECK(!vtp_parse_common_frame(frame, total - 1, key, NULL, NULL, NULL,
                                NULL, out, sizeof(out), &out_len));
  /* length prefix inconsistent with the message */
  memcpy(bad, frame, total);
  bad[3] += 1;
  CHECK(!vtp_parse_common_frame(bad, total, key, NULL, NULL, NULL, NULL, out,
                                sizeof(out), &out_len));
  /* output buffer too small */
  CHECK(!vtp_parse_common_frame(frame, total, key, NULL, NULL, NULL, NULL,
                                out, 50, &out_len));

  /* empty payload */
  guint8 frame0[64];
  gsize t0 = vtp_build_common_frame(frame0, sizeof(frame0), key,
                                    VTP_MODE_COMMON, 0, 0, 1, NULL, 0);
  CHECK(t0 != (gsize)-1);
  out_len = 0;
  CHECK(vtp_parse_common_frame(frame0, t0, key, &mode, NULL, NULL, NULL, out,
                               sizeof(out), &out_len));
  CHECK(out_len == 0);

  /* header field propagation: mode nibble, stream type, scene */
  guint8 frame2[512];
  gsize t2 = vtp_build_common_frame(frame2, sizeof(frame2), key, 3, 0x1234,
                                    0x5678, 7, data, 10);
  CHECK(t2 != (gsize)-1);
  CHECK(vtp_parse_common_frame(frame2, t2, key, &mode, &st, &scene, &ts, out,
                               sizeof(out), &out_len));
  CHECK(mode == 3 && st == 0x1234 && scene == 0x5678 && ts == 7 &&
        out_len == 10);

  /* an ext-bit frame must be rejected by the stand (the public API never
   * emits them, so forge one: seal a header with bit 28 set) */
  guint8 plain2[VTP_HEADER_LEN + 4];
  memset(plain2, 0, sizeof(plain2));
  plain2[0] = (guint8)((VTP_FLAG_EXT_PRESENT >> 24) & 0xff);
  plain2[1] = VTP_MODE_COMMON;
  plain2[8] = 4; /* payloadLen = 4 */
  memcpy(plain2 + VTP_HEADER_LEN, "abcd", 4);
  guint8 nonce[VTP_NONCE_LEN];
  for (guint i = 0; i < VTP_NONCE_LEN; i++) nonce[i] = (guint8)i;
  gsize p2 = sizeof(plain2);
  gsize f2 = 4 + VTP_NONCE_LEN + p2 + VTP_TAG_LEN;
  guint8 fbuf[128];
  fbuf[0] = 0;
  fbuf[1] = 0;
  fbuf[2] = (guint8)((f2 - 4) >> 8);
  fbuf[3] = (guint8)((f2 - 4) & 0xff);
  memcpy(fbuf + 4, nonce, VTP_NONCE_LEN);
  CHECK(softbus_aes_gcm_encrypt(key, VTP_KEY_LEN, nonce, VTP_NONCE_LEN, NULL,
                                0, plain2, p2, fbuf + 4 + VTP_NONCE_LEN,
                                fbuf + f2 - VTP_TAG_LEN));
  CHECK(!vtp_parse_common_frame(fbuf, f2, key, NULL, NULL, NULL, NULL, out,
                                sizeof(out), &out_len));
}

/* ============================ h264 test file ============================ */

static void test_h264_testfile(void) {
  gchar *dir = g_build_filename(g_get_tmp_dir(), "hwphonelink-hs-test", NULL);
  g_mkdir_with_parents(dir, 0755);

  CHECK(!h264_testfile_generate(dir, 7, 4096, NULL, NULL)); /* below minimum */
  CHECK(!h264_testfile_generate(NULL, 7, 40000, NULL, NULL));

  gchar *path = NULL, *wire = NULL;
  CHECK(h264_testfile_generate(dir, 7, 40000, &path, &wire));
  CHECK(path != NULL && wire != NULL);
  if (path != NULL && wire != NULL) {
    /* wire-name convention */
    CHECK(wire[0] == 'h' && wire[1] == 's' && wire[2] == '-');
    CHECK(strlen(wire) == 3 + 64 + 5);
    CHECK(g_str_has_suffix(wire, ".h264"));
    gchar *want = h264_testfile_name_sha(wire);
    CHECK(want != NULL && strlen(want) == 64);

    gchar *data = NULL;
    gsize len = 0;
    CHECK(g_file_get_contents(path, &data, &len, NULL));
    CHECK(len >= 8192 && len <= 40000 + 4108); /* budget ± one NAL */
    if (len > 0) {
      GChecksum *c = g_checksum_new(G_CHECKSUM_SHA256);
      g_checksum_update(c, (const guchar *)data, (gssize)len);
      if (want != NULL) CHECK(strcmp(g_checksum_get_string(c), want) == 0);
      g_checksum_free(c);

      /* protocol-level verify passes and reports the NAL structure */
      gchar *det = NULL;
      CHECK(h264_testfile_verify(path, wire, &det));
      CHECK(det != NULL && strlen(det) > 0);
      g_free(det);

      /* start code at offset 0, first NAL = SPS */
      CHECK(data[0] == 0 && data[1] == 0 && data[2] == 0 && data[3] == 1);
      CHECK((data[4] & 0x1f) == 7);

      /* corrupt one byte on disk → sha mismatch → verify fails */
      data[100] ^= 0x55;
      CHECK(g_file_set_contents(path, (gchar *)data, (gssize)len, NULL));
      det = NULL;
      CHECK(!h264_testfile_verify(path, wire, &det));
      g_free(det);
    }
    g_free(data);

    /* deterministic per seed; different seed → different content */
    gchar *path2 = NULL, *wire2 = NULL;
    CHECK(h264_testfile_generate(dir, 7, 40000, &path2, &wire2));
    CHECK(wire2 != NULL && strcmp(wire2, wire) == 0);
    g_free(path2);
    g_free(wire2);
    CHECK(h264_testfile_generate(dir, 8, 40000, &path2, &wire2));
    CHECK(wire2 != NULL && strcmp(wire2, wire) != 0);
    g_free(path2);
    g_free(wire2);
  }
  g_free(path);
  g_free(wire);
  g_free(dir);

  /* name_sha parsing: strict "hs-<hex64>.h264" */
  gchar *sha = h264_testfile_name_sha("hs-" "0123456789abcdef0123456789abcdef"
                                      "0123456789abcdef0123456789abcdef.h264");
  CHECK(sha != NULL && strlen(sha) == 64);
  g_free(sha);
  CHECK(h264_testfile_name_sha("xh-0123456789abcdef0123456789abcdef"
                               "0123456789abcdef0123456789abcdef.h264") ==
        NULL);
  CHECK(h264_testfile_name_sha("hs-z123456789abcdef0123456789abcdef"
                               "0123456789abcdef0123456789abcdef.h264") ==
        NULL); /* non-hex */
  CHECK(h264_testfile_name_sha("hs-0123456789abcdef0123456789abcdef"
                               "0123456789abcdef0123456789abcde.h264") ==
        NULL); /* 63 hex chars */
  CHECK(h264_testfile_name_sha("hs-0123456789abcdef0123456789abcdef"
                               "0123456789abcdef0123456789abcdef.bin") ==
        NULL);
  CHECK(h264_testfile_name_sha(NULL) == NULL);
}

/* ======================= Remote input encoder ======================= */

/*
 * Expected packet: hdr(10) + body(L) + ts(4) + pad.
 * hdr[0] = flags1 remap (0x60 -> 0x06), hdr[1] = class, hdr[2..3] =
 * u16 BE total, hdr[4] = flags2.
 */
static void test_remote_input_touch(void) {
  g_print("remote input: touch vectors (cnt 1/2, zero tail)\n");
  guint8 buf[64];
  gsize n = 0;

  RemoteInputEvent ev;
  memset(&ev, 0, sizeof(ev));
  ev.type = REMOTE_INPUT_TOUCH;
  ev.subtype = 0; /* down -> action 0x0e */
  ev.flags1 = 0x60;
  ev.flags2 = 0x05;
  ev.touch_cnt = 1;
  ev.touch_ids[0] = 7;
  ev.touch_x[0] = 1234.0;
  ev.touch_y[0] = -5678.0;

  CHECK(remote_input_build(&ev, 0x01020304, buf, sizeof(buf), &n) == 0);
  CHECK(n == 28); /* L=13, (13+4) odd -> pad */
  static const guint8 exp1[28] = {
      0x06, 0x00, 0x00, 0x1c, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x0e, 0x00, 0x0b, 0x01, /* action, lenfield 11, cnt */
      0x07, 0x04, 0xd2, 0xe9, 0xd2, /* id, x=1234, y=-5678 */
      0x00, 0x00, 0x00, 0x00, /* zero tail (4*cnt) */
      0x01, 0x02, 0x03, 0x04, /* ts u32 BE */
      0x00 /* pad */
  };
  CHECK(memcmp(buf, exp1, sizeof(exp1)) == 0);

  /* cnt=2, move (sub 2): L=22, (22+4) even -> no pad, 8 zero tail B */
  memset(&ev, 0, sizeof(ev));
  ev.type = REMOTE_INPUT_TOUCH;
  ev.subtype = 2;
  ev.flags1 = 0x60;
  ev.flags2 = 0x05;
  ev.touch_cnt = 2;
  ev.touch_ids[0] = 1;
  ev.touch_ids[1] = 2;
  ev.touch_x[0] = 10.0;
  ev.touch_y[0] = 30.0;
  ev.touch_x[1] = -20.0;
  ev.touch_y[1] = 40.0;

  CHECK(remote_input_build(&ev, 0x01020304, buf, sizeof(buf), &n) == 0);
  CHECK(n == 36);
  static const guint8 exp2[36] = {
      0x06, 0x00, 0x00, 0x24, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x02, 0x00, 0x13, 0x02, /* action 0x02, lenfield 19, cnt 2 */
      0x01, 0x00, 0x0a, 0x00, 0x1e, /* p1: id 1, (10, 30) */
      0x02, 0xff, 0xec, 0x00, 0x28, /* p2: id 2, (-20, 40) */
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* zero tail */
      0x01, 0x02, 0x03, 0x04, /* ts */
  };
  CHECK(memcmp(buf, exp2, sizeof(exp2)) == 0);
}

static void test_remote_input_key_mouse(void) {
  g_print("remote input: key + mouse vectors\n");
  guint8 buf[64];
  gsize n = 0;

  RemoteInputEvent ev;
  memset(&ev, 0, sizeof(ev));
  ev.type = REMOTE_INPUT_KEY;
  ev.subtype = 1; /* up -> action 4 */
  ev.key_f16a = 0x0123;
  ev.key_f16b = 0x4567;
  ev.key_f32 = 0xAABBCCDD;

  CHECK(remote_input_build(&ev, 0x00000001, buf, sizeof(buf), &n) == 0);
  CHECK(n == 26);
  static const guint8 exp_key[26] = {
      0x00, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x04, 0x00, 0x09, 0x00, 0x01, 0x23, 0x45, 0x67,
      0xaa, 0xbb, 0xcc, 0xdd,
      0x00, 0x00, 0x00, 0x01,
  };
  CHECK(memcmp(buf, exp_key, sizeof(exp_key)) == 0);

  memset(&ev, 0, sizeof(ev));
  ev.type = REMOTE_INPUT_MOUSE;
  ev.subtype = 2; /* up -> action 0x10 */
  ev.mouse_button = 2;
  ev.mouse_x = 10.5;  /* trunc -> 10 */
  ev.mouse_y = -20.7; /* trunc -> -20 */
  ev.mouse_z = 0.0;
  ev.mouse_w = 6250.0;

  CHECK(remote_input_build(&ev, 0, buf, sizeof(buf), &n) == 0);
  CHECK(n == 26);
  static const guint8 exp_mouse[26] = {
      0x00, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x10, 0x00, 0x09, 0x02, /* action 0x10, button 2 */
      0x00, 0x0a, 0xff, 0xec, 0x00, 0x00, 0x18, 0x6a,
      0x00, 0x00, 0x00, 0x00,
  };
  CHECK(memcmp(buf, exp_mouse, sizeof(exp_mouse)) == 0);
}

static void test_remote_input_zoom_scroll(void) {
  g_print("remote input: zoom + scroll vectors\n");
  guint8 buf[64];
  gsize n = 0;

  RemoteInputEvent ev;
  memset(&ev, 0, sizeof(ev));
  ev.type = REMOTE_INPUT_ZOOM;
  ev.zoom_x = -1.5;  /* trunc -> -1 -> 0xFFFF */
  ev.zoom_y = 2.25;  /* trunc -> 2 */
  ev.zoom_pressure = 0.0; /* bits 0 -> 00 00 */

  CHECK(remote_input_build(&ev, 0, buf, sizeof(buf), &n) == 0);
  CHECK(n == 24); /* L=9, (9+4) odd -> pad */
  static const guint8 exp_zoom[24] = {
      0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x05, 0x00, 0x07,
      0xff, 0xff, 0x00, 0x02,
      0x00, 0x00, /* pressure low 2 bytes LE */
      0x00, 0x00, 0x00, 0x00, /* ts */
      0x00 /* pad */
  };
  CHECK(memcmp(buf, exp_zoom, sizeof(exp_zoom)) == 0);

  memset(&ev, 0, sizeof(ev));
  ev.type = REMOTE_INPUT_SCROLL;
  ev.subtype = 1; /* action 0x07 */
  ev.scroll_axis = 1;  /* input[21] -> body[3] */
  ev.scroll_delta = -2; /* input[20] -> body[4] */

  CHECK(remote_input_build(&ev, 0, buf, sizeof(buf), &n) == 0);
  CHECK(n == 20); /* L=5, (5+4) odd -> pad: 10+5+4+1 */
  static const guint8 exp_scroll[20] = {
      0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x07, 0x00, 0x03, 0x01, 0xfe,
      0x00, 0x00, 0x00, 0x00,
      0x00 /* pad */
  };
  CHECK(memcmp(buf, exp_scroll, sizeof(exp_scroll)) == 0);
}

static void test_remote_input_wheel_vkey(void) {
  g_print("remote input: wheel + vkey vectors\n");
  guint8 buf[64];
  gsize n = 0;

  RemoteInputEvent ev;
  memset(&ev, 0, sizeof(ev));
  ev.type = REMOTE_INPUT_WHEEL;
  ev.wheel_dir = 0x07; /* -> ((7&6)<<1)|(7&1) = 0x0d */
  ev.wheel_f1 = 0x02bc;
  ev.wheel_x = 50.0;
  ev.wheel_y = -3.0;

  CHECK(remote_input_build(&ev, 0, buf, sizeof(buf), &n) == 0);
  CHECK(n == 24); /* L=10, (10+4) even -> no pad */
  static const guint8 exp_wheel[24] = {
      0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x0c, 0x00, 0x07, 0x0d, 0x02, 0xbc,
      0x00, 0x32, 0xff, 0xfd,
      0x00, 0x00, 0x00, 0x00,
  };
  CHECK(memcmp(buf, exp_wheel, sizeof(exp_wheel)) == 0);

  memset(&ev, 0, sizeof(ev));
  ev.type = REMOTE_INPUT_VKEY;
  ev.subtype = 2; /* action 4 */
  ev.vkey_x = 3.2;  /* -> 3 */
  ev.vkey_y = -8.0; /* -> -8 */

  CHECK(remote_input_build(&ev, 0, buf, sizeof(buf), &n) == 0);
  CHECK(n == 22); /* L=7, (7+4) odd -> pad; hdr[1] class = 3 */
  static const guint8 exp_vkey[22] = {
      0x00, 0x03, 0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x04, 0x00, 0x05,
      0x00, 0x03, 0xff, 0xf8,
      0x00, 0x00, 0x00, 0x00,
      0x00 /* pad */
  };
  CHECK(memcmp(buf, exp_vkey, sizeof(exp_vkey)) == 0);
}

static void test_remote_input_input7_message(void) {
  g_print("remote input: input7 (focus/content) + message vectors\n");
  guint8 buf[64];
  gsize n = 0;

  RemoteInputEvent ev;
  memset(&ev, 0, sizeof(ev));
  ev.type = REMOTE_INPUT_INPUT7;
  ev.subtype = 1; /* focus */
  ev.focus_f1 = 9;
  ev.focus_f2 = 1.5; /* -> 1 */
  ev.focus_f3 = -2.5; /* -> -2 */
  ev.focus_f4 = 0.0;
  ev.focus_f5 = 65535.9; /* -> 65535 */

  CHECK(remote_input_build(&ev, 0, buf, sizeof(buf), &n) == 0);
  CHECK(n == 26); /* hdr[1] class = 2 */
  static const guint8 exp_focus[26] = {
      0x00, 0x02, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x01, 0x00, 0x09, 0x09,
      0x00, 0x01, 0xff, 0xfe, 0x00, 0x00, 0xff, 0xff,
      0x00, 0x00, 0x00, 0x00,
  };
  CHECK(memcmp(buf, exp_focus, sizeof(exp_focus)) == 0);

  memset(&ev, 0, sizeof(ev));
  ev.type = REMOTE_INPUT_INPUT7;
  ev.subtype = 0; /* content */
  ev.content = "abc";
  ev.content_len = 3;

  CHECK(remote_input_build(&ev, 0, buf, sizeof(buf), &n) == 0);
  CHECK(n == 22); /* L=8, (8+4) even -> no pad */
  static const guint8 exp_content[22] = {
      0x00, 0x02, 0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x05, 0x00, 0x03, /* action, lenfield 5, len 3 */
      0x61, 0x62, 0x63,
      0x00, 0x00, 0x00, 0x00,
  };
  CHECK(memcmp(buf, exp_content, sizeof(exp_content)) == 0);

  memset(&ev, 0, sizeof(ev));
  ev.type = REMOTE_INPUT_MESSAGE;
  ev.subtype = 0; /* action 6 */
  ev.msg_len = 5; /* payload = 3 B */
  static const guint8 payload3[3] = {0x48, 0x49, 0x00};
  ev.msg_payload = payload3;

  CHECK(remote_input_build(&ev, 0, buf, sizeof(buf), &n) == 0);
  CHECK(n == 24); /* L=10, even -> no pad; hdr[1] class = 4 */
  static const guint8 exp_msg5[24] = {
      0x00, 0x04, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x06, 0x00, 0x07, 0x00, 0x05, 0x00, 0x00,
      0x48, 0x49, 0x00,
      0x00, 0x00, 0x00, 0x00,
  };
  CHECK(memcmp(buf, exp_msg5, sizeof(exp_msg5)) == 0);

  memset(&ev, 0, sizeof(ev));
  ev.type = REMOTE_INPUT_MESSAGE;
  ev.subtype = 1; /* action 7 */
  ev.msg_len = 6; /* payload = 4 B */
  static const guint8 payload4[4] = {1, 2, 3, 4};
  ev.msg_payload = payload4;

  CHECK(remote_input_build(&ev, 0, buf, sizeof(buf), &n) == 0);
  CHECK(n == 26); /* L=11, (11+4) odd -> pad */
  static const guint8 exp_msg6[26] = {
      0x00, 0x04, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x07, 0x00, 0x09, 0x00, 0x06, 0x00, 0x00,
      0x01, 0x02, 0x03, 0x04,
      0x00, 0x00, 0x00, 0x00,
      0x00 /* pad */
  };
  CHECK(memcmp(buf, exp_msg6, sizeof(exp_msg6)) == 0);
}

static void test_remote_input_errors(void) {
  g_print("remote input: validation errors\n");
  guint8 buf[64];
  gsize n = 0;

  RemoteInputEvent ev;
  memset(&ev, 0, sizeof(ev));

  /* Dead types */
  ev.type = 4;
  CHECK(remote_input_build(&ev, 0, buf, sizeof(buf), &n) == -1);
  ev.type = 5;
  CHECK(remote_input_build(&ev, 0, buf, sizeof(buf), &n) == -1);
  ev.type = 0xb;
  CHECK(remote_input_build(&ev, 0, buf, sizeof(buf), &n) == -1);

  /* Touch: cnt out of range, bad subtype */
  ev.type = REMOTE_INPUT_TOUCH;
  ev.subtype = 3;
  ev.touch_cnt = 1;
  CHECK(remote_input_build(&ev, 0, buf, sizeof(buf), &n) == -1);
  ev.subtype = 0;
  ev.touch_cnt = 0;
  CHECK(remote_input_build(&ev, 0, buf, sizeof(buf), &n) == -1);
  ev.touch_cnt = 5;
  CHECK(remote_input_build(&ev, 0, buf, sizeof(buf), &n) == -1);

  /* Bad subtypes per type */
  ev.type = REMOTE_INPUT_KEY;
  ev.subtype = 2;
  CHECK(remote_input_build(&ev, 0, buf, sizeof(buf), &n) == -1);
  ev.type = REMOTE_INPUT_SCROLL;
  ev.subtype = 2;
  CHECK(remote_input_build(&ev, 0, buf, sizeof(buf), &n) == -1);
  ev.type = REMOTE_INPUT_MOUSE;
  ev.subtype = 3;
  CHECK(remote_input_build(&ev, 0, buf, sizeof(buf), &n) == -1);
  ev.type = REMOTE_INPUT_INPUT7;
  ev.subtype = 2;
  CHECK(remote_input_build(&ev, 0, buf, sizeof(buf), &n) == -1);
  ev.type = REMOTE_INPUT_WHEEL;
  ev.subtype = 2;
  CHECK(remote_input_build(&ev, 0, buf, sizeof(buf), &n) == -1);
  ev.type = REMOTE_INPUT_VKEY;
  ev.subtype = 4;
  CHECK(remote_input_build(&ev, 0, buf, sizeof(buf), &n) == -1);
  ev.type = REMOTE_INPUT_MESSAGE;
  ev.subtype = 2;
  CHECK(remote_input_build(&ev, 0, buf, sizeof(buf), &n) == -1);

  /* Message length bounds */
  static const guint8 pl[8] = {0};
  ev.subtype = 0;
  ev.msg_len = 1; /* (len-2) wraps in the original */
  ev.msg_payload = pl;
  CHECK(remote_input_build(&ev, 0, buf, sizeof(buf), &n) == -1);
  ev.msg_len = 473;
  CHECK(remote_input_build(&ev, 0, buf, sizeof(buf), &n) == -1);
  ev.msg_len = 5;
  ev.msg_payload = NULL;
  CHECK(remote_input_build(&ev, 0, buf, sizeof(buf), &n) == -1);

  /* Content length bounds */
  ev.type = REMOTE_INPUT_INPUT7;
  ev.subtype = 0;
  ev.content = "x";
  ev.content_len = 473;
  CHECK(remote_input_build(&ev, 0, buf, sizeof(buf), &n) == -1);
  ev.content = NULL;
  ev.content_len = 1;
  CHECK(remote_input_build(&ev, 0, buf, sizeof(buf), &n) == -1);

  /* Capacity: touch cnt=1 needs 28, reject 27 */
  memset(&ev, 0, sizeof(ev));
  ev.type = REMOTE_INPUT_TOUCH;
  ev.touch_cnt = 1;
  CHECK(remote_input_build(&ev, 0, buf, 27, &n) == -1);

  /* NULL arguments */
  CHECK(remote_input_build(NULL, 0, buf, sizeof(buf), &n) == -1);
  ev.touch_cnt = 1;
  CHECK(remote_input_build(&ev, 0, NULL, sizeof(buf), &n) == -1);
  CHECK(remote_input_build(&ev, 0, buf, sizeof(buf), NULL) == -1);
}

/* ============================ DMSDP control ============================ */

static const gchar *const kDmsdpSid = "hwphonelink-mirror";

/* Exact stand wire strings (spec 6.5.12). */
static const gchar *const kDmsdpSetupWire =
    "SETUP * DMSDP/1.0\r\n"
    "CSeq: 0\r\n"
    "ServiceID: hwphonelink-mirror\r\n"
    "ServiceType: 0\r\n"
    "DataSessionID: 1\r\n"
    "Backup: 0\r\n"
    "Transport: RTP/AVP/UDP;unicast;client_port=54323-54323\r\n"
    "\r\n";

static const gchar *const kDmsdpSetupReplyWire =
    "DMSDP/1.0 200 OK\r\n"
    "CSeq: 0\r\n"
    "ServiceID: hwphonelink-mirror\r\n"
    "ServiceType: 0\r\n"
    "DataSessionID: 1\r\n"
    "Transport: RTP/AVP/UDP;unicast;client_port=54323-54323;server_port="
    "54324-54324\r\n"
    "\r\n";

static const gchar *const kDmsdpPlayWire =
    "PLAY * DMSDP/1.0\r\n"
    "CSeq: 1\r\n"
    "ServiceID: hwphonelink-mirror\r\n"
    "ServiceType: 0\r\n"
    "DataSessionID: 1\r\n"
    "\r\n";

static const gchar *const kDmsdpCommonReplyWire =
    "DMSDP/1.0 200 OK\r\n"
    "CSeq: 1\r\n"
    "ServiceID: hwphonelink-mirror\r\n"
    "ServiceType: 0\r\n"
    "DataSessionID: 1\r\n"
    "\r\n";

static void test_dmsdp_build_wire(void) {
  g_print("dmsdp: builder byte-exact stand vectors\n");
  guint8 buf[2048];
  gsize n = 0;
  DmsdpMsg m;

  dmsdp_msg_setup(&m, 0, kDmsdpSid, 0, 1, 0, 54323, 54323);
  CHECK(dmsdp_build(&m, buf, sizeof(buf), &n) == 0);
  CHECK(n == strlen(kDmsdpSetupWire));
  CHECK(memcmp(buf, kDmsdpSetupWire, n) == 0);

  dmsdp_msg_setup_reply(&m, 0, kDmsdpSid, 0, 1, 54323, 54323, 54324, 54324);
  CHECK(dmsdp_build(&m, buf, sizeof(buf), &n) == 0);
  CHECK(n == strlen(kDmsdpSetupReplyWire));
  CHECK(memcmp(buf, kDmsdpSetupReplyWire, n) == 0);

  dmsdp_msg_play(&m, 1, kDmsdpSid, 0, 1);
  CHECK(dmsdp_build(&m, buf, sizeof(buf), &n) == 0);
  CHECK(n == strlen(kDmsdpPlayWire));
  CHECK(memcmp(buf, kDmsdpPlayWire, n) == 0);

  dmsdp_msg_common_reply(&m, 1, kDmsdpSid, 0, 1);
  CHECK(dmsdp_build(&m, buf, sizeof(buf), &n) == 0);
  CHECK(n == strlen(kDmsdpCommonReplyWire));
  CHECK(memcmp(buf, kDmsdpCommonReplyWire, n) == 0);

  /* type 8 with status != 200 is rejected */
  memset(&m, 0, sizeof(m));
  m.type = DMSDP_TYPE_RESPONSE;
  m.status = 404;
  CHECK(dmsdp_build(&m, buf, sizeof(buf), &n) == -1);

  /* unknown type rejected */
  memset(&m, 0, sizeof(m));
  m.type = 9;
  CHECK(dmsdp_build(&m, buf, sizeof(buf), &n) == -1);

  /* flag set but string missing rejected */
  memset(&m, 0, sizeof(m));
  m.type = DMSDP_TYPE_SETUP;
  m.flags1 = DMSDP_FLAG_SERVICE_ID;
  m.service_id = NULL;
  CHECK(dmsdp_build(&m, buf, sizeof(buf), &n) == -1);

  /* cap too small rejected */
  dmsdp_msg_play(&m, 1, kDmsdpSid, 0, 1);
  CHECK(dmsdp_build(&m, buf, 3, &n) == -1);
}

static void test_dmsdp_frame(void) {
  g_print("dmsdp: NoCrypto 3-byte frame\n");
  guint8 buf[4096];
  gsize n = 0;

  CHECK(dmsdp_frame("abc", 3, buf, sizeof(buf), &n) == 0);
  CHECK(n == 6);
  CHECK(buf[0] == 0x00);
  CHECK(buf[1] == 0x00);
  CHECK(buf[2] == 0x03);
  CHECK(memcmp(buf + 3, "abc", 3) == 0);

  /* N > 0x5DC rejected */
  CHECK(dmsdp_frame("x", 0x5dd, buf, sizeof(buf), &n) == -1);

  /* N == 0x5DC accepted; cap = 3 + N exactly */
  static gchar big[0x5dc + 3];
  memset(big, 'a', 0x5dc);
  CHECK(dmsdp_frame(big, 0x5dc, buf, sizeof(buf), &n) == 0);
  CHECK(n == 3 + 0x5dc);
  CHECK(buf[1] == 0x05);
  CHECK(buf[2] == 0xdc);
  CHECK(dmsdp_frame(big, 0x5dc, buf, 3 + 0x5dc, &n) == 0);
  CHECK(dmsdp_frame(big, 0x5dc, buf, 2 + 0x5dc, &n) == -1);

  /* NULL args */
  CHECK(dmsdp_frame(NULL, 3, buf, sizeof(buf), &n) == -1);
  CHECK(dmsdp_frame("abc", 3, NULL, sizeof(buf), &n) == -1);
  CHECK(dmsdp_frame("abc", 3, buf, sizeof(buf), NULL) == -1);
}

static void test_dmsdp_parse_roundtrip(void) {
  g_print("dmsdp: parser on the four stand vectors\n");
  DmsdpParsed p;

  /* SETUP */
  CHECK(dmsdp_parse(kDmsdpSetupWire, strlen(kDmsdpSetupWire), &p) == 0);
  CHECK(p.type == DMSDP_TYPE_SETUP);
  CHECK(p.flags1 == 0x81c01); /* CSeq|SID|SType|DSID|Transport */
  CHECK(p.flags2 == 0x2); /* Backup */
  CHECK(p.cseq == 0);
  CHECK(p.service_id != NULL && strcmp(p.service_id, "hwphonelink-mirror") == 0);
  CHECK(p.service_type == 0);
  CHECK(p.data_session_id == 1);
  CHECK(p.client_port_lo == 54323 && p.client_port_hi == 54323);
  CHECK(p.server_port_lo == 0 && p.server_port_hi == 0);
  CHECK(p.backup == 0);
  dmsdp_parsed_free(&p);

  /* SetupReply (response 200, combined Transport) */
  CHECK(dmsdp_parse(kDmsdpSetupReplyWire, strlen(kDmsdpSetupReplyWire), &p) == 0);
  CHECK(p.type == DMSDP_TYPE_RESPONSE);
  CHECK(p.response_fail == 0);
  CHECK(p.flags1 == 0x81c01);
  CHECK(p.flags2 == 0);
  CHECK(p.cseq == 0);
  CHECK(p.client_port_lo == 54323 && p.client_port_hi == 54323);
  CHECK(p.server_port_lo == 54324 && p.server_port_hi == 54324);
  dmsdp_parsed_free(&p);

  /* PLAY */
  CHECK(dmsdp_parse(kDmsdpPlayWire, strlen(kDmsdpPlayWire), &p) == 0);
  CHECK(p.type == DMSDP_TYPE_PLAY);
  CHECK(p.flags1 == 0x1c01);
  CHECK(p.flags2 == 0);
  CHECK(p.cseq == 1);
  CHECK(p.data_session_id == 1);
  dmsdp_parsed_free(&p);

  /* CommonReply */
  CHECK(dmsdp_parse(kDmsdpCommonReplyWire, strlen(kDmsdpCommonReplyWire), &p) == 0);
  CHECK(p.type == DMSDP_TYPE_RESPONSE);
  CHECK(p.response_fail == 0);
  CHECK(p.flags1 == 0x1c01);
  CHECK(p.cseq == 1);
  dmsdp_parsed_free(&p);

  /* Frame wrap + strip + parse */
  guint8 frame[512];
  gsize fn = 0;
  CHECK(dmsdp_frame(kDmsdpSetupWire, strlen(kDmsdpSetupWire), frame,
                    sizeof(frame), &fn) == 0);
  CHECK(frame[0] == 0x00);
  gsize tl = ((gsize)frame[1] << 8) | frame[2];
  CHECK(tl == strlen(kDmsdpSetupWire));
  CHECK(dmsdp_parse((const gchar *)frame + 3, tl, &p) == 0);
  CHECK(p.type == DMSDP_TYPE_SETUP);
  dmsdp_parsed_free(&p);
}

static void test_dmsdp_parse_errors(void) {
  g_print("dmsdp: parser error cases\n");
  DmsdpParsed p;

  /* no colon -> -5 */
  static const gchar *t1 = "PLAY * DMSDP/1.0\r\nNoColon\r\n\r\n";
  CHECK(dmsdp_parse(t1, strlen(t1), &p) == -5);

  /* unknown key silently ignored */
  static const gchar *t2 = "PLAY * DMSDP/1.0\r\nBogus: 1\r\n\r\n";
  CHECK(dmsdp_parse(t2, strlen(t2), &p) == 0);
  CHECK(p.flags1 == 0);
  dmsdp_parsed_free(&p);

  /* prefix key match: "CSe" -> CSeq */
  static const gchar *t3 = "PLAY * DMSDP/1.0\r\nCSe: 1\r\n\r\n";
  CHECK(dmsdp_parse(t3, strlen(t3), &p) == 0);
  CHECK(p.cseq == 1);
  dmsdp_parsed_free(&p);

  /* response 404 -> type 8, response_fail */
  static const gchar *t4 = "DMSDP/1.0 404 NF\r\n\r\n";
  CHECK(dmsdp_parse(t4, strlen(t4), &p) == 0);
  CHECK(p.type == DMSDP_TYPE_RESPONSE);
  CHECK(p.response_fail == 1);
  dmsdp_parsed_free(&p);

  /* all-digits response line -> -2 */
  static const gchar *t5 = "DMSDP/1.0 200\r\n\r\n";
  CHECK(dmsdp_parse(t5, strlen(t5), &p) == -2);

  /* no digits in response line -> -2 */
  static const gchar *t6 = "DMSDP/1.0  OK\r\n\r\n";
  CHECK(dmsdp_parse(t6, strlen(t6), &p) == -2);

  /* reason longer than 12 chars -> -2 */
  static const gchar *t7 = "DMSDP/1.0 200 VeryLongReason\r\n\r\n";
  CHECK(dmsdp_parse(t7, strlen(t7), &p) == -2);

  /* Codec soft-ignored: flag bit cleared */
  static const gchar *t8 = "PLAY * DMSDP/1.0\r\nCodec: 1\r\n\r\n";
  CHECK(dmsdp_parse(t8, strlen(t8), &p) == 0);
  CHECK(p.flags1 == 0);
  dmsdp_parsed_free(&p);

  /* KaRetry soft-ignored */
  static const gchar *t9 = "PLAY * DMSDP/1.0\r\nKaRetry: 5\r\n\r\n";
  CHECK(dmsdp_parse(t9, strlen(t9), &p) == 0);
  CHECK(p.flags1 == 0);
  dmsdp_parsed_free(&p);

  /* "CSeq:3" (no space after colon): value "3" parses fine (RE:
   * ParseInteger has no sign for '3'; atoi("3") = 3) */
  static const gchar *t10 = "PLAY * DMSDP/1.0\r\nCSeq:3\r\n\r\n";
  CHECK(dmsdp_parse(t10, strlen(t10), &p) == 0);
  CHECK(p.cseq == 3);
  dmsdp_parsed_free(&p);

  /* value " 3" (leading space) parses fine */
  static const gchar *t11 = "PLAY * DMSDP/1.0\r\nCSeq: 3\r\n\r\n";
  CHECK(dmsdp_parse(t11, strlen(t11), &p) == 0);
  CHECK(p.cseq == 3);
  dmsdp_parsed_free(&p);

  /* ParseInteger degenerates (RE 0x180019b40): the sign slot
   * ((c-0x2b)&0xfd==0) holds exactly for '+' and '/' */
  static const gchar *t17a = "PLAY * DMSDP/1.0\r\nCSeq: +3\r\n\r\n";
  CHECK(dmsdp_parse(t17a, strlen(t17a), &p) == 0);
  CHECK(p.cseq == 3);
  dmsdp_parsed_free(&p);

  /* '/3': '/' is NOT a sign slot (mask 0xfd keeps only '+'/'-');
   * the digit check fails on '/' -> -1 */
  static const gchar *t17b = "PLAY * DMSDP/1.0\r\nCSeq: /3\r\n\r\n";
  CHECK(dmsdp_parse(t17b, strlen(t17b), &p) == -1);

  /* "-3": '-' IS a sign slot; digits OK; atoi("-3") wraps -> 0xfffffffd */
  static const gchar *t17c = "PLAY * DMSDP/1.0\r\nCSeq: -3\r\n\r\n";
  CHECK(dmsdp_parse(t17c, strlen(t17c), &p) == 0);
  CHECK(p.cseq == 0xfffffffd);
  dmsdp_parsed_free(&p);

  /* " +": space then sign, strlen == 2 -> no lone-sign error; the
   * digit loop is empty and atoi(" +") = 0 */
  static const gchar *t17d = "PLAY * DMSDP/1.0\r\nCSeq: +\r\n\r\n";
  CHECK(dmsdp_parse(t17d, strlen(t17d), &p) == 0);
  CHECK(p.cseq == 0);
  dmsdp_parsed_free(&p);

  /* lone sign slot (no space): strlen == 1 -> -1 */
  static const gchar *t17h = "PLAY * DMSDP/1.0\r\nCSeq:+\r\n\r\n";
  CHECK(dmsdp_parse(t17h, strlen(t17h), &p) == -1);

  /* trailing junk -> -1 */
  static const gchar *t17e = "PLAY * DMSDP/1.0\r\nCSeq: 12x\r\n\r\n";
  CHECK(dmsdp_parse(t17e, strlen(t17e), &p) == -1);

  /* value longer than 16 bytes -> -9 */
  static const gchar *t17f =
      "PLAY * DMSDP/1.0\r\nCSeq: 12345678901234567\r\n\r\n";
  CHECK(dmsdp_parse(t17f, strlen(t17f), &p) == -9);

  /* value " " (single space): buffer is " ", atoi(" ") = 0 */
  static const gchar *t17g = "PLAY * DMSDP/1.0\r\nCSeq: \r\n\r\n";
  CHECK(dmsdp_parse(t17g, strlen(t17g), &p) == 0);
  CHECK(p.cseq == 0);
  dmsdp_parsed_free(&p);

  /* trigger-method body, CL 28 = exact trigger 1 */
  static const gchar *t12 =
      "PLAY * DMSDP/1.0\r\nContent-Length: 28\r\n\r\n"
      "msdp_trigger_method: SETUP\r\n";
  CHECK(dmsdp_parse(t12, strlen(t12), &p) == 0);
  CHECK(p.trigger_idx == 1);
  dmsdp_parsed_free(&p);

  /* trigger body with wrong length content -> -2 */
  static const gchar *t13 =
      "PLAY * DMSDP/1.0\r\nContent-Length: 28\r\n\r\n"
      "msdp_trigger_method: FOOOO\r\n";
  CHECK(dmsdp_parse(t13, strlen(t13), &p) == -2);

  /* Content-Length mismatch -> -2 */
  static const gchar *t14 =
      "PLAY * DMSDP/1.0\r\nContent-Length: 27\r\n\r\n"
      "msdp_trigger_method: SETUP\r\n";
  CHECK(dmsdp_parse(t14, strlen(t14), &p) == -2);

  /* repeated Transport: no dup check in the RE; the last line
   * re-parses and its first match wins -> 0, client 3-4 */
  static const gchar *t15 =
      "PLAY * DMSDP/1.0\r\n"
      "Transport: RTP/AVP/UDP;unicast;client_port=1-2\r\n"
      "Transport: RTP/AVP/UDP;unicast;client_port=3-4\r\n"
      "\r\n";
  CHECK(dmsdp_parse(t15, strlen(t15), &p) == 0);
  CHECK(p.client_port_lo == 3 && p.client_port_hi == 4);
  CHECK(p.server_port_lo == 0 && p.server_port_hi == 0);
  dmsdp_parsed_free(&p);

  /* bad client port range: silent 0, ports stay 0, server pass
   * skipped (RE jumps to the epilogue) */
  static const gchar *t18 =
      "PLAY * DMSDP/1.0\r\n"
      "Transport: RTP/AVP/UDP;unicast;client_port=x;server_port=1-2\r\n"
      "\r\n";
  CHECK(dmsdp_parse(t18, strlen(t18), &p) == 0);
  CHECK(p.client_port_lo == 0 && p.client_port_hi == 0);
  CHECK(p.server_port_lo == 0 && p.server_port_hi == 0);
  dmsdp_parsed_free(&p);

  /* Transport prefix mismatch -> silent 0 (no fields touched) */
  static const gchar *t19 =
      "PLAY * DMSDP/1.0\r\nTransport: UDP/AVP/UDP;unicast;client_port=1-2\r\n"
      "\r\n";
  CHECK(dmsdp_parse(t19, strlen(t19), &p) == 0);
  CHECK(p.client_port_lo == 0);
  CHECK((p.flags1 & 0x00080000u) != 0); /* the flag is OR'd before parse */
  dmsdp_parsed_free(&p);

  /* empty input -> -2 */
  CHECK(dmsdp_parse("", 0, &p) == -2);

  /* start line without CRLF -> -2 */
  static const gchar *t16 = "PLAY * DMSDP/1.0";
  CHECK(dmsdp_parse(t16, strlen(t16), &p) == -2);
}

static void test_dmsdp_client_fsm(void) {
  g_print("dmsdp: client FSM happy path + error cases\n");
  DmsdpClient *c = dmsdp_client_new();
  CHECK(dmsdp_client_state(c) == DMSDP_CL_INIT);

  DmsdpMsg m;
  DmsdpParsed p;
  guint8 frame[2048];
  gchar text[2048];
  gsize n = 0;

  /* happy path */
  dmsdp_msg_setup(&m, 0, kDmsdpSid, 0, 1, 0, 54323, 54323);
  CHECK(dmsdp_client_send(c, &m, frame, sizeof(frame), &n) == 0);
  CHECK(dmsdp_client_state(c) == DMSDP_CL_WAIT_SETUP_REPLY);
  gsize tl = strlen(kDmsdpSetupWire);
  CHECK(n == 3 + tl);
  CHECK(frame[0] == 0x00);
  CHECK(frame[1] == (guint8)(tl >> 8));
  CHECK(frame[2] == (guint8)(tl & 0xff));
  CHECK(memcmp(frame + 3, kDmsdpSetupWire, tl) == 0);

  dmsdp_msg_setup_reply(&m, 0, kDmsdpSid, 0, 1, 54323, 54323, 54324, 54324);
  CHECK(dmsdp_build(&m, (guint8 *)text, sizeof(text), &n) == 0);
  CHECK(dmsdp_parse(text, n, &p) == 0);
  CHECK(dmsdp_client_recv(c, &p) == 0);
  CHECK(dmsdp_client_state(c) == DMSDP_CL_SEND_PLAY);
  dmsdp_parsed_free(&p);

  dmsdp_msg_play(&m, 1, kDmsdpSid, 0, 1);
  CHECK(dmsdp_client_send(c, &m, frame, sizeof(frame), &n) == 0);
  CHECK(dmsdp_client_state(c) == DMSDP_CL_WAIT_PLAY_REPLY);
  CHECK(n == 3 + strlen(kDmsdpPlayWire));
  CHECK(memcmp(frame + 3, kDmsdpPlayWire, strlen(kDmsdpPlayWire)) == 0);

  dmsdp_msg_common_reply(&m, 1, kDmsdpSid, 0, 1);
  CHECK(dmsdp_build(&m, (guint8 *)text, sizeof(text), &n) == 0);
  CHECK(dmsdp_parse(text, n, &p) == 0);
  CHECK(dmsdp_client_recv(c, &p) == 0);
  CHECK(dmsdp_client_state(c) == DMSDP_CL_READY);

  /* READY ignores further replies */
  CHECK(dmsdp_client_recv(c, &p) == 0);
  CHECK(dmsdp_client_state(c) == DMSDP_CL_READY);
  dmsdp_parsed_free(&p);
  dmsdp_client_free(c);

  /* error: send PLAY in INIT -> ERROR */
  c = dmsdp_client_new();
  dmsdp_msg_play(&m, 0, kDmsdpSid, 0, 1);
  CHECK(dmsdp_client_send(c, &m, frame, sizeof(frame), &n) == -1);
  CHECK(dmsdp_client_state(c) == DMSDP_CL_ERROR);
  dmsdp_client_free(c);

  /* error: SETUP with cseq != 0 in INIT -> ERROR */
  c = dmsdp_client_new();
  dmsdp_msg_setup(&m, 5, kDmsdpSid, 0, 1, 0, 54323, 54323);
  CHECK(dmsdp_client_send(c, &m, frame, sizeof(frame), &n) == -1);
  CHECK(dmsdp_client_state(c) == DMSDP_CL_ERROR);
  dmsdp_client_free(c);

  /* error: reply with wrong CSeq in WAIT_SETUP_REPLY -> ERROR */
  c = dmsdp_client_new();
  dmsdp_msg_setup(&m, 0, kDmsdpSid, 0, 1, 0, 54323, 54323);
  CHECK(dmsdp_client_send(c, &m, frame, sizeof(frame), &n) == 0);
  dmsdp_msg_common_reply(&m, 7, kDmsdpSid, 0, 1);
  CHECK(dmsdp_build(&m, (guint8 *)text, sizeof(text), &n) == 0);
  CHECK(dmsdp_parse(text, n, &p) == 0);
  CHECK(dmsdp_client_recv(c, &p) == -1);
  CHECK(dmsdp_client_state(c) == DMSDP_CL_ERROR);
  dmsdp_parsed_free(&p);
  dmsdp_client_free(c);

  /* error: reply before any send (INIT) -> ERROR */
  c = dmsdp_client_new();
  dmsdp_msg_common_reply(&m, 0, kDmsdpSid, 0, 1);
  CHECK(dmsdp_build(&m, (guint8 *)text, sizeof(text), &n) == 0);
  CHECK(dmsdp_parse(text, n, &p) == 0);
  CHECK(dmsdp_client_recv(c, &p) == -1);
  CHECK(dmsdp_client_state(c) == DMSDP_CL_ERROR);
  dmsdp_parsed_free(&p);
  dmsdp_client_free(c);

  /* error: send after READY -> -1, state stays READY */
  c = dmsdp_client_new();
  dmsdp_msg_setup(&m, 0, kDmsdpSid, 0, 1, 0, 54323, 54323);
  CHECK(dmsdp_client_send(c, &m, frame, sizeof(frame), &n) == 0);
  dmsdp_msg_setup_reply(&m, 0, kDmsdpSid, 0, 1, 54323, 54323, 54324, 54324);
  CHECK(dmsdp_build(&m, (guint8 *)text, sizeof(text), &n) == 0);
  CHECK(dmsdp_parse(text, n, &p) == 0);
  CHECK(dmsdp_client_recv(c, &p) == 0);
  dmsdp_msg_play(&m, 1, kDmsdpSid, 0, 1);
  CHECK(dmsdp_client_send(c, &m, frame, sizeof(frame), &n) == 0);
  dmsdp_msg_common_reply(&m, 1, kDmsdpSid, 0, 1);
  CHECK(dmsdp_build(&m, (guint8 *)text, sizeof(text), &n) == 0);
  CHECK(dmsdp_parse(text, n, &p) == 0);
  CHECK(dmsdp_client_recv(c, &p) == 0);
  CHECK(dmsdp_client_send(c, &m, frame, sizeof(frame), &n) == -1);
  CHECK(dmsdp_client_state(c) == DMSDP_CL_READY);
  dmsdp_parsed_free(&p);
  dmsdp_client_free(c);
}

/* ============================ Main ============================ */

int main(void) {
  g_print("hwphonelink proto tests\n");

  g_mutex_init(&test_lock);
  g_cond_init(&test_cond);

  test_frame_roundtrip();
  test_frame_buf_incremental();
  test_frame_bad_magic();
  test_beacon_roundtrip();
  test_hkdf();
  test_aes_gcm();
  test_hmac();
  test_auth_fsm_psk();
  test_auth_wrong_psk();
  test_auth_retry_exhaustion();
  test_session_socketpair();
  test_dfile_header_unpack();
  test_dfile_setting_roundtrip();
  test_dfile_file_header_roundtrip();
  test_dfile_idlist_roundtrip();
  test_dfile_data_roundtrip();
  test_dfile_ack_v1();
  test_dfile_ack_v2();
  test_dfile_ack_bad();
  test_dfile_rst_roundtrip();
  test_ft_testfile();
  test_fillp_head();
  test_fillp_mgmt_roundtrip();
  test_fillp_cookie();
  test_vtp_frame();
  test_h264_testfile();
  test_remote_input_touch();
  test_remote_input_key_mouse();
  test_remote_input_zoom_scroll();
  test_remote_input_wheel_vkey();
  test_remote_input_input7_message();
  test_remote_input_errors();
  test_dmsdp_build_wire();
  test_dmsdp_frame();
  test_dmsdp_parse_roundtrip();
  test_dmsdp_parse_errors();
  test_dmsdp_client_fsm();

  g_mutex_clear(&test_lock);
  g_cond_clear(&test_cond);

  if (failures == 0) {
    g_print("ALL TESTS PASSED\n");
    return 0;
  }
  g_print("%d TEST(S) FAILED\n", failures);
  return 1;
}
