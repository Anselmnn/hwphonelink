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

  g_mutex_clear(&test_lock);
  g_cond_clear(&test_cond);

  if (failures == 0) {
    g_print("ALL TESTS PASSED\n");
    return 0;
  }
  g_print("%d TEST(S) FAILED\n", failures);
  return 1;
}
