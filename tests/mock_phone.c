/*
 * mock_phone.c - Replay-stand "phone" for the dsoftbus protocol
 *
 * Emulates the phone side of the Multi-Screen stack without a real device:
 *   1. Publishes a CoAP discovery beacon (224.0.1.187:5683, plus a unicast
 *      copy to the daemon so same-host testing is deterministic).
 *   2. Connects to the daemon's TCP session port and wraps the connection
 *      in a SoftbusSession (the PC is the accepting side).
 *   3. Runs the HiChain 4-state auth FSM as the PASSIVE side in PSK mode.
 *   4. On success, sends a "P40-PING" payload and verifies the daemon's
 *      echo — validating the session data path end to end.
 *   5. Opens a raw-TCP DFile connection to the daemon, pushes a
 *      deterministic test file (ft-<sha>.bin, verified by the daemon)
 *      and receives the daemon's reverse push (verified by the engine
 *      from the wire name) — bidirectional E2E. Skippable with --no-ft.
 *
 * Exit codes: 0 = full handshake + echo + FT OK, 1 = failure/timeout.
 */

#include <glib.h>
#include <gio/gio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "proto/softbus_defs.h"
#include "proto/softbus_device.h"
#include "proto/softbus_auth.h"
#include "proto/softbus_session.h"
#include "proto/softbus_crypto.h"
#include "proto/dfile_conn.h"
#include "proto/ft_testfile.h"

#define MOCK_PING "P40-PING"
#define MOCK_TIMEOUT_MS 45000
#define MOCK_FT_SEED 1
#define MOCK_FT_SIZE (1024 * 1024) /* 1 MiB = 713 blocks @ 1472, last 512 */

static GMainLoop *loop = NULL;
static gint exit_code = 1;
static SoftbusSession *session = NULL;
static SoftbusAuth *auth = NULL;

/* DFile phase state. The push is started from the engine thread
 * (on_ft_negotiated); results/closure fire there too and are marshalled
 * to the main loop with g_main_context_invoke. */
static DFileConn *ft_dc = NULL;
static volatile gint ft_push_done = 0;
static volatile gint ft_pull_done = 0;
static volatile gint ft_finished = 0;
static guint ft_port = 54322;
static gboolean skip_ft = FALSE;

/* Runs on the main thread (either directly from the timeout source, or
 * via g_main_context_invoke from the session pump thread). GSourceFunc. */
static int set_exit(gpointer code) {
  int c = GPOINTER_TO_INT(code);
  if (exit_code != 0) exit_code = c;
  g_main_loop_quit(loop);
  return 0;
}

static void print_keys(const gchar *who) {
  const guint8 *ck = softbus_auth_get_control_key(auth);
  const guint8 *dk = softbus_auth_get_data_key(auth);
  if (ck) {
    gchar *h = softbus_to_hex(ck, softbus_auth_get_key_len(auth));
    g_print("mock-phone: [%s] control-key: %s\n", who, h);
    g_free(h);
  }
  if (dk) {
    gchar *h = softbus_to_hex(dk, softbus_auth_get_key_len(auth));
    g_print("mock-phone: [%s] data-key: %s\n", who, h);
    g_free(h);
  }
}

/* ============================ DFile phase ============================
 *
 * After the echo check the mock opens a raw-TCP DFile client connection
 * to the daemon (proto/dfile_conn.h), pushes a deterministic test file
 * (ft-<sha256>.bin) and receives the daemon's reverse push. The wire
 * name convention lets the receiver verify content without extra
 * metadata.
 *
 * Engine callbacks fire on the DFile engine thread; they only marshal
 * to the main loop via g_main_context_invoke().
 */

/* Marshalled: print + fail with @msg (takes ownership of the string). */
static int ft_fail(gpointer msg) {
  g_print("mock-phone: FT FAILED: %s\n", (const gchar *)msg);
  g_free(msg);
  return set_exit(GINT_TO_POINTER(1));
}

static void ft_fail_invoke(const gchar *reason) {
  g_main_context_invoke_full(NULL, G_PRIORITY_DEFAULT, (GSourceFunc)ft_fail,
                             g_strdup(reason), NULL);
}

/* Both directions verified → exit 0 (exactly once). */
static int ft_mark_done(gpointer p) {
  (void)p;
  if (g_atomic_int_exchange(&ft_finished, 1)) return 0;
  g_print("mock-phone: FT E2E OK (push + pull verified)\n");
  return set_exit(GINT_TO_POINTER(0));
}

static void on_ft_negotiated(DFileConn *dc, gpointer user_data) {
  (void)user_data;
  g_print("mock-phone: DFile session negotiated (block size %u)\n",
          dfile_conn_block_size(dc));

  /* Push file A: deterministic test content, self-describing name. */
  gchar *dir = g_build_filename(g_get_tmp_dir(), "hwphonelink-mock-ft",
                                NULL);
  gchar *path = NULL;
  gchar *wire_name = NULL;
  if (g_mkdir_with_parents(dir, 0755) < 0 ||
      !ft_testfile_generate(dir, MOCK_FT_SEED, MOCK_FT_SIZE, &path,
                            &wire_name)) {
    g_print("mock-phone: test file generation failed\n");
    g_free(dir);
    ft_fail_invoke("cannot generate test file");
    return;
  }
  g_print("mock-phone: pushing %s (%u bytes)\n", wire_name,
          (unsigned)MOCK_FT_SIZE);
  DFileSendItem item = {path, wire_name, 0};
  GError *err = NULL;
  if (!dfile_conn_send_files(dc, &item, 1, &err)) {
    g_print("mock-phone: push start failed: %s\n", err ? err->message : "?");
    g_clear_error(&err);
    ft_fail_invoke("push start failed");
  }
  g_free(path);
  g_free(wire_name);
  g_free(dir);
}

static void on_ft_file_list(DFileConn *dc, const DFileHeaderEntry *entries,
                            gsize n, gpointer user_data) {
  (void)dc;
  (void)user_data;
  for (gsize i = 0; i < n; i++)
    g_print("mock-phone: incoming file %u: %s (%" G_GUINT64_FORMAT
            " bytes)\n", (unsigned)entries[i].file_id, entries[i].name,
            entries[i].file_size);
}

static void on_ft_result(DFileConn *dc, gboolean is_sender, gboolean ok,
                         const gchar *msg, gpointer user_data) {
  (void)dc;
  (void)user_data;
  if (!ok) {
    ft_fail_invoke(msg);
    return;
  }
  g_print("mock-phone: FT %s done: %s\n", is_sender ? "push" : "pull", msg);
  if (is_sender)
    g_atomic_int_set(&ft_push_done, 1);
  else
    g_atomic_int_set(&ft_pull_done, 1);
  if (ft_push_done && ft_pull_done)
    g_main_context_invoke(NULL, ft_mark_done, NULL);
}

static void on_ft_closed(DFileConn *dc, gpointer user_data) {
  (void)dc;
  (void)user_data;
  g_print("mock-phone: DFile session closed\n");
  if (!(ft_push_done && ft_pull_done))
    ft_fail_invoke("FT session closed before both transfers completed");
  /* The mock keeps its external ref until main() cleanup. */
}

/* Called on the session pump thread after the echo check. A blocking
 * connect here is fine — the daemon's FT listener is already up. */
static void start_ft(const gchar *server_ip) {
  GError *err = NULL;
  DFileConn *dc = dfile_conn_new_client(server_ip, ft_port, &err);
  if (dc == NULL) {
    g_print("mock-phone: DFile connect failed: %s\n",
            err ? err->message : "?");
    g_clear_error(&err);
    ft_fail_invoke("DFile connect failed");
    return;
  }
  gchar *rxdir = g_build_filename(g_get_tmp_dir(), "hwphonelink-mock-ft-rx",
                                  NULL);
  g_mkdir_with_parents(rxdir, 0755);
  dfile_conn_set_recv_dir(dc, rxdir);
  g_free(rxdir);
  dfile_conn_set_callbacks(dc, on_ft_negotiated, on_ft_file_list,
                           on_ft_result, on_ft_closed, NULL);
  ft_dc = dc;
}

/* Session data callback (pump thread). */
static void on_data(SoftbusSession *s, const guint8 *data, gsize len,
                    gpointer user_data) {
  if (softbus_auth_get_state(auth) == SOFTBUS_AUTH_STATE_DONE) {
    /* Post-auth: the daemon echoes payloads. Our ping must come back. */
    if (len == strlen(MOCK_PING) && memcmp(data, MOCK_PING, len) == 0) {
      g_print("mock-phone: echo of %s received — session data path OK\n",
              MOCK_PING);
      if (skip_ft)
        g_main_context_invoke(NULL, set_exit, GINT_TO_POINTER(0));
      else
        start_ft((const gchar *)user_data);
    }
    return;
  }

  gchar *reply = NULL;
  GError *err = NULL;
  SoftbusAuthResult result = softbus_auth_feed(auth, (const gchar *)data,
                                               len, &reply, &err);
  if (err) {
    g_print("mock-phone: auth error: %s\n", err->message);
    g_clear_error(&err);
  }
  if (reply) {
    GError *serr = NULL;
    if (!softbus_session_send_json(s, reply, &serr)) {
      g_print("mock-phone: reply send failed: %s\n",
              serr ? serr->message : "?");
      g_clear_error(&serr);
    }
    g_free(reply);
  }

  switch (result) {
    case SOFTBUS_AUTH_RESULT_COMPLETE: {
      const SoftbusDevice *peer = softbus_auth_get_peer(auth);
      g_print("mock-phone: AUTH COMPLETE (PSK) with %s\n",
              peer ? softbus_device_get_id(peer) : "pc");
      print_keys("phone");
      GError *serr = NULL;
      if (!softbus_session_send(s, (const guint8 *)MOCK_PING,
                                strlen(MOCK_PING), &serr)) {
        g_print("mock-phone: ping send failed: %s\n",
                serr ? serr->message : "?");
        g_clear_error(&serr);
        g_main_context_invoke(NULL, set_exit, GINT_TO_POINTER(1));
      }
      break;
    }
    case SOFTBUS_AUTH_RESULT_FAILED:
      g_print("mock-phone: AUTH FAILED\n");
      g_main_context_invoke(NULL, set_exit, GINT_TO_POINTER(1));
      break;
    default:
      break;
  }
}

/* Send the discovery beacon: multicast + unicast to the daemon. */
static void send_beacon(SoftbusDevice *dev, const gchar *server_ip) {
  GError *err = NULL;
  gchar *beacon = softbus_device_pack_beacon(dev, &err);
  if (!beacon) {
    g_print("mock-phone: beacon pack failed: %s\n", err ? err->message : "?");
    g_clear_error(&err);
    return;
  }

  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    g_print("mock-phone: cannot open UDP socket: %s\n", g_strerror(errno));
    g_free(beacon);
    return;
  }

  struct sockaddr_in dst;
  memset(&dst, 0, sizeof(dst));
  dst.sin_family = AF_INET;
  dst.sin_port = htons(SOFTBUS_COAP_PORT);
  inet_pton(AF_INET, SOFTBUS_COAP_MCAST_ADDR, &dst.sin_addr);
  if (sendto(fd, beacon, strlen(beacon), 0,
             (struct sockaddr *)&dst, sizeof(dst)) < 0) {
    g_print("mock-phone: multicast beacon failed: %s\n", g_strerror(errno));
  } else {
    g_print("mock-phone: beacon published to %s:%d (%zu bytes)\n",
            SOFTBUS_COAP_MCAST_ADDR, SOFTBUS_COAP_PORT, strlen(beacon));
  }

  /* Unicast copy to the daemon (deterministic for same-host testing). */
  struct sockaddr_in dst2 = dst;
  inet_pton(AF_INET, server_ip, &dst2.sin_addr);
  if (sendto(fd, beacon, strlen(beacon), 0,
             (struct sockaddr *)&dst2, sizeof(dst2)) < 0) {
    g_print("mock-phone: unicast beacon failed: %s\n", g_strerror(errno));
  } else {
    g_print("mock-phone: beacon also sent to %s:%d\n",
            server_ip, SOFTBUS_COAP_PORT);
  }

  close(fd);
  g_free(beacon);
}

static gboolean on_timeout(gpointer data) {
  (void)data;
  g_print("mock-phone: timed out waiting for handshake/echo\n");
  set_exit(GINT_TO_POINTER(1));
  return G_SOURCE_REMOVE;
}

int main(int argc, char *argv[]) {
  g_autoptr(GError) error = NULL;
  g_autoptr(GOptionContext) context = NULL;

  gchar *server_ip = NULL;
  guint server_port = 54321;
  gint ft_port_opt = 54322;
  gchar *psk = NULL;
  gchar *device_id = "mock-phone-001";

  GOptionEntry entries[] = {
    {"server-ip", 0, 0, G_OPTION_ARG_STRING, &server_ip, "Daemon IP to connect to", "IP"},
    {"server-port", 0, 0, G_OPTION_ARG_INT, &server_port, "Daemon session TCP port (default 54321)", "PORT"},
    {"ft-port", 0, 0, G_OPTION_ARG_INT, &ft_port_opt, "Daemon DFile (file transfer) TCP port (default 54322)", "PORT"},
    {"no-ft", 0, G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE, &skip_ft, "Skip the DFile transfer phase (session test only)", NULL},
    {"psk", 0, 0, G_OPTION_ARG_STRING, &psk, "Pre-provisioned PSK (default: test PSK)", "SECRET"},
    {"id", 0, 0, G_OPTION_ARG_STRING, &device_id, "Mock phone device id", "ID"},
    {NULL}
  };

  context = g_option_context_new("hwphonelink-mock-phone [OPTIONS]");
  g_option_context_add_main_entries(context, entries, NULL);
  if (!g_option_context_parse(context, &argc, &argv, &error)) {
    g_printerr("Option parsing failed: %s\n", error->message);
    return 1;
  }
  if (server_ip == NULL) {
    g_printerr("--server-ip is required\n");
    g_printerr("%s", g_option_context_get_help(context, TRUE, NULL));
    return 1;
  }
  if (ft_port_opt < 0) {
    g_printerr("--ft-port must be >= 0\n");
    return 1;
  }
  ft_port = (guint)ft_port_opt;
  if (psk == NULL) {
    psk = g_strdup(g_getenv("HWPONELINK_PSK"));
    if (psk == NULL || psk[0] == '\0') {
      g_free(psk);
      psk = g_strdup("hwphonelink-test-psk");
    }
  }

  /* 1. Local device record (what the phone would advertise). */
  SoftbusDevice *dev = softbus_device_new();
  dev->device_id = g_strdup(device_id);
  dev->device_name = g_strdup("HUAWEI P40 Pro (mock)");
  dev->device_type = SOFTBUS_DEVTYPE_PHONE;
  dev->capabilities = SOFTBUS_CAP_CASTPLUS | SOFTBUS_CAP_DVKIT |
                      SOFTBUS_CAP_OSD | SOFTBUS_CAP_MULTISCREEN;
  dev->auth_port = 45678;
  dev->session_port = 45679;
  dev->proxy_port = 45680;
  dev->ble_mac = g_strdup("aa:bb:cc:dd:ee:ff");

  gchar *dstr = softbus_device_to_string(dev);
  g_print("mock-phone: %s\n", dstr);
  g_free(dstr);

  /* 2. Publish the discovery beacon. */
  send_beacon(dev, server_ip);

  /* 3. Connect to the daemon's session listener (retry: it may be starting). */
  GSocketClient *client = g_socket_client_new();
  g_socket_client_set_timeout(client, 5);
  GSocketConnection *conn = NULL;
  for (int attempt = 1; attempt <= 10 && conn == NULL; attempt++) {
    GError *cerr = NULL;
    conn = g_socket_client_connect_to_host(client, server_ip, server_port,
                                           NULL, &cerr);
    if (!conn) {
      g_print("mock-phone: connect %s:%u attempt %d failed: %s\n",
              server_ip, server_port, attempt, cerr->message);
      g_clear_error(&cerr);
      g_usleep(500 * 1000);
    }
  }
  g_object_unref(client);
  if (!conn) {
    g_print("mock-phone: could not connect to daemon at %s:%u\n",
            server_ip, server_port);
    softbus_device_unref(dev);
    return 1;
  }
  g_print("mock-phone: connected to %s:%u\n", server_ip, server_port);

  /* 4. Session + passive auth. */
  session = softbus_session_new(conn, SOFTBUS_SESSION_MESSAGE);
  if (!session) {
    g_print("mock-phone: session creation failed\n");
    g_object_unref(conn);
    softbus_device_unref(dev);
    return 1;
  }
  g_object_unref(conn);  /* the session owns its ref */

  auth = softbus_auth_new(dev, NULL, (const guint8 *)psk, strlen(psk));
  /* user_data carries the daemon IP for the post-echo DFile phase. */
  softbus_session_set_data_cb(session, on_data, (gpointer)server_ip, NULL);

  /* 5. Main loop (timeout guards the whole handshake). */
  loop = g_main_loop_new(NULL, FALSE);
  g_timeout_add(MOCK_TIMEOUT_MS, on_timeout, NULL);
  g_main_loop_run(loop);

  /* Cleanup */
  g_print("mock-phone: exiting with code %d\n", exit_code);
  if (ft_dc) {
    dfile_conn_close(ft_dc);
    dfile_conn_unref(ft_dc);
    ft_dc = NULL;
  }
  softbus_session_stop(session);
  g_object_unref(session);
  softbus_auth_free(auth);
  softbus_device_unref(dev);
  g_main_loop_unref(loop);
  g_free(psk);
  return exit_code;
}
