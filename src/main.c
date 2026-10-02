/*
 * main.c - hwphonelinkd main entry point
 *
 * Huawei Multi-Screen Collaboration daemon for Linux.
 * Supports dual Wi-Fi transport: SoftAP (primary) + P2P-GO (fallback) +
 * Infrastructure/LAN mode.
 *
 * M2: accepted TCP connections are wrapped in dsoftbus sessions
 * (proto/softbus_session.h) and run the HiChain 4-state auth FSM in PSK
 * mode (proto/softbus_auth.h). On success the session keys are derived
 * (HKDF-SHA256 → AES-256-GCM) and the session stays open for data;
 * payloads received after auth are echoed back (replay-stand behaviour).
 */

#include "transport/wifi_transport.h"
#include "transport/softap_backend.h"
#include "transport/p2p_backend.h"
#include "proto/softbus_device.h"
#include "proto/softbus_auth.h"
#include "proto/softbus_session.h"
#include "proto/softbus_crypto.h"
#include "proto/dfile_conn.h"
#include "proto/ft_testfile.h"
#include "proto/dmsdp.h"
#include "proto/fillp_conn.h"
#include "proto/h264_testfile.h"
#include "proto/remote_input.h"
#include "proto/stream_file.h"
#include "proto/vtp_frame.h"
#include "mirror_player.h"
#include <glib.h>
#include <gio/gio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static GMainLoop *main_loop = NULL;
static HwPhoneLinkTransport *transport = NULL;

/* Local identity + pre-provisioned PSK (PSK-mode auth, replay stand). */
static SoftbusDevice *local_device = NULL;
static gchar *psk = NULL;

/* DFile (file transfer) listener: raw TCP, separate from the dsoftbus
 * session connection. One DFileConn engine per accepted connection. */
static GSocketService *ft_service = NULL;

/*
 * GSocketService lifetime API differs between this system's GLib build
 * (g_socket_service_start/stop/is_active, g_socket_service_new() with no
 * argument) and upstream GLib (no such functions; g_socket_service_new()
 * takes a worker count and start/stop live on GSocketListener).  Meson
 * probes the API surface and defines HAS_GLIB_SVC_LIFETIME when the
 * g_socket_service_* variants exist.  Everything else used here
 * (add_inet_port, the "incoming" signal with the
 * gboolean (GSocketService*, GSocketConnection*, GObject*) vfunc) is
 * identical in both.
 */
static GSocketService *ft_service_create(void) {
#if defined(HAS_GLIB_SVC_LIFETIME)
  return g_socket_service_new();
#else
  return g_socket_service_new(0);
#endif
}

static gboolean ft_service_start_listen(GSocketService *svc, guint16 port,
                                        GError **error) {
#if defined(HAS_GLIB_SVC_LIFETIME)
  g_socket_service_start(svc);
  if (!g_socket_service_is_active(svc)) {
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                "FT listener failed to start on port %u", port);
    return FALSE;
  }
  return TRUE;
#else
  return g_socket_listener_start(G_SOCKET_LISTENER(svc), error);
#endif
}

static void ft_service_teardown(GSocketService *svc) {
#if defined(HAS_GLIB_SVC_LIFETIME)
  g_socket_service_stop(svc);
#else
  g_socket_listener_stop(G_SOCKET_LISTENER(svc));
#endif
  g_object_unref(svc);
}
static gchar *ft_dir = NULL;
static gchar *ft_send_spec = NULL;
static guint ft_port = 0;

/* Stream phase (fillp + VTP, spec §8): after the DFile phase the daemon
 * starts a fillp UDP engine on stream_port (client role: it initiates
 * the handshake against the peer's fillp server on stream_peer_port)
 * and runs one bidirectional StreamFile — sends stream_send_spec
 * (file B) and receives the peer's file (file A) into stream_dir.
 * The stream_* flags live on the fillp engine thread; every engine
 * action is marshalled to the main loop with g_main_context_invoke().
 */
static FillpEngine *stream_engine = NULL;
static FillpPeer *stream_peer = NULL;
static StreamFile *stream_sf = NULL;
static gchar *ft_peer_ip = NULL; /* peer address learned from DFile */
static guint stream_port = 54323;
static guint stream_peer_port = 54324;
static gchar *stream_dir = NULL;
static gchar *stream_send_spec = NULL;
#define STREAM_CONNECT_MAX 3
static volatile gint stream_tx_done = 0;
static volatile gint stream_rx_done = 0;
static volatile gint stream_failed = 0;
static volatile gint stream_established = 0;
static volatile gint stream_attempts = 0;

/*
 * M3 (spec §8.7): DMSDP control session on the dsoftbus session socket
 * plus the mirror plane.
 *
 *   - At auth completion the daemon (client) sends SETUP (CSeq 0,
 *     client_port = its fillp client port). The mock phone replies
 *     SetupReply (combined Transport, server_port) and the daemon sends
 *     PLAY (CSeq 1); on the CommonReply the client FSM reaches READY.
 *   - At READY the daemon sends the deterministic 12-event RemoteCtrl
 *     input sequence (PC -> phone only) over the session; the mock
 *     verifies it byte-exact.
 *   - When the received stream file is the H.264 clip (wire name
 *     hs-<sha>.h264) the main loop runs the mirror player on it.
 *
 * dmsdp_cl lives on the session pump thread (created at auth
 * completion, fed by on_session_data); the flags are atomics.
 */
static DmsdpClient *dmsdp_cl = NULL;
static volatile gint dmsdp_ready = 0;
static volatile gint dmsdp_failed = 0;
static guint dmsdp_client_port = 54323; /* = stream_port (fillp client) */
static gchar *stream_rx_name = NULL;    /* fillp engine thread */

/* GSourceFunc, main loop; defined in the stream section below. */
static int stream_start_invoke(gpointer data);

static void signal_handler(int signum) {
  g_print("Received signal %d, shutting down...\n", signum);
  if (main_loop) g_main_loop_quit(main_loop);
}

static void on_state_changed(HwPhoneLinkTransport *transport,
                               HwPhoneLinkState old_state,
                               HwPhoneLinkState new_state,
                               gpointer user_data) {
  const gchar *old_str = "unknown";
  const gchar *new_str = "unknown";

  switch (old_state) {
    case HWPHONELINK_STATE_STOPPED: old_str = "STOPPED"; break;
    case HWPHONELINK_STATE_STARTING: old_str = "STARTING"; break;
    case HWPHONELINK_STATE_RUNNING: old_str = "RUNNING"; break;
    case HWPHONELINK_STATE_STOPPING: old_str = "STOPPING"; break;
    case HWPHONELINK_STATE_ERROR: old_str = "ERROR"; break;
  }
  switch (new_state) {
    case HWPHONELINK_STATE_STOPPED: new_str = "STOPPED"; break;
    case HWPHONELINK_STATE_STARTING: new_str = "STARTING"; break;
    case HWPHONELINK_STATE_RUNNING: new_str = "RUNNING"; break;
    case HWPHONELINK_STATE_STOPPING: new_str = "STOPPING"; break;
    case HWPHONELINK_STATE_ERROR: new_str = "ERROR"; break;
  }

  g_print("Transport state: %s -> %s\n", old_str, new_str);

  if (new_state == HWPHONELINK_STATE_ERROR) {
    g_print("Transport error, attempting fallback...\n");
    // TODO: Implement fallback logic
  }
}

static void on_client_connected(HwPhoneLinkTransport *transport,
                                  const gchar *mac,
                                  const gchar *ip,
                                  gpointer user_data) {
  g_print("Client connected: %s (%s)\n", mac, ip);
}

static void on_client_disconnected(HwPhoneLinkTransport *transport,
                                    const gchar *mac,
                                    gpointer user_data) {
  g_print("Client disconnected: %s\n", mac);
}

/* ============================ dsoftbus session (M2) ============================ */

static void print_hex(const gchar *label, const guint8 *data, gsize len) {
  gchar *hex = softbus_to_hex(data, len);
  g_print("%s: %s\n", label, hex);
  g_free(hex);
}

/* ============================ DMSDP control (M3, spec §8.7) ============================
 *
 * All functions below run on the session pump thread (on_session_data).
 * The mock phone is the DMSDP server: it answers the SETUP with a
 * SetupReply (combined Transport, server_port = its fillp server port)
 * and the PLAY with a CommonReply; the pinned wire strings are
 * byte-verified on both sides (spec §8.7).
 */

#define DMSDP_STAND_SERVICE "hwphonelink-mirror"
#define DMSDP_INPUT_EVENTS 12

/* Deterministic PC -> phone input sequence (spec §6.4/§8.7): covers all
 * live RemoteCtrl types; the byte-exact totals are 28/28/28/26/26/26/20/
 * 22/24/22/24/24 and the mock phone verifies every packet byte by byte.
 * Timestamps are ts = 1000 + 16*i. */
static void send_input_sequence(SoftbusSession *session) {
  static const RemoteInputEvent events[DMSDP_INPUT_EVENTS] = {
      [0] = {.type = REMOTE_INPUT_TOUCH, .subtype = 0, .touch_cnt = 1,
             .touch_ids = {1}, .touch_x = {1234.0}, .touch_y = {5678.0}},
      [1] = {.type = REMOTE_INPUT_TOUCH, .subtype = 1, .touch_cnt = 1,
             .touch_ids = {1}, .touch_x = {1300.0}, .touch_y = {5700.0}},
      [2] = {.type = REMOTE_INPUT_TOUCH, .subtype = 2, .touch_cnt = 1,
             .touch_ids = {1}, .touch_x = {1300.0}, .touch_y = {5700.0}},
      [3] = {.type = REMOTE_INPUT_KEY, .subtype = 0, .key_f16a = 0x0001},
      [4] = {.type = REMOTE_INPUT_KEY, .subtype = 1, .key_f16a = 0x0001},
      [5] = {.type = REMOTE_INPUT_MOUSE, .subtype = 1, .mouse_button = 0,
             .mouse_x = 100.5, .mouse_y = 200.25, .mouse_z = 0.0,
             .mouse_w = 6250.0},
      [6] = {.type = REMOTE_INPUT_SCROLL, .subtype = 0, .scroll_axis = 0,
             .scroll_delta = 3},
      [7] = {.type = REMOTE_INPUT_VKEY, .subtype = 0, .vkey_x = 0.0,
             .vkey_y = 0.0},
      [8] = {.type = REMOTE_INPUT_WHEEL, .subtype = 0, .wheel_dir = 1},
      [9] = {.type = REMOTE_INPUT_INPUT7, .subtype = 0, .content = "hi",
             .content_len = 2},
      [10] = {.type = REMOTE_INPUT_MESSAGE, .subtype = 0, .msg_len = 5,
              .msg_payload = (const guint8 *)"hi!"},
      [11] = {.type = REMOTE_INPUT_ZOOM, .subtype = 0, .zoom_x = 10.0,
              .zoom_y = 20.0, .zoom_pressure = 1.0},
  };

  for (guint i = 0; i < DMSDP_INPUT_EVENTS; i++) {
    guint8 pkt[REMOTE_INPUT_MAX_TOTAL];
    gsize n = 0;
    GError *err = NULL;
    if (remote_input_build(&events[i], 1000 + 16 * i, pkt, sizeof(pkt),
                           &n) != 0) {
      g_print("MIRROR INPUT: event %u build failed\n", (unsigned)i);
      g_atomic_int_set(&dmsdp_failed, 1);
      return;
    }
    if (!softbus_session_send(session, pkt, n, &err)) {
      g_print("MIRROR INPUT: event %u send failed: %s\n", (unsigned)i,
              err != NULL ? err->message : "?");
      g_clear_error(&err);
      g_atomic_int_set(&dmsdp_failed, 1);
      return;
    }
  }
  g_print("MIRROR INPUT: sent %d RemoteCtrl events (deterministic "
          "sequence, spec 6.4)\n",
          DMSDP_INPUT_EVENTS);
}

/* Start the DMSDP control session: send the SETUP (CSeq 0). */
static void dmsdp_send_setup(SoftbusSession *session) {
  DmsdpMsg msg;
  guint8 wire[3 + DMSDP_TEXT_MAX];
  gsize n = 0;
  GError *err = NULL;

  dmsdp_msg_setup(&msg, 0, DMSDP_STAND_SERVICE, 0, 1, 0, dmsdp_client_port,
                  dmsdp_client_port);
  if (dmsdp_client_send(dmsdp_cl, &msg, wire, sizeof(wire), &n) != 0) {
    g_print("DMSDP: SETUP build failed\n");
    g_atomic_int_set(&dmsdp_failed, 1);
    return;
  }
  if (!softbus_session_send(session, wire, n, &err)) {
    g_print("DMSDP: SETUP send failed: %s\n",
            err != NULL ? err->message : "?");
    g_clear_error(&err);
    g_atomic_int_set(&dmsdp_failed, 1);
    return;
  }
  g_print("DMSDP: SETUP sent (CSeq 0, client_port=%u-%u)\n",
          (unsigned)dmsdp_client_port, (unsigned)dmsdp_client_port);
}

/* Feed a parsed reply to the client FSM and act on the transition:
 * SEND_PLAY -> send the PLAY (CSeq 1); READY -> input sequence. */
static void dmsdp_handle_reply(SoftbusSession *session,
                               const DmsdpParsed *p) {
  if (dmsdp_client_recv(dmsdp_cl, p) != 0) {
    g_print("DMSDP: reply rejected by the client FSM\n");
    g_atomic_int_set(&dmsdp_failed, 1);
    return;
  }
  switch (dmsdp_client_state(dmsdp_cl)) {
  case DMSDP_CL_SEND_PLAY: {
    DmsdpMsg msg;
    guint8 wire[3 + DMSDP_TEXT_MAX];
    gsize n = 0;
    GError *err = NULL;
    dmsdp_msg_play(&msg, 1, DMSDP_STAND_SERVICE, 0, 1);
    if (dmsdp_client_send(dmsdp_cl, &msg, wire, sizeof(wire), &n) != 0) {
      g_print("DMSDP: PLAY build failed\n");
      g_atomic_int_set(&dmsdp_failed, 1);
      return;
    }
    if (!softbus_session_send(session, wire, n, &err)) {
      g_print("DMSDP: PLAY send failed: %s\n",
              err != NULL ? err->message : "?");
      g_clear_error(&err);
      g_atomic_int_set(&dmsdp_failed, 1);
      return;
    }
    g_print("DMSDP: SetupReply OK — PLAY sent (CSeq 1)\n");
    break;
  }
  case DMSDP_CL_READY:
    g_atomic_int_set(&dmsdp_ready, 1);
    g_print("DMSDP: CommonReply OK — control session READY\n");
    send_input_sequence(session);
    break;
  default:
    break; /* WAIT_*: the reply was consumed, nothing to send yet */
  }
}

/*
 * Session data callback (runs on the session pump thread).
 * Before auth completes: feeds frames to the auth FSM and sends replies.
 * After auth completes (M3): DMSDP NoCrypto frames ([0x00][u16 BE N]
 * [text]) are fed to the control client FSM; anything else (the mock's
 * P40-PING) is echoed back (the M2 session net).
 */
static void on_session_data(SoftbusSession *session,
                            const guint8 *data, gsize len,
                            gpointer user_data) {
  SoftbusAuth *auth = (SoftbusAuth *)user_data;
  if (auth == NULL) return;

  if (softbus_auth_get_state(auth) == SOFTBUS_AUTH_STATE_DONE) {
    /* Post-auth (M3): a DMSDP NoCrypto frame is control traffic — feed
     * it to the client FSM instead of echoing it. A RemoteCtrl packet
     * never arrives here (input is PC -> phone only), so any other
     * payload is the mock's P40-PING and keeps the M2 echo path. */
    if (dmsdp_cl != NULL &&
        dmsdp_client_state(dmsdp_cl) != DMSDP_CL_ERROR && len >= 3 &&
        data[0] == DMSDP_FRAME_TYPE_NOCRYPTO) {
      guint16 n = (guint16)(((guint)data[1] << 8) | data[2]);
      if (n <= DMSDP_FRAME_MAX_PAYLOAD && (gsize)(3 + n) == len) {
        DmsdpParsed parsed;
        dmsdp_parsed_init(&parsed);
        if (dmsdp_parse((const gchar *)(data + 3), n, &parsed) == 0) {
          dmsdp_handle_reply(session, &parsed);
          dmsdp_parsed_free(&parsed);
          return;
        }
        dmsdp_parsed_free(&parsed);
        g_print("DMSDP: received frame did not parse (len %u)\n", (unsigned)n);
        g_atomic_int_set(&dmsdp_failed, 1);
        return;
      }
    }
    GError *err = NULL;
    if (!softbus_session_send(session, data, len, &err)) {
      g_print("Session echo failed: %s\n", err != NULL ? err->message : "?");
      g_clear_error(&err);
    }
    return;
  }

  gchar *reply = NULL;
  GError *err = NULL;
  SoftbusAuthResult result = softbus_auth_feed(auth, (const gchar *)data,
                                               len, &reply, &err);
  if (err) {
    g_print("Auth: %s\n", err->message);
    g_clear_error(&err);
  }
  if (reply) {
    if (!softbus_session_send_json(session, reply, &err)) {
      g_print("Auth send failed: %s\n", err ? err->message : "?");
      g_clear_error(&err);
    }
    g_free(reply);
  }

  switch (result) {
    case SOFTBUS_AUTH_RESULT_COMPLETE: {
      const gchar *peer_id = softbus_device_get_id(softbus_auth_get_peer(auth));
      g_print("AUTH COMPLETE (PSK) with %s\n", peer_id ? peer_id : "peer");
      print_hex("  control-key", softbus_auth_get_control_key(auth),
                softbus_auth_get_key_len(auth));
      print_hex("  data-key", softbus_auth_get_data_key(auth),
                softbus_auth_get_key_len(auth));
      /*
       * M3: start the DMSDP control session on the session socket
       * (the socket stays open through the FT and stream phases — the
       * fillp plane rides a separate UDP connection). The SETUP's
       * client_port is the daemon's fillp client port.
       */
      if (stream_port > 0) {
        dmsdp_cl = dmsdp_client_new();
        dmsdp_client_port = stream_port;
        dmsdp_send_setup(session);
      }
      break;
    }
    case SOFTBUS_AUTH_RESULT_FAILED:
      g_print("AUTH FAILED\n");
      break;
    default:
      break;
  }
}

/*
 * New session from the transport (accept thread). We are the ACTIVE side
 * of the auth FSM (the PC initiates dsoftbus negotiation).
 */
static void on_session_opened(HwPhoneLinkTransport *t,
                              gpointer session_ptr,
                              const gchar *peer_ip,
                              gpointer user_data) {
  SoftbusSession *session = SOFTBUS_SESSION(session_ptr);

  SoftbusAuth *auth = softbus_auth_new(local_device, NULL,
                                       (const guint8 *)psk, strlen(psk));
  if (auth == NULL) {
    g_print("Failed to create auth context\n");
    return;
  }
  /* Auth context lives with the session (freed on dispose). */
  g_object_set_data_full(G_OBJECT(session), "auth", auth,
                         (GDestroyNotify)softbus_auth_free);
  softbus_session_set_data_cb(session, on_session_data, auth, NULL);

  g_print("Session from %s: starting dsoftbus auth (PSK, active)\n",
          peer_ip ? peer_ip : "?");

  gchar *first = NULL;
  GError *err = NULL;
  if (softbus_auth_begin_active(auth, &first, &err) == SOFTBUS_AUTH_RESULT_SEND) {
    if (!softbus_session_send_json(session, first, &err)) {
      g_print("Auth start send failed: %s\n", err ? err->message : "?");
      g_clear_error(&err);
    }
    g_free(first);
  } else {
    g_print("Auth start failed: %s\n", err ? err->message : "no initial message");
    g_clear_error(&err);
  }
}

static void on_session_closed(HwPhoneLinkTransport *t,
                              gpointer session_ptr,
                              gpointer user_data) {
  (void)session_ptr;
  g_print("Session closed\n");
}

/* ============================ DFile (file transfer) ============================
 *
 * Raw-TCP DFile engine (proto/dfile_conn.h). When the peer pushes a file
 * list we immediately start a reverse send (bidirectional on the same
 * connection), so the replay stand verifies both directions.
 *
 * All callbacks below run on the DFileConn engine thread.
 */

typedef struct {
  gboolean sent_back;
} FtSession;

static void on_ft_negotiated(DFileConn *dc, gpointer user_data) {
  (void)user_data;
  g_print("FT: DFile session negotiated (block size %u)\n",
          dfile_conn_block_size(dc));
}

static void on_ft_file_list(DFileConn *dc, const DFileHeaderEntry *entries,
                            gsize n, gpointer user_data) {
  FtSession *s = (FtSession *)user_data;
  for (gsize i = 0; i < n; i++)
    g_print("FT: incoming file %u: %s (%" G_GUINT64_FORMAT " bytes)\n",
            (unsigned)entries[i].file_id, entries[i].name,
            entries[i].file_size);

  if (ft_send_spec == NULL || *ft_send_spec == '\0' || s->sent_back) return;
  s->sent_back = TRUE;

  DFileSendItem item = {NULL, NULL, 0};
  if (g_str_has_prefix(ft_send_spec, "gen:")) {
    /* gen:<seed>:<size> — deterministic self-checking test file. */
    gchar **parts = g_strsplit(ft_send_spec, ":", 3);
    gboolean ok = parts[1] != NULL && parts[2] != NULL && parts[1][0] &&
                  parts[2][0];
    guint64 seed = ok ? g_ascii_strtoull(parts[1], NULL, 10) : 0;
    guint64 size = ok ? g_ascii_strtoull(parts[2], NULL, 10) : 0;
    gchar *dir = g_build_filename(g_get_tmp_dir(), "hwphonelink-ft-send",
                                  NULL);
    if (ok && g_mkdir_with_parents(dir, 0755) >= 0 &&
        ft_testfile_generate(dir, seed, size, &item.path, &item.name)) {
      g_print("FT: generating send file %s (%" G_GUINT64_FORMAT
              " bytes, seed %" G_GUINT64_FORMAT ")\n",
              item.name, size, seed);
    } else {
      ok = FALSE;
    }
    g_free(dir);
    g_strfreev(parts);
    if (!ok) {
      g_print("FT: failed to generate send file (spec %s)\n", ft_send_spec);
      s->sent_back = FALSE;
      return;
    }
  } else {
    item.path = g_strdup(ft_send_spec);
    item.name = g_strdup(g_path_get_basename(ft_send_spec));
  }

  GError *err = NULL;
  if (!dfile_conn_send_files(dc, &item, 1, &err)) {
    g_print("FT: start reverse send failed: %s\n", err ? err->message : "?");
    g_clear_error(&err);
    s->sent_back = FALSE;
  }
  g_free(item.path);
  g_free(item.name);
}

static void on_ft_result(DFileConn *dc, gboolean is_sender, gboolean ok,
                         const gchar *msg, gpointer user_data) {
  (void)dc;
  (void)user_data;
  g_print("FT: %s transfer %s: %s\n", is_sender ? "send" : "recv",
          ok ? "OK" : "FAILED", msg);
  /* Stand sync point: once our reverse push is fully acked the peer's
   * DFile phase is over and its fillp server is (about to be) up —
   * start the stream phase from the main loop. */
  if (is_sender && ok && stream_port > 0 && !stream_failed &&
      !stream_established) {
    g_main_context_invoke(NULL, stream_start_invoke, NULL);
  }
}

static void on_ft_closed(DFileConn *dc, gpointer user_data) {
  g_print("FT: DFile session closed\n");
  g_free(user_data);
  /* Drop the session's external ref; the engine's internal ref keeps the
   * structure alive until its thread exits. */
  dfile_conn_unref(dc);
}

static gboolean on_ft_connection(GSocketService *service,
                                 GSocketConnection *conn,
                                 gpointer source_object) {
  (void)service;
  (void)source_object;

  gchar *ip = NULL;
  GError *aerr = NULL;
  GSocketAddress *raddr = g_socket_connection_get_remote_address(conn, &aerr);
  if (raddr && G_IS_INET_SOCKET_ADDRESS(raddr)) {
    GInetAddress *ia = g_inet_socket_address_get_address(
        G_INET_SOCKET_ADDRESS(raddr));
    if (ia) ip = g_inet_address_to_string(ia);
    g_object_unref(raddr);
  } else if (raddr) {
    g_object_unref(raddr);
  }
  g_clear_error(&aerr);
  g_print("FT: DFile session from %s\n", ip ? ip : "?");

  /* Remember the peer address: the stream phase (fillp connect) needs
   * it, and the DFile session is what tells us who the peer is. */
  g_free(ft_peer_ip);
  ft_peer_ip = ip;
  ip = NULL;

  DFileConn *dc = dfile_conn_new_server(conn);
  if (dc == NULL) {
    g_print("FT: engine start failed\n");
    g_object_unref(conn);
    return TRUE;
  }
  FtSession *s = g_new0(FtSession, 1);
  dfile_conn_set_recv_dir(dc, ft_dir);
  dfile_conn_set_callbacks(dc, on_ft_negotiated, on_ft_file_list,
                           on_ft_result, on_ft_closed, s);
  g_free(ip);
  return TRUE;
}

/* ============================ Stream (fillp + VTP) ============================
 *
 * Replay-stand screen-streaming phase (spec §8): after the DFile phase
 * completes, the daemon starts a fillp UDP engine on stream_port and
 * plays the CLIENT role against the peer's fillp server
 * (stream_peer_port). One bidirectional StreamFile runs on the
 * connection: the daemon sends stream_send_spec (file B) and receives
 * the peer's file (file A) into stream_dir.
 *
 * Engine callbacks fire on the fillp engine thread; all engine actions
 * are marshalled to the main loop with g_main_context_invoke().
 */

static void stream_connect(void);
static gboolean stream_retry_timeout(gpointer data);

/* Main thread. One client connect per call; a failed synchronous
 * connect schedules a 1 s retry (the peer's server may still be
 * binding), a lost handshake arrives later as on_closed and is
 * retried the same way. */
static void stream_connect(void) {
  if (stream_engine == NULL) return;
  if (ft_peer_ip == NULL) {
    g_print("STREAM: no peer address (the DFile phase did not run)\n");
    g_atomic_int_set(&stream_failed, 1);
    return;
  }
  g_atomic_int_inc(&stream_attempts);
  if (stream_attempts > STREAM_CONNECT_MAX) {
    g_print("STREAM: giving up after %d connect attempts\n",
            STREAM_CONNECT_MAX);
    g_atomic_int_set(&stream_failed, 1);
    return;
  }
  GError *err = NULL;
  FillpPeer *p = fillp_engine_connect(stream_engine, ft_peer_ip,
                                      stream_peer_port, &err);
  if (p == NULL) {
    g_print("STREAM: connect %s:%u attempt %d failed: %s\n", ft_peer_ip,
            (unsigned)stream_peer_port, (int)stream_attempts,
            err ? err->message : "unknown");
    g_clear_error(&err);
    g_timeout_add_seconds(1, stream_retry_timeout, NULL);
  } else {
    g_print("STREAM: fillp connect to %s:%u (attempt %d)\n", ft_peer_ip,
            (unsigned)stream_peer_port, (int)stream_attempts);
  }
}

static gboolean stream_retry_timeout(gpointer data) {
  (void)data;
  stream_connect();
  return G_SOURCE_REMOVE;
}

/*
 * M3: received the metadata frame of the peer's file (fillp engine
 * thread). Remember the wire name: on completion a hs-<sha>.h264 name
 * means the file is the mirror clip and gets decoded.
 */
static void on_stream_rx_meta(StreamFile *sf, const gchar *name,
                              guint64 size, gpointer user_data) {
  (void)sf;
  (void)user_data;
  g_free(stream_rx_name);
  stream_rx_name = g_strdup(name);
  g_print("STREAM: receiving %s (%" G_GUINT64_FORMAT " bytes)\n", name, size);
}

typedef struct {
  gchar *path;
  gchar *name;
} MirrorJob;

/* Main loop: run the mirror player on the received clip. */
static int mirror_decode_invoke(gpointer data) {
  MirrorJob *job = (MirrorJob *)data;
  guint64 frames = 0;
  gint rc = mirror_player_play_file(job->path, &frames);
  if (rc == 0)
    g_print("MIRROR: decoded %" G_GUINT64_FORMAT " frames from %s — "
            "mirror E2E OK\n",
            frames, job->name);
  else
    g_print("MIRROR: decode FAILED for %s (%" G_GUINT64_FORMAT
            " frames before failure)\n",
            job->name, frames);
  g_free(job->path);
  g_free(job->name);
  g_free(job);
  return 0;
}

/* One direction finished (fillp engine thread). */
static void on_stream_done(StreamFile *sf, gboolean is_send, gboolean ok,
                           const gchar *message, gpointer user_data) {
  (void)sf;
  (void)user_data;
  g_print("STREAM: %s %s: %s\n", is_send ? "send" : "recv",
          ok ? "OK" : "FAILED", message);
  g_free((gchar *)message);
  if (!ok) {
    g_atomic_int_set(&stream_failed, 1);
    return;
  }
  if (is_send)
    g_atomic_int_set(&stream_tx_done, 1);
  else
    g_atomic_int_set(&stream_rx_done, 1);
  if (stream_tx_done && stream_rx_done) {
    g_print("STREAM: both directions verified — closing fillp peer\n");
    if (stream_peer != NULL) fillp_peer_close(stream_peer);
  }
  /*
   * M3: the peer's file follows the hs-<sha>.h264 wire convention — it
   * is the mirror clip (already sha/structure-verified by stream_file).
   * Decode it on the main loop (GStreamer needs the main context).
   */
  if (!is_send && stream_rx_name != NULL &&
      h264_testfile_name_sha(stream_rx_name) != NULL) {
    gchar *name = g_strdup(stream_rx_name);
    gchar *path = g_build_filename(stream_dir, name, NULL);
    g_free(stream_rx_name);
    stream_rx_name = NULL;
    MirrorJob *job = g_new0(MirrorJob, 1);
    job->path = path;
    job->name = name;
    g_main_context_invoke_full(NULL, G_PRIORITY_DEFAULT,
                               (GSourceFunc)mirror_decode_invoke, job, NULL);
  }
}

/* Handshake complete (fillp engine thread): attach the StreamFile. */
static void on_stream_established(FillpEngine *engine, FillpPeer *peer,
                                  gpointer user_data) {
  (void)engine;
  (void)user_data;
  g_atomic_int_set(&stream_established, 1);
  stream_peer = peer;

  guint8 key[VTP_KEY_LEN];
  vtp_derive_key((const guint8 *)psk, strlen(psk), key);
  stream_sf = stream_file_new(peer, key);
  stream_file_set_recv_dir(stream_sf, stream_dir);
  stream_file_set_callbacks(stream_sf, on_stream_rx_meta, on_stream_done,
                            NULL);

  /* Resolve the send spec ("none"/empty = receive-only). */
  gchar *path = NULL;
  gchar *wire_name = NULL;
  gboolean sending = stream_send_spec != NULL && *stream_send_spec != '\0' &&
                     g_strcmp0(stream_send_spec, "none") != 0;
  if (sending) {
    if (g_str_has_prefix(stream_send_spec, "gen:")) {
      gchar **parts = g_strsplit(stream_send_spec, ":", 3);
      gboolean ok = parts[1] != NULL && parts[2] != NULL && parts[1][0] &&
                    parts[2][0];
      guint64 seed = ok ? g_ascii_strtoull(parts[1], NULL, 10) : 0;
      guint64 size = ok ? g_ascii_strtoull(parts[2], NULL, 10) : 0;
      gchar *dir =
          g_build_filename(g_get_tmp_dir(), "hwphonelink-streamgen", NULL);
      if (ok && g_mkdir_with_parents(dir, 0755) >= 0 &&
          ft_testfile_generate(dir, seed, size, &path, &wire_name)) {
        g_print("STREAM: generating send file %s (%" G_GUINT64_FORMAT
                " bytes, seed %" G_GUINT64_FORMAT ")\n",
                wire_name, size, seed);
      }
      g_free(dir);
      g_strfreev(parts);
    } else {
      path = g_strdup(stream_send_spec);
      wire_name = g_strdup(g_path_get_basename(stream_send_spec));
    }
  }
  if (path == NULL) {
    g_print("STREAM: receive-only session (no send spec)\n");
    stream_file_attach(stream_sf);
    return;
  }
  GError *err = NULL;
  if (!stream_file_start_send(stream_sf, path, wire_name, &err)) {
    g_print("STREAM: start send failed: %s\n", err ? err->message : "?");
    g_clear_error(&err);
    g_atomic_int_set(&stream_failed, 1);
    stream_file_attach(stream_sf); /* keep the receive direction live */
  }
  g_free(path);
  g_free(wire_name);
}

/* Peer teardown (fillp engine thread); the peer is dead after this. */
static void on_stream_closed(FillpEngine *engine, FillpPeer *peer,
                             const gchar *reason, gpointer user_data) {
  (void)engine;
  (void)user_data;
  g_print("STREAM: fillp peer closed: %s\n", reason);
  if (stream_sf != NULL) {
    stream_file_close(stream_sf);
    stream_sf = NULL;
  }
  if (stream_peer == peer) stream_peer = NULL;

  if (stream_failed || (stream_tx_done && stream_rx_done)) return;
  if (stream_established) {
    g_print("STREAM: session closed before both directions completed\n");
    g_atomic_int_set(&stream_failed, 1);
    return;
  }
  /* Handshake never completed (the peer's fillp server was probably not
   * bound yet): retry the connect from the main thread. */
  g_main_context_invoke(NULL, stream_start_invoke, NULL);
}

/* Main thread: create the engine (once) and start the client connect. */
static void stream_start(void) {
  if (stream_failed) return;
  if (stream_engine == NULL) {
    GError *err = NULL;
    stream_engine = fillp_engine_new(stream_port, &err);
    if (stream_engine == NULL) {
      g_printerr("STREAM: cannot start fillp engine on UDP port %u: %s\n",
                 (unsigned)stream_port, err ? err->message : "unknown");
      g_clear_error(&err);
      g_atomic_int_set(&stream_failed, 1);
      return;
    }
    fillp_engine_set_callbacks(stream_engine, on_stream_established, NULL,
                               NULL, on_stream_closed, NULL);
    g_print("STREAM: fillp engine on UDP port %u\n", (unsigned)stream_port);
  }
  stream_connect();
}

static int stream_start_invoke(gpointer data) {
  (void)data;
  stream_start();
  return 0;
}

static SoftbusDevice* build_local_device(const gchar *device_id) {
  SoftbusDevice *dev = softbus_device_new();
  dev->device_id = g_strdup(device_id);
  dev->device_name = g_strdup("Mint PC (hwphonelink)");
  dev->device_type = SOFTBUS_DEVTYPE_PC;
  dev->capabilities = SOFTBUS_CAP_CASTPLUS | SOFTBUS_CAP_DVKIT |
                      SOFTBUS_CAP_OSD | SOFTBUS_CAP_MULTISCREEN;
  return dev;
}

int main(int argc, char *argv[]) {
  g_autoptr(GError) error = NULL;
  g_autoptr(GOptionContext) context = NULL;

  gchar *phy_name = "phy0";
  gchar *sta_interface = "wlp1s0";
  gboolean use_p2p_fallback = FALSE;
  gboolean use_infra = FALSE;
  gchar *device_id = NULL;
  gint ft_port_opt = 54322;
  gint stream_port_opt = 54323;
  gint stream_peer_port_opt = 54324;

  GOptionEntry entries[] = {
    {"phy", 'p', 0, G_OPTION_ARG_STRING, &phy_name, "Physical interface name (e.g., phy0)", "PHY"},
    {"interface", 'i', 0, G_OPTION_ARG_STRING, &sta_interface, "Station interface name (e.g., wlp1s0)", "IFACE"},
    {"p2p-fallback", 'f', 0, G_OPTION_ARG_NONE, &use_p2p_fallback, "Use P2P-GO fallback instead of SoftAP", NULL},
    {"infra", 'n', 0, G_OPTION_ARG_NONE, &use_infra, "Use Infrastructure mode (LAN/Wi-Fi/Ethernet) instead of SoftAP", NULL},
    {"device-id", 0, 0, G_OPTION_ARG_STRING, &device_id, "Local device id for dsoftbus auth (default: hwphonelink-pc-001)", "ID"},
    {"psk", 0, 0, G_OPTION_ARG_STRING, &psk, "Pre-provisioned PSK for auth (default: $HWPONELINK_PSK or built-in test PSK)", "SECRET"},
    {"ft-port", 0, 0, G_OPTION_ARG_INT, &ft_port_opt, "DFile (file transfer) TCP port, 0 disables the listener (default 54322)", "PORT"},
    {"ft-dir", 0, 0, G_OPTION_ARG_STRING, &ft_dir, "Directory for received files (default: ./ft-received)", "DIR"},
    {"ft-send", 0, 0, G_OPTION_ARG_STRING, &ft_send_spec, "Auto-send after receiving: PATH, or gen:<seed>:<size> for a deterministic test file (default: off)", "SPEC"},
    {"stream-port", 0, 0, G_OPTION_ARG_INT, &stream_port_opt, "fillp (stream) UDP client port, 0 disables streaming (default 54323)", "PORT"},
    {"stream-peer-port", 0, 0, G_OPTION_ARG_INT, &stream_peer_port_opt, "Peer's fillp (stream) UDP server port (default 54324)", "PORT"},
    {"stream-dir", 0, 0, G_OPTION_ARG_STRING, &stream_dir, "Directory for stream-received files (default: ./stream-received)", "DIR"},
    {"stream-send", 0, 0, G_OPTION_ARG_STRING, &stream_send_spec, "File to send over the stream: PATH, or gen:<seed>:<size> for a deterministic test file (default: gen:2:1048576 when streaming is enabled; \"none\" = receive-only)", "SPEC"},
    {NULL}
  };

  context = g_option_context_new("- Huawei Multi-Screen Transport Daemon");
  g_option_context_add_main_entries(context, entries, NULL);

  if (!g_option_context_parse(context, &argc, &argv, &error)) {
    g_printerr("Option parsing failed: %s\n", error->message);
    return 1;
  }

  if (psk == NULL) {
    psk = g_strdup(g_getenv("HWPONELINK_PSK"));
    if (psk == NULL || psk[0] == '\0') {
      g_free(psk);
      psk = g_strdup("hwphonelink-test-psk");
      g_print("No PSK given — using built-in test PSK (replay stand only)\n");
    }
  }
  if (ft_port_opt < 0) {
    g_printerr("--ft-port must be >= 0\n");
    return 1;
  }
  ft_port = (guint)ft_port_opt;
  if (stream_port_opt < 0 || stream_peer_port_opt < 0) {
    g_printerr("--stream-port/--stream-peer-port must be >= 0\n");
    return 1;
  }
  stream_port = (guint)stream_port_opt;
  stream_peer_port = (guint)stream_peer_port_opt;
  if (device_id == NULL) {
    device_id = g_strdup("hwphonelink-pc-001");
  }

  // Check root (not required for infrastructure mode — no AP/virtif creation)
  if (geteuid() != 0) {
    if (!use_infra) {
      g_printerr("This program must be run as root (SoftAP/P2P modes need "
                 "interface management). Hint: use --infra for plain LAN mode.\n");
      return 1;
    }
    g_print("Running without root (infra mode)\n");
  }

  // Setup signals
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  local_device = build_local_device(device_id);

  // Create transport
  if (use_infra) {
    g_print("Using Infrastructure transport (LAN)...\n");
    transport = hw_phone_link_infra_backend_new(sta_interface, &error);
  } else if (use_p2p_fallback) {
    g_print("Using P2P-GO fallback transport...\n");
    transport = hw_phone_link_p2p_backend_new(phy_name, sta_interface, &error);
  } else {
    g_print("Using SoftAP transport (primary)...\n");
    transport = hw_phone_link_softap_backend_new(phy_name, sta_interface, &error);
  }

  if (!transport) {
    g_printerr("Failed to create transport: %s\n", error->message);
    softbus_device_unref(local_device);
    return 1;
  }

  // Connect signals
  g_signal_connect(transport, "state-changed", G_CALLBACK(on_state_changed), NULL);
  g_signal_connect(transport, "client-connected", G_CALLBACK(on_client_connected), NULL);
  g_signal_connect(transport, "client-disconnected", G_CALLBACK(on_client_disconnected), NULL);
  g_signal_connect(transport, "session-opened", G_CALLBACK(on_session_opened), NULL);
  g_signal_connect(transport, "session-closed", G_CALLBACK(on_session_closed), NULL);

  // Start transport
  if (!hw_phone_link_transport_start(transport, &error)) {
    g_printerr("Failed to start transport: %s\n", error->message);
    g_object_unref(transport);
    softbus_device_unref(local_device);
    return 1;
  }

  g_print("Transport started successfully\n");
  g_print("AP Interface: %s\n", hw_phone_link_transport_get_ap_interface(transport));
  g_print("AP IP: %s\n", hw_phone_link_transport_get_ap_ip(transport));
  g_print("Channel: %u\n", hw_phone_link_transport_get_ap_channel(transport));
  gchar *dstr = softbus_device_to_string(local_device);
  g_print("Local device: %s\n", dstr);
  g_free(dstr);

  // DFile (file transfer) listener
  if (ft_port > 0) {
    if (ft_dir == NULL) ft_dir = g_strdup("ft-received");
    if (g_mkdir_with_parents(ft_dir, 0755) < 0) {
      g_printerr("Cannot create receive dir %s: %s\n", ft_dir,
                 g_strerror(errno));
      return 1;
    }
    ft_service = ft_service_create();
    GError *lerr = NULL;
    if (!g_socket_listener_add_inet_port(G_SOCKET_LISTENER(ft_service),
                                         (guint16)ft_port, NULL, &lerr)) {
      g_printerr("FT: cannot listen on port %u: %s\n", ft_port,
                 lerr->message);
      g_clear_error(&lerr);
      g_object_unref(ft_service);
      ft_service = NULL;
    } else {
      g_signal_connect(ft_service, "incoming",
                       G_CALLBACK(on_ft_connection), NULL);
      if (!ft_service_start_listen(ft_service, (guint16)ft_port, &lerr)) {
        g_printerr("FT: cannot listen on port %u: %s\n", ft_port,
                   lerr->message);
        g_clear_error(&lerr);
        g_object_unref(ft_service);
        ft_service = NULL;
      } else {
        g_print("FT: DFile listener on port %u (recv dir: %s%s)\n", ft_port,
                ft_dir, ft_send_spec ? " (auto-send after receive)" : "");
      }
    }
  }

  // Stream (fillp + VTP) phase configuration
  if (stream_port > 0) {
    if (stream_dir == NULL) stream_dir = g_strdup("stream-received");
    if (g_mkdir_with_parents(stream_dir, 0755) < 0) {
      g_printerr("Cannot create stream receive dir %s: %s\n", stream_dir,
                 g_strerror(errno));
      return 1;
    }
    if (stream_send_spec == NULL)
      stream_send_spec = g_strdup("gen:2:1048576");
    g_print("STREAM: fillp client will start on UDP port %u after the DFile "
            "phase (send: %s, recv dir: %s)\n",
            (unsigned)stream_port, stream_send_spec, stream_dir);
    if (ft_port == 0)
      g_print("STREAM: warning: the stream phase is triggered after the DFile "
              "phase; with --ft-port 0 it will never start\n");
  }

  // Run main loop
  main_loop = g_main_loop_new(NULL, FALSE);
  g_main_loop_run(main_loop);

  // Cleanup
  g_print("Stopping transport...\n");
  if (dmsdp_cl != NULL) {
    dmsdp_client_free(dmsdp_cl);
    dmsdp_cl = NULL;
  }
  g_free(stream_rx_name);
  if (stream_engine != NULL) {
    fillp_engine_close(stream_engine);
    fillp_engine_unref(stream_engine);
    stream_engine = NULL;
  }
  if (ft_service) {
    ft_service_teardown(ft_service);
    ft_service = NULL;
  }
  hw_phone_link_transport_stop(transport, NULL);
  g_object_unref(transport);
  g_main_loop_unref(main_loop);
  softbus_device_unref(local_device);
  g_free(psk);
  g_free(device_id);
  g_free(ft_dir);
  g_free(ft_send_spec);
  g_free(ft_peer_ip);
  g_free(stream_dir);
  g_free(stream_send_spec);

  g_print("Daemon stopped\n");
  return 0;
}
