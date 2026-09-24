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

/*
 * Session data callback (runs on the session pump thread).
 * Before auth completes: feeds frames to the auth FSM and sends replies.
 * After auth completes: echoes payloads back (replay stand).
 */
static void on_session_data(SoftbusSession *session,
                            const guint8 *data, gsize len,
                            gpointer user_data) {
  SoftbusAuth *auth = (SoftbusAuth *)user_data;
  if (auth == NULL) return;

  if (softbus_auth_get_state(auth) == SOFTBUS_AUTH_STATE_DONE) {
    /* Post-auth: echo the payload (validates the session data path). */
    GError *err = NULL;
    if (!softbus_session_send(session, data, len, &err)) {
      g_print("Session echo failed: %s\n", err ? err->message : "?");
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

  GOptionEntry entries[] = {
    {"phy", 'p', 0, G_OPTION_ARG_STRING, &phy_name, "Physical interface name (e.g., phy0)", "PHY"},
    {"interface", 'i', 0, G_OPTION_ARG_STRING, &sta_interface, "Station interface name (e.g., wlp1s0)", "IFACE"},
    {"p2p-fallback", 'f', 0, G_OPTION_ARG_NONE, &use_p2p_fallback, "Use P2P-GO fallback instead of SoftAP", NULL},
    {"infra", 'n', 0, G_OPTION_ARG_NONE, &use_infra, "Use Infrastructure mode (LAN/Wi-Fi/Ethernet) instead of SoftAP", NULL},
    {"device-id", 0, 0, G_OPTION_ARG_STRING, &device_id, "Local device id for dsoftbus auth (default: hwphonelink-pc-001)", "ID"},
    {"psk", 0, 0, G_OPTION_ARG_STRING, &psk, "Pre-provisioned PSK for auth (default: $HWPONELINK_PSK or built-in test PSK)", "SECRET"},
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
  g_print("Local device: %s\n", softbus_device_to_string(local_device));

  // Run main loop
  main_loop = g_main_loop_new(NULL, FALSE);
  g_main_loop_run(main_loop);

  // Cleanup
  g_print("Stopping transport...\n");
  hw_phone_link_transport_stop(transport, NULL);
  g_object_unref(transport);
  g_main_loop_unref(main_loop);
  softbus_device_unref(local_device);
  g_free(psk);
  g_free(device_id);

  g_print("Daemon stopped\n");
  return 0;
}
