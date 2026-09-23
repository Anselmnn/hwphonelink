/*
 * main.c - hwphonelinkd main entry point
 *
 * Huawei Multi-Screen Collaboration daemon for Linux.
 * Supports dual Wi-Fi transport: SoftAP (primary) + P2P-GO (fallback).
 */

#include "transport/wifi_transport.h"
#include "transport/softap_backend.h"
#include "transport/p2p_backend.h"
#include <glib.h>
#include <gio/gio.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

static GMainLoop *main_loop = NULL;
static HwPhoneLinkTransport *transport = NULL;

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

int main(int argc, char *argv[]) {
  g_autoptr(GError) error = NULL;
  g_autoptr(GOptionContext) context = NULL;

  gchar *phy_name = "phy0";
  gchar *sta_interface = "wlp1s0";
  gboolean use_p2p_fallback = FALSE;
  gboolean use_infra = FALSE;

  GOptionEntry entries[] = {
    {"phy", 'p', 0, G_OPTION_ARG_STRING, &phy_name, "Physical interface name (e.g., phy0)", "PHY"},
    {"interface", 'i', 0, G_OPTION_ARG_STRING, &sta_interface, "Station interface name (e.g., wlp1s0)", "IFACE"},
    {"p2p-fallback", 'f', 0, G_OPTION_ARG_NONE, &use_p2p_fallback, "Use P2P-GO fallback instead of SoftAP", NULL},
    {"infra", 'n', 0, G_OPTION_ARG_NONE, &use_infra, "Use Infrastructure mode (LAN/Wi-Fi/Ethernet) instead of SoftAP", NULL},
    {NULL}
  };

  context = g_option_context_new("- Huawei Multi-Screen Transport Daemon");
  g_option_context_add_main_entries(context, entries, NULL);

  if (!g_option_context_parse(context, &argc, &argv, &error)) {
    g_printerr("Option parsing failed: %s\n", error->message);
    return 1;
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
    return 1;
  }

  // Connect signals
  g_signal_connect(transport, "state-changed", G_CALLBACK(on_state_changed), NULL);
  g_signal_connect(transport, "client-connected", G_CALLBACK(on_client_connected), NULL);
  g_signal_connect(transport, "client-disconnected", G_CALLBACK(on_client_disconnected), NULL);

  // Start transport
  if (!hw_phone_link_transport_start(transport, &error)) {
    g_printerr("Failed to start transport: %s\n", error->message);
    g_object_unref(transport);
    return 1;
  }

  g_print("Transport started successfully\n");
  g_print("AP Interface: %s\n", hw_phone_link_transport_get_ap_interface(transport));
  g_print("AP IP: %s\n", hw_phone_link_transport_get_ap_ip(transport));
  g_print("Channel: %u\n", hw_phone_link_transport_get_ap_channel(transport));

  // Run main loop
  main_loop = g_main_loop_new(NULL, FALSE);
  g_main_loop_run(main_loop);

  // Cleanup
  g_print("Stopping transport...\n");
  hw_phone_link_transport_stop(transport, NULL);
  g_object_unref(transport);
  g_main_loop_unref(main_loop);

  g_print("Daemon stopped\n");
  return 0;
}