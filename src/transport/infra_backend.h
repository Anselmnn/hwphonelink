/*
 * infra_backend.h - Infrastructure Mode backend (LAN/Wi-Fi/Ethernet)
 *
 * Uses existing network infrastructure (router, switch) instead of creating AP.
 * Discovery: CoAP multicast (224.0.1.187:5683) + mDNS
 * Transport: Direct TCP/UDP over LAN IP
 */

#pragma once

#include "wifi_transport.h"

typedef struct _HwPhoneLinkInfraBackend HwPhoneLinkInfraBackend;

#define HWPHONELINK_TYPE_INFRA_BACKEND (hw_phone_link_infra_backend_get_type())
G_DECLARE_FINAL_TYPE(HwPhoneLinkInfraBackend, hw_phone_link_infra_backend,
                     HWPHONELINK, INFRA_BACKEND, HwPhoneLinkTransport)

/* Factory */
HwPhoneLinkTransport* hw_phone_link_infra_backend_new(const gchar *interface,
                                                       GError **error);

/* Configuration */
typedef struct {
  gchar *interface;           // e.g., "wlp1s0" or "eth0"
  gchar *local_ip;            // Our LAN IP
  guint coap_port;            // CoAP multicast port (5683)
  gchar *coap_multicast_ip;   // "224.0.1.187"
  guint mdns_port;            // mDNS port (5353)
  gchar *service_name;        // "_hw-multiscreen._tcp.local"
  guint session_port;         // TCP session port
  guint auth_port;            // TCP auth port
} HwPhoneLinkInfraConfig;