/*
 * wifi_transport.h - Unified Wi-Fi transport interface for Huawei Multi-Screen
 *
 * Supports dual backend: SoftAP (hostapd) + P2P-GO (wpa_supplicant)
 * RTL8822CE/rtw88 tested: concurrent STA+AP works, internet preserved.
 */

#pragma once

#include <glib.h>
#include <gio/gio.h>

#define HWPHONELINK_AP_IP "192.168.137.1"
#define HWPHONELINK_AP_NETMASK "255.255.255.0"
#define HWPHONELINK_DHCP_START "192.168.137.2"
#define HWPHONELINK_DHCP_END "192.168.137.254"
#define HWPHONELINK_DEFAULT_CHANNEL 40  /* 5G, preferred per PC Manager logs */
#define HWPHONELINK_FALLBACK_CHANNEL 1  /* 2.4G fallback */

typedef enum {
  HWPHONELINK_TRANSPORT_SOFTAP = 0,  /* hostapd + dnsmasq (primary) */
  HWPHONELINK_TRANSPORT_P2P_GO = 1,  /* wpa_supplicant P2P-GO (fallback) */
} HwPhoneLinkTransportType;

typedef enum {
  HWPHONELINK_STATE_STOPPED = 0,
  HWPHONELINK_STATE_STARTING,
  HWPHONELINK_STATE_RUNNING,
  HWPHONELINK_STATE_STOPPING,
  HWPHONELINK_STATE_ERROR,
} HwPhoneLinkState;

typedef struct _HwPhoneLinkTransport HwPhoneLinkTransport;
typedef struct _HwPhoneLinkTransportClass HwPhoneLinkTransportClass;

struct _HwPhoneLinkTransport {
  GObject parent_instance;
};

struct _HwPhoneLinkTransportClass {
  GObjectClass parent_class;

  /* Virtual methods */
  gboolean (*start)(HwPhoneLinkTransport *self, GError **error);
  gboolean (*stop)(HwPhoneLinkTransport *self, GError **error);
  HwPhoneLinkState (*get_state)(HwPhoneLinkTransport *self);
  const gchar* (*get_ap_interface)(HwPhoneLinkTransport *self);
  const gchar* (*get_ap_ip)(HwPhoneLinkTransport *self);
  guint (*get_ap_channel)(HwPhoneLinkTransport *self);
};

#define HWPHONELINK_TYPE_TRANSPORT (hw_phone_link_transport_get_type())
G_DECLARE_DERIVABLE_TYPE(HwPhoneLinkTransport, hw_phone_link_transport, HWPHONELINK, TRANSPORT, GObject)

/* Factory */
HwPhoneLinkTransport* hw_phone_link_transport_new(HwPhoneLinkTransportType type,
                                                   const gchar *phy_name,
                                                   const gchar *sta_interface,
                                                   GError **error);

/* Common operations */
gboolean hw_phone_link_transport_start(HwPhoneLinkTransport *self, GError **error);
gboolean hw_phone_link_transport_stop(HwPhoneLinkTransport *self, GError **error);
HwPhoneLinkState hw_phone_link_transport_get_state(HwPhoneLinkTransport *self);
const gchar* hw_phone_link_transport_get_ap_interface(HwPhoneLinkTransport *self);
const gchar* hw_phone_link_transport_get_ap_ip(HwPhoneLinkTransport *self);
guint hw_phone_link_transport_get_ap_channel(HwPhoneLinkTransport *self);

/* Signal: state-changed (old_state, new_state) */
#define HWPHONELINK_TRANSPORT_SIGNAL_STATE_CHANGED "state-changed"

/* Signal: client-connected (mac, ip) */
#define HWPHONELINK_TRANSPORT_SIGNAL_CLIENT_CONNECTED "client-connected"

/* Signal: client-disconnected (mac) */
#define HWPHONELINK_TRANSPORT_SIGNAL_CLIENT_DISCONNECTED "client-disconnected"