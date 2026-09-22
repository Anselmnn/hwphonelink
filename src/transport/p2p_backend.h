/*
 * p2p_backend.h - P2P-GO backend using wpa_supplicant
 *
 * Fallback transport when SoftAP is not available.
 * Uses wpa_supplicant P2P interface for GO mode.
 */

#pragma once

#include "wifi_transport.h"

typedef struct _HwPhoneLinkP2PBackend HwPhoneLinkP2PBackend;
typedef struct _HwPhoneLinkP2PBackendClass HwPhoneLinkP2PBackendClass;

struct _HwPhoneLinkP2PBackend {
  HwPhoneLinkTransport parent_instance;
};

struct _HwPhoneLinkP2PBackendClass {
  HwPhoneLinkTransportClass parent_class;
};

#define HWPHONELINK_TYPE_P2P_BACKEND (hw_phone_link_p2p_backend_get_type())
G_DECLARE_FINAL_TYPE(HwPhoneLinkP2PBackend, hw_phone_link_p2p_backend,
                     HWPHONELINK, P2P_BACKEND, HwPhoneLinkTransport)

/* Factory */
HwPhoneLinkTransport* hw_phone_link_p2p_backend_new(const gchar *phy_name,
                                                     const gchar *sta_interface,
                                                     GError **error);

/* P2P-specific configuration */
typedef struct {
  gchar *ap_interface;
  gchar *sta_interface;
  gchar *phy_name;
  gchar *wpa_supplicant_conf;
  gchar *p2p_device_name;
  guint channel;
} HwPhoneLinkP2PConfig;