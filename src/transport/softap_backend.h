/*
 * softap_backend.h - SoftAP backend using hostapd + dnsmasq
 *
 * Primary transport for Huawei Multi-Screen on Linux.
 * RTL8822CE/rtw88 validated: concurrent STA+AP works, internet preserved.
 */

#pragma once

#include "wifi_transport.h"

#define HWPHONELINK_SOFTAP_CONFIG_DIR "/etc/hwphonelink"
#define HWPHONELINK_SOFTAP_RUN_DIR "/run/hwphonelink"

typedef struct _HwPhoneLinkSoftapBackend HwPhoneLinkSoftapBackend;

#define HWPHONELINK_TYPE_SOFTAP_BACKEND (hw_phone_link_softap_backend_get_type())
G_DECLARE_FINAL_TYPE(HwPhoneLinkSoftapBackend, hw_phone_link_softap_backend,
                     HWPHONELINK, SOFTAP_BACKEND, HwPhoneLinkTransport)

/* Factory function */
HwPhoneLinkTransport* hw_phone_link_softap_backend_new(const gchar *phy_name,
                                                        const gchar *sta_interface,
                                                        GError **error);

/* Configuration */
typedef struct {
  gchar *ap_interface;
  gchar *sta_interface;
  gchar *phy_name;
  gchar *ssid;
  gchar *passphrase;
  guint channel;
  gchar *ap_ip;
  gchar *netmask;
  gchar *dhcp_start;
  gchar *dhcp_end;
  gchar *config_dir;
  gchar *run_dir;
} HwPhoneLinkSoftapConfig;

void hw_phone_link_softap_config_init(HwPhoneLinkSoftapConfig *config,
                                       const gchar *phy_name,
                                       const gchar *sta_interface);
void hw_phone_link_softap_config_free(HwPhoneLinkSoftapConfig *config);