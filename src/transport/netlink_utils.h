/*
 * netlink_utils.h - libnl3 helpers for wireless interface management
 *
 * Creates AP interface, manages IP addresses, routes, and netlink events.
 */

#pragma once

#include <glib.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#define NL80211_CMD_NEW_INTERFACE 0x07
#define NL80211_CMD_DEL_INTERFACE 0x08
#define NL80211_CMD_GET_INTERFACE 0x09
#define NL80211_CMD_SET_INTERFACE 0x0A

#define NL80211_IFTYPE_UNSPECIFIED 0
#define NL80211_IFTYPE_ADHOC 1
#define NL80211_IFTYPE_STATION 2
#define NL80211_IFTYPE_AP 3
#define NL80211_IFTYPE_AP_VLAN 4
#define NL80211_IFTYPE_WDS 5
#define NL80211_IFTYPE_MONITOR 6
#define NL80211_IFTYPE_MESH_POINT 7
#define NL80211_IFTYPE_P2P_CLIENT 8
#define NL80211_IFTYPE_P2P_GO 9
#define NL80211_IFTYPE_P2P_DEVICE 10

#define NL80211_ATTR_IFINDEX 3
#define NL80211_ATTR_IFNAME 4
#define NL80211_ATTR_IFTYPE 5

typedef struct _HwPhoneLinkNlHandle HwPhoneLinkNlHandle;

HwPhoneLinkNlHandle* hw_phone_link_nl_handle_new(GError **error);
void hw_phone_link_nl_handle_free(HwPhoneLinkNlHandle *handle);

/* Create virtual AP interface on phy */
gboolean hw_phone_link_nl_create_ap_interface(HwPhoneLinkNlHandle *handle,
                                               const gchar *phy_name,
                                               const gchar *ap_ifname,
                                               GError **error);

/* Delete virtual interface */
gboolean hw_phone_link_nl_delete_interface(HwPhoneLinkNlHandle *handle,
                                            const gchar *ifname,
                                            GError **error);

/* Set interface up/down */
gboolean hw_phone_link_nl_set_interface_up(HwPhoneLinkNlHandle *handle,
                                            const gchar *ifname,
                                            gboolean up,
                                            GError **error);

/* Add/remove IP address */
gboolean hw_phone_link_nl_add_ip_address(HwPhoneLinkNlHandle *handle,
                                          const gchar *ifname,
                                          const gchar *ip_cidr,
                                          GError **error);

gboolean hw_phone_link_nl_remove_ip_address(HwPhoneLinkNlHandle *handle,
                                             const gchar *ifname,
                                             const gchar *ip_cidr,
                                             GError **error);

/* Get interface index by name */
int hw_phone_link_nl_get_ifindex(HwPhoneLinkNlHandle *handle,
                                  const gchar *ifname,
                                  GError **error);

/* Wait for interface to appear/disappear */
gboolean hw_phone_link_nl_wait_interface(HwPhoneLinkNlHandle *handle,
                                          const gchar *ifname,
                                          gboolean should_exist,
                                          guint timeout_ms,
                                          GError **error);