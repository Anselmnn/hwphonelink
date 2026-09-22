/*
 * netlink_utils.c - libnl3 implementation for wireless interface management
 */

#include "netlink_utils.h"
#include <netlink/route/link.h>
#include <netlink/route/addr.h>
#include <netlink/route/link/bridge.h>
#include <netlink/route/neighbour.h>
#include <netlink/route/rtnl.h>
#include <netlink/route/link/vlan.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <gio/gio.h>

struct _HwPhoneLinkNlHandle {
  struct nl_sock *sock;
  struct nl_cache *link_cache;
  int nl80211_id;
};

static int _wait_for_ack(struct nl_msg *msg, void *arg) {
  return NL_OK;
}

static int _no_seq_check(struct nl_msg *msg, void *arg) {
  return NL_OK;
}

HwPhoneLinkNlHandle* hw_phone_link_nl_handle_new(GError **error) {
  HwPhoneLinkNlHandle *handle = g_new0(HwPhoneLinkNlHandle, 1);

  handle->sock = nl_socket_alloc();
  if (!handle->sock) {
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "nl_socket_alloc failed");
    goto fail;
  }

  if (nl_connect(handle->sock, NETLINK_GENERIC) < 0) {
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "nl_connect failed");
    goto fail;
  }

  nl_socket_disable_seq_check(handle->sock);
  nl_socket_disable_auto_ack(handle->sock);
  nl_socket_modify_cb(handle->sock, NL_CB_VALID, NL_CB_CUSTOM, _no_seq_check, NULL);
  nl_socket_modify_cb(handle->sock, NL_CB_ACK, NL_CB_CUSTOM, _wait_for_ack, NULL);

  handle->nl80211_id = genl_ctrl_resolve(handle->sock, "nl80211");
  if (handle->nl80211_id < 0) {
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "nl80211 not found");
    goto fail;
  }

  if (rtnl_link_alloc_cache(handle->sock, AF_UNSPEC, &handle->link_cache) < 0) {
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "link cache alloc failed");
    goto fail;
  }

  return handle;

fail:
  hw_phone_link_nl_handle_free(handle);
  return NULL;
}

void hw_phone_link_nl_handle_free(HwPhoneLinkNlHandle *handle) {
  if (!handle) return;
  if (handle->link_cache) nl_cache_free(handle->link_cache);
  if (handle->sock) nl_socket_free(handle->sock);
  g_free(handle);
}

static struct nl_msg* _create_nl80211_msg(HwPhoneLinkNlHandle *handle, int cmd, int flags) {
  struct nl_msg *msg = nlmsg_alloc();
  if (!msg) return NULL;

  genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, handle->nl80211_id, 0, flags, cmd, 0);
  return msg;
}

gboolean hw_phone_link_nl_create_ap_interface(HwPhoneLinkNlHandle *handle,
                                               const gchar *phy_name,
                                               const gchar *ap_ifname,
                                               GError **error) {
  struct nl_msg *msg = _create_nl80211_msg(handle, NL80211_CMD_NEW_INTERFACE, NLM_F_CREATE | NLM_F_EXCL);
  if (!msg) {
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "nlmsg_alloc failed");
    return FALSE;
  }

  // Parse phy index from name (e.g., "phy0" -> 0)
  int phy_idx = 0;
  if (g_str_has_prefix(phy_name, "phy")) {
    phy_idx = atoi(phy_name + 3);
  }

  if (phy_idx >= 0) {
    NLA_PUT_U32(msg, NL80211_ATTR_WIPHY, phy_idx);
  }

  NLA_PUT_STRING(msg, NL80211_ATTR_IFNAME, ap_ifname);
  NLA_PUT_U32(msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_AP);

  int err = nl_send_auto(handle->sock, msg);
  nlmsg_free(msg);

  if (err < 0) {
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                "nl80211 create interface failed: %s", nl_geterror(err));
    return FALSE;
  }

  return TRUE;

nla_put_failure:
  nlmsg_free(msg);
  g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "NLA_PUT failed");
  return FALSE;
}

gboolean hw_phone_link_nl_delete_interface(HwPhoneLinkNlHandle *handle,
                                            const gchar *ifname,
                                            GError **error) {
  struct nl_msg *msg = _create_nl80211_msg(handle, NL80211_CMD_DEL_INTERFACE, 0);
  if (!msg) {
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "nlmsg_alloc failed");
    return FALSE;
  }

  NLA_PUT_STRING(msg, NL80211_ATTR_IFNAME, ifname);

  int err = nl_send_auto(handle->sock, msg);
  nlmsg_free(msg);

  if (err < 0) {
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                "nl80211 delete interface failed: %s", nl_geterror(err));
    return FALSE;
  }

  return TRUE;

nla_put_failure:
  nlmsg_free(msg);
  g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "NLA_PUT failed");
  return FALSE;
}

gboolean hw_phone_link_nl_set_interface_up(HwPhoneLinkNlHandle *handle,
                                            const gchar *ifname,
                                            gboolean up,
                                            GError **error) {
  struct rtnl_link *link = rtnl_link_get_by_name(handle->link_cache, ifname);
  if (!link) {
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
                "Interface %s not found", ifname);
    return FALSE;
  }

  rtnl_link_set_flags(link, up ? IFF_UP : 0);
  rtnl_link_unset_flags(link, up ? 0 : IFF_UP);

  int err = rtnl_link_change(handle->sock, link, link, 0);
  rtnl_link_put(link);

  if (err < 0) {
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                "Set interface %s %s failed: %s", ifname, up ? "up" : "down", nl_geterror(err));
    return FALSE;
  }

  return TRUE;
}

gboolean hw_phone_link_nl_add_ip_address(HwPhoneLinkNlHandle *handle,
                                          const gchar *ifname,
                                          const gchar *ip_cidr,
                                          GError **error) {
  int ifindex = hw_phone_link_nl_get_ifindex(handle, ifname, error);
  if (ifindex < 0) return FALSE;

  struct nl_msg *msg = nlmsg_alloc();
  if (!msg) {
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "nlmsg_alloc failed");
    return FALSE;
  }

  struct nlmsghdr *hdr = nlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ,
                                    RTM_NEWADDR, sizeof(struct ifaddrmsg), NLM_F_CREATE | NLM_F_EXCL);
  struct ifaddrmsg *ifa = nlmsg_data(hdr);
  ifa->ifa_family = AF_INET;
  ifa->ifa_prefixlen = 24; // /24
  ifa->ifa_flags = 0;
  ifa->ifa_scope = RT_SCOPE_UNIVERSE;
  ifa->ifa_index = ifindex;

  // Parse IP
  gchar **parts = g_strsplit(ip_cidr, "/", 2);
  struct in_addr addr;
  inet_pton(AF_INET, parts[0], &addr);
  g_strfreev(parts);

  NLA_PUT(msg, IFA_LOCAL, sizeof(addr), &addr);
  NLA_PUT(msg, IFA_ADDRESS, sizeof(addr), &addr);

  int err = nl_send_auto(handle->sock, msg);
  nlmsg_free(msg);

  if (err < 0) {
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                "Add IP address failed: %s", nl_geterror(err));
    return FALSE;
  }

  return TRUE;

nla_put_failure:
  nlmsg_free(msg);
  g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "NLA_PUT failed");
  return FALSE;
}

gboolean hw_phone_link_nl_remove_ip_address(HwPhoneLinkNlHandle *handle,
                                             const gchar *ifname,
                                             const gchar *ip_cidr,
                                             GError **error) {
  int ifindex = hw_phone_link_nl_get_ifindex(handle, ifname, error);
  if (ifindex < 0) return FALSE;

  struct nl_msg *msg = nlmsg_alloc();
  if (!msg) {
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "nlmsg_alloc failed");
    return FALSE;
  }

  struct nlmsghdr *hdr = nlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ,
                                    RTM_DELADDR, sizeof(struct ifaddrmsg), 0);
  struct ifaddrmsg *ifa = nlmsg_data(hdr);
  ifa->ifa_family = AF_INET;
  ifa->ifa_prefixlen = 24;
  ifa->ifa_flags = 0;
  ifa->ifa_scope = RT_SCOPE_UNIVERSE;
  ifa->ifa_index = ifindex;

  gchar **parts = g_strsplit(ip_cidr, "/", 2);
  struct in_addr addr;
  inet_pton(AF_INET, parts[0], &addr);
  g_strfreev(parts);

  NLA_PUT(msg, IFA_LOCAL, sizeof(addr), &addr);

  int err = nl_send_auto(handle->sock, msg);
  nlmsg_free(msg);

  if (err < 0) {
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                "Remove IP address failed: %s", nl_geterror(err));
    return FALSE;
  }

  return TRUE;

nla_put_failure:
  nlmsg_free(msg);
  g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "NLA_PUT failed");
  return FALSE;
}

int hw_phone_link_nl_get_ifindex(HwPhoneLinkNlHandle *handle,
                                  const gchar *ifname,
                                  GError **error) {
  struct rtnl_link *link = rtnl_link_get_by_name(handle->link_cache, ifname);
  if (!link) {
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
                "Interface %s not found", ifname);
    return -1;
  }
  int ifindex = rtnl_link_get_ifindex(link);
  rtnl_link_put(link);
  return ifindex;
}

gboolean hw_phone_link_nl_wait_interface(HwPhoneLinkNlHandle *handle,
                                          const gchar *ifname,
                                          gboolean should_exist,
                                          guint timeout_ms,
                                          GError **error) {
  gint64 start = g_get_monotonic_time();

  while (TRUE) {
    struct rtnl_link *link = rtnl_link_get_by_name(handle->link_cache, ifname);
    gboolean exists = (link != NULL);
    if (link) rtnl_link_put(link);

    if (exists == should_exist) return TRUE;

    gint64 elapsed = g_get_monotonic_time() - start;
    if (elapsed > (gint64)timeout_ms * 1000) {
      g_set_error(error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT,
                  "Timeout waiting for interface %s to %s",
                  ifname, should_exist ? "appear" : "disappear");
      return FALSE;
    }

    usleep(100000); // 100ms
  }
}