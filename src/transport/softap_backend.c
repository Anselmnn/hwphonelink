/*
 * softap_backend.c - SoftAP backend implementation (hostapd + dnsmasq)
 *
 * Primary transport for Huawei Multi-Screen on Linux.
 * Validated on RTL8822CE/rtw88: concurrent STA+AP works, internet preserved.
 */

#include "softap_backend.h"
#include "netlink_utils.h"
#include <glib.h>
#include <gio/gio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

struct _HwPhoneLinkSoftapBackend {
  HwPhoneLinkTransport parent_instance;
};

typedef struct {
  HwPhoneLinkSoftapConfig config;
  HwPhoneLinkNlHandle *nl_handle;
  GSubprocess *hostapd_proc;
  GSubprocess *dnsmasq_proc;
  HwPhoneLinkState state;
  GMutex state_mutex;
  guint hostapd_pid;
  guint dnsmasq_pid;
} HwPhoneLinkSoftapBackendPrivate;

G_DEFINE_TYPE_WITH_PRIVATE(HwPhoneLinkSoftapBackend, hw_phone_link_softap_backend, HWPHONELINK_TYPE_TRANSPORT)

#define HWPHONELINK_SOFTAP_BACKEND_GET_PRIVATE(obj) \
  (hw_phone_link_softap_backend_get_instance_private(HWPHONELINK_SOFTAP_BACKEND(obj)))

static HwPhoneLinkSoftapBackendPrivate* _priv(HwPhoneLinkSoftapBackend *self) {
  return HWPHONELINK_SOFTAP_BACKEND_GET_PRIVATE(self);
}

static void hw_phone_link_softap_backend_finalize(GObject *object) {
  HwPhoneLinkSoftapBackend *self = HWPHONELINK_SOFTAP_BACKEND(object);
  HwPhoneLinkSoftapBackendPrivate *priv = _priv(self);
  g_mutex_clear(&priv->state_mutex);
  hw_phone_link_softap_config_free(&priv->config);
  if (priv->nl_handle) hw_phone_link_nl_handle_free(priv->nl_handle);
  G_OBJECT_CLASS(hw_phone_link_softap_backend_parent_class)->finalize(object);
}

static gboolean _ensure_dirs(const HwPhoneLinkSoftapConfig *config, GError **error) {
  if (g_mkdir_with_parents(config->run_dir, 0755) < 0) {
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                "Failed to create run dir %s: %s", config->run_dir, g_strerror(errno));
    return FALSE;
  }
  return TRUE;
}

static gboolean _generate_hostapd_conf(const HwPhoneLinkSoftapConfig *config, GError **error) {
  gchar *path = g_build_filename(config->config_dir, "hostapd.conf", NULL);
  gchar *content = g_strdup_printf(
    "interface=%s\n"
    "driver=nl80211\n"
    "ssid=%s\n"
    "hw_mode=%s\n"
    "channel=%u\n"
    "ieee80211n=1\n"
    "ieee80211ac=1\n"
    "wpa=2\n"
    "wpa_passphrase=%s\n"
    "wpa_key_mgmt=WPA-PSK\n"
    "rsn_pairwise=CCMP\n"
    "wmm_enabled=1\n"
    "ieee80211d=1\n"
    "country_code=CN\n"
    "ieee80211h=1\n",
    config->ap_interface,
    config->ssid,
    config->channel <= 14 ? "g" : "a",
    config->channel,
    config->passphrase
  );

  if (g_file_set_contents(path, content, -1, NULL) == FALSE) {
    g_free(path);
    g_free(content);
    return FALSE;
  }
  g_free(path);
  g_free(content);
  return TRUE;
}

static gboolean _generate_dnsmasq_conf(const HwPhoneLinkSoftapConfig *config, GError **error) {
  gchar *path = g_build_filename(config->config_dir, "dnsmasq.conf", NULL);
  gchar *content = g_strdup_printf(
    "interface=%s\n"
    "bind-interfaces\n"
    "dhcp-range=%s,%s,12h\n"
    "dhcp-option=3,%s\n"
    "dhcp-option=6,%s\n"
    "no-hosts\n"
    "addn-hosts=%s/hosts\n"
    "log-queries\n"
    "log-dhcp\n"
    "pid-file=%s/dnsmasq.pid\n"
    "dhcp-leasefile=%s/dnsmasq.leases\n"
    "dhcp-authoritative\n",
    config->ap_interface,
    config->dhcp_start,
    config->dhcp_end,
    config->ap_ip,
    config->ap_ip,
    config->config_dir,
    config->run_dir,
    config->run_dir
  );

  if (g_file_set_contents(path, content, -1, NULL) == FALSE) {
    g_free(path);
    g_free(content);
    return FALSE;
  }
  g_free(path);
  g_free(content);

  // Create minimal hosts file
  gchar *hosts_path = g_build_filename(config->config_dir, "hosts", NULL);
  gchar *hosts_content = g_strdup_printf("%s\tphone.local\n", config->ap_ip);
  g_file_set_contents(hosts_path, hosts_content, -1, NULL);
  g_free(hosts_path);
  g_free(hosts_content);

  return TRUE;
}

static gboolean _write_psk_file(const HwPhoneLinkSoftapConfig *config, GError **error) {
  // Generate PSK file for hostapd (if using wpa_psk_file)
  gchar *psk_path = g_build_filename(config->run_dir, "hostapd.psk", NULL);
  // For now, hostapd reads passphrase from config directly
  // This is a placeholder for future HKDF-based PSK generation
  g_free(psk_path);
  return TRUE;
}

static gboolean _start_hostapd(HwPhoneLinkSoftapBackend *self, GError **error) {
  gchar *config_path = g_build_filename(_priv(self)->config.config_dir, "hostapd.conf", NULL);
  gchar *pid_path = g_build_filename(_priv(self)->config.run_dir, "hostapd.pid", NULL);

  gchar *argv[] = {
    "hostapd",
    "-B",  // daemon mode
    "-P", pid_path,
    config_path,
    NULL
  };

  GSubprocess *proc = g_subprocess_launcher_spawnv(
    g_subprocess_launcher_new(G_SUBPROCESS_FLAGS_NONE),
    (const gchar* const*)argv,
    error
  );

  g_free(config_path);
  g_free(pid_path);

  if (!proc) return FALSE;

  // Read PID
  gchar *pid_content = NULL;
  if (g_file_get_contents(pid_path, &pid_content, NULL, NULL)) {
    _priv(self)->hostapd_pid = atoi(pid_content);
    g_free(pid_content);
  }

  g_object_unref(proc);
  return TRUE;
}

static gboolean _start_dnsmasq(HwPhoneLinkSoftapBackend *self, GError **error) {
  gchar *config_path = g_build_filename(_priv(self)->config.config_dir, "dnsmasq.conf", NULL);
  gchar *pid_path = g_build_filename(_priv(self)->config.run_dir, "dnsmasq.pid", NULL);
  gchar *lease_path = g_build_filename(_priv(self)->config.run_dir, "dnsmasq.leases", NULL);

  gchar *argv[] = {
    "dnsmasq",
    "-C", config_path,
    "-x", pid_path,
    "-l", lease_path,
    "--no-daemon",
    NULL
  };

  GSubprocessLauncher *launcher = g_subprocess_launcher_new(G_SUBPROCESS_FLAGS_NONE);
  g_subprocess_launcher_set_environ(launcher, (gchar**)g_get_environ());

  GSubprocess *proc = g_subprocess_launcher_spawnv(launcher, (const gchar* const*)argv, error);
  g_object_unref(launcher);

  if (!proc) {
    g_free(config_path);
    g_free(pid_path);
    g_free(lease_path);
    return FALSE;
  }

  _priv(self)->dnsmasq_proc = proc;

  // Read PID
  gchar *pid_content = NULL;
  if (g_file_get_contents(pid_path, &pid_content, NULL, NULL)) {
    _priv(self)->dnsmasq_pid = atoi(pid_content);
    g_free(pid_content);
  }

  g_free(config_path);
  g_free(pid_path);
  g_free(lease_path);
  return TRUE;
}

static gboolean _stop_process(guint pid, const gchar *name) {
  if (pid > 0) {
    kill(pid, SIGTERM);
    for (int i = 0; i < 50; i++) {
      if (kill(pid, 0) != 0) break;
      usleep(100000);
    }
    if (kill(pid, 0) == 0) kill(pid, SIGKILL);
  }
  return TRUE;
}

static gboolean hw_phone_link_softap_backend_start(HwPhoneLinkTransport *transport, GError **error) {
  HwPhoneLinkSoftapBackend *self = HWPHONELINK_SOFTAP_BACKEND(transport);

  g_mutex_lock(&_priv(self)->state_mutex);
  if (_priv(self)->state != HWPHONELINK_STATE_STOPPED) {
    g_mutex_unlock(&_priv(self)->state_mutex);
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Already running");
    return FALSE;
  }
  _priv(self)->state = HWPHONELINK_STATE_STARTING;
  g_mutex_unlock(&_priv(self)->state_mutex);

  g_object_notify_by_pspec(G_OBJECT(transport), g_param_spec_enum("state", "", "", HWPHONELINK_TYPE_STATE, HWPHONELINK_STATE_STARTING, G_PARAM_READABLE));

  // 1. Ensure directories
  if (!_ensure_dirs(&_priv(self)->config, error)) return FALSE;

  // 2. Create AP interface via netlink
  gchar *ap_ifname = g_strdup(_priv(self)->config.ap_interface);
  if (!hw_phone_link_nl_create_ap_interface(_priv(self)->nl_handle,
                                             _priv(self)->config.phy_name,
                                             ap_ifname,
                                             error)) {
    g_free(ap_ifname);
    return FALSE;
  }
  g_free(ap_ifname);

  // Wait for interface to appear
  if (!hw_phone_link_nl_wait_interface(_priv(self)->nl_handle, _priv(self)->config.ap_interface, TRUE, 5000, error)) {
    return FALSE;
  }

  // 3. Set AP interface up
  if (!hw_phone_link_nl_set_interface_up(_priv(self)->nl_handle, _priv(self)->config.ap_interface, TRUE, error)) {
    return FALSE;
  }

  // 4. Add IP address
  gchar *ip_cidr = g_strdup_printf("%s/24", _priv(self)->config.ap_ip);
  if (!hw_phone_link_nl_add_ip_address(_priv(self)->nl_handle, _priv(self)->config.ap_interface, ip_cidr, error)) {
    g_free(ip_cidr);
    return FALSE;
  }
  g_free(ip_cidr);

  // 5. Block NetworkManager from managing AP interface
  GSubprocess *nmcli = g_subprocess_launcher_spawnv(
    g_subprocess_launcher_new(G_SUBPROCESS_FLAGS_NONE),
    (const gchar* const[]){"nmcli", "device", "set", _priv(self)->config.ap_interface, "managed", "no", NULL},
    error
  );
  if (nmcli) g_object_unref(nmcli);

  // 6. Generate configs
  if (!_generate_hostapd_conf(&_priv(self)->config, error)) return FALSE;
  if (!_generate_dnsmasq_conf(&_priv(self)->config, error)) return FALSE;
  if (!_write_psk_file(&_priv(self)->config, error)) return FALSE;

  // 7. Start hostapd
  if (!_start_hostapd(self, error)) {
    _priv(self)->state = HWPHONELINK_STATE_ERROR;
    return FALSE;
  }

  // 8. Start dnsmasq
  if (!_start_dnsmasq(self, error)) {
    _stop_process(_priv(self)->hostapd_pid, "hostapd");
    _priv(self)->hostapd_pid = 0;
    _priv(self)->state = HWPHONELINK_STATE_ERROR;
    return FALSE;
  }

  // 9. Enable IP forwarding and NAT for phone internet access
  GSubprocess *iptables = g_subprocess_launcher_spawnv(
    g_subprocess_launcher_new(G_SUBPROCESS_FLAGS_NONE),
    (const gchar* const[]){"sh", "-c",
      "echo 1 > /proc/sys/net/ipv4/ip_forward && "
      "iptables -t nat -A POSTROUTING -s 192.168.137.0/24 -o wlp1s0 -j MASQUERADE && "
      "iptables -A FORWARD -i wlp1s0_ap -o wlp1s0 -j ACCEPT && "
      "iptables -A FORWARD -i wlp1s0 -o wlp1s0_ap -m state --state RELATED,ESTABLISHED -j ACCEPT",
      NULL},
    error
  );
  if (iptables) g_object_unref(iptables);

  g_mutex_lock(&_priv(self)->state_mutex);
  _priv(self)->state = HWPHONELINK_STATE_RUNNING;
  g_mutex_unlock(&_priv(self)->state_mutex);

  g_object_notify_by_pspec(G_OBJECT(transport), g_param_spec_enum("state", "", "", HWPHONELINK_TYPE_STATE, HWPHONELINK_STATE_RUNNING, G_PARAM_READABLE));
  g_signal_emit_by_name(transport, "state-changed", HWPHONELINK_STATE_STARTING, HWPHONELINK_STATE_RUNNING);

  return TRUE;
}

static gboolean hw_phone_link_softap_backend_stop(HwPhoneLinkTransport *transport, GError **error) {
  HwPhoneLinkSoftapBackend *self = HWPHONELINK_SOFTAP_BACKEND(transport);

  g_mutex_lock(&_priv(self)->state_mutex);
  if (_priv(self)->state == HWPHONELINK_STATE_STOPPED || _priv(self)->state == HWPHONELINK_STATE_STOPPING) {
    g_mutex_unlock(&_priv(self)->state_mutex);
    return TRUE;
  }
  _priv(self)->state = HWPHONELINK_STATE_STOPPING;
  g_mutex_unlock(&_priv(self)->state_mutex);

  g_object_notify_by_pspec(G_OBJECT(transport), g_param_spec_enum("state", "", "", HWPHONELINK_TYPE_STATE, HWPHONELINK_STATE_STOPPING, G_PARAM_READABLE));

  // Stop dnsmasq
  if (_priv(self)->dnsmasq_proc) {
    g_subprocess_force_exit(_priv(self)->dnsmasq_proc);
    g_object_unref(_priv(self)->dnsmasq_proc);
    _priv(self)->dnsmasq_proc = NULL;
  }
  _stop_process(_priv(self)->dnsmasq_pid, "dnsmasq");
  _priv(self)->dnsmasq_pid = 0;

  // Stop hostapd
  _stop_process(_priv(self)->hostapd_pid, "hostapd");
  _priv(self)->hostapd_pid = 0;

  // Remove iptables rules
  GSubprocess *iptables = g_subprocess_launcher_spawnv(
    g_subprocess_launcher_new(G_SUBPROCESS_FLAGS_NONE),
    (const gchar* const[]){"sh", "-c",
      "iptables -t nat -D POSTROUTING -s 192.168.137.0/24 -o wlp1s0 -j MASQUERADE 2>/dev/null; "
      "iptables -D FORWARD -i wlp1s0_ap -o wlp1s0 -j ACCEPT 2>/dev/null; "
      "iptables -D FORWARD -i wlp1s0 -o wlp1s0_ap -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null",
      NULL},
    NULL
  );
  if (iptables) g_object_unref(iptables);

  // Remove IP address
  gchar *ip_cidr = g_strdup_printf("%s/24", _priv(self)->config.ap_ip);
  hw_phone_link_nl_remove_ip_address(_priv(self)->nl_handle, _priv(self)->config.ap_interface, ip_cidr, NULL);
  g_free(ip_cidr);

  // Set interface down
  hw_phone_link_nl_set_interface_up(_priv(self)->nl_handle, _priv(self)->config.ap_interface, FALSE, NULL);

  // Delete AP interface
  hw_phone_link_nl_delete_interface(_priv(self)->nl_handle, _priv(self)->config.ap_interface, NULL);

  g_mutex_lock(&_priv(self)->state_mutex);
  _priv(self)->state = HWPHONELINK_STATE_STOPPED;
  g_mutex_unlock(&_priv(self)->state_mutex);

  g_object_notify_by_pspec(G_OBJECT(transport), g_param_spec_enum("state", "", "", HWPHONELINK_TYPE_STATE, HWPHONELINK_STATE_STOPPED, G_PARAM_READABLE));
  g_signal_emit_by_name(transport, "state-changed", HWPHONELINK_STATE_STOPPING, HWPHONELINK_STATE_STOPPED);

  return TRUE;
}

static HwPhoneLinkState hw_phone_link_softap_backend_get_state(HwPhoneLinkTransport *transport) {
  HwPhoneLinkSoftapBackend *self = HWPHONELINK_SOFTAP_BACKEND(transport);
  g_mutex_lock(&_priv(self)->state_mutex);
  HwPhoneLinkState state = _priv(self)->state;
  g_mutex_unlock(&_priv(self)->state_mutex);
  return state;
}

static const gchar* hw_phone_link_softap_backend_get_ap_interface(HwPhoneLinkTransport *transport) {
  HwPhoneLinkSoftapBackend *self = HWPHONELINK_SOFTAP_BACKEND(transport);
  return _priv(self)->config.ap_interface;
}

static const gchar* hw_phone_link_softap_backend_get_ap_ip(HwPhoneLinkTransport *transport) {
  HwPhoneLinkSoftapBackend *self = HWPHONELINK_SOFTAP_BACKEND(transport);
  return _priv(self)->config.ap_ip;
}

static guint hw_phone_link_softap_backend_get_ap_channel(HwPhoneLinkTransport *transport) {
  HwPhoneLinkSoftapBackend *self = HWPHONELINK_SOFTAP_BACKEND(transport);
  return _priv(self)->config.channel;
}

static void hw_phone_link_softap_backend_class_init(HwPhoneLinkSoftapBackendClass *klass) {
  GObjectClass *object_class = G_OBJECT_CLASS(klass);
  HwPhoneLinkTransportClass *transport_class = HWPHONELINK_TRANSPORT_CLASS(klass);

  object_class->finalize = hw_phone_link_softap_backend_finalize;

  transport_class->start = hw_phone_link_softap_backend_start;
  transport_class->stop = hw_phone_link_softap_backend_stop;
  transport_class->get_state = hw_phone_link_softap_backend_get_state;
  transport_class->get_ap_interface = hw_phone_link_softap_backend_get_ap_interface;
  transport_class->get_ap_ip = hw_phone_link_softap_backend_get_ap_ip;
  transport_class->get_ap_channel = hw_phone_link_softap_backend_get_ap_channel;
}

static void hw_phone_link_softap_backend_init(HwPhoneLinkSoftapBackend *self) {
  g_mutex_init(&_priv(self)->state_mutex);
  _priv(self)->state = HWPHONELINK_STATE_STOPPED;
}

void hw_phone_link_softap_config_init(HwPhoneLinkSoftapConfig *config,
                                       const gchar *phy_name,
                                       const gchar *sta_interface) {
  memset(config, 0, sizeof(*config));
  config->phy_name = g_strdup(phy_name ? phy_name : "phy0");
  config->sta_interface = g_strdup(sta_interface ? sta_interface : "wlp1s0");
  config->ap_interface = g_strdup("wlp1s0_ap");
  config->ssid = g_strdup("HUAWEI_PC");
  config->passphrase = g_strdup("");  // Will be generated via HKDF
  config->channel = HWPHONELINK_DEFAULT_CHANNEL;
  config->ap_ip = g_strdup(HWPHONELINK_AP_IP);
  config->netmask = g_strdup(HWPHONELINK_AP_NETMASK);
  config->dhcp_start = g_strdup(HWPHONELINK_DHCP_START);
  config->dhcp_end = g_strdup(HWPHONELINK_DHCP_END);
  config->config_dir = g_strdup(HWPHONELINK_SOFTAP_CONFIG_DIR);
  config->run_dir = g_strdup(HWPHONELINK_SOFTAP_RUN_DIR);
}

void hw_phone_link_softap_config_free(HwPhoneLinkSoftapConfig *config) {
  g_free(config->ap_interface);
  g_free(config->sta_interface);
  g_free(config->phy_name);
  g_free(config->ssid);
  g_free(config->passphrase);
  g_free(config->ap_ip);
  g_free(config->netmask);
  g_free(config->dhcp_start);
  g_free(config->dhcp_end);
  g_free(config->config_dir);
  g_free(config->run_dir);
  memset(config, 0, sizeof(*config));
}

HwPhoneLinkTransport* hw_phone_link_softap_backend_new(const gchar *phy_name,
                                                        const gchar *sta_interface,
                                                        GError **error) {
  HwPhoneLinkSoftapBackend *self = g_object_new(HWPHONELINK_TYPE_SOFTAP_BACKEND, NULL);

  hw_phone_link_softap_config_init(&_priv(self)->config, phy_name, sta_interface);

  _priv(self)->nl_handle = hw_phone_link_nl_handle_new(error);
  if (!_priv(self)->nl_handle) {
    g_object_unref(self);
    return NULL;
  }

  return HWPHONELINK_TRANSPORT(self);
}