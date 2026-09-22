/*
 * p2p_backend.c - P2P-GO backend using wpa_supplicant
 *
 * Fallback transport when SoftAP is not available.
 * Uses wpa_supplicant P2P interface for GO mode.
 */

#include "p2p_backend.h"
#include "netlink_utils.h"
#include <glib.h>
#include <gio/gio.h>
#include <string.h>
#include <stdlib.h>

struct _HwPhoneLinkP2PBackend {
  HwPhoneLinkTransport parent_instance;
};

typedef struct {
  HwPhoneLinkP2PConfig config;
  HwPhoneLinkNlHandle *nl_handle;
  GSubprocess *wpa_supplicant_proc;
  HwPhoneLinkState state;
  GMutex state_mutex;
} HwPhoneLinkP2PBackendPrivate;

G_DEFINE_TYPE_WITH_PRIVATE(HwPhoneLinkP2PBackend, hw_phone_link_p2p_backend, HWPHONELINK_TYPE_TRANSPORT)

#define HWPHONELINK_P2P_BACKEND_GET_PRIVATE(obj) \
  (hw_phone_link_p2p_backend_get_instance_private(HWPHONELINK_P2P_BACKEND(obj)))

static HwPhoneLinkP2PBackendPrivate* _priv(HwPhoneLinkP2PBackend *self) {
  return HWPHONELINK_P2P_BACKEND_GET_PRIVATE(self);
}

static void hw_phone_link_p2p_backend_finalize(GObject *object) {
  HwPhoneLinkP2PBackend *self = HWPHONELINK_P2P_BACKEND(object);
  HwPhoneLinkP2PBackendPrivate *priv = _priv(self);
  g_mutex_clear(&priv->state_mutex);
  if (priv->nl_handle) hw_phone_link_nl_handle_free(priv->nl_handle);
  G_OBJECT_CLASS(hw_phone_link_p2p_backend_parent_class)->finalize(object);
}

static gboolean _generate_wpa_supplicant_conf(const HwPhoneLinkP2PConfig *config, GError **error) {
  gchar *content = g_strdup_printf(
    "ctrl_interface=/run/wpa_supplicant\n"
    "ctrl_interface_group=wheel\n"
    "update_config=1\n"
    "device_name=%s\n"
    "device_type=1-0050F204-1\n"
    "driver_param=use_p2p_group_interface=1\n"
    "p2p_go_intent=15\n"
    "p2p_go_ht40=1\n"
    "p2p_go_vht=1\n"
    "p2p_go_cc=40\n"
    "p2p_listen_reg_class=81\n"
    "p2p_listen_channel=%u\n"
    "p2p_oper_reg_class=81\n"
    "p2p_oper_channel=%u\n"
    "p2p_pref_chan=%u\n"
    "p2p_go_max_inactivity=300\n"
    "p2p_passphrase_len=8\n",
    config->p2p_device_name,
    config->channel,
    config->channel,
    config->channel
  );

  if (g_file_set_contents(config->wpa_supplicant_conf, content, -1, error) == FALSE) {
    g_free(content);
    return FALSE;
  }
  g_free(content);
  return TRUE;
}

static gboolean hw_phone_link_p2p_backend_start(HwPhoneLinkTransport *transport, GError **error) {
  HwPhoneLinkP2PBackend *self = HWPHONELINK_P2P_BACKEND(transport);

  g_mutex_lock(&_priv(self)->state_mutex);
  if (_priv(self)->state != HWPHONELINK_STATE_STOPPED) {
    g_mutex_unlock(&_priv(self)->state_mutex);
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Already running");
    return FALSE;
  }
  _priv(self)->state = HWPHONELINK_STATE_STARTING;
  g_mutex_unlock(&_priv(self)->state_mutex);

  // Generate wpa_supplicant config
  if (!_generate_wpa_supplicant_conf(&_priv(self)->config, error)) return FALSE;

  // Start wpa_supplicant with P2P
  gchar *argv[] = {
    "wpa_supplicant",
    "-i", _priv(self)->config.ap_interface,
    "-c", _priv(self)->config.wpa_supplicant_conf,
    "-D", "nl80211",
    "-B",
    NULL
  };

  GSubprocess *proc = g_subprocess_launcher_spawnv(
    g_subprocess_launcher_new(G_SUBPROCESS_FLAGS_NONE),
    (const gchar* const*)argv,
    error
  );

  if (!proc) return FALSE;
  _priv(self)->wpa_supplicant_proc = proc;

  // TODO: Use wpa_cli to start P2P-GO
  // wpa_cli -i wlp1s0 p2p_group_add freq=5200

  g_mutex_lock(&_priv(self)->state_mutex);
  _priv(self)->state = HWPHONELINK_STATE_RUNNING;
  g_mutex_unlock(&_priv(self)->state_mutex);

  return TRUE;
}

static gboolean hw_phone_link_p2p_backend_stop(HwPhoneLinkTransport *transport, GError **error) {
  HwPhoneLinkP2PBackend *self = HWPHONELINK_P2P_BACKEND(transport);

  g_mutex_lock(&_priv(self)->state_mutex);
  if (_priv(self)->state == HWPHONELINK_STATE_STOPPED) {
    g_mutex_unlock(&_priv(self)->state_mutex);
    return TRUE;
  }
  g_mutex_unlock(&_priv(self)->state_mutex);

  if (_priv(self)->wpa_supplicant_proc) {
    g_subprocess_force_exit(_priv(self)->wpa_supplicant_proc);
    g_object_unref(_priv(self)->wpa_supplicant_proc);
    _priv(self)->wpa_supplicant_proc = NULL;
  }

  g_mutex_lock(&_priv(self)->state_mutex);
  _priv(self)->state = HWPHONELINK_STATE_STOPPED;
  g_mutex_unlock(&_priv(self)->state_mutex);

  return TRUE;
}

static HwPhoneLinkState hw_phone_link_p2p_backend_get_state(HwPhoneLinkTransport *transport) {
  HwPhoneLinkP2PBackend *self = HWPHONELINK_P2P_BACKEND(transport);
  g_mutex_lock(&_priv(self)->state_mutex);
  HwPhoneLinkState state = _priv(self)->state;
  g_mutex_unlock(&_priv(self)->state_mutex);
  return state;
}

static const gchar* hw_phone_link_p2p_backend_get_ap_interface(HwPhoneLinkTransport *transport) {
  HwPhoneLinkP2PBackend *self = HWPHONELINK_P2P_BACKEND(transport);
  return _priv(self)->config.ap_interface;
}

static const gchar* hw_phone_link_p2p_backend_get_ap_ip(HwPhoneLinkTransport *transport) {
  return HWPHONELINK_AP_IP;
}

static guint hw_phone_link_p2p_backend_get_ap_channel(HwPhoneLinkTransport *transport) {
  HwPhoneLinkP2PBackend *self = HWPHONELINK_P2P_BACKEND(transport);
  return _priv(self)->config.channel;
}

static void hw_phone_link_p2p_backend_class_init(HwPhoneLinkP2PBackendClass *klass) {
  GObjectClass *object_class = G_OBJECT_CLASS(klass);
  HwPhoneLinkTransportClass *transport_class = HWPHONELINK_TRANSPORT_CLASS(klass);

  object_class->finalize = hw_phone_link_p2p_backend_finalize;

  transport_class->start = hw_phone_link_p2p_backend_start;
  transport_class->stop = hw_phone_link_p2p_backend_stop;
  transport_class->get_state = hw_phone_link_p2p_backend_get_state;
  transport_class->get_ap_interface = hw_phone_link_p2p_backend_get_ap_interface;
  transport_class->get_ap_ip = hw_phone_link_p2p_backend_get_ap_ip;
  transport_class->get_ap_channel = hw_phone_link_p2p_backend_get_ap_channel;
}

static void hw_phone_link_p2p_backend_init(HwPhoneLinkP2PBackend *self) {
  g_mutex_init(&_priv(self)->state_mutex);
  _priv(self)->state = HWPHONELINK_STATE_STOPPED;

  _priv(self)->config.ap_interface = g_strdup("p2p-wlp1s0-0");
  _priv(self)->config.sta_interface = g_strdup("wlp1s0");
  _priv(self)->config.phy_name = g_strdup("phy0");
  _priv(self)->config.wpa_supplicant_conf = g_strdup("/etc/hwphonelink/wpa_supplicant_p2p.conf");
  _priv(self)->config.p2p_device_name = g_strdup("HUAWEI_PC_P2P");
  _priv(self)->config.channel = HWPHONELINK_DEFAULT_CHANNEL;
}

HwPhoneLinkTransport* hw_phone_link_p2p_backend_new(const gchar *phy_name,
                                                     const gchar *sta_interface,
                                                     GError **error) {
  HwPhoneLinkP2PBackend *self = g_object_new(HWPHONELINK_TYPE_P2P_BACKEND, NULL);
  _priv(self)->nl_handle = hw_phone_link_nl_handle_new(error);
  if (!_priv(self)->nl_handle) {
    g_object_unref(self);
    return NULL;
  }
  return HWPHONELINK_TRANSPORT(self);
}