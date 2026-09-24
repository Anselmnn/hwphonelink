/*
 * wifi_transport.c - Base transport implementation
 *
 * GObject base class for Wi-Fi transport backends.
 */

#include "wifi_transport.h"
#include "softap_backend.h"
#include "p2p_backend.h"
#include "infra_backend.h"

GType hw_phone_link_state_get_type(void) {
  static GType type = 0;
  if (type == 0) {
    static const GEnumValue values[] = {
      { HWPHONELINK_STATE_STOPPED, "HWPHONELINK_STATE_STOPPED", "stopped" },
      { HWPHONELINK_STATE_STARTING, "HWPHONELINK_STATE_STARTING", "starting" },
      { HWPHONELINK_STATE_RUNNING, "HWPHONELINK_STATE_RUNNING", "running" },
      { HWPHONELINK_STATE_STOPPING, "HWPHONELINK_STATE_STOPPING", "stopping" },
      { HWPHONELINK_STATE_ERROR, "HWPHONELINK_STATE_ERROR", "error" },
      { 0, NULL, NULL }
    };
    type = g_enum_register_static("HwPhoneLinkState", values);
  }
  return type;
}

G_DEFINE_ABSTRACT_TYPE(HwPhoneLinkTransport, hw_phone_link_transport, G_TYPE_OBJECT)

enum {
  PROP_0,
  PROP_STATE,
  PROP_AP_INTERFACE,
  PROP_AP_IP,
  PROP_AP_CHANNEL,
  N_PROPS
};

static GParamSpec *obj_properties[N_PROPS] = { NULL };

static void hw_phone_link_transport_set_property(GObject *object,
                                                  guint property_id,
                                                  const GValue *value,
                                                  GParamSpec *pspec) {
  G_OBJECT_WARN_INVALID_PROPERTY_ID(object, property_id, pspec);
}

static void hw_phone_link_transport_get_property(GObject *object,
                                                  guint property_id,
                                                  GValue *value,
                                                  GParamSpec *pspec) {
  HwPhoneLinkTransport *self = HWPHONELINK_TRANSPORT(object);
  HwPhoneLinkTransportClass *klass = HWPHONELINK_TRANSPORT_GET_CLASS(self);

  switch (property_id) {
    case PROP_STATE:
      g_value_set_enum(value, klass->get_state(self));
      break;
    case PROP_AP_INTERFACE:
      g_value_set_string(value, klass->get_ap_interface(self));
      break;
    case PROP_AP_IP:
      g_value_set_string(value, klass->get_ap_ip(self));
      break;
    case PROP_AP_CHANNEL:
      g_value_set_uint(value, klass->get_ap_channel(self));
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID(object, property_id, pspec);
      break;
  }
}

static void hw_phone_link_transport_class_init(HwPhoneLinkTransportClass *klass) {
  GObjectClass *object_class = G_OBJECT_CLASS(klass);

  object_class->set_property = hw_phone_link_transport_set_property;
  object_class->get_property = hw_phone_link_transport_get_property;

  obj_properties[PROP_STATE] =
    g_param_spec_enum("state", "State", "Transport state",
                      HWPHONELINK_TYPE_STATE,
                      HWPHONELINK_STATE_STOPPED,
                      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

  obj_properties[PROP_AP_INTERFACE] =
    g_param_spec_string("ap-interface", "AP Interface", "AP interface name",
                        NULL, G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

  obj_properties[PROP_AP_IP] =
    g_param_spec_string("ap-ip", "AP IP", "AP IP address",
                        NULL, G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

  obj_properties[PROP_AP_CHANNEL] =
    g_param_spec_uint("ap-channel", "AP Channel", "AP Wi-Fi channel",
                      0, 165, HWPHONELINK_DEFAULT_CHANNEL,
                      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

  g_object_class_install_properties(object_class, N_PROPS, obj_properties);

  /* Signals */
  g_signal_new("state-changed",
               G_TYPE_FROM_CLASS(klass),
               G_SIGNAL_RUN_LAST,
               0, NULL, NULL,
               NULL,
               G_TYPE_NONE, 2,
               HWPHONELINK_TYPE_STATE, HWPHONELINK_TYPE_STATE);

  g_signal_new("client-connected",
               G_TYPE_FROM_CLASS(klass),
               G_SIGNAL_RUN_LAST,
               0, NULL, NULL,
               NULL,
               G_TYPE_NONE, 2,
               G_TYPE_STRING, G_TYPE_STRING);

  g_signal_new("client-disconnected",
               G_TYPE_FROM_CLASS(klass),
               G_SIGNAL_RUN_LAST,
               0, NULL, NULL,
               NULL,
               G_TYPE_NONE, 1,
               G_TYPE_STRING);

  /*
   * dsoftbus session signals (M2). The first parameter is a
   * SoftbusSession* (see proto/softbus_session.h) passed as a raw pointer.
   * The transport keeps the session alive (it owns a ref) until the peer
   * disconnects or the transport stops, so handlers may use the pointer
   * without taking their own ref.
   */
  g_signal_new("session-opened",
               G_TYPE_FROM_CLASS(klass),
               G_SIGNAL_RUN_LAST,
               0, NULL, NULL,
               NULL,
               G_TYPE_NONE, 2,
               G_TYPE_POINTER, G_TYPE_STRING);

  g_signal_new("session-closed",
               G_TYPE_FROM_CLASS(klass),
               G_SIGNAL_RUN_LAST,
               0, NULL, NULL,
               NULL,
               G_TYPE_NONE, 1,
               G_TYPE_POINTER);
}

static void hw_phone_link_transport_init(HwPhoneLinkTransport *self) {
}

gboolean hw_phone_link_transport_start(HwPhoneLinkTransport *self, GError **error) {
  HwPhoneLinkTransportClass *klass = HWPHONELINK_TRANSPORT_GET_CLASS(self);
  return klass->start(self, error);
}

gboolean hw_phone_link_transport_stop(HwPhoneLinkTransport *self, GError **error) {
  HwPhoneLinkTransportClass *klass = HWPHONELINK_TRANSPORT_GET_CLASS(self);
  return klass->stop(self, error);
}

HwPhoneLinkState hw_phone_link_transport_get_state(HwPhoneLinkTransport *self) {
  HwPhoneLinkTransportClass *klass = HWPHONELINK_TRANSPORT_GET_CLASS(self);
  return klass->get_state(self);
}

const gchar* hw_phone_link_transport_get_ap_interface(HwPhoneLinkTransport *self) {
  HwPhoneLinkTransportClass *klass = HWPHONELINK_TRANSPORT_GET_CLASS(self);
  return klass->get_ap_interface(self);
}

const gchar* hw_phone_link_transport_get_ap_ip(HwPhoneLinkTransport *self) {
  HwPhoneLinkTransportClass *klass = HWPHONELINK_TRANSPORT_GET_CLASS(self);
  return klass->get_ap_ip(self);
}

guint hw_phone_link_transport_get_ap_channel(HwPhoneLinkTransport *self) {
  HwPhoneLinkTransportClass *klass = HWPHONELINK_TRANSPORT_GET_CLASS(self);
  return klass->get_ap_channel(self);
}

/* Factory */
HwPhoneLinkTransport* hw_phone_link_transport_new(HwPhoneLinkTransportType type,
                                                   const gchar *phy_name,
                                                   const gchar *sta_interface,
                                                   GError **error) {
  switch (type) {
    case HWPHONELINK_TRANSPORT_SOFTAP:
      return hw_phone_link_softap_backend_new(phy_name, sta_interface, error);
    case HWPHONELINK_TRANSPORT_P2P_GO:
      return hw_phone_link_p2p_backend_new(phy_name, sta_interface, error);
    case HWPHONELINK_TRANSPORT_INFRA:
      return hw_phone_link_infra_backend_new(sta_interface, error);
    default:
      g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                  "Unknown transport type: %d", type);
      return NULL;
  }
}