/*
 * softbus_device.c - Device record + discovery beacon (CoAP JSON)
 */

#include "softbus_device.h"

#include <json-glib/json-glib.h>
#include <string.h>

/* ============================ Lifecycle ============================ */

SoftbusDevice* softbus_device_new(void) {
  SoftbusDevice *dev = g_new0(SoftbusDevice, 1);
  dev->refcount = 1;
  return dev;
}

SoftbusDevice* softbus_device_ref(SoftbusDevice *dev) {
  if (dev) dev->refcount++;
  return dev;
}

void softbus_device_unref(SoftbusDevice *dev) {
  if (dev == NULL) return;
  if (dev->refcount > 0 && --dev->refcount == 0) {
    g_free(dev->device_id);
    g_free(dev->device_name);
    g_free(dev->ble_mac);
    g_free(dev->peer_ip);
    g_free(dev);
  }
}

/* ============================ Accessors ============================ */

const gchar* softbus_device_get_id(const SoftbusDevice *dev) { return dev ? dev->device_id : NULL; }
const gchar* softbus_device_get_name(const SoftbusDevice *dev) { return dev ? dev->device_name : NULL; }
SoftbusDeviceType softbus_device_get_type(const SoftbusDevice *dev) { return dev ? dev->device_type : SOFTBUS_DEVTYPE_PHONE; }
guint32 softbus_device_get_capabilities(const SoftbusDevice *dev) { return dev ? dev->capabilities : 0; }
guint16 softbus_device_get_auth_port(const SoftbusDevice *dev) { return dev ? dev->auth_port : 0; }
guint16 softbus_device_get_session_port(const SoftbusDevice *dev) { return dev ? dev->session_port : 0; }
guint16 softbus_device_get_proxy_port(const SoftbusDevice *dev) { return dev ? dev->proxy_port : 0; }
const gchar* softbus_device_get_ble_mac(const SoftbusDevice *dev) { return dev ? dev->ble_mac : NULL; }
const gchar* softbus_device_get_peer_ip(const SoftbusDevice *dev) { return dev ? dev->peer_ip : NULL; }

void softbus_device_set_peer_ip(SoftbusDevice *dev, const gchar *ip) {
  if (dev == NULL) return;
  g_free(dev->peer_ip);
  dev->peer_ip = g_strdup(ip);
}

/* ============================ Beacon (de)serialization ============================ */

/* json-glib 1.x removed json_to_data() — serialize via JsonGenerator. */
static gchar* _node_to_data(JsonNode *root, gboolean pretty) {
  JsonGenerator *gen = json_generator_new();
  json_generator_set_pretty(gen, pretty);
  json_generator_set_root(gen, root);
  gchar *out = json_generator_to_data(gen, NULL);
  g_object_unref(gen);
  return out;
}

gchar* softbus_device_pack_beacon(const SoftbusDevice *dev, GError **error) {
  if (dev == NULL) {
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "dev is NULL");
    return NULL;
  }

  JsonObject *obj = json_object_new();
  if (dev->device_id)
    json_object_set_string_member(obj, SOFTBUS_JSON_DEVICE_ID, dev->device_id);
  if (dev->device_name)
    json_object_set_string_member(obj, SOFTBUS_JSON_DEVICE_NAME, dev->device_name);
  json_object_set_int_member(obj, SOFTBUS_JSON_DEVICE_TYPE, (gint64)dev->device_type);
  json_object_set_int_member(obj, SOFTBUS_JSON_CAPABILITIES, (gint64)dev->capabilities);
  json_object_set_int_member(obj, SOFTBUS_JSON_AUTH_PORT, (gint64)dev->auth_port);
  json_object_set_int_member(obj, SOFTBUS_JSON_SESSION_PORT, (gint64)dev->session_port);
  json_object_set_int_member(obj, SOFTBUS_JSON_PROXY_PORT, (gint64)dev->proxy_port);
  if (dev->ble_mac)
    json_object_set_string_member(obj, SOFTBUS_JSON_BLE_MAC, dev->ble_mac);

  JsonNode *root = json_node_new(JSON_NODE_OBJECT);
  json_node_take_object(root, obj);

  gchar *out = _node_to_data(root, TRUE);  /* pretty print */
  json_node_free(root);
  return out;
}

SoftbusDevice* softbus_device_parse_beacon(const gchar *json, gsize len, GError **error) {
  if (json == NULL) {
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "json is NULL");
    return NULL;
  }

  JsonParser *parser = json_parser_new();
  gboolean ok = json_parser_load_from_data(parser, json, (gssize)len, error);
  if (!ok) {
    g_object_unref(parser);  /* json-glib 1.x: parser is a GObject */
    return NULL;
  }

  JsonNode *root = json_parser_get_root(parser);
  if (root == NULL || !JSON_NODE_HOLDS_OBJECT(root)) {
    g_object_unref(parser);
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "beacon is not a JSON object");
    return NULL;
  }

  JsonObject *obj = json_node_get_object(root);
  SoftbusDevice *dev = softbus_device_new();

  if (json_object_has_member(obj, SOFTBUS_JSON_DEVICE_ID)) {
    const gchar *s = json_object_get_string_member(obj, SOFTBUS_JSON_DEVICE_ID);
    if (s) dev->device_id = g_strdup(s);
  }
  if (json_object_has_member(obj, SOFTBUS_JSON_DEVICE_NAME)) {
    const gchar *s = json_object_get_string_member(obj, SOFTBUS_JSON_DEVICE_NAME);
    if (s) dev->device_name = g_strdup(s);
  }
  if (json_object_has_member(obj, SOFTBUS_JSON_DEVICE_TYPE))
    dev->device_type = (SoftbusDeviceType)json_object_get_int_member(obj, SOFTBUS_JSON_DEVICE_TYPE);
  if (json_object_has_member(obj, SOFTBUS_JSON_CAPABILITIES))
    dev->capabilities = (guint32)json_object_get_int_member(obj, SOFTBUS_JSON_CAPABILITIES);
  if (json_object_has_member(obj, SOFTBUS_JSON_AUTH_PORT))
    dev->auth_port = (guint16)json_object_get_int_member(obj, SOFTBUS_JSON_AUTH_PORT);
  if (json_object_has_member(obj, SOFTBUS_JSON_SESSION_PORT))
    dev->session_port = (guint16)json_object_get_int_member(obj, SOFTBUS_JSON_SESSION_PORT);
  if (json_object_has_member(obj, SOFTBUS_JSON_PROXY_PORT))
    dev->proxy_port = (guint16)json_object_get_int_member(obj, SOFTBUS_JSON_PROXY_PORT);
  if (json_object_has_member(obj, SOFTBUS_JSON_BLE_MAC)) {
    const gchar *s = json_object_get_string_member(obj, SOFTBUS_JSON_BLE_MAC);
    if (s) dev->ble_mac = g_strdup(s);
  }

  /* A beacon without a device id is unusable for auth. */
  if (dev->device_id == NULL) {
    softbus_device_unref(dev);
    g_object_unref(parser);
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "beacon missing 'deviceId'");
    return NULL;
  }

  g_object_unref(parser);
  return dev;
}

gchar* softbus_device_to_string(const SoftbusDevice *dev) {
  if (dev == NULL) return g_strdup("(null)");
  return g_strdup_printf(
      "id=%s name=%s type=%u caps=0x%x auth=%u session=%u proxy=%u mac=%s peer=%s",
      dev->device_id ?: "?",
      dev->device_name ?: "?",
      dev->device_type,
      dev->capabilities,
      dev->auth_port,
      dev->session_port,
      dev->proxy_port,
      dev->ble_mac ?: "?",
      dev->peer_ip ?: "?");
}
