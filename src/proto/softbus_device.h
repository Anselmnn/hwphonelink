/*
 * softbus_device.h - Device record + discovery beacon (CoAP JSON)
 *
 * Discovery (spec §3.1, §12.2): devices publish a JSON beacon over CoAP
 * multicast 224.0.1.187:5683 (and/or BLE advertising TLV §3.2).
 *
 * Beacon schema (mock phone fixture, spec §12.2):
 * {
 *   "deviceId": "mock-phone-001",
 *   "deviceName": "HUAWEI P40 Pro",
 *   "deviceType": 1,
 *   "capabilities": 15,
 *   "authPort": 45678,
 *   "sessionPort": 45679,
 *   "proxyPort": 45680,
 *   "bleMac": "aa:bb:cc:dd:ee:ff"
 * }
 */

#pragma once

#include <glib.h>
#include "softbus_defs.h"

typedef struct {
  guint refcount;

  gchar *device_id;
  gchar *device_name;
  SoftbusDeviceType device_type;
  guint32 capabilities;   /* SOFTBUS_CAP_* bitmap */

  /* Endpoints advertised by the peer (dynamic ports, spec §2.2) */
  guint16 auth_port;
  guint16 session_port;
  guint16 proxy_port;

  gchar *ble_mac;

  /* Peer address as seen from discovery (multicast source) */
  gchar *peer_ip;
} SoftbusDevice;

SoftbusDevice* softbus_device_new(void);
SoftbusDevice* softbus_device_ref(SoftbusDevice *dev);
void softbus_device_unref(SoftbusDevice *dev);

/* Accessors */
const gchar* softbus_device_get_id(const SoftbusDevice *dev);
const gchar* softbus_device_get_name(const SoftbusDevice *dev);
SoftbusDeviceType softbus_device_get_type(const SoftbusDevice *dev);
guint32 softbus_device_get_capabilities(const SoftbusDevice *dev);
guint16 softbus_device_get_auth_port(const SoftbusDevice *dev);
guint16 softbus_device_get_session_port(const SoftbusDevice *dev);
guint16 softbus_device_get_proxy_port(const SoftbusDevice *dev);
const gchar* softbus_device_get_ble_mac(const SoftbusDevice *dev);
const gchar* softbus_device_get_peer_ip(const SoftbusDevice *dev);

/* Set peer_ip (discovery fills it from the multicast source address). */
void softbus_device_set_peer_ip(SoftbusDevice *dev, const gchar *ip);

/*
 * Encode a local device record into a beacon JSON string.
 * Returns newly-allocated string (or NULL + error).
 */
gchar* softbus_device_pack_beacon(const SoftbusDevice *dev, GError **error);

/*
 * Parse a beacon JSON payload received from a peer.
 * Returns a new SoftbusDevice, or NULL + error if the payload is not a
 * valid beacon (wrong keys / types).
 */
SoftbusDevice* softbus_device_parse_beacon(const gchar *json, gsize len,
                                           GError **error);

/* Human-readable dump (for logs). */
gchar* softbus_device_to_string(const SoftbusDevice *dev);
