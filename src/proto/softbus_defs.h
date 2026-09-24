/*
 * softbus_defs.h - dsoftbus protocol constants (Huawei Multi-Screen)
 *
 * Values from static RE of PCManager 14.0.7.260 + EMUI 12 P40 Pro,
 * cross-checked against OpenHarmony dsoftbus. See:
 *   /home/tech/hw-re/docs/protocol/multiscreen-spec.md
 */

#pragma once

#include <stdint.h>

/* ============================ Frame (TLV) ============================ */

/* Magic 0x5342 = "SB" (SoftBus) — first two bytes of every frame */
#define SOFTBUS_FRAME_MAGIC_0 0x53
#define SOFTBUS_FRAME_MAGIC_1 0x42

#define SOFTBUS_FRAME_VERSION 1

/* Header: Magic(2) Version(1) Flags(1) Length(4, BE) */
/* Body:    SessionId(8) SeqNum(4, BE) Type(1) Flags(1) ExtLen(2, BE) Payload */
#define SOFTBUS_FRAME_HEADER_SIZE 8    /* magic..length */
#define SOFTBUS_FRAME_SESSION_ID_SIZE 8
#define SOFTBUS_FRAME_FIXED_BODY_SIZE (SOFTBUS_FRAME_SESSION_ID_SIZE + 4 + 1 + 1 + 2)
#define SOFTBUS_FRAME_MIN_SIZE (SOFTBUS_FRAME_HEADER_SIZE + SOFTBUS_FRAME_FIXED_BODY_SIZE)

/* Frame-level flags (Flags byte at offset 2) */
#define SOFTBUS_FRAME_FLAG_FIN  (1u << 0)  /* last frame of a message */
#define SOFTBUS_FRAME_FLAG_ACK  (1u << 1)  /* ack/reliability flag */
#define SOFTBUS_FRAME_FLAG_ENC  (1u << 2)  /* payload encrypted */
#define SOFTBUS_FRAME_FLAG_COMP (1u << 3)  /* payload compressed */

/* Per-packet flags (Flags byte after Type) */
#define SOFTBUS_PKT_FLAG_NONE 0u

/* Max payload per frame (keep under typical MTU for UDP path) */
#define SOFTBUS_FRAME_MAX_PAYLOAD 65507

/* ============================ Session types ============================
 * From softbus_trans_def.h / Session Interface v1.0 (spec §5.2)
 */
typedef enum {
  SOFTBUS_SESSION_MESSAGE = 1,   /* small reliable messages (TCP/proxy) */
  SOFTBUS_SESSION_BYTES = 2,     /* generic byte stream */
  SOFTBUS_SESSION_FILE = 3,      /* large file transfer (FT protocol) */
  SOFTBUS_SESSION_STREAM = 4,    /* real-time A/V (UDP) */
  SOFTBUS_SESSION_D2D = 10,      /* device-to-device control (auth chan) */
} SoftbusSessionType;

/* ============================ Device types ============================ */
typedef enum {
  SOFTBUS_DEVTYPE_PHONE = 1,
  SOFTBUS_DEVTYPE_PC = 2,
  SOFTBUS_DEVTYPE_TV = 3,
  SOFTBUS_DEVTYPE_WATCH = 4,
} SoftbusDeviceType;

/* Capability bitmap (BLE adv type 0x4, spec §3.1) */
#define SOFTBUS_CAP_CASTPLUS    (1u << 0)  /* 0x01 */
#define SOFTBUS_CAP_DVKIT       (1u << 1)  /* 0x02 */
#define SOFTBUS_CAP_OSD         (1u << 2)  /* 0x04 */
#define SOFTBUS_CAP_MULTISCREEN (1u << 3)  /* 0x08 */

/* ============================ Discovery ============================ */

/* CoAP discovery (spec §3.1): standard CoAP multicast */
#define SOFTBUS_COAP_MCAST_ADDR "224.0.1.187"
#define SOFTBUS_COAP_PORT 5683

/* JSON keys of the discovery beacon (spec §12.2, auth_session_json.c) */
#define SOFTBUS_JSON_DEVICE_ID     "deviceId"
#define SOFTBUS_JSON_DEVICE_NAME   "deviceName"
#define SOFTBUS_JSON_DEVICE_TYPE   "deviceType"
#define SOFTBUS_JSON_CAPABILITIES  "capabilities"
#define SOFTBUS_JSON_AUTH_PORT     "authPort"
#define SOFTBUS_JSON_SESSION_PORT  "sessionPort"
#define SOFTBUS_JSON_PROXY_PORT    "proxyPort"
#define SOFTBUS_JSON_BLE_MAC       "bleMac"

/* Negotiation JSON keys (spec §5.4, libsoftbus_server.dll strings) */
#define SOFTBUS_JSON_BUSINESS_TYPE  "BUSINESS_TYPE"
#define SOFTBUS_JSON_MY_CHANNEL_ID  "MY_CHANNEL_ID"
#define SOFTBUS_JSON_MY_PORT        "MY_PORT"
#define SOFTBUS_JSON_BUS_NAME       "BUS_NAME"
#define SOFTBUS_JSON_CLIENT_BUS_NAME "CLIENT_BUS_NAME"
#define SOFTBUS_JSON_API_VERSION    "API_VERSION"
#define SOFTBUS_JSON_STREAM_TYPE    "STREAM_TYPE"

#define SOFTBUS_BUS_NAME_PC       "com.huawei.multiscreen"
#define SOFTBUS_BUS_NAME_PHONE    "com.huawei.mirror"

/* ============================ Auth (HiChain FSM) ============================
 * 4-state FSM from auth_session_fsm.c (spec §4.1)
 */
typedef enum {
  SOFTBUS_AUTH_STATE_IDLE = 0,
  SOFTBUS_AUTH_STATE_SYNC_NEGOTIATION,  /* exchange protocol version */
  SOFTBUS_AUTH_STATE_SYNC_DEVICE_ID,    /* exchange device IDs */
  SOFTBUS_AUTH_STATE_DEVICE_AUTH,       /* HiChain / PSK authentication */
  SOFTBUS_AUTH_STATE_SYNC_DEVICE_INFO,  /* device info + session keys */
  SOFTBUS_AUTH_STATE_DONE,
  SOFTBUS_AUTH_STATE_FAILED,
} SoftbusAuthState;

/* FSM timing (spec §4.1): ~30s per state, 3 retries at 300ms */
#define SOFTBUS_AUTH_STATE_TIMEOUT_MS 30000
#define SOFTBUS_AUTH_RETRIES 3
#define SOFTBUS_AUTH_RETRY_INTERVAL_MS 300

/* Auth JSON keys (auth_session_json.c) */
#define SOFTBUS_JSON_AUTH_STATE       "authState"
#define SOFTBUS_JSON_AUTH_ID          "authId"
#define SOFTBUS_JSON_PROTO_VERSION    "protoVersion"
#define SOFTBUS_JSON_DEVICE_ID_SHORT  "deviceId"
#define SOFTBUS_JSON_AUTH_TYPE        "authType"
#define SOFTBUS_JSON_PSK_ID           "pskId"
#define SOFTBUS_JSON_NONCE            "nonce"
#define SOFTBUS_JSON_SIG              "signature"
#define SOFTBUS_JSON_SESSION_KEY_LEN  "sessionKeyLen"

/* authType values */
#define SOFTBUS_AUTH_TYPE_HICHAIN_V1   1
#define SOFTBUS_AUTH_TYPE_IDENTITY_V2  2
#define SOFTBUS_AUTH_TYPE_PSK          3  /* local PSK (replay stand / mock) */

#define SOFTBUS_PROTO_VERSION 1

/* Session key size (HKDF-SHA256 output, AES-256-GCM) */
#define SOFTBUS_SESSION_KEY_LEN 32
#define SOFTBUS_GCM_IV_LEN 12
#define SOFTBUS_GCM_TAG_LEN 16

/* HKDF info strings */
#define SOFTBUS_HKDF_INFO_CONTROL "softbus-control-key"
#define SOFTBUS_HKDF_INFO_DATA    "softbus-data-key"

/* ============================ Error codes ============================
 * From PC Manager logs / softbus error defs (spec §11)
 */
#define SOFTBUS_ERR_OK                0
#define SOFTBUS_ERR_INVALID_PARAM    (-1)
#define SOFTBUS_ERR_AUTH_FAILED      1001   /* HiChain authentication failed */
#define SOFTBUS_ERR_IDENTITY_UNAVAIL 1002   /* Identity Service V2 unavailable */
#define SOFTBUS_ERR_DISC_TIMEOUT     2001   /* BLE/CoAP timeout */
#define SOFTBUS_ERR_CAP_MISMATCH     2002   /* capability mismatch */
#define SOFTBUS_ERR_CHANNEL_CREATE   3001   /* channel creation failed */
#define SOFTBUS_ERR_PEER_OFFLINE     3002   /* peer offline / session closed */
#define SOFTBUS_ERR_FRAME            4001   /* malformed frame */
#define SOFTBUS_ERR_FRAME_MAGIC      4002
#define SOFTBUS_ERR_FRAME_LEN        4003
#define SOFTBUS_ERR_IO               5001
