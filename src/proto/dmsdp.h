/*
 * dmsdp.h - DMSDP control plane (session control text)
 *
 * RE'd from libdmsdp.dll (spec section 6.5): NoCrypto 3-byte TLV
 * framing + an HTTP-like text grammar, the header builder (BuildPkt,
 * 6.5.4-6.5.5), the parser (AnalyzePkt, 6.5.7) and a minimal client
 * FSM for the M3 stand flow (SETUP -> SetupReply -> PLAY ->
 * CommonReply -> READY, 6.5.12).
 *
 * Framing (spec 6.5.1):
 *
 *   [1 B type][u16 BE N][N B text]
 *
 * type 0x00 = NoCrypto, N <= 0x5DC (1500).
 *
 * Text (spec 6.5.2):
 *
 *   <start line>\r\n <header>... \r\n
 *
 * The start line is one of the 8 method lines or `DMSDP/1.0 200 OK`;
 * the trailing blank CRLF is always present.
 *
 * Builder fidelity (spec 6.5.4-6.5.6): fixed header order (CSeq,
 * service triple, crypto quad, Fillp/Codec/TCP, Backup/Simple/
 * PolyPackage, UdpKA/KaRetry, Transport), ports printed lo-hi, the
 * combined Transport line (b14) overrides the client-only line (b13).
 *
 * Parser fidelity (spec 6.5.7): string values are stored with the
 * leading space after the colon stripped (AnalyzeStringPara skips it
 * once before the copy); unknown keys are silently ignored;
 * Codec/KaRetry values are soft-ignored (the OR'd flag bit is
 * cleared); parse_integer degenerates: "3" -> -1, " 3" -> 3,
 * " " -> 0.
 */

#pragma once

#include <glib.h>

G_BEGIN_DECLS

#define DMSDP_FRAME_TYPE_NOCRYPTO 0x00
#define DMSDP_FRAME_MAX_PAYLOAD 0x5dc /* 1500 */
#define DMSDP_TEXT_MAX 0x578 /* BuildPkt fixed buffer (1400 B) */

/* Wire method types (spec 6.5.2) */
enum {
  DMSDP_TYPE_OPTIONS = 0,
  DMSDP_TYPE_SETUP = 1,
  DMSDP_TYPE_PLAY = 2,
  DMSDP_TYPE_TEARDOWN = 3,
  DMSDP_TYPE_SET_PARAMETER = 4,
  DMSDP_TYPE_GET_PARAMETER = 5,
  DMSDP_TYPE_RESETUP = 6,
  DMSDP_TYPE_TRIGGER_RECONN = 7,
  DMSDP_TYPE_RESPONSE = 8,
};

/* Encoder flag space (spec 6.5.5) */
#define DMSDP_FLAG_CSEQ 0x00000001u
#define DMSDP_FLAG_CRYPTO_VER 0x00000002u
#define DMSDP_FLAG_CRYPTO_SWITCH 0x00000004u
#define DMSDP_FLAG_CRYPTO_ALG 0x00000008u
#define DMSDP_FLAG_CRYPTO_ABILITY 0x00000010u
#define DMSDP_FLAG_UDP_KA 0x00000020u
#define DMSDP_FLAG_UDP_KA_PORT 0x00000040u /* parser only (no builder line) */
#define DMSDP_FLAG_FILLP 0x00000080u
#define DMSDP_FLAG_CODEC 0x00000100u
#define DMSDP_FLAG_TCP 0x00000200u
#define DMSDP_FLAG_SERVICE_ID 0x00000400u
#define DMSDP_FLAG_SERVICE_TYPE 0x00000800u
#define DMSDP_FLAG_DATA_SESSION_ID 0x00001000u
#define DMSDP_FLAG_TRANSPORT_CLIENT 0x00002000u
#define DMSDP_FLAG_TRANSPORT_COMBINED 0x00004000u
#define DMSDP_FLAG_KA_RETRY 0x00400000u

/* flags2 (encoder) */
#define DMSDP_FLAG2_BACKUP 0x2u
#define DMSDP_FLAG2_SIMPLE 0x8u
#define DMSDP_FLAG2_POLY_PACKAGE 0x10u

/*
 * Encoder message. Mirrors the per-case stack ctx (spec 6.5.5): only
 * the fields whose flag bit is set are emitted.
 */
typedef struct {
  guint32 type; /* 0..8; 8 = response */
  guint32 status; /* 200 (type 8 only) */
  guint32 flags1;
  guint32 flags2; /* DMSDP_FLAG2_* */
  guint32 cseq;
  const gchar *service_id;
  guint32 service_type;
  guint32 data_session_id;
  guint8 crypto_ver;
  guint8 crypto_switch;
  guint8 crypto_ability;
  const gchar *crypto_alg;
  guint8 udp_ka;
  guint8 fillp;
  guint8 tcp;
  guint32 codec;
  guint32 ka_retry;
  guint32 backup;
  guint32 simple;
  guint32 poly_package;
  guint32 client_port_lo;
  guint32 client_port_hi;
  guint32 server_port_lo;
  guint32 server_port_hi;
} DmsdpMsg;

/*
 * Parser out-struct. Layout matches the RE'd field offsets (spec
 * 6.5.3): +0x00 type ... +0x87 poly_package (checked by _Static_assert
 * in dmsdp.c).
 *
 * String fields (crypto_alg, service_id, av_param, video_meta,
 * device_trace_id) are g_malloc'd on success; release them with
 * dmsdp_parsed_free(). Values are stored with the leading space after
 * the colon stripped (the RE skips it once before the copy).
 */
typedef struct {
  guint32 type; /* +0x00 0..8 */
  guint32 flags1; /* +0x04 */
  guint32 flags2; /* +0x08 */
  guint32 trigger_idx; /* +0x0c 1..5, 0 = no body */
  guint32 response_fail; /* +0x10 type 8 with status != 200 */
  guint32 cseq; /* +0x14 */
  guint32 content_length; /* +0x18 */
  guint8 crypto_ver; /* +0x1c */
  guint8 crypto_switch; /* +0x1d */
  const gchar *crypto_alg; /* +0x20 */
  guint8 crypto_ability; /* +0x28 */
  guint8 udp_ka; /* +0x29 */
  guint32 udp_ka_port; /* +0x2c */
  guint32 gps_server_port; /* +0x30 */
  guint8 fillp; /* +0x34 */
  guint8 tcp; /* +0x35 */
  const gchar *service_id; /* +0x38 */
  guint32 service_type; /* +0x40 */
  guint32 data_session_id; /* +0x44 */
  guint32 client_port_lo; /* +0x48 */
  guint32 client_port_hi; /* +0x4c */
  guint32 server_port_lo; /* +0x50 */
  guint32 server_port_hi; /* +0x54 */
  guint32 time_server_port; /* +0x58 */
  guint32 time_us_high; /* +0x5c */
  guint32 time_us_low; /* +0x60 */
  const gchar *av_param; /* +0x68 Video/Audio (Audio overwrites) */
  const gchar *video_meta; /* +0x70 */
  const gchar *device_trace_id; /* +0x78 */
  guint32 multi_trans; /* +0x80 */
  guint8 backup; /* +0x84 */
  guint8 reply_type; /* +0x85 */
  guint8 simple; /* +0x86 */
  guint8 poly_package; /* +0x87 */
} DmsdpParsed;

void dmsdp_parsed_init(DmsdpParsed *p); /* zero */
void dmsdp_parsed_free(DmsdpParsed *p); /* free strings */

/*
 * Parse one DMSDP text block (framing stripped).
 * Returns 0 on success, else a negative RE error code (-2, -4, -5, -9,
 * ...). String fields in `out` are allocated on success.
 */
gint dmsdp_parse(const gchar *buf, gsize len, DmsdpParsed *out);

/*
 * Build one text block (start line + headers + trailing blank CRLF).
 * Returns 0 on success and stores the text length in *out_len; -1 on
 * an invalid message (type > 8, type 8 with status != 200, missing
 * string for a set flag) or cap < text length.
 */
gint dmsdp_build(const DmsdpMsg *msg, guint8 *out, gsize cap, gsize *out_len);

/*
 * Wrap a text block in the 3-byte NoCrypto TLV frame:
 * [0x00][u16 BE N][text], N <= 0x5DC. Returns 0 / -1.
 */
gint dmsdp_frame(const gchar *text, gsize len, guint8 *out, gsize cap,
                 gsize *out_len);

/* Per-case helpers (spec 6.5.6 datasession table) */
void dmsdp_msg_setup(DmsdpMsg *m, guint32 cseq, const gchar *service_id,
                     guint32 service_type, guint32 data_session_id,
                     guint32 backup, guint32 client_port_lo,
                     guint32 client_port_hi);
void dmsdp_msg_setup_reply(DmsdpMsg *m, guint32 cseq,
                           const gchar *service_id, guint32 service_type,
                           guint32 data_session_id, guint32 client_port_lo,
                           guint32 client_port_hi, guint32 server_port_lo,
                           guint32 server_port_hi);
void dmsdp_msg_play(DmsdpMsg *m, guint32 cseq, const gchar *service_id,
                    guint32 service_type, guint32 data_session_id);
void dmsdp_msg_common_reply(DmsdpMsg *m, guint32 cseq,
                            const gchar *service_id, guint32 service_type,
                            guint32 data_session_id);

/*
 * Minimal client FSM for the M3 stand flow (spec 6.5.12):
 *
 *   INIT --send SETUP cseq 0--> WAIT_SETUP_REPLY
 *        --recv reply cseq 0--> SEND_PLAY
 *   SEND_PLAY --send PLAY cseq 1--> WAIT_PLAY_REPLY
 *             --recv reply cseq 1--> READY (further replies ignored)
 *
 * A reply is a type 8 with status 200 and CSeq equal to the pending
 * one; anything else (including a send in a state that does not
 * expect one) -> ERROR.
 */
typedef enum {
  DMSDP_CL_INIT = 0,
  DMSDP_CL_WAIT_SETUP_REPLY,
  DMSDP_CL_SEND_PLAY,
  DMSDP_CL_WAIT_PLAY_REPLY,
  DMSDP_CL_READY,
  DMSDP_CL_ERROR,
} DmsdpClientState;

typedef struct _DmsdpClient DmsdpClient;

DmsdpClient *dmsdp_client_new(void);
void dmsdp_client_free(DmsdpClient *c);
DmsdpClientState dmsdp_client_state(const DmsdpClient *c);

/* FSM check + dmsdp_build + dmsdp_frame. 0 on success (framed wire
 * bytes in out), -1 on FSM violation or build error. */
gint dmsdp_client_send(DmsdpClient *c, const DmsdpMsg *msg, guint8 *out,
                       gsize cap, gsize *out_len);

/* Accept a parsed reply. 0 = accepted / ignored, -1 = ERROR state. */
gint dmsdp_client_recv(DmsdpClient *c, const DmsdpParsed *p);

G_END_DECLS
