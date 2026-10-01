/*
 * fillp_frame.c - fillp (Dstream) packet codec
 *
 * Pure buffer codec — see fillp_frame.h for the wire format. All
 * multi-byte integers are big-endian on the wire.
 */

#include "proto/fillp_frame.h"
#include "proto/softbus_crypto.h"

#include <string.h>

/* ============================ BE helpers ============================ */

static void put_u16(guint8 *p, guint16 v) {
  p[0] = (guint8)(v >> 8);
  p[1] = (guint8)(v & 0xff);
}

static void put_u32(guint8 *p, guint32 v) {
  p[0] = (guint8)(v >> 24);
  p[1] = (guint8)(v >> 16);
  p[2] = (guint8)(v >> 8);
  p[3] = (guint8)(v & 0xff);
}

static void put_u64(guint8 *p, guint64 v) {
  put_u32(p, (guint32)(v >> 32));
  put_u32(p + 4, (guint32)(v & 0xffffffff));
}

static guint16 get_u16(const guint8 *p) {
  return (guint16)(((guint16)p[0] << 8) | (guint16)p[1]);
}

static guint32 get_u32(const guint8 *p) {
  return ((guint32)get_u16(p) << 16) | (guint32)get_u16(p + 2);
}

static guint64 get_u64(const guint8 *p) {
  return ((guint64)get_u32(p) << 32) | (guint64)get_u32(p + 4);
}

/* ============================ Head ============================ */

gsize fillp_encode_head(guint8 *buf, FpPktType type, guint16 extra,
                        guint16 data_len, guint32 pkt_num, guint32 seq_num) {
  guint16 flag = ((guint16)(type & 0x0f) << 8) | (extra & 0x00ff);
  put_u16(buf, flag);
  put_u16(buf + 2, data_len);
  put_u32(buf + 4, pkt_num);
  put_u32(buf + 8, seq_num);
  return FILLP_HLEN;
}

gboolean fillp_decode_head(const guint8 *buf, gsize len, FpPktType *type_out,
                           guint16 *flags_out, guint16 *data_len_out,
                           guint32 *pkt_num_out, guint32 *seq_num_out) {
  if (len < FILLP_HLEN) return FALSE;
  guint16 flag = get_u16(buf);
  if (((flag >> 12) & 0x0f) != 0) return FALSE; /* version must be 0 */
  if (type_out) *type_out = (FpPktType)((flag >> 8) & 0x0f);
  if (flags_out) *flags_out = flag & 0x00ff;
  if (data_len_out) *data_len_out = get_u16(buf + 2);
  if (pkt_num_out) *pkt_num_out = get_u32(buf + 4);
  if (seq_num_out) *seq_num_out = get_u32(buf + 8);
  return TRUE;
}

gboolean fp_num_isbigger(guint32 a, guint32 b) {
  return (gint32)(a - b) > 0;
}

/* ============================ Management ============================ */

gssize fillp_encode_conn_req(guint8 *buf, gsize cap,
                             guint32 cookie_preserve_time_us,
                             guint32 send_cache, guint32 recv_cache,
                             guint64 timestamp_us) {
  if (cap < FILLP_HLEN + FILLP_CONN_REQ_LEN) return -1;
  fillp_encode_head(buf, FP_PKT_CONN_REQ, 0, FILLP_CONN_REQ_LEN, 0, 0);
  guint8 *p = buf + FILLP_HLEN;
  put_u32(p, cookie_preserve_time_us);
  put_u32(p + 4, send_cache);
  put_u32(p + 8, recv_cache);
  put_u64(p + 12, timestamp_us);
  return FILLP_HLEN + FILLP_CONN_REQ_LEN;
}

gboolean fillp_decode_conn_req(const guint8 *buf, gsize len,
                               guint32 *cookie_preserve_time_us,
                               guint32 *send_cache, guint32 *recv_cache,
                               guint64 *timestamp_us) {
  if (len != FILLP_HLEN + FILLP_CONN_REQ_LEN) return FALSE;
  const guint8 *p = buf + FILLP_HLEN;
  if (cookie_preserve_time_us) *cookie_preserve_time_us = get_u32(p);
  if (send_cache) *send_cache = get_u32(p + 4);
  if (recv_cache) *recv_cache = get_u32(p + 8);
  if (timestamp_us) *timestamp_us = get_u64(p + 12);
  return TRUE;
}

gssize fillp_encode_conn_req_ack(guint8 *buf, gsize cap, guint16 tag_cookie,
                                 const guint8 cookie[FILLP_COOKIE_LEN],
                                 guint64 timestamp_us) {
  if (cap < FILLP_HLEN + FILLP_CONN_REQ_ACK_LEN) return -1;
  fillp_encode_head(buf, FP_PKT_CONN_REQ_ACK, 0, FILLP_CONN_REQ_ACK_LEN, 0, 0);
  guint8 *p = buf + FILLP_HLEN;
  put_u16(p, tag_cookie);
  put_u16(p + 2, FILLP_COOKIE_LEN);
  memcpy(p + 4, cookie, FILLP_COOKIE_LEN);
  put_u64(p + 4 + FILLP_COOKIE_LEN, timestamp_us);
  return FILLP_HLEN + FILLP_CONN_REQ_ACK_LEN;
}

gboolean fillp_decode_conn_req_ack(const guint8 *buf, gsize len,
                                   guint16 *tag_cookie,
                                   guint8 cookie_out[FILLP_COOKIE_LEN],
                                   guint64 *timestamp_us) {
  if (len != FILLP_HLEN + FILLP_CONN_REQ_ACK_LEN) return FALSE;
  const guint8 *p = buf + FILLP_HLEN;
  if (tag_cookie) *tag_cookie = get_u16(p);
  if (get_u16(p + 2) != FILLP_COOKIE_LEN) return FALSE;
  if (cookie_out) memcpy(cookie_out, p + 4, FILLP_COOKIE_LEN);
  if (timestamp_us) *timestamp_us = get_u64(p + 4 + FILLP_COOKIE_LEN);
  return TRUE;
}

gssize fillp_encode_conn_confirm(guint8 *buf, gsize cap, guint16 tag_cookie,
                                 const guint8 cookie[FILLP_COOKIE_LEN],
                                 const guint8 local_addr[FILLP_ADDR_LEN]) {
  if (cap < FILLP_HLEN + FILLP_CONN_CONFIRM_LEN) return -1;
  fillp_encode_head(buf, FP_PKT_CONN_CONFIRM, 0, FILLP_CONN_CONFIRM_LEN, 0, 0);
  guint8 *p = buf + FILLP_HLEN;
  put_u16(p, tag_cookie);
  put_u16(p + 2, FILLP_COOKIE_LEN);
  memcpy(p + 4, cookie, FILLP_COOKIE_LEN);
  memcpy(p + 4 + FILLP_COOKIE_LEN, local_addr, FILLP_ADDR_LEN);
  return FILLP_HLEN + FILLP_CONN_CONFIRM_LEN;
}

gboolean fillp_decode_conn_confirm(const guint8 *buf, gsize len,
                                   guint16 *tag_cookie,
                                   guint8 cookie_out[FILLP_COOKIE_LEN],
                                   guint8 local_addr_out[FILLP_ADDR_LEN]) {
  if (len != FILLP_HLEN + FILLP_CONN_CONFIRM_LEN) return FALSE;
  const guint8 *p = buf + FILLP_HLEN;
  if (tag_cookie) *tag_cookie = get_u16(p);
  if (get_u16(p + 2) != FILLP_COOKIE_LEN) return FALSE;
  if (cookie_out) memcpy(cookie_out, p + 4, FILLP_COOKIE_LEN);
  if (local_addr_out)
    memcpy(local_addr_out, p + 4 + FILLP_COOKIE_LEN, FILLP_ADDR_LEN);
  return TRUE;
}

gssize fillp_encode_conn_confirm_ack(guint8 *buf, gsize cap,
                                     guint32 send_cache, guint32 recv_cache,
                                     guint32 pkt_size,
                                     const guint8 local_addr[FILLP_ADDR_LEN]) {
  if (cap < FILLP_HLEN + FILLP_CONN_CONFIRM_ACK_LEN) return -1;
  fillp_encode_head(buf, FP_PKT_CONN_CONFIRM_ACK, 0, FILLP_CONN_CONFIRM_ACK_LEN,
                    0, 0);
  guint8 *p = buf + FILLP_HLEN;
  put_u32(p, send_cache);
  put_u32(p + 4, recv_cache);
  put_u32(p + 8, pkt_size);
  memcpy(p + 12, local_addr, FILLP_ADDR_LEN);
  return FILLP_HLEN + FILLP_CONN_CONFIRM_ACK_LEN;
}

gboolean fillp_decode_conn_confirm_ack(const guint8 *buf, gsize len,
                                       guint32 *send_cache,
                                       guint32 *recv_cache,
                                       guint32 *pkt_size,
                                       guint8 local_addr_out[FILLP_ADDR_LEN]) {
  if (len != FILLP_HLEN + FILLP_CONN_CONFIRM_ACK_LEN) return FALSE;
  const guint8 *p = buf + FILLP_HLEN;
  if (send_cache) *send_cache = get_u32(p);
  if (recv_cache) *recv_cache = get_u32(p + 4);
  if (pkt_size) *pkt_size = get_u32(p + 8);
  if (local_addr_out) memcpy(local_addr_out, p + 12, FILLP_ADDR_LEN);
  return TRUE;
}

gssize fillp_encode_nack(guint8 *buf, gsize cap, FpPktType type,
                         guint32 begin_pkt, guint32 end_pkt, guint32 seq_num,
                         guint64 random_num) {
  if (cap < FILLP_HLEN + FILLP_NACK_LEN) return -1;
  /* payload.lastPktNum = end - 1: "retransmit (begin, end)" */
  fillp_encode_head(buf, type, 0, FILLP_NACK_LEN, begin_pkt, seq_num);
  guint8 *p = buf + FILLP_HLEN;
  put_u32(p, end_pkt - 1);
  put_u64(p + 4, random_num);
  return FILLP_HLEN + FILLP_NACK_LEN;
}

gboolean fillp_decode_nack(const guint8 *buf, gsize len, guint32 *begin_pkt,
                           guint32 *end_pkt, guint32 *seq_num) {
  if (len != FILLP_HLEN + FILLP_NACK_LEN) return FALSE;
  guint32 last_payload;
  if (!fillp_decode_head(buf, len, NULL, NULL, NULL, begin_pkt, seq_num))
    return FALSE;
  last_payload = get_u32(buf + FILLP_HLEN);
  if (end_pkt) *end_pkt = last_payload + 1;
  return TRUE;
}

gssize fillp_encode_pack(guint8 *buf, gsize cap, guint32 ack_seq,
                         guint32 ack_pkt, guint32 lost_seq,
                         guint32 rcv_list_bytes) {
  if (cap < FILLP_HLEN + FILLP_PACK_LEN) return -1;
  fillp_encode_head(buf, FP_PKT_PACK, 0, FILLP_PACK_LEN, ack_pkt, ack_seq);
  guint8 *p = buf + FILLP_HLEN;
  put_u16(p, 0);             /* flag */
  put_u16(p + 2, 0);         /* pktLoss */
  put_u32(p + 4, 0);         /* rate */
  put_u32(p + 8, 0);         /* oppositeSetRate */
  put_u32(p + 12, lost_seq); /* lostSeq */
  put_u32(p + 16, 0);        /* reserved (rtt/timestamp) */
  put_u32(p + 20, 0);        /* bgnPktNum */
  put_u32(p + 24, 0);        /* endPktNum */
  put_u16(p + 28, 0);        /* optsOffset */
  put_u32(p + 30, rcv_list_bytes);
  put_u32(p + 34, 0);        /* owdPktSendTs */
  put_u32(p + 38, 0);        /* owdPackDelay */
  put_u32(p + 42, 0);        /* queueingDelay */
  return FILLP_HLEN + FILLP_PACK_LEN;
}

gboolean fillp_decode_pack(const guint8 *buf, gsize len, guint32 *ack_seq,
                           guint32 *ack_pkt, guint32 *lost_seq,
                           guint32 *rcv_list_bytes) {
  if (len < FILLP_HLEN + FILLP_PACK_LEN) return FALSE;
  if (!fillp_decode_head(buf, len, NULL, NULL, NULL, ack_pkt, ack_seq))
    return FALSE;
  const guint8 *p = buf + FILLP_HLEN;
  if (lost_seq) *lost_seq = get_u32(p + 12);
  if (rcv_list_bytes) *rcv_list_bytes = get_u32(p + 30);
  return TRUE;
}

gssize fillp_encode_fin(guint8 *buf, gsize cap, guint16 flag) {
  if (cap < FILLP_HLEN + FILLP_FIN_LEN) return -1;
  fillp_encode_head(buf, FP_PKT_FIN, 0, FILLP_FIN_LEN, 0, 0);
  put_u16(buf + FILLP_HLEN, flag);
  return FILLP_HLEN + FILLP_FIN_LEN;
}

gboolean fillp_decode_fin(const guint8 *buf, gsize len, guint16 *flag) {
  if (len != FILLP_HLEN + FILLP_FIN_LEN) return FALSE;
  if (flag) *flag = get_u16(buf + FILLP_HLEN);
  return TRUE;
}

/* ============================ Cookie ============================ */

void fillp_addr_fill_ipv4(guint8 addr[FILLP_ADDR_LEN], guint16 port,
                          const guint8 ipv4[4]) {
  memset(addr, 0, FILLP_ADDR_LEN);
  put_u16(addr, 2); /* AF_INET */
  put_u16(addr + 2, port);
  memcpy(addr + 4, ipv4, 4);
}

static void cookie_hmac(const guint8 cookie[FILLP_COOKIE_LEN],
                        const guint8 local_addr[FILLP_ADDR_LEN],
                        const guint8 mac_key[32], guint8 out[32]) {
  /* HMAC input = cookie[32..108) || localAddr[28] = 104 bytes. */
  guint8 input[FILLP_COOKIE_LEN - 32 + FILLP_ADDR_LEN];
  memcpy(input, cookie + 32, FILLP_COOKIE_LEN - 32);
  memcpy(input + FILLP_COOKIE_LEN - 32, local_addr, FILLP_ADDR_LEN);
  softbus_hmac_sha256(mac_key, 32, input, sizeof(input), out);
}

void fillp_cookie_fill(guint8 cookie[FILLP_COOKIE_LEN],
                       const guint8 mac_key[32], guint64 gen_time_us,
                       guint32 life_time_us, guint32 local_pkt_seq,
                       guint32 local_msg_seq, guint32 remote_pkt_seq,
                       guint32 remote_msg_seq, guint32 remote_send_cache,
                       guint32 remote_recv_cache, guint16 src_port,
                       guint16 addr_type,
                       const guint8 remote_addr[FILLP_ADDR_LEN],
                       const guint8 local_addr[FILLP_ADDR_LEN]) {
  memset(cookie, 0, FILLP_COOKIE_LEN);
  guint8 *p = cookie;
  /* digest[32] filled last; arr[16] = generation time in the first 8 bytes */
  p += 32;
  put_u64(p, gen_time_us);
  p += 16;
  put_u32(p, life_time_us);
  put_u32(p + 4, local_pkt_seq);
  put_u32(p + 8, remote_pkt_seq);
  put_u32(p + 12, local_msg_seq);
  put_u32(p + 16, remote_msg_seq);
  put_u32(p + 20, remote_send_cache);
  put_u32(p + 24, remote_recv_cache);
  put_u16(p + 28, src_port);
  put_u16(p + 30, addr_type);
  memcpy(p + 32, remote_addr, FILLP_ADDR_LEN);
  cookie_hmac(cookie, local_addr, mac_key, cookie);
}

gboolean fillp_cookie_verify(const guint8 cookie[FILLP_COOKIE_LEN],
                             const guint8 mac_key[32],
                             const guint8 local_addr[FILLP_ADDR_LEN]) {
  guint8 digest[32];
  cookie_hmac(cookie, local_addr, mac_key, digest);
  /* Constant-time comparison. */
  volatile guint acc = 0;
  for (guint i = 0; i < 32; i++) acc |= cookie[i] ^ digest[i];
  return acc == 0;
}
