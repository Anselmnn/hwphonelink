/*
 * vtp_frame.c - VTP (Video Transmission Protocol) frame layer
 *
 * Pure frame codec — see vtp_frame.h for the wire format.
 */

#include "proto/vtp_frame.h"
#include "proto/softbus_crypto.h"

#include <string.h>

static void put_u32(guint8 *p, guint32 v) {
  p[0] = (guint8)(v >> 24);
  p[1] = (guint8)(v >> 16);
  p[2] = (guint8)(v >> 8);
  p[3] = (guint8)(v & 0xff);
}

static guint32 get_u32(const guint8 *p) {
  guint32 v = 0;
  for (int i = 0; i < 4; i++) v = (v << 8) | p[i];
  return v;
}

gsize vtp_common_frame_size(gsize data_len) {
  /* 4 (length prefix) + 12 (nonce) + 16 (header) + data + 16 (tag) */
  return 4 + VTP_NONCE_LEN + VTP_HEADER_LEN + data_len + VTP_TAG_LEN;
}

gsize vtp_build_common_frame(guint8 *out, gsize cap,
                             const guint8 key[VTP_KEY_LEN], guint16 mode,
                             guint16 stream_type, guint16 scene,
                             guint32 timestamp_ns, const guint8 *data,
                             gsize data_len) {
  gsize total = vtp_common_frame_size(data_len);
  if (cap < total) return (gsize)-1;

  guint8 pt[VTP_HEADER_LEN];
  guint32 flags = ((guint32)(mode & 0xf) << 24) | (stream_type & 0xffff);
  put_u32(pt, flags);
  put_u32(pt + 4, timestamp_ns);
  put_u32(pt + 8, (guint32)data_len); /* no ext: payloadLen = dataLen */
  put_u32(pt + 12, (guint32)(scene & 0xffff) << 16);

  gsize pt_len = VTP_HEADER_LEN + data_len;
  guint8 *plain = g_new(guint8, pt_len);
  memcpy(plain, pt, VTP_HEADER_LEN);
  if (data_len > 0) memcpy(plain + VTP_HEADER_LEN, data, data_len);

  guint8 nonce[VTP_NONCE_LEN];
  gboolean ok = softbus_random_bytes(nonce, sizeof(nonce));
  if (ok) {
    put_u32(out, (guint32)(total - 4));
    memcpy(out + 4, nonce, VTP_NONCE_LEN);
    ok = softbus_aes_gcm_encrypt(key, VTP_KEY_LEN, nonce, VTP_NONCE_LEN,
                                 NULL, 0, plain, pt_len,
                                 out + 4 + VTP_NONCE_LEN, out + total - 16);
  }
  g_free(plain);
  return ok ? total : (gsize)-1;
}

gboolean vtp_parse_common_frame(const guint8 *msg, gsize msg_len,
                                const guint8 key[VTP_KEY_LEN],
                                guint16 *mode_out, guint16 *stream_type_out,
                                guint16 *scene_out, guint32 *timestamp_ns_out,
                                guint8 *out, gsize out_cap, gsize *out_len) {
  if (msg_len < 4 + VTP_NONCE_LEN + VTP_HEADER_LEN + VTP_TAG_LEN) return FALSE;
  guint32 n = get_u32(msg);
  /* N = nonce + sealed plaintext + tag; sealed min = header + tag */
  if (n < VTP_NONCE_LEN + VTP_HEADER_LEN + VTP_TAG_LEN) return FALSE;
  if (msg_len != 4 + n) return FALSE;

  const guint8 *nonce = msg + 4;
  gsize ct_len = n - VTP_NONCE_LEN - VTP_TAG_LEN; /* sealed plaintext */
  const guint8 *ct = msg + 4 + VTP_NONCE_LEN;
  const guint8 *tag = msg + 4 + n - VTP_TAG_LEN;

  guint8 *plain = g_new(guint8, ct_len);
  gboolean ok = softbus_aes_gcm_decrypt(key, VTP_KEY_LEN, nonce, VTP_NONCE_LEN,
                                        NULL, 0, ct, ct_len, tag, plain);
  if (!ok) { /* tag check failed: wrong key / tampered */
    g_free(plain);
    return FALSE;
  }

  guint32 flags = get_u32(plain);
  guint32 ts = get_u32(plain + 4);
  guint32 payload_len = get_u32(plain + 8);
  guint32 scene_hi = get_u32(plain + 12);

  /* The stand never uses ext (bit 28); reject frames that do. */
  if (flags & VTP_FLAG_EXT_PRESENT) {
    g_free(plain);
    return FALSE;
  }
  if (payload_len != ct_len - VTP_HEADER_LEN) {
    g_free(plain);
    return FALSE;
  }
  if (payload_len > out_cap) {
    g_free(plain);
    return FALSE;
  }

  if (mode_out) *mode_out = (guint16)((flags >> 24) & 0xf);
  if (stream_type_out) *stream_type_out = (guint16)(flags & 0xffff);
  if (scene_out) *scene_out = (guint16)((scene_hi >> 16) & 0xffff);
  if (timestamp_ns_out) *timestamp_ns_out = ts;
  if (payload_len > 0) memcpy(out, plain + VTP_HEADER_LEN, payload_len);
  if (out_len) *out_len = payload_len;
  g_free(plain);
  return TRUE;
}

void vtp_derive_key(const guint8 *psk, gsize psk_len,
                    guint8 key[VTP_KEY_LEN]) {
  softbus_hkdf_sha256(psk, psk_len, NULL, 0, "vtp-stream-key", key,
                      VTP_KEY_LEN);
}
