/*
 * vtp_frame.h - VTP (Video Transmission Protocol) frame layer
 *
 * RE'd from libsoftbus_stream.so (spec §8.4-8.5). VTP rides on top of a
 * fillp message: one fillp message == one VTP frame. The stand uses the
 * COMMON framing (headerMode 1..3):
 *
 *   [u32 BE N][12B nonce][AES-256-GCM ciphertext][16B tag]
 *
 * where N = 12 + (16 + extSize + dataLen) + 16, i.e. nonce + sealed
 * plaintext (16-byte header + ext + app data) + GCM tag. The 4-byte
 * length prefix is part of the fillp message itself.
 *
 * Sealed 16-byte header (BE):
 *   [0..4)  u32 flags = (extPresent << 28) | ((mode & 0xf) << 24)
 *                        | (streamType & 0xffff)
 *   [4..8)  u32 timestamp (ns)
 *   [8..12) u32 payloadLen = extSize + dataLen
 *   [12..16) u32 (scene & 0xffff) << 16
 *
 * Encryption: AES-256-GCM (EVP_aead_aes_256_gcm in the binary), 12-byte
 * RANDOM nonce per frame, no AAD, 16-byte tag.
 *
 * The 32-byte key is what the app passes to CreateClient/CreateServer /
 * InitVtpInstance in the real stack (derivation lives in the upper
 * softbus layer). Stand derivation (spec §8.7):
 *
 *   key = HKDF-SHA256(ikm = PSK, salt = NULL, info = "vtp-stream-key")
 *
 * Both ends derive it from the same pre-provisioned PSK.
 */

#pragma once

#include <glib.h>

G_BEGIN_DECLS

#define VTP_KEY_LEN    32
#define VTP_NONCE_LEN  12
#define VTP_TAG_LEN    16
#define VTP_HEADER_LEN 16

/* Mode nibble used by the stand (1..3 = COMMON in the binary). */
#define VTP_MODE_COMMON 1

/* Stand header values: no ext, no scene, stream type 0. */
#define VTP_FLAG_EXT_PRESENT 0x10000000u

/*
 * Build a complete VTP frame (4B length prefix + nonce + ct + tag) into
 * @out (>= vtp_common_frame_size(@data_len)); returns total size, or -1
 * on overflow. @mode is the mode nibble, @timestamp_ns is stamped into
 * the header.
 */
gsize vtp_common_frame_size(gsize data_len);
gsize vtp_build_common_frame(guint8 *out, gsize cap,
                             const guint8 key[VTP_KEY_LEN], guint16 mode,
                             guint16 stream_type, guint16 scene,
                             guint32 timestamp_ns, const guint8 *data,
                             gsize data_len);

/*
 * Parse a complete VTP frame (as received from fillp). On success fills
 * the header fields (NULL ok) and the app data into @out (capacity
 * @out_cap; @out_len = actual). Returns FALSE on short buffer, size
 * mismatch, GCM tag failure or payloadLen inconsistency.
 */
gboolean vtp_parse_common_frame(const guint8 *msg, gsize msg_len,
                                const guint8 key[VTP_KEY_LEN],
                                guint16 *mode_out, guint16 *stream_type_out,
                                guint16 *scene_out, guint32 *timestamp_ns_out,
                                guint8 *out, gsize out_cap, gsize *out_len);

/*
 * Stand key derivation: HKDF-SHA256(ikm = @psk, salt = NULL,
 * info = "vtp-stream-key") into @key[32]. Both ends must use the same
 * PSK.
 */
void vtp_derive_key(const guint8 *psk, gsize psk_len,
                    guint8 key[VTP_KEY_LEN]);

G_END_DECLS
