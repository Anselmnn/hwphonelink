/*
 * softbus_crypto.h - Crypto primitives for dsoftbus (OpenSSL)
 *
 * - HKDF-SHA256 session key derivation (spec §4.2: AuthGeneratePsk /
 *   ComputeAndSavePsk → HKDF)
 * - AES-256-GCM for the data plane (spec §10.3)
 * - HMAC-SHA256 for PSK-mode authentication (replay stand / mock phone;
 *   cloud HiChain V1/V2 is a separate adapter, M5)
 */

#pragma once

#include <glib.h>
#include "softbus_defs.h"

/*
 * HKDF-SHA256.
 * @ikm  input key material (e.g. PSK, HiChain shared secret)
 * @salt optional (NULL = empty salt)
 * @info context string (e.g. SOFTBUS_HKDF_INFO_CONTROL)
 * @out  exactly @out_len bytes derived (<= 255 for SHA256)
 * Returns TRUE on success.
 */
gboolean softbus_hkdf_sha256(const guint8 *ikm, gsize ikm_len,
                             const guint8 *salt, gsize salt_len,
                             const gchar *info,
                             guint8 *out, gsize out_len);

/*
 * HKDF with deterministic session salt: sort(device_id_a, device_id_b)
 * concatenated. Both sides derive identical keys.
 */
gboolean softbus_hkdf_session_keys(const gchar *device_id_a,
                                   const gchar *device_id_b,
                                   const guint8 *ikm, gsize ikm_len,
                                   guint8 control_key[SOFTBUS_SESSION_KEY_LEN],
                                   guint8 data_key[SOFTBUS_SESSION_KEY_LEN]);

/*
 * AES-256-GCM encrypt.
 * @plaintext @pt_len → @ciphertext (same size, in-place OK) + @tag
 * @iv @iv_len (use SOFTBUS_GCM_IV_LEN), @aad optional additional data.
 */
gboolean softbus_aes_gcm_encrypt(const guint8 *key, gsize key_len,
                                 const guint8 *iv, gsize iv_len,
                                 const guint8 *aad, gsize aad_len,
                                 const guint8 *plaintext, gsize pt_len,
                                 guint8 *ciphertext,
                                 guint8 tag[SOFTBUS_GCM_TAG_LEN]);

/*
 * AES-256-GCM decrypt (verifies tag).
 * Returns FALSE if the tag check fails (tampering / wrong key).
 */
gboolean softbus_aes_gcm_decrypt(const guint8 *key, gsize key_len,
                                 const guint8 *iv, gsize iv_len,
                                 const guint8 *aad, gsize aad_len,
                                 const guint8 *ciphertext, gsize ct_len,
                                 const guint8 tag[SOFTBUS_GCM_TAG_LEN],
                                 guint8 *plaintext);

/*
 * HMAC-SHA256. Output is exactly 32 bytes.
 */
gboolean softbus_hmac_sha256(const guint8 *key, gsize key_len,
                             const guint8 *data, gsize data_len,
                             guint8 out[32]);

/*
 * Random bytes (CSPRNG).
 */
gboolean softbus_random_bytes(guint8 *out, gsize len);

/* Hex encode/decode helpers */
gchar* softbus_to_hex(const guint8 *data, gsize len);
gboolean softbus_from_hex(const gchar *hex, guint8 *out, gsize out_cap, gsize *out_len);
