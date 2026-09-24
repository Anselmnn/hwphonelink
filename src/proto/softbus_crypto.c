/*
 * softbus_crypto.c - Crypto primitives for dsoftbus (OpenSSL 3)
 */

#include "softbus_crypto.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <string.h>

/* ============================ HKDF ============================ */

gboolean softbus_hkdf_sha256(const guint8 *ikm, gsize ikm_len,
                             const guint8 *salt, gsize salt_len,
                             const gchar *info,
                             guint8 *out, gsize out_len) {
  if (ikm == NULL || out == NULL || out_len == 0 || out_len > 255) return FALSE;

  /* OpenSSL 3 EVP_KDF (provider-based; the legacy EVP_PKEY_HKDF_* control
   * API was removed in 3.5). */
  EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
  if (kdf == NULL) return FALSE;
  EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
  EVP_KDF_free(kdf);
  if (kctx == NULL) return FALSE;

  OSSL_PARAM params[5];
  guint8 *info_buf = NULL;
  int i = 0;
  params[i++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                 (char *)"SHA256", 0);
  if (ikm_len > 0)
    params[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                                    (void *)ikm, ikm_len);
  if (salt != NULL && salt_len > 0)
    params[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                                    (void *)salt, salt_len);
  if (info != NULL && info[0] != '\0') {
    info_buf = g_malloc((gsize)strlen(info));
    memcpy(info_buf, info, strlen(info));
    params[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                                    info_buf, strlen(info));
  }
  params[i] = OSSL_PARAM_construct_end();

  gboolean ok = EVP_KDF_derive(kctx, out, (size_t)out_len, params) == 1;

  g_free(info_buf);
  EVP_KDF_CTX_free(kctx);
  return ok;
}

gboolean softbus_hkdf_session_keys(const gchar *device_id_a,
                                   const gchar *device_id_b,
                                   const guint8 *ikm, gsize ikm_len,
                                   guint8 control_key[SOFTBUS_SESSION_KEY_LEN],
                                   guint8 data_key[SOFTBUS_SESSION_KEY_LEN]) {
  if (device_id_a == NULL || device_id_b == NULL || ikm == NULL) return FALSE;
  if (control_key == NULL || data_key == NULL) return FALSE;

  /* Deterministic salt = sorted(device_id_a, device_id_b) concatenated.
   * Both sides compute the same salt regardless of who is "local". */
  const gchar *first = device_id_a;
  const gchar *second = device_id_b;
  if (g_strcmp0(device_id_a, device_id_b) > 0) {
    first = device_id_b;
    second = device_id_a;
  }

  gsize salt_len = strlen(first) + strlen(second);
  guint8 *salt = NULL;
  if (salt_len > 0) {
    salt = g_malloc(salt_len);
    memcpy(salt, first, strlen(first));
    memcpy(salt + strlen(first), second, strlen(second));
  }

  gboolean ok = softbus_hkdf_sha256(ikm, ikm_len, salt, salt_len,
                                    SOFTBUS_HKDF_INFO_CONTROL,
                                    control_key, SOFTBUS_SESSION_KEY_LEN) &&
                softbus_hkdf_sha256(ikm, ikm_len, salt, salt_len,
                                    SOFTBUS_HKDF_INFO_DATA,
                                    data_key, SOFTBUS_SESSION_KEY_LEN);

  g_free(salt);
  return ok;
}

/* ============================ AES-256-GCM ============================ */

gboolean softbus_aes_gcm_encrypt(const guint8 *key, gsize key_len,
                                 const guint8 *iv, gsize iv_len,
                                 const guint8 *aad, gsize aad_len,
                                 const guint8 *plaintext, gsize pt_len,
                                 guint8 *ciphertext,
                                 guint8 tag[SOFTBUS_GCM_TAG_LEN]) {
  if (key == NULL || iv == NULL || ciphertext == NULL || tag == NULL) return FALSE;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (ctx == NULL) return FALSE;

  gboolean ok = FALSE;
  int outl = 0, tmp = 0;

  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, NULL) != 1) goto done;
  if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto done;

  /* AAD (additional authenticated data) — no output */
  if (aad != NULL && aad_len > 0 &&
      EVP_EncryptUpdate(ctx, NULL, &outl, aad, (int)aad_len) != 1) goto done;

  if (pt_len > 0 &&
      EVP_EncryptUpdate(ctx, ciphertext, &outl, plaintext, (int)pt_len) != 1) goto done;
  if (EVP_EncryptFinal_ex(ctx, ciphertext + outl, &tmp) != 1) goto done;

  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, SOFTBUS_GCM_TAG_LEN, tag) != 1) goto done;

  ok = TRUE;
done:
  EVP_CIPHER_CTX_free(ctx);
  return ok;
}

gboolean softbus_aes_gcm_decrypt(const guint8 *key, gsize key_len,
                                 const guint8 *iv, gsize iv_len,
                                 const guint8 *aad, gsize aad_len,
                                 const guint8 *ciphertext, gsize ct_len,
                                 const guint8 tag[SOFTBUS_GCM_TAG_LEN],
                                 guint8 *plaintext) {
  if (key == NULL || iv == NULL || ciphertext == NULL || tag == NULL) return FALSE;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (ctx == NULL) return FALSE;

  gboolean ok = FALSE;
  int outl = 0, tmp = 0;

  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, NULL) != 1) goto done;
  if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto done;

  if (aad != NULL && aad_len > 0 &&
      EVP_DecryptUpdate(ctx, NULL, &outl, aad, (int)aad_len) != 1) goto done;

  if (ct_len > 0 &&
      EVP_DecryptUpdate(ctx, plaintext, &outl, ciphertext, (int)ct_len) != 1) goto done;

  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, SOFTBUS_GCM_TAG_LEN, (void *)tag) != 1) goto done;
  if (EVP_DecryptFinal_ex(ctx, plaintext + outl, &tmp) != 1) goto done;  /* fails on tag mismatch */

  ok = TRUE;
done:
  EVP_CIPHER_CTX_free(ctx);
  return ok;
}

/* ============================ HMAC-SHA256 ============================ */

gboolean softbus_hmac_sha256(const guint8 *key, gsize key_len,
                             const guint8 *data, gsize data_len,
                             guint8 out[32]) {
  if (key == NULL || data == NULL || out == NULL) return FALSE;

  /* OpenSSL 3 provider-based MAC API (the classic HMAC() is deprecated). */
  EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
  if (mac == NULL) return FALSE;

  EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
  EVP_MAC_free(mac);
  if (ctx == NULL) return FALSE;

  OSSL_PARAM params[2];
  params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA256", 0);
  params[1] = OSSL_PARAM_construct_end();

  gboolean ok = FALSE;
  if (EVP_MAC_init(ctx, key, key_len, params) == 1 &&
      EVP_MAC_update(ctx, data, data_len) == 1) {
    size_t outl = 0;
    if (EVP_MAC_final(ctx, out, &outl, 32) == 1 && outl == 32) {
      ok = TRUE;
    }
  }
  EVP_MAC_CTX_free(ctx);
  return ok;
}

/* ============================ Random + hex ============================ */

gboolean softbus_random_bytes(guint8 *out, gsize len) {
  if (out == NULL || len == 0) return FALSE;
  return RAND_bytes(out, (int)len) == 1;
}

gchar* softbus_to_hex(const guint8 *data, gsize len) {
  static const gchar *digits = "0123456789abcdef";
  gchar *out = g_malloc(len * 2 + 1);
  for (gsize i = 0; i < len; i++) {
    out[i*2]   = digits[data[i] >> 4];
    out[i*2+1] = digits[data[i] & 0x0f];
  }
  out[len*2] = '\0';
  return out;
}

gboolean softbus_from_hex(const gchar *hex, guint8 *out, gsize out_cap, gsize *out_len) {
  if (hex == NULL || out == NULL) return FALSE;
  gsize hex_len = strlen(hex);
  if (hex_len % 2 != 0) return FALSE;
  gsize n = hex_len / 2;
  if (n > out_cap) return FALSE;

  for (gsize i = 0; i < n; i++) {
    guint hi, lo;
    gchar h = hex[i*2], l = hex[i*2+1];
    if (h >= '0' && h <= '9') hi = h - '0';
    else if (h >= 'a' && h <= 'f') hi = h - 'a' + 10;
    else if (h >= 'A' && h <= 'F') hi = h - 'A' + 10;
    else return FALSE;
    if (l >= '0' && l <= '9') lo = l - '0';
    else if (l >= 'a' && l <= 'f') lo = l - 'a' + 10;
    else if (l >= 'A' && l <= 'F') lo = l - 'A' + 10;
    else return FALSE;
    out[i] = (guint8)((hi << 4) | lo);
  }
  if (out_len) *out_len = n;
  return TRUE;
}
