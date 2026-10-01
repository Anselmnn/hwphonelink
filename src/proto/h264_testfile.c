/*
 * h264_testfile.c - deterministic H.264 (Annex-B) replay-stand test files
 */

#include "proto/h264_testfile.h"

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

/* NAL sizes (bytes of payload, before emulation prevention). */
#define H264_SPS_PAYLOAD  17
#define H264_PPS_PAYLOAD  4
#define H264_SLICE_PAYLOAD 4096

/* nal_ref_idc=3 / 1, types 7 / 8 / 5 / 1. */
#define H264_NAL_SPS   0x67
#define H264_NAL_PPS   0x68
#define H264_NAL_IDR   0x65
#define H264_NAL_NONIDR 0x41

static const guint8 START_CODE[4] = {0x00, 0x00, 0x00, 0x01};

/* Same 3-stage splitmix64 as ft_testfile.c (deterministic per seed). */
static guint8 h264_byte(guint64 seed, guint64 i) {
  guint64 z = seed + i;
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
  z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
  z = z ^ (z >> 31);
  return (guint8)(z & 0xff);
}

/*
 * Append one NAL: start code + header + @raw_len content bytes with
 * emulation prevention. *content_i is the running content-byte counter
 * (advanced only for kept bytes).
 */
static void append_nal(GByteArray *a, guint64 seed, guint64 *content_i,
                       guint8 nal_hdr, gsize raw_len) {
  g_byte_array_append(a, START_CODE, 4);
  g_byte_array_append(a, &nal_hdr, 1);
  for (gsize i = 0; i < raw_len; i++) {
    guint8 b = h264_byte(seed, *content_i + i);
    if (a->len >= 2 && a->data[a->len - 2] == 0x00 &&
        a->data[a->len - 1] == 0x00 && b <= 0x03)
      g_byte_array_append(a, (const guint8[]){0x03}, 1);
    g_byte_array_append(a, &b, 1);
  }
  *content_i += raw_len;
}

gboolean h264_testfile_generate(const gchar *dir, guint64 seed, guint64 size,
                                gchar **out_path, gchar **out_wire_name) {
  if (out_path) *out_path = NULL;
  if (out_wire_name) *out_wire_name = NULL;
  if (dir == NULL || size < 8192) return FALSE;

  GByteArray *a = g_byte_array_new();
  guint64 content_i = 0;
  append_nal(a, seed, &content_i, H264_NAL_SPS, H264_SPS_PAYLOAD);
  append_nal(a, seed, &content_i, H264_NAL_PPS, H264_PPS_PAYLOAD);
  append_nal(a, seed, &content_i, H264_NAL_IDR, H264_SLICE_PAYLOAD);
  for (;;) {
    gsize before = a->len;
    append_nal(a, seed, &content_i, H264_NAL_NONIDR, H264_SLICE_PAYLOAD);
    if (a->len > size) {
      g_byte_array_set_size(a, before); /* budget exceeded: drop NAL */
      break;
    }
  }

  gchar *path = g_build_filename(dir, "hsgen.h264", NULL);
  gint fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) {
    g_byte_array_free(a, TRUE);
    g_free(path);
    return FALSE;
  }
  gboolean ok = (pwrite(fd, a->data, a->len, 0) == (gssize)a->len);
  close(fd);

  if (!ok) {
    g_byte_array_free(a, TRUE);
    unlink(path);
    g_free(path);
    return FALSE;
  }

  GChecksum *sha = g_checksum_new(G_CHECKSUM_SHA256);
  g_checksum_update(sha, a->data, (gssize)a->len);
  gchar *hex = g_strdup(g_checksum_get_string(sha)); /* lowercase */
  g_checksum_free(sha);
  g_byte_array_free(a, TRUE);

  if (out_path)
    *out_path = path;
  else
    g_free(path);
  if (out_wire_name)
    *out_wire_name = g_strdup_printf("hs-%s.h264", hex);
  if (!out_wire_name)
    g_free(hex);
  return TRUE;
}

gchar* h264_testfile_name_sha(const gchar *wire_name) {
  static const char prefix[] = "hs-";
  static const char suffix[] = ".h264";
  if (wire_name == NULL) return NULL;
  gsize len = strlen(wire_name);
  gsize p = strlen(prefix);
  gsize s = strlen(suffix);
  if (len < p + 64 + s) return NULL;
  if (memcmp(wire_name, prefix, p) != 0) return NULL;
  if (memcmp(wire_name + len - s, suffix, s) != 0) return NULL;
  gsize hexlen = len - p - s;
  if (hexlen != 64) return NULL;
  for (gsize i = 0; i < hexlen; i++)
    if (!g_ascii_isxdigit(wire_name[p + i])) return NULL;
  return g_strndup(wire_name + p, hexlen);
}

gboolean h264_testfile_verify(const gchar *path, const gchar *wire_name,
                              gchar **out_details) {
  if (out_details) *out_details = NULL;
  gchar *data = NULL;
  gsize len = 0;
  if (!g_file_get_contents(path, &data, &len, NULL) || len < 10) {
    g_free(data);
    return FALSE;
  }

  gboolean ok = TRUE;
  GString *details = g_string_new(NULL);

  /* 1. sha256 vs wire name (only when the name is conventional). */
  gchar *expected_sha = h264_testfile_name_sha(wire_name);
  if (expected_sha) {
    GChecksum *sha = g_checksum_new(G_CHECKSUM_SHA256);
    g_checksum_update(sha, (const guchar *)data, (gssize)len);
    gchar *actual = g_strdup(g_checksum_get_string(sha));
    g_checksum_free(sha);
    if (g_strcmp0(actual, expected_sha) != 0) {
      ok = FALSE;
      g_string_append_printf(details, "sha mismatch: got %s want %s", actual,
                             expected_sha);
    } else {
      g_string_append(details, "sha ok; ");
    }
    g_free(actual);
  } else {
    g_string_append(details, "sha unchecked (non-conventional name); ");
  }
  g_free(expected_sha);

  /* 2. start-code scan: the first code is at offset 0; every 00 00 00 01
   * is a NAL start (emulation prevention rules out in-payload matches). */
  if (len < 5 || data[0] != 0 || data[1] != 0 || data[2] != 0 ||
      data[3] != 0x01) {
    g_string_append(details, "no start code at file head");
    ok = FALSE;
  }

  guint nals = 0;
  guint8 first_types[3] = {0, 0, 0};
  gboolean types_ok = TRUE;
  for (gsize i = 0; i + 4 < len; i++) {
    if (data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 0 &&
        data[i + 3] == 0x01) {
      if (nals < 3) first_types[nals] = (guint8)(data[i + 4] & 0x1f);
      else if ((data[i + 4] & 0x1f) != 1) types_ok = FALSE; /* non-IDR */
      nals++;
      i += 3; /* resume scan after the code */
    }
  }
  if (nals < 3 || first_types[0] != 7 || first_types[1] != 8 ||
      first_types[2] != 5 || !types_ok) {
    ok = FALSE;
    g_string_append_printf(
        details, "bad NAL structure: %u NALs, first types %u/%u/%u", nals,
        first_types[0], first_types[1], first_types[2]);
  } else {
    g_string_append_printf(details, "%u NALs (SPS+PPS+IDR+%u non-IDR), "
                                   "start codes ok", nals, nals - 3);
  }

  g_free(data);
  if (out_details) *out_details = g_string_free(details, FALSE);
  else g_string_free(details, TRUE);
  return ok;
}
