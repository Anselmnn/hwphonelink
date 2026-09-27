/*
 * ft_testfile.c - deterministic DFile replay-stand test files
 */

#include "proto/ft_testfile.h"

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

/* 3-stage splitmix64: cheap, well-mixed, deterministic across runs. */
static guint8 ft_byte(guint64 seed, guint64 i) {
  guint64 z = seed + i;
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
  z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
  z = z ^ (z >> 31);
  return (guint8)(z & 0xff);
}

gboolean ft_testfile_generate(const gchar *dir, guint64 seed, guint64 size,
                              gchar **out_path, gchar **out_wire_name) {
  if (out_path) *out_path = NULL;
  if (out_wire_name) *out_wire_name = NULL;
  if (dir == NULL || size == 0) return FALSE;

  gchar *path = g_build_filename(dir, "ftgen.bin", NULL);
  gint fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) {
    g_free(path);
    return FALSE;
  }

  GChecksum *sha = g_checksum_new(G_CHECKSUM_SHA256);
  guint8 buf[65536];
  guint64 done = 0;
  gboolean ok = TRUE;
  while (done < size) {
    gsize chunk = (gsize)(size - done);
    if (chunk > sizeof(buf)) chunk = sizeof(buf);
    for (gsize i = 0; i < chunk; i++)
      buf[i] = ft_byte(seed, done + i);
    if (pwrite(fd, buf, chunk, (off_t)done) != (gssize)chunk) {
      ok = FALSE;
      break;
    }
    g_checksum_update(sha, buf, (gssize)chunk);
    done += chunk;
  }
  close(fd);

  if (!ok) {
    g_checksum_free(sha);
    unlink(path);
    g_free(path);
    return FALSE;
  }
  gchar *hex = g_strdup(g_checksum_get_string(sha)); /* lowercase */
  g_checksum_free(sha);
  if (out_path)
    *out_path = path;
  else
    g_free(path);
  if (out_wire_name)
    *out_wire_name = g_strdup_printf("ft-%s.bin", hex);
  g_free(hex);
  return TRUE;
}

gchar* ft_testfile_name_sha(const gchar *wire_name) {
  static const char prefix[] = "ft-";
  static const char suffix[] = ".bin";
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
