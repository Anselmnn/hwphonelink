/*
 * ft_testfile.h - deterministic DFile replay-stand test files
 *
 * Shared by the daemon and the mock phone. Content is deterministic:
 *   byte[i] = splitmix64(seed + i) & 0xff
 *
 * Wire-name convention: "ft-<sha256-lowercase-hex>.bin". The receiver
 * recomputes the sha256 of the stored file and verifies it against the
 * name, so a transfer is self-describing and self-checking.
 */

#pragma once

#include <glib.h>

/*
 * Generate @size bytes with @seed into <@dir>/ftgen.bin.
 * On success sets *out_path (on-disk path) and *out_wire_name
 * ("ft-<sha>.bin"); both g_malloc'd, caller frees.
 */
gboolean ft_testfile_generate(const gchar *dir, guint64 seed, guint64 size,
                              gchar **out_path, gchar **out_wire_name);

/*
 * If @wire_name follows the "ft-<hex64>.bin" convention, return a
 * g_malloc'ed lowercase sha256 hex; otherwise NULL.
 */
gchar* ft_testfile_name_sha(const gchar *wire_name);
