/*
 * h264_testfile.h - deterministic H.264 (Annex-B) replay-stand test files
 *
 * No ffmpeg/GStreamer on the host, so the streaming stand validates at
 * the protocol level: the generator emits a deterministic Annex-B
 * bytestream (spec §8.7):
 *
 *   SPS (nal_type 7) + PPS (nal_type 8) + IDR (nal_type 5) +
 *   N non-IDR NALs (nal_type 1), each preceded by a 4-byte start code
 *   (00 00 00 01); payload content = splitmix64(seed + i) with proper
 *   emulation-prevention 0x03 insertion (00 00 followed by 00..03).
 *
 * @size is a BUDGET: NALs are appended while they fit; the actual
 * length is reported via the generated file (± one NAL).
 *
 * Wire-name convention: "hs-<sha256-lowercase-hex>.h264". The receiver
 * verifies: sha256 of the assembled file, start-code scan, NAL count,
 * and the NAL type sequence (7, 8, 5, then 1...).
 */

#pragma once

#include <glib.h>

/*
 * Generate a deterministic Annex-B bytestream (budget @size bytes,
 * @seed) into <@dir>/hsgen.h264. On success sets *out_path and
 * *out_wire_name ("hs-<sha>.h264"); both g_malloc'd, caller frees.
 */
gboolean h264_testfile_generate(const gchar *dir, guint64 seed, guint64 size,
                                gchar **out_path, gchar **out_wire_name);

/*
 * If @wire_name follows the "hs-<hex64>.h264" convention, return a
 * g_malloc'ed lowercase sha256 hex; otherwise NULL.
 */
gchar* h264_testfile_name_sha(const gchar *wire_name);

/*
 * Protocol-level verification of a received file:
 *   1. sha256 matches the wire name (when the name is hs-<sha>.h264);
 *   2. the file starts with a 4-byte start code and every 00 00 00 01
 *      occurrence is a NAL start (guaranteed by emulation prevention);
 *   3. NAL type sequence: 7 (SPS), 8 (PPS), 5 (IDR), then 1 (non-IDR).
 * On success sets *out_details (g_malloc'ed summary).
 */
gboolean h264_testfile_verify(const gchar *path, const gchar *wire_name,
                              gchar **out_details);
