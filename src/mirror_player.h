/*
 * mirror_player.h - screen-mirror playback (GStreamer H.264 decode)
 *
 * M3 replay stand (spec §8.7): decodes the Annex-B H.264 clip the mock
 * phone pushes over the VTP stream. Two render paths:
 *
 *   - DISPLAY present: the decoded video is shown in a GTK3 window
 *     (ximagesink), so the desktop user sees the mirror;
 *   - headless (CI / SSH shell): fakesink.
 *
 * In both paths the decoded frame count is probed on the avdec_h264
 * src pad, and the decode is driven from the default GLib main context
 * (the daemon's main-loop thread) until EOS, error, or a 60 s timeout.
 */

#pragma once

#include <glib.h>

G_BEGIN_DECLS

/*
 * Decode the Annex-B H.264 file at @path. Blocks on the default main
 * context until EOS, a pipeline error, or a 60 s timeout.
 *
 * Returns 0 on success (*out_frames then holds the number of decoded
 * frames, > 0); -1 on failure (*out_frames then holds the number of
 * frames decoded before the failure).
 */
gint mirror_player_play_file(const gchar *path, guint64 *out_frames);

G_END_DECLS
