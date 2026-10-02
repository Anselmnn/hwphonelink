/*
 * mirror_player.c - screen-mirror playback (GStreamer H.264 decode)
 *
 * Pipeline (spec §8.7):
 *
 *   appsrc ! h264parse ! avdec_h264 name=dec ! (display: videoconvert !
 *   ximagesink | headless: fakesink)
 *
 * The clip bytes are pushed to appsrc (format=bytes, do-timestamp
 * auto-stamps, is-live=false) from a dedicated push thread; with
 * block=true (the default) the push paces itself against the decoder.
 * A BUFFER probe on the decoder src pad counts the decoded frames. The
 * decode runs on the default main context; the caller blocks in a local
 * GMainLoop until EOS, error, or a 60 s timeout.
 */

#include "mirror_player.h"

#include <gst/app/gstappsrc.h>
#include <gst/gst.h>
#include <gtk/gtk.h>

#define MIRROR_TIMEOUT_MS 60000
#define MIRROR_CHUNK (64 * 1024)

typedef struct {
  guint8 *data;
  gsize len;
  gsize pos;
  GstAppSrc *src;
  GMainLoop *loop;
  gboolean done;
} MirrorFeed;

/* Decoded-frame counter (module is used single-shot by the daemon). */
static gint g_frames = 0;

static GstPadProbeReturn on_decoded(GstPad *pad, GstPadProbeInfo *info,
                                    gpointer user_data) {
  (void)pad;
  (void)info;
  (void)user_data;
  g_atomic_int_inc(&g_frames);
  return GST_PAD_PROBE_OK;
}

/* Push thread: feed the clip to appsrc, then end of stream. push_buffer
 * blocks while the queue is full (block=true), so the loop paces the
 * decode in real time; it exits on a non-OK flow (pipeline teardown).
 * gst_app_src_push_buffer() takes full ownership of the buffer
 * ((transfer full), freed on FLUSHING/EOS too), so it must NOT be
 * unrefed afterwards — that would leave a dangling pointer in the
 * appsrc queue (g_assert_not_reached on the next pop). */
static gpointer push_thread(gpointer user_data) {
  MirrorFeed *f = (MirrorFeed *)user_data;
  while (f->pos < f->len) {
    gsize chunk = f->len - f->pos;
    if (chunk > MIRROR_CHUNK) chunk = MIRROR_CHUNK;
    GstBuffer *buf = gst_buffer_new_allocate(NULL, chunk, NULL);
    if (buf == NULL) break;
    gst_buffer_fill(buf, 0, f->data + f->pos, chunk);
    GstFlowReturn fr = gst_app_src_push_buffer(f->src, buf);
    if (fr != GST_FLOW_OK) break;
    f->pos += chunk;
  }
  gst_app_src_end_of_stream(f->src);
  return NULL;
}

/* GstBusFunc (default main context): stop on ERROR / EOS. */
static int on_bus(GstBus *bus, GstMessage *m, gpointer user_data) {
  (void)bus;
  MirrorFeed *f = (MirrorFeed *)user_data;
  if (m->type != GST_MESSAGE_ERROR && m->type != GST_MESSAGE_EOS)
    return TRUE;
  if (m->type == GST_MESSAGE_ERROR) {
    GError *e = NULL;
    gchar *dbg = NULL;
    gst_message_parse_error(m, &e, &dbg);
    g_print("MIRROR: GStreamer error: %s\n", e ? e->message : "unknown");
    if (dbg != NULL) g_free(dbg);
    if (e != NULL) g_error_free(e);
  }
  f->done = TRUE;
  g_main_loop_quit(f->loop);
  return TRUE;
}

static gboolean on_timeout(gpointer user_data) {
  MirrorFeed *f = (MirrorFeed *)user_data;
  if (!f->done) g_print("MIRROR: decode timed out\n");
  f->done = TRUE;
  g_main_loop_quit(f->loop);
  return G_SOURCE_REMOVE;
}

gint mirror_player_play_file(const gchar *path, guint64 *out_frames) {
  if (out_frames != NULL) *out_frames = 0;
  if (path == NULL) return -1;
  gst_init(NULL, NULL); /* idempotent */

  gchar *text = NULL;
  gsize len = 0;
  if (!g_file_get_contents(path, &text, &len, NULL) || len == 0) {
    g_print("MIRROR: cannot read %s\n", path);
    g_free(text);
    return -1;
  }

  /* Render path: a GTK window when a usable X display exists. */
  gboolean display = g_getenv("DISPLAY") != NULL;
  if (display) {
    int argc = 0;
    gchar **argv = NULL;
    if (!gtk_init_check(&argc, &argv)) {
      g_print("MIRROR: no usable display — decoding to fakesink\n");
      display = FALSE;
    }
  }

  /* caps=video/x-h264 without stream-format: the clip is Annex-B, so
   * h264parse parses SPS/PPS out of the stream itself (it refuses
   * stream-format=avc caps that carry no codec_data). */
  const gchar *pipeline_str = display
      ? "appsrc name=src format=bytes is-live=false do-timestamp=true "
        "caps=video/x-h264 ! h264parse ! "
        "avdec_h264 name=dec ! videoconvert ! ximagesink name=sink"
      : "appsrc name=src format=bytes is-live=false do-timestamp=true "
        "caps=video/x-h264 ! h264parse ! "
        "avdec_h264 name=dec ! fakesink name=sink";

  GError *err = NULL;
  GstElement *pipe = gst_parse_launch(pipeline_str, &err);
  if (pipe == NULL) {
    g_print("MIRROR: pipeline launch failed: %s\n",
            err != NULL ? err->message : "unknown");
    g_clear_error(&err);
    g_free(text);
    return -1;
  }

  GtkWidget *window = NULL;
  if (display) {
    GstElement *sink = gst_bin_get_by_name(GST_BIN(pipe), "sink");
    if (sink != NULL) {
      window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
      gtk_window_set_title(GTK_WINDOW(window), "hwphonelink: screen mirror");
      gtk_container_add(GTK_CONTAINER(window), GTK_WIDGET(sink));
      gtk_widget_show_all(window);
      g_object_unref(sink);
    }
  }

  GstElement *src = gst_bin_get_by_name(GST_BIN(pipe), "src");
  GstElement *dec = gst_bin_get_by_name(GST_BIN(pipe), "dec");
  if (src == NULL || dec == NULL) {
    g_print("MIRROR: pipeline element lookup failed\n");
    if (window != NULL) gtk_widget_destroy(window);
    g_object_unref(pipe);
    g_free(text);
    return -1;
  }

  g_atomic_int_set(&g_frames, 0);
  GstPad *pad = gst_element_get_static_pad(dec, "src");
  if (pad != NULL) {
    gst_pad_add_probe(pad, GST_PAD_PROBE_TYPE_BUFFER, on_decoded, NULL, NULL);
    gst_object_unref(pad);
  }

  MirrorFeed feed = {
      (guint8 *)text, len, 0, (GstAppSrc *)src, NULL, FALSE,
  };
  GstBus *bus = gst_element_get_bus(pipe);
  guint watch_id = gst_bus_add_watch(bus, on_bus, &feed);
  g_object_unref(bus);
  feed.loop = g_main_loop_new(NULL, FALSE);
  guint timeout_id = g_timeout_add(MIRROR_TIMEOUT_MS, on_timeout, &feed);

  GThread *pt = g_thread_new("mirror-push", push_thread, &feed);
  if (gst_element_set_state(pipe, GST_STATE_PLAYING) ==
      GST_STATE_CHANGE_FAILURE)
    g_print("MIRROR: state change to PLAYING failed\n");

  g_main_loop_run(feed.loop);

  guint64 frames = (guint64)g_atomic_int_get(&g_frames);
  if (out_frames != NULL) *out_frames = frames;

  g_source_remove(timeout_id);
  if (watch_id != 0) g_source_remove(watch_id);
  gst_element_set_state(pipe, GST_STATE_NULL);
  g_thread_join(pt);
  g_main_loop_unref(feed.loop);
  if (window != NULL) gtk_widget_destroy(window);
  g_object_unref(src);
  g_object_unref(dec);
  g_object_unref(pipe);
  g_free(text);
  return frames > 0 ? 0 : -1;
}
