/*
 * stream_file.c - VTP file session over a fillp peer
 *
 * See stream_file.h for the wire convention and threading model. All
 * state is touched on the fillp engine thread (fill func, on_data,
 * on_tx_complete, on_closed).
 */

#include "proto/stream_file.h"

#include "proto/ft_testfile.h"
#include "proto/h264_testfile.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* One VTP frame carries at most this many app bytes; a frame may span
 * several fillp DATA packets (fillp is a byte stream). */
#define SF_VTP_CHUNK 32768

typedef enum {
  SF_RX_WAIT = 0, /* awaiting the peer's metadata frame */
  SF_RX_DATA,
  SF_RX_DONE,
  SF_RX_FAILED,
} SFRxState;

typedef enum {
  SF_TX_IDLE = 0,
  SF_TX_ACTIVE, /* metadata sent/queued, data in flight */
  SF_TX_DONE,   /* all bytes queued, awaiting on_tx_complete */
  SF_TX_FAILED,
} SFTxState;

struct _StreamFile {
  FillpPeer *peer; /* non-owning */
  guint8 key[VTP_KEY_LEN];
  gchar *recv_dir;
  StreamFileOnRxMetaCb on_rx_meta;
  StreamFileDoneCb on_done;
  gpointer user_data;
  gboolean closed;

  /* receive */
  GByteArray *rxbuf;
  SFRxState rx_state;
  guint64 rx_total;
  guint64 rx_received;
  gchar *rx_name;
  gchar *rx_path;
  gchar *rx_expected_sha;
  gint rx_fd;
  GChecksum *rx_sha;

  /* send */
  SFTxState tx_state;
  gchar *tx_path;
  gchar *tx_wire;
  gint tx_fd;
  guint64 tx_total;
  guint64 tx_offset;
  gboolean tx_meta_sent;
};

/* ============================ BE helpers ============================ */

static guint32 sf_get_u32(const guint8 *p) {
  return ((guint32)p[0] << 24) | ((guint32)p[1] << 16) | ((guint32)p[2] << 8) |
         (guint32)p[3];
}

static guint64 sf_get_u64(const guint8 *p) {
  return ((guint64)sf_get_u32(p) << 32) | (guint64)sf_get_u32(p + 4);
}

static void sf_put_u64(guint8 *p, guint64 v) {
  p[0] = (guint8)(v >> 56);
  p[1] = (guint8)(v >> 48);
  p[2] = (guint8)(v >> 40);
  p[3] = (guint8)(v >> 32);
  p[4] = (guint8)(v >> 24);
  p[5] = (guint8)(v >> 16);
  p[6] = (guint8)(v >> 8);
  p[7] = (guint8)(v & 0xff);
}

static void sf_put_u16(guint8 *p, guint16 v) {
  p[0] = (guint8)(v >> 8);
  p[1] = (guint8)(v & 0xff);
}

/* ============================ Failure ============================ */

/*
 * Report both in-progress directions as failed. Engine thread. The
 * receiver direction is only reported when the app actually expects a
 * file (recv_dir set).
 */
static void sf_fail(StreamFile *sf, const gchar *why) {
  if (sf->rx_state == SF_RX_WAIT && sf->recv_dir != NULL) {
    sf->rx_state = SF_RX_FAILED;
    if (sf->on_done) sf->on_done(sf, FALSE, FALSE, g_strdup(why), sf->user_data);
  } else if (sf->rx_state == SF_RX_DATA) {
    sf->rx_state = SF_RX_FAILED;
    if (sf->on_done) sf->on_done(sf, FALSE, FALSE, g_strdup(why), sf->user_data);
  }
  if (sf->tx_state == SF_TX_ACTIVE) {
    sf->tx_state = SF_TX_FAILED;
    if (sf->on_done) sf->on_done(sf, TRUE, FALSE, g_strdup(why), sf->user_data);
  }
}

/* ============================ Send ============================ */

/*
 * Build one VTP frame from @data and append it to the peer's fillp
 * stream. Engine thread. Returns bytes queued, 0 on failure.
 */
static gssize sf_send_frame(FillpPeer *peer, StreamFile *sf,
                            const guint8 *data, gsize data_len) {
  gsize need = vtp_common_frame_size(data_len);
  guint8 *frame = g_new(guint8, need);
  gsize total = vtp_build_common_frame(frame, need, sf->key, VTP_MODE_COMMON, 0,
                                       0, (guint32)g_get_monotonic_time(), data,
                                       data_len);
  gssize queued = 0;
  if (total != (gsize)-1) {
    fillp_peer_send(peer, frame, total);
    queued = (gssize)total;
  }
  g_free(frame);
  return queued;
}

/*
 * Fill func called by the fillp engine (engine thread) while the peer's
 * send queue is below its watermark. Queues the metadata frame first,
 * then file chunks; returns -1 exactly once, after the final chunk.
 */
static gssize sf_fill(FillpPeer *peer, gpointer app_data) {
  StreamFile *sf = (StreamFile *)app_data;
  if (sf->tx_state != SF_TX_ACTIVE)
    return sf->tx_state == SF_TX_DONE ? -1 : 0;

  if (!sf->tx_meta_sent) {
    gsize name_len = strlen(sf->tx_wire);
    gsize meta_len = 8 + 2 + name_len;
    guint8 *meta = g_new(guint8, meta_len);
    sf_put_u64(meta, sf->tx_total);
    sf_put_u16(meta + 8, (guint16)name_len);
    memcpy(meta + 10, sf->tx_wire, name_len);
    gssize queued = sf_send_frame(peer, sf, meta, meta_len);
    g_free(meta);
    if (queued <= 0) {
      sf_fail(sf, "VTP metadata frame build failed");
      return 0;
    }
    sf->tx_meta_sent = TRUE;
    return queued;
  }

  if (sf->tx_fd < 0) return -1;
  guint8 *chunk = g_new(guint8, SF_VTP_CHUNK);
  gssize n = pread(sf->tx_fd, chunk, SF_VTP_CHUNK, (off_t)sf->tx_offset);
  if (n < 0) {
    g_free(chunk);
    sf_fail(sf, "send file read error");
    return 0;
  }
  if (n == 0) {
    g_free(chunk);
    return -1; /* final byte already queued */
  }
  gssize queued = sf_send_frame(peer, sf, chunk, (gsize)n);
  g_free(chunk);
  if (queued <= 0) {
    sf_fail(sf, "VTP frame build failed");
    return 0;
  }
  sf->tx_offset += (guint64)n;
  return queued;
}

/* Engine thread: the peer's send queue drained and every packet is
 * acked. */
static void sf_on_tx_complete(FillpEngine *engine, FillpPeer *peer,
                              gpointer user_data) {
  (void)engine;
  (void)peer;
  StreamFile *sf = (StreamFile *)user_data;
  if (sf->closed) return;
  if (sf->tx_state != SF_TX_ACTIVE) return;
  sf->tx_state = SF_TX_DONE;
  gchar *msg = g_strdup_printf("%" G_GUINT64_FORMAT " bytes sent and acked",
                               sf->tx_total);
  g_print("streamfile: send complete: %s\n", msg);
  if (sf->on_done)
    sf->on_done(sf, TRUE, TRUE, msg, sf->user_data);
  else
    g_free(msg);
}

/* ============================ Receive ============================ */

/*
 * Process one complete VTP frame (as reassembled from the fillp byte
 * stream). Engine thread. Returns FALSE on a fatal frame error.
 */
static gboolean sf_process_frame(StreamFile *sf, const guint8 *frame,
                                 gsize frame_total) {
  if (sf->rx_state == SF_RX_DONE || sf->rx_state == SF_RX_FAILED) return TRUE;

  guint8 *out = g_new(guint8, SF_VTP_CHUNK);
  gsize out_len = 0;
  gboolean ok = vtp_parse_common_frame(frame, frame_total, sf->key, NULL, NULL,
                                       NULL, NULL, out, SF_VTP_CHUNK, &out_len);
  if (!ok) {
    g_free(out);
    sf_fail(sf, "bad VTP frame (GCM tag or size mismatch)");
    return FALSE;
  }

  if (sf->rx_state == SF_RX_WAIT) {
    /* Metadata: [u64 total][u16 name_len][name] */
    if (sf->recv_dir == NULL || out_len < 10) {
      g_free(out);
      sf_fail(sf, "metadata frame invalid or no recv dir");
      return FALSE;
    }
    guint64 total = sf_get_u64(out);
    guint16 name_len = (guint16)((out[8] << 8) | out[9]);
    if (out_len != (gsize)(10 + name_len)) {
      g_free(out);
      sf_fail(sf, "metadata frame size mismatch");
      return FALSE;
    }
    gchar *name = g_strndup((gchar *)out + 10, name_len);
    g_free(out);
    if (name_len == 0 || strchr(name, '/') != NULL ||
        strstr(name, "..") != NULL || name[0] == '.') {
      g_free(name);
      sf_fail(sf, "bad received file name");
      return FALSE;
    }
    sf->rx_name = name;
    sf->rx_path = g_build_filename(sf->recv_dir, name, NULL);
    sf->rx_fd = open(sf->rx_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (sf->rx_fd < 0) {
      g_free(sf->rx_path);
      sf->rx_path = NULL;
      sf_fail(sf, "cannot open received file");
      return FALSE;
    }
    sf->rx_sha = g_checksum_new(G_CHECKSUM_SHA256);
    sf->rx_total = total;
    sf->rx_received = 0;
    sf->rx_expected_sha = h264_testfile_name_sha(name);
    if (sf->rx_expected_sha == NULL) sf->rx_expected_sha = ft_testfile_name_sha(name);
    sf->rx_state = SF_RX_DATA;
    g_print("streamfile: receiving %s (%" G_GUINT64_FORMAT " bytes)\n", name,
            total);
    if (sf->on_rx_meta) sf->on_rx_meta(sf, name, total, sf->user_data);
    return TRUE;
  }

  /* SF_RX_DATA: raw file chunk */
  if (out_len > 0) {
    if (sf->rx_received + out_len > sf->rx_total) {
      g_free(out);
      sf_fail(sf, "received more bytes than declared total");
      return FALSE;
    }
    gssize w = pwrite(sf->rx_fd, out, out_len, (off_t)sf->rx_received);
    if (w != (gssize)out_len) {
      g_free(out);
      sf_fail(sf, "received file write error");
      return FALSE;
    }
    g_checksum_update(sf->rx_sha, out, (gssize)out_len);
    sf->rx_received += out_len;
  }
  g_free(out);

  if (sf->rx_received == sf->rx_total) {
    if (sf->rx_fd >= 0) {
      close(sf->rx_fd);
      sf->rx_fd = -1;
    }
    gboolean okv = TRUE;
    GString *det = g_string_new(NULL);
    if (g_str_has_suffix(sf->rx_name, ".h264")) {
      gchar *h264_det = NULL;
      if (h264_testfile_verify(sf->rx_path, sf->rx_name, &h264_det))
        g_string_append(det, h264_det);
      else {
        okv = FALSE;
        g_string_append(det, h264_det ? h264_det : "h264 verify failed");
      }
      g_free(h264_det);
    } else if (sf->rx_expected_sha != NULL) {
      gchar *hex = g_strdup(g_checksum_get_string(sf->rx_sha));
      if (g_strcmp0(hex, sf->rx_expected_sha) == 0)
        g_string_append(det, "sha ok");
      else {
        okv = FALSE;
        g_string_append_printf(det, "sha mismatch: got %s want %s", hex,
                               sf->rx_expected_sha);
      }
      g_free(hex);
    } else {
      g_string_append(det, "sha unchecked (non-conventional name)");
    }
    g_checksum_free(sf->rx_sha);
    sf->rx_sha = NULL;
    sf->rx_state = SF_RX_DONE;
    g_print("streamfile: received %s: %s\n", sf->rx_path, det->str);
    if (sf->on_done)
      sf->on_done(sf, FALSE, okv, g_string_free(det, FALSE), sf->user_data);
    else
      g_string_free(det, TRUE);
  }
  return TRUE;
}

/*
 * Engine thread: contiguous fillp stream bytes. Reassemble VTP frames
 * (4-byte length prefix, then N bytes) across deliveries.
 */
static void sf_on_data(FillpEngine *engine, FillpPeer *peer,
                       const guint8 *data, gsize len, gpointer user_data) {
  (void)engine;
  (void)peer;
  StreamFile *sf = (StreamFile *)user_data;
  if (sf->closed) return;
  g_byte_array_append(sf->rxbuf, data, len);
  for (;;) {
    if (sf->rx_state == SF_RX_FAILED || sf->rx_state == SF_RX_DONE) break;
    if (sf->rxbuf->len < 4) break;
    guint32 n = sf_get_u32(sf->rxbuf->data);
    if (sf->rxbuf->len < 4u + n) break; /* incomplete frame */
    gsize frame_total = 4u + (gsize)n;
    gboolean cont = sf_process_frame(sf, sf->rxbuf->data, frame_total);
    g_byte_array_remove_range(sf->rxbuf, 0, frame_total);
    if (!cont) break;
  }
}

/* ============================ Public API ============================ */

StreamFile* stream_file_new(FillpPeer *peer, const guint8 key[VTP_KEY_LEN]) {
  StreamFile *sf = g_new0(StreamFile, 1);
  sf->peer = peer;
  memcpy(sf->key, key, VTP_KEY_LEN);
  sf->rxbuf = g_byte_array_new();
  sf->rx_state = SF_RX_WAIT;
  sf->rx_fd = -1;
  sf->tx_state = SF_TX_IDLE;
  sf->tx_fd = -1;
  return sf;
}

void stream_file_set_recv_dir(StreamFile *sf, const gchar *dir) {
  if (sf == NULL) return;
  g_free(sf->recv_dir);
  sf->recv_dir = g_strdup(dir);
}

void stream_file_set_callbacks(StreamFile *sf, StreamFileOnRxMetaCb on_rx_meta,
                               StreamFileDoneCb on_done, gpointer user_data) {
  if (sf == NULL) return;
  sf->on_rx_meta = on_rx_meta;
  sf->on_done = on_done;
  sf->user_data = user_data;
}

void stream_file_attach(StreamFile *sf) {
  if (sf == NULL || sf->closed) return;
  fillp_peer_set_app_data(sf->peer, sf);
  /* Peer stream bytes can only be processed after on_established
   * returns, so registering here (from on_established) cannot miss the
   * peer's first data packet. */
  fillp_peer_set_stream_cbs(sf->peer, sf_on_data, sf_on_tx_complete, sf);
}

gboolean stream_file_start_send(StreamFile *sf, const gchar *path,
                                const gchar *wire_name, GError **error) {
  static GQuark quark = 0;
  if (quark == 0)
    quark = g_quark_from_static_string("hwphonelink-streamfile-error-quark");
  if (sf == NULL || sf->closed) {
    g_set_error_literal(error, quark, 1, "stream file closed");
    return FALSE;
  }
  if (sf->tx_state != SF_TX_IDLE) {
    g_set_error_literal(error, quark, 1, "already sending");
    return FALSE;
  }
  struct stat st;
  if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
    g_set_error(error, quark, 1, "cannot stat %s: %s", path,
                g_strerror(errno));
    return FALSE;
  }
  gint fd = open(path, O_RDONLY);
  if (fd < 0) {
    g_set_error(error, quark, 1, "cannot open %s: %s", path,
                g_strerror(errno));
    return FALSE;
  }
  sf->tx_fd = fd;
  sf->tx_path = g_strdup(path);
  sf->tx_wire = g_strdup(wire_name);
  sf->tx_total = (guint64)st.st_size;
  sf->tx_offset = 0;
  sf->tx_meta_sent = FALSE;
  sf->tx_state = SF_TX_ACTIVE;
  fillp_peer_set_fill_func(sf->peer, sf_fill);
  stream_file_attach(sf);
  g_print("streamfile: sending %s (%" G_GUINT64_FORMAT " bytes) as %s\n", path,
          (guint64)st.st_size, wire_name);
  return TRUE;
}

void stream_file_close(StreamFile *sf) {
  if (sf == NULL) return;
  sf->closed = TRUE;
  if (sf->rxbuf) g_byte_array_free(sf->rxbuf, TRUE);
  if (sf->rx_sha) g_checksum_free(sf->rx_sha);
  if (sf->rx_fd >= 0) close(sf->rx_fd);
  if (sf->tx_fd >= 0) close(sf->tx_fd);
  g_free(sf->recv_dir);
  g_free(sf->rx_name);
  g_free(sf->rx_path);
  g_free(sf->rx_expected_sha);
  g_free(sf->tx_path);
  g_free(sf->tx_wire);
  g_free(sf);
}

const gchar* stream_file_rx_state_name(StreamFile *sf) {
  if (sf == NULL) return "null";
  switch (sf->rx_state) {
  case SF_RX_WAIT:
    return "wait-meta";
  case SF_RX_DATA:
    return "data";
  case SF_RX_DONE:
    return "done";
  case SF_RX_FAILED:
    return "failed";
  }
  return "?";
}

const gchar* stream_file_tx_state_name(StreamFile *sf) {
  if (sf == NULL) return "null";
  switch (sf->tx_state) {
  case SF_TX_IDLE:
    return "idle";
  case SF_TX_ACTIVE:
    return "active";
  case SF_TX_DONE:
    return "done";
  case SF_TX_FAILED:
    return "failed";
  }
  return "?";
}
