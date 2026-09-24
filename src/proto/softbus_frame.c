/*
 * softbus_frame.c - dsoftbus TLV frame codec (implementation)
 */

#include "softbus_frame.h"

#include <gio/gio.h>
#include <string.h>
#include <arpa/inet.h>

/* ============================ Pack ============================ */

gsize softbus_frame_pack(const SoftbusFrame *frame, guint8 *out, gsize out_cap) {
  if (frame == NULL || out == NULL) return 0;
  if (frame->payload_len > SOFTBUS_FRAME_MAX_PAYLOAD) return 0;

  gsize total = SOFTBUS_FRAME_MIN_SIZE + frame->payload_len + frame->ext_len;
  if (out_cap < total) return 0;

  guint8 *p = out;

  /* Header */
  p[0] = SOFTBUS_FRAME_MAGIC_0;
  p[1] = SOFTBUS_FRAME_MAGIC_1;
  p[2] = SOFTBUS_FRAME_VERSION;
  p[3] = frame->flags;
  guint32 len_be = GUINT32_TO_BE((guint32)total);
  memcpy(p + 4, &len_be, 4);
  p += SOFTBUS_FRAME_HEADER_SIZE;

  /* Session ID (8B) */
  memcpy(p, frame->session_id, SOFTBUS_FRAME_SESSION_ID_SIZE);
  p += SOFTBUS_FRAME_SESSION_ID_SIZE;

  /* Sequence number (4B, BE) */
  guint32 seq_be = GUINT32_TO_BE(frame->seq);
  memcpy(p, &seq_be, 4);
  p += 4;

  /* Type + packet flags + ext len */
  *p++ = frame->type;
  *p++ = frame->pkt_flags;
  guint16 ext_be = GUINT16_TO_BE(frame->ext_len);
  memcpy(p, &ext_be, 2);
  p += 2;

  /* Payload */
  if (frame->payload_len > 0 && frame->payload != NULL) {
    memcpy(p, frame->payload, frame->payload_len);
    p += frame->payload_len;
  }
  /* Extension area (reserved) — zero-filled */
  if (frame->ext_len > 0) {
    memset(p, 0, frame->ext_len);
    p += frame->ext_len;
  }

  return (gsize)(p - out);
}

/* ============================ Unpack ============================ */

gssize softbus_frame_unpack(const guint8 *in, gsize in_len, SoftbusFrame *frame) {
  if (in == NULL || frame == NULL) return -1;

  if (in_len < SOFTBUS_FRAME_HEADER_SIZE) return -2;  /* incomplete */

  if (in[0] != SOFTBUS_FRAME_MAGIC_0 || in[1] != SOFTBUS_FRAME_MAGIC_1) {
    return -1;  /* bad magic */
  }
  if (in[2] != SOFTBUS_FRAME_VERSION) {
    return -1;  /* unsupported version */
  }

  guint32 total;
  memcpy(&total, in + 4, 4);
  total = GUINT32_FROM_BE(total);

  if (total < SOFTBUS_FRAME_MIN_SIZE || total > SOFTBUS_FRAME_MAX_PAYLOAD + SOFTBUS_FRAME_MIN_SIZE) {
    return -1;  /* corrupt length */
  }
  if (in_len < (gsize)total) return -2;  /* incomplete */

  const guint8 *p = in + SOFTBUS_FRAME_HEADER_SIZE;

  memset(frame, 0, sizeof(*frame));
  frame->flags = in[3];
  memcpy(frame->session_id, p, SOFTBUS_FRAME_SESSION_ID_SIZE);
  p += SOFTBUS_FRAME_SESSION_ID_SIZE;

  guint32 seq_be;
  memcpy(&seq_be, p, 4);
  frame->seq = GUINT32_FROM_BE(seq_be);
  p += 4;

  frame->type = *p++;
  frame->pkt_flags = *p++;
  guint16 ext_be;
  memcpy(&ext_be, p, 2);
  frame->ext_len = GUINT16_FROM_BE(ext_be);
  p += 2;

  if (frame->ext_len > (guint16)(total - SOFTBUS_FRAME_MIN_SIZE)) {
    return -1;  /* ext_len larger than the body — corrupt */
  }
  gsize payload_len = (gsize)total - SOFTBUS_FRAME_MIN_SIZE - frame->ext_len;
  frame->payload = (guint8 *)p;  /* points into @in */
  frame->payload_len = payload_len;

  return (gssize)total;
}

/* ============================ Stream buffer ============================ */

struct _SoftbusFrameBuf {
  GByteArray *data;
};

SoftbusFrameBuf* softbus_frame_buf_new(void) {
  SoftbusFrameBuf *buf = g_new0(SoftbusFrameBuf, 1);
  buf->data = g_byte_array_new();
  return buf;
}

void softbus_frame_buf_free(SoftbusFrameBuf *buf) {
  if (buf == NULL) return;
  g_byte_array_free(buf->data, TRUE);
  g_free(buf);
}

gboolean softbus_frame_buf_append(SoftbusFrameBuf *buf, const guint8 *data,
                                  gsize len, GError **error) {
  if (buf == NULL || (data == NULL && len > 0)) {
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "bad args");
    return FALSE;
  }
  if (len > 0) {
    g_byte_array_append(buf->data, data, len);
  }
  return TRUE;
}

gboolean softbus_frame_buf_pop(SoftbusFrameBuf *buf, SoftbusFrame *frame,
                               GError **error) {
  if (buf == NULL || frame == NULL) {
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "bad args");
    return FALSE;
  }

  while (buf->data->len > 0) {
    gssize n = softbus_frame_unpack(buf->data->data, buf->data->len, frame);
    if (n > 0) {
      /*
       * Copy the payload out of the buffer storage BEFORE removing the frame:
       * remove_range() memmoves the remaining bytes down, which invalidates
       * any pointer into the storage (and a trailing payload read would run
       * past the logical end). frame->payload becomes a malloc'd copy owned
       * by the caller (NULL for empty payloads); free it with g_free().
       */
      if (frame->payload != NULL && frame->payload_len > 0)
        frame->payload = g_memdup2(frame->payload, frame->payload_len);
      else
        frame->payload = NULL;
      g_byte_array_remove_range(buf->data, 0, (guint)n);
      return TRUE;
    }
    if (n == -1) {
      /* Corrupt stream (bad magic/version/length): resync by resetting. */
      g_byte_array_set_size(buf->data, 0);
      g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                  "corrupt frame (bad magic/version/length)");
      return FALSE;
    }
    /* n == -2: need more bytes */
    return FALSE;
  }

  /* No data buffered */
  return FALSE;
}

gsize softbus_frame_buf_pending(const SoftbusFrameBuf *buf) {
  return buf ? buf->data->len : 0;
}

void softbus_frame_buf_reset(SoftbusFrameBuf *buf) {
  if (buf) g_byte_array_set_size(buf->data, 0);
}
