/*
 * softbus_frame.h - dsoftbus TLV frame codec
 *
 * Wire format (spec §5.3, trans_assemble_tlv.c / trans_tcp_process_data.c):
 *
 *   off  len  field
 *   ---  ---  -----------------------------------------------
 *   0    2    Magic 0x5342 ("SB")
 *   2    1    Version (1)
 *   3    1    Frame flags (FIN/ACK/ENC/COMP)
 *   4    4    Total frame length, big-endian (incl. this header)
 *   8    8    Session ID
 *   16   4    Sequence number, big-endian
 *   20   1    Session type (SOFTBUS_SESSION_*)
 *   21   1    Packet flags
 *   22   2    Extension length, big-endian (reserved, 0)
 *   24   ..   Payload (payload_len = total_len - 24 - ext_len)
 */

#pragma once

#include <glib.h>
#include "softbus_defs.h"

typedef struct {
  guint8  session_id[SOFTBUS_FRAME_SESSION_ID_SIZE];
  guint32 seq;
  guint8  type;      /* SoftbusSessionType */
  guint8  flags;     /* SOFTBUS_FRAME_FLAG_* */
  guint8  pkt_flags; /* SOFTBUS_PKT_FLAG_* */
  guint16 ext_len;   /* reserved */
  guint8 *payload;
  gsize   payload_len;
} SoftbusFrame;

/*
 * Serialize a frame into @out.
 * Returns total frame size, or 0 if @out_cap is too small / params invalid.
 */
gsize softbus_frame_pack(const SoftbusFrame *frame, guint8 *out, gsize out_cap);

/*
 * Parse one complete frame from @in.
 * Returns bytes consumed (>= SOFTBUS_FRAME_MIN_SIZE), or:
 *   -1 : invalid magic/version or corrupt length
 *   -2 : incomplete — need at least -ret - 2 more bytes
 * @frame->payload points into @in (do not free).
 */
gssize softbus_frame_unpack(const guint8 *in, gsize in_len, SoftbusFrame *frame);

/*
 * Incremental stream buffer: feed socket chunks, pop complete frames.
 */
typedef struct _SoftbusFrameBuf SoftbusFrameBuf;

SoftbusFrameBuf* softbus_frame_buf_new(void);
void softbus_frame_buf_free(SoftbusFrameBuf *buf);

/* Append @len bytes from @data. Returns FALSE + sets error on alloc failure. */
gboolean softbus_frame_buf_append(SoftbusFrameBuf *buf, const guint8 *data,
                                  gsize len, GError **error);

/*
 * Try to pop the next complete frame.
 * On success fills @frame and returns TRUE: @frame->payload is a
 * newly-allocated copy of the payload owned by the caller (free it with
 * g_free() after use; NULL for empty payloads).
 * On failure @frame is left untouched: FALSE without error means more data
 * is needed; FALSE with error means the stream is corrupt and the buffer
 * was reset.
 */
gboolean softbus_frame_buf_pop(SoftbusFrameBuf *buf, SoftbusFrame *frame,
                               GError **error);

/* Number of buffered bytes. */
gsize softbus_frame_buf_pending(const SoftbusFrameBuf *buf);

/* Reset (drop buffered data). */
void softbus_frame_buf_reset(SoftbusFrameBuf *buf);
