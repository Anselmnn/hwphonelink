/*
 * remote_input.h - RemoteCtrl input packet encoder (PC -> phone)
 *
 * RE'd from HosDmsdpProvider.dll (spec section 6.4):
 *   RemoteUtil::RemoteController::ConstructRemoteCtrlPacket (VMA
 *   0x180018b10), the ConstructInputBody dispatcher (0x180018e90) and
 *   the per-type Construct*Event builders.
 *
 * Wire format (spec 6.4.1-6.4.3):
 *
 *   [10 B header][body L B][u32 BE ts][1 B pad if (L+4) odd]
 *   total = 10 + L + 4 + pad
 *
 * The encoder zero-initialises the whole packet region before writing
 * any field (the original zeroed the entire out buffer with `rep
 * stosb`). The zero bytes are structurally load-bearing: reserved
 * header area hdr[5..9] and the 4*cnt trailing bytes of a touch body
 * must be 0x00.
 *
 * M3 API deltas vs the original (spec 6.4.13):
 *   - `ts` is an explicit parameter (u32, relative ms). The original
 *     derives it from a QueryPerformanceCounter base/freq pair that is
 *     never initialised (garbage in practice).
 *   - `cap < total` -> -1 before anything is written; the original has
 *     scattered capacity checks and can overrun small buffers.
 *   - Touch point count is constrained to 1..4 (the original accepts 0
 *     and >4 with garbage reads).
 *   - Types 4 and 5 are rejected (dead in the original: type 4 -> stub
 *     bodylen -1; type 5 -> tail entry with L=0 -> -1).
 *
 * double -> coordinate u16 conversion is cvttsd2si truncation to gint32
 * followed by taking the low 16 bits, big-endian on the wire:
 * (guint16)(gint32)v.
 */

#pragma once

#include <glib.h>

G_BEGIN_DECLS

#define REMOTE_INPUT_HDR_LEN 10
#define REMOTE_INPUT_MAX_TOTAL 512 /* message len 472 -> 492 B; margin */

/* Wire input types (spec 6.4). 4/5 are dead in the original. */
enum {
  REMOTE_INPUT_TOUCH = 0,
  REMOTE_INPUT_KEY = 1,
  REMOTE_INPUT_ZOOM = 2,
  REMOTE_INPUT_SCROLL = 3,
  /* 4: dead (stub returns bodylen -1) */
  /* 5: dead (tail entry, L=0 -> -1) */
  REMOTE_INPUT_MOUSE = 6,
  REMOTE_INPUT_INPUT7 = 7,
  REMOTE_INPUT_WHEEL = 8,
  REMOTE_INPUT_VKEY = 9,
  REMOTE_INPUT_MESSAGE = 0xa,
};

/*
 * Flat per-type event. Only the fields of ev->type are read; the rest
 * may stay zero. Field names refer to the original `input[]` offsets
 * (spec 6.4 per-type tables).
 */
typedef struct {
  guint32 type; /* 0..0xa; 4/5 -> -1 */
  guint32 subtype;
  guint8 flags1; /* remapped into hdr[0]: b3->bit3, b5->bit2, b6->bit1 */
  guint8 flags2; /* -> hdr[4] verbatim */

  /* TOUCH (0): cnt 1..4, sub 0/1/2 -> action 0x0e/0x0f/0x02 */
  guint8 touch_cnt;
  guint8 touch_ids[4]; /* input[21+4p..22+4p) ids */
  gdouble touch_x[4]; /* input[32+8p..40+8p) */
  gdouble touch_y[4]; /* input[112+8p..120+8p) */

  /* KEY (1): sub 0/1 -> action 3/4 */
  guint16 key_f16a; /* input[22..24) */
  guint16 key_f16b; /* input[24..26) */
  guint32 key_f32; /* input[28..32) */

  /* ZOOM (2): sub unconstrained */
  gdouble zoom_x; /* input[16..24) */
  gdouble zoom_y; /* input[24..32) */
  gdouble zoom_pressure; /* input[32..40): low 2 bytes of the bit
                             pattern, written little-endian */

  /* SCROLL (3): sub 0/1 -> action 0x06/0x07 */
  guint8 scroll_axis; /* input[21] */
  gint8 scroll_delta; /* input[20] */

  /* MOUSE (6): sub 0/1/2 -> action 0x0e/0x0f/0x10 */
  guint8 mouse_button; /* input[20] */
  gdouble mouse_x; /* input[24..32) */
  gdouble mouse_y; /* input[32..40) */
  gdouble mouse_z; /* input[40..48) */
  gdouble mouse_w; /* input[48..56) */

  /* INPUT7 (7): sub 0 = content string, sub 1 = focus, else -1 */
  const gchar *content; /* sub 0: string, content_len bytes */
  guint16 content_len; /* sub 0: <= 472 */
  guint8 focus_f1; /* sub 1: input[24] */
  gdouble focus_f2; /* sub 1: input[32..40) */
  gdouble focus_f3; /* sub 1: input[40..48) */
  gdouble focus_f4; /* sub 1: input[48..56) */
  gdouble focus_f5; /* sub 1: input[56..64) */

  /* WHEEL (8): sub 0/1 -> action 0x0c/0x0d */
  guint8 wheel_dir; /* input[20]; field = ((dir&6)<<1)|(dir&1) */
  guint16 wheel_f1; /* input[22..24) */
  gdouble wheel_x; /* input[24..32) */
  gdouble wheel_y; /* input[32..40) */

  /* VKEY (9): sub 0..3 -> action 2..5 */
  gdouble vkey_x; /* input[24..32) */
  gdouble vkey_y; /* input[32..40) */

  /* MESSAGE (0xa): sub 0/1 -> action 6/7; len 2..472 */
  guint32 msg_len; /* wire len (u16); payload = len-2 bytes */
  const guint8 *msg_payload;
} RemoteInputEvent;

/*
 * Encode one input event into `out`.
 *
 * Returns 0 on success and stores the full packet size in *out_len
 * (total = 10 + L + 4 + pad). Returns -1 on any validation failure
 * (unknown type, invalid subtype, touch cnt out of range, length
 * overflow, cap < total, NULL out).
 */
gssize remote_input_build(const RemoteInputEvent *ev, guint32 ts,
                          guint8 *out, gsize cap, gsize *out_len);

G_END_DECLS
