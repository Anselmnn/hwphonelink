/*
 * remote_input.c - RemoteCtrl input packet encoder (PC -> phone)
 *
 * Implements the RE'd builders (spec 6.4):
 *
 *   touch   0x180019640   key   0x180019d10   mouse 0x180019ad0
 *   zoom    0x180018f36   scroll 0x19047      input7 0x18001a1c0
 *   wheel   0x18001a690   vkey  0x18001a8b0   message 0x18001aac0
 *   common tail (ts + pad) 0x180019207, epilogue 0x180019313
 *
 * Outer header (ConstructRemoteCtrlPacket 0x180018b10):
 *   hdr[0]   = ((f1>>6)&1)<<1 | ((f1>>5)&1)<<2 | ((f1>>3)&1)<<3
 *   hdr[1]   = class: type 5->1, 7->2, 9->3, 0xa->4, else 0
 *   hdr[2..3] = u16 BE total packet size
 *   hdr[4]   = flags2; hdr[5..9] = 0
 */

#include "proto/remote_input.h"

#include <string.h>

static void put_u16be(guint8 *p, guint16 v) {
  p[0] = (guint8)(v >> 8);
  p[1] = (guint8)(v & 0xff);
}

static void put_u32be(guint8 *p, guint32 v) {
  p[0] = (guint8)(v >> 24);
  p[1] = (guint8)(v >> 16);
  p[2] = (guint8)(v >> 8);
  p[3] = (guint8)(v & 0xff);
}

/* double -> wire u16: cvttsd2si truncation, low 16 bits */
static guint16 d16(gdouble v) { return (guint16)(gint32)v; }

/* Body length field of the variable-length builders (touch, input7
 * content, message): (L & 1) + (L - 3) */
static guint16 lenfield(gsize L) { return (guint16)((L & 1) + (L - 3)); }

/*
 * Validate the event and compute the body length L.
 * Returns 0 on success, -1 on invalid event.
 */
static int body_len(const RemoteInputEvent *ev, gsize *out_l) {
  gsize L = 0;
  switch (ev->type) {
  case REMOTE_INPUT_TOUCH:
    if (ev->touch_cnt < 1 || ev->touch_cnt > 4 || ev->subtype > 2) return -1;
    L = 9 * (gsize)ev->touch_cnt + 4;
    break;
  case REMOTE_INPUT_KEY:
    if (ev->subtype > 1) return -1;
    L = 12;
    break;
  case REMOTE_INPUT_ZOOM:
    L = 9;
    break;
  case REMOTE_INPUT_SCROLL:
    if (ev->subtype > 1) return -1;
    L = 5;
    break;
  case REMOTE_INPUT_MOUSE:
    if (ev->subtype > 2) return -1;
    L = 12;
    break;
  case REMOTE_INPUT_INPUT7:
    if (ev->subtype == 0) {
      if (ev->content_len > 472) return -1;
      if (ev->content_len > 0 && ev->content == NULL) return -1;
      L = (gsize)ev->content_len + 5;
    } else if (ev->subtype == 1) {
      L = 12;
    } else {
      return -1;
    }
    break;
  case REMOTE_INPUT_WHEEL:
    if (ev->subtype > 1) return -1;
    L = 10;
    break;
  case REMOTE_INPUT_VKEY:
    if (ev->subtype > 3) return -1;
    L = 7;
    break;
  case REMOTE_INPUT_MESSAGE:
    if (ev->subtype > 1) return -1;
    /* Original checks (len-3) <= 469 and (len-2) <= 470 in 16 bits;
     * len < 2 wraps both and fails. */
    if (ev->msg_len < 2 || ev->msg_len > 472) return -1;
    if (ev->msg_payload == NULL) return -1;
    L = (gsize)ev->msg_len + 5;
    break;
  default:
    return -1; /* 4, 5 and > 0xa */
  }
  *out_l = L;
  return 0;
}

gssize remote_input_build(const RemoteInputEvent *ev, guint32 ts,
                          guint8 *out, gsize cap, gsize *out_len) {
  if (ev == NULL || out == NULL || out_len == NULL) return -1;

  gsize L;
  if (body_len(ev, &L) != 0) return -1;

  gsize pad = (L + 4) & 1;
  gsize total = REMOTE_INPUT_HDR_LEN + L + 4 + pad;
  if (cap < total) return -1;

  /*
   * Zero-initialise the whole packet region before writing any field
   * (the original zeroed the entire out buffer with `rep stosb`).
   * Structurally load-bearing: reserved hdr[5..9] and the 4*cnt
   * trailing bytes of a touch body must be 0x00.
   */
  memset(out, 0, total);

  guint8 *b = out + REMOTE_INPUT_HDR_LEN;
  switch (ev->type) {
  case REMOTE_INPUT_TOUCH: {
    static const guint8 action[3] = {0x0e, 0x0f, 0x02};
    b[0] = action[ev->subtype];
    put_u16be(b + 1, lenfield(L));
    b[3] = ev->touch_cnt;
    for (guint i = 0; i < ev->touch_cnt; i++) {
      /* Points packed with stride 5 from body offset 4; only 4+5*cnt
       * bytes are written, the 4*cnt tail stays zero. */
      guint8 *q = b + 4 + 5 * (gsize)i;
      q[0] = ev->touch_ids[i];
      put_u16be(q + 1, d16(ev->touch_x[i]));
      put_u16be(q + 3, d16(ev->touch_y[i]));
    }
    break;
  }
  case REMOTE_INPUT_KEY: {
    b[0] = (guint8)(3 + ev->subtype);
    put_u16be(b + 1, 9);
    b[3] = 0;
    put_u16be(b + 4, ev->key_f16a);
    put_u16be(b + 6, ev->key_f16b);
    put_u32be(b + 8, ev->key_f32);
    break;
  }
  case REMOTE_INPUT_ZOOM: {
    guint64 bits;
    memcpy(&bits, &ev->zoom_pressure, sizeof(bits));
    b[0] = 0x05;
    put_u16be(b + 1, 7);
    put_u16be(b + 3, d16(ev->zoom_x));
    put_u16be(b + 5, d16(ev->zoom_y));
    b[7] = (guint8)(bits & 0xff);
    b[8] = (guint8)((bits >> 8) & 0xff);
    break;
  }
  case REMOTE_INPUT_SCROLL: {
    b[0] = (guint8)(0x06 + ev->subtype);
    put_u16be(b + 1, 3);
    b[3] = ev->scroll_axis; /* axis = input[21], delta = input[20] */
    b[4] = (guint8)ev->scroll_delta;
    break;
  }
  case REMOTE_INPUT_MOUSE: {
    static const guint8 action[3] = {0x0e, 0x0f, 0x10};
    b[0] = action[ev->subtype];
    put_u16be(b + 1, 9);
    b[3] = ev->mouse_button;
    put_u16be(b + 4, d16(ev->mouse_x));
    put_u16be(b + 6, d16(ev->mouse_y));
    put_u16be(b + 8, d16(ev->mouse_z));
    put_u16be(b + 10, d16(ev->mouse_w));
    break;
  }
  case REMOTE_INPUT_INPUT7:
    if (ev->subtype == 0) {
      b[0] = 0x00;
      put_u16be(b + 1, lenfield(L));
      put_u16be(b + 3, ev->content_len);
      if (ev->content_len > 0) memcpy(b + 5, ev->content, ev->content_len);
    } else {
      b[0] = 0x01;
      put_u16be(b + 1, 9);
      b[3] = ev->focus_f1;
      put_u16be(b + 4, d16(ev->focus_f2));
      put_u16be(b + 6, d16(ev->focus_f3));
      put_u16be(b + 8, d16(ev->focus_f4));
      put_u16be(b + 10, d16(ev->focus_f5));
    }
    break;
  case REMOTE_INPUT_WHEEL: {
    b[0] = (guint8)(0x0c + ev->subtype);
    put_u16be(b + 1, 7);
    b[3] = (guint8)(((ev->wheel_dir & 0x06) << 1) | (ev->wheel_dir & 0x01));
    put_u16be(b + 4, ev->wheel_f1);
    put_u16be(b + 6, d16(ev->wheel_x));
    put_u16be(b + 8, d16(ev->wheel_y));
    break;
  }
  case REMOTE_INPUT_VKEY: {
    b[0] = (guint8)(2 + ev->subtype);
    put_u16be(b + 1, 5);
    put_u16be(b + 3, d16(ev->vkey_x));
    put_u16be(b + 5, d16(ev->vkey_y));
    break;
  }
  case REMOTE_INPUT_MESSAGE: {
    b[0] = (guint8)(6 + ev->subtype);
    put_u16be(b + 1, lenfield(L));
    put_u16be(b + 3, (guint16)ev->msg_len);
    put_u16be(b + 5, (guint16)(ev->msg_len >> 16)); /* = 0 for len <= 472 */
    memcpy(b + 7, ev->msg_payload, (gsize)(ev->msg_len - 2));
    break;
  }
  default:
    return -1; /* unreachable: body_len validated */
  }

  /* Header */
  out[0] = (guint8)(((ev->flags1 >> 6) & 1) << 1 |
                    ((ev->flags1 >> 5) & 1) << 2 |
                    ((ev->flags1 >> 3) & 1) << 3);
  if (ev->type == REMOTE_INPUT_INPUT7)
    out[1] = 2;
  else if (ev->type == REMOTE_INPUT_VKEY)
    out[1] = 3;
  else if (ev->type == REMOTE_INPUT_MESSAGE)
    out[1] = 4;
  else
    out[1] = 0;
  put_u16be(out + 2, (guint16)total);
  out[4] = ev->flags2;

  /* Timestamp (u32 BE); the pad byte is already zero */
  put_u32be(out + REMOTE_INPUT_HDR_LEN + L, ts);

  *out_len = total;
  return 0;
}
