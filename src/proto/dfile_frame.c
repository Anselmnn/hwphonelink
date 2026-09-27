/*
 * dfile_frame.c - DFile (t2stack nstackx) frame codec
 *
 * Pure buffer codec — see dfile_frame.h for the wire format. All
 * multi-byte integers are big-endian on the wire.
 */

#include "proto/dfile_frame.h"

#include <string.h>

/* ============================ BE helpers ============================ */

static void put_u16(guint8 *p, guint16 v) {
  p[0] = (guint8)(v >> 8);
  p[1] = (guint8)(v & 0xff);
}

static void put_u32(guint8 *p, guint32 v) {
  p[0] = (guint8)(v >> 24);
  p[1] = (guint8)(v >> 16);
  p[2] = (guint8)(v >> 8);
  p[3] = (guint8)(v & 0xff);
}

static void put_u64(guint8 *p, guint64 v) {
  put_u32(p, (guint32)(v >> 32));
  put_u32(p + 4, (guint32)(v & 0xffffffff));
}

static guint16 get_u16(const guint8 *p) {
  return (guint16)(((guint16)p[0] << 8) | (guint16)p[1]);
}

static guint32 get_u32(const guint8 *p) {
  return ((guint32)get_u16(p) << 16) | (guint32)get_u16(p + 2);
}

static guint64 get_u64(const guint8 *p) {
  return ((guint64)get_u32(p) << 32) | (guint64)get_u32(p + 4);
}

/* Bounds-checked writer: tracks position, fails closed. */
typedef struct {
  guint8 *base;
  gsize   cap;
  gsize   pos;
  gboolean ok;
} W;

/* Payload writers start behind the 8-byte frame header; write_header()
 * fills out[0..7] after the payload has been placed. */
static void w_init(W *w, guint8 *base, gsize cap) {
  w->base = base;
  w->cap = cap;
  w->pos = DFILE_FRAME_HEADER_LEN;
  w->ok = TRUE;
}

static void *w_at(W *w, gsize n) {
  if (!w->ok || w->pos + n > w->cap) {
    w->ok = FALSE;
    return NULL;
  }
  guint8 *p = w->base + w->pos;
  w->pos += n;
  return p;
}

static void w_u16(W *w, guint16 v) {
  guint8 *p = (guint8 *)w_at(w, 2);
  if (p) put_u16(p, v);
}

static void w_u32(W *w, guint32 v) {
  guint8 *p = (guint8 *)w_at(w, 4);
  if (p) put_u32(p, v);
}

static void w_u64(W *w, guint64 v) {
  guint8 *p = (guint8 *)w_at(w, 8);
  if (p) put_u64(p, v);
}

static void w_bytes(W *w, const guint8 *src, gsize n) {
  guint8 *p = (guint8 *)w_at(w, n);
  if (p) memcpy(p, src, n);
}

/* Bounds-checked reader. */
typedef struct {
  const guint8 *base;
  gsize         len;
  gsize         pos;
  gboolean      ok;
} R;

static void r_init(R *r, const guint8 *base, gsize len) {
  r->base = base;
  r->len = len;
  r->pos = 0;
  r->ok = TRUE;
}

static const void *r_take(R *r, gsize n) {
  if (!r->ok || r->pos + n > r->len) {
    r->ok = FALSE;
    return NULL;
  }
  const guint8 *p = r->base + r->pos;
  r->pos += n;
  return p;
}

static guint16 r_u16(R *r) {
  const guint8 *p = (const guint8 *)r_take(r, 2);
  return p ? get_u16(p) : 0;
}

static guint32 r_u32(R *r) {
  const guint8 *p = (const guint8 *)r_take(r, 4);
  return p ? get_u32(p) : 0;
}

static guint64 r_u64(R *r) {
  const guint8 *p = (const guint8 *)r_take(r, 8);
  return p ? get_u64(p) : 0;
}

/* ============================ Header ============================ */

int dfile_frame_header_pack(const DFileFrameHeader *h, guint8 *out) {
  if (h == NULL || out == NULL) return -1;
  if (h->length == 0 || h->length > DFILE_FRAME_MAX_LEN) return -1;
  out[0] = h->type;
  out[1] = h->flag;
  put_u16(out + 2, h->session_id);
  put_u16(out + 4, h->trans_id);
  put_u16(out + 6, h->length);
  return 0;
}

int dfile_frame_header_unpack(const guint8 *in, gsize in_len,
                              DFileFrameHeader *h) {
  if (in == NULL || h == NULL) return -2;
  if (in_len < DFILE_FRAME_HEADER_LEN) return -1;
  h->type = in[0];
  h->flag = in[1];
  h->session_id = get_u16(in + 2);
  h->trans_id = get_u16(in + 4);
  h->length = get_u16(in + 6);
  if (h->length == 0 || h->length > DFILE_FRAME_MAX_LEN) return -2;
  return 0;
}

/*
 * Common decode prelude: the frame must hold exactly header + `length`
 * payload bytes and carry the expected type. Returns the payload pointer
 * or NULL.
 */
static const guint8 *frame_payload(const guint8 *frame, gsize frame_len,
                                   DFileFrameType type, gsize *payload_len) {
  DFileFrameHeader h;
  if (dfile_frame_header_unpack(frame, frame_len, &h) != 0) return NULL;
  if (h.type != (guint8)type) return NULL;
  if (frame_len != (gsize)DFILE_FRAME_HEADER_LEN + h.length) return NULL;
  *payload_len = h.length;
  return frame + DFILE_FRAME_HEADER_LEN;
}

/* Write an 8-byte header with the given type/length into @out. */
static void write_header(guint8 *out, DFileFrameType type, guint8 flag,
                         guint16 trans_id, guint16 length) {
  DFileFrameHeader h = {
    .type = (guint8)type,
    .flag = flag,
    .session_id = 0,
    .trans_id = trans_id,
    .length = length,
  };
  (void)dfile_frame_header_pack(&h, out);
}

/* ============================ Encoders ============================ */

gssize dfile_encode_setting(guint8 *out, gsize cap, const DFileSetting *s) {
  if (s == NULL) return -1;
  gsize need = DFILE_FRAME_HEADER_LEN + DFILE_SETTING_PAYLOAD_LEN;
  if (out == NULL || cap < need) return -1;

  W w;
  w_init(&w, out, cap);
  w_u16(&w, s->mtu);
  w_u16(&w, s->conn_type);
  w_u32(&w, s->dfile_version);
  w_u32(&w, s->abm_capability);
  w_u32(&w, s->capability);
  w_u32(&w, s->data_frame_size);
  w_u32(&w, s->caps_check);
  {
    /* productVersion[64] — NUL padded */
    char pv[64] = {0};
    if (s->product_version[0] != '\0') {
      gsize n = strlen(s->product_version);
      if (n > 63) n = 63;
      memcpy(pv, s->product_version, n);
    }
    w_bytes(&w, (const guint8 *)pv, 64);
  }
  /* 4 single-byte fields: isSupport160M, isSupportMtp, mtpPort, headerEnc */
  {
    guint8 b[4] = {
      (guint8)s->is_support_160m,
      (guint8)s->is_support_mtp,
      (guint8)s->mtp_port,
      (guint8)s->header_enc,
    };
    w_bytes(&w, b, 4);
  }
  w_u32(&w, s->mtp_capability);
  w_u32(&w, s->cipher_capability);

  if (!w.ok || w.pos != DFILE_SETTING_PAYLOAD_LEN + DFILE_FRAME_HEADER_LEN)
    return -1;
  write_header(out, DFILE_FRAME_SETTING, 0, 0, DFILE_SETTING_PAYLOAD_LEN);
  return (gssize)w.pos;
}

gssize dfile_encode_file_header(guint8 *out, gsize cap, guint16 trans_id,
                                guint16 node_number,
                                const DFileHeaderEntry *entries,
                                gsize start, gsize count, gsize *n_written) {
  if (n_written) *n_written = 0;
  if (entries == NULL || count == 0 || start + count > DFILE_MAX_FILE_NUM)
    return -1;

  /* Frame size grows per entry; encode as many as fit in @cap. */
  gsize written = 0;
  gsize pos = DFILE_FRAME_HEADER_LEN + 2; /* header + nodeNumber */
  for (gsize i = 0; i < count; i++) {
    const DFileHeaderEntry *e = &entries[start + i];
    gsize name_len = strlen(e->name);
    if (name_len >= DFILE_MAX_FILE_NAME_LEN) return -1;
    gsize entry_size = 2 + 8 + 2 + name_len; /* id+size+nameLen+name */
    if (pos + entry_size > cap) break;
    written++;
    pos += entry_size;
  }
  if (written == 0) return -1;

  W w;
  w_init(&w, out, cap);
  w_u16(&w, node_number);
  for (gsize i = 0; i < written; i++) {
    const DFileHeaderEntry *e = &entries[start + i];
    gsize name_len = strlen(e->name);
    w_u16(&w, e->file_id);
    w_u64(&w, e->file_size);
    w_u16(&w, (guint16)name_len);
    w_bytes(&w, (const guint8 *)e->name, name_len);
  }
  if (!w.ok) return -1;
  write_header(out, DFILE_FRAME_FILE_HEADER, 0, trans_id,
               (guint16)(w.pos - DFILE_FRAME_HEADER_LEN));
  if (n_written) *n_written = written;
  return (gssize)w.pos;
}

gssize dfile_encode_idlist(guint8 *out, gsize cap, DFileFrameType type,
                           guint8 flag, guint16 trans_id,
                           const guint16 *ids, gsize n) {
  gsize payload = 2 * n;
  if (n > DFILE_MAX_FILE_NUM) return -1;
  if (out == NULL || cap < DFILE_FRAME_HEADER_LEN + payload) return -1;
  if (n > 0 && ids == NULL) return -1;

  W w;
  w_init(&w, out, cap);
  for (gsize i = 0; i < n; i++) w_u16(&w, ids[i]);
  if (!w.ok) return -1;
  write_header(out, type, flag, trans_id, (guint16)payload);
  return (gssize)w.pos;
}

gssize dfile_encode_data(guint8 *out, gsize cap, guint16 trans_id,
                         guint8 flag, guint16 file_id, guint32 block_seq,
                         const guint8 *payload, gsize payload_len) {
  gsize frame_len = DFILE_FRAME_HEADER_LEN + 6 + payload_len;
  if (frame_len > DFILE_FRAME_MAX_SIZE) return -1;
  if (out == NULL || cap < frame_len) return -1;
  if (payload_len > 0 && payload == NULL) return -1;

  W w;
  w_init(&w, out, cap);
  w_u16(&w, file_id);
  w_u32(&w, block_seq);
  w_bytes(&w, payload, payload_len);
  if (!w.ok) return -1;
  write_header(out, DFILE_FRAME_FILE_DATA, flag, trans_id,
               (guint16)(6 + payload_len));
  return (gssize)frame_len;
}

gssize dfile_encode_ack(guint8 *out, gsize cap, gboolean v2,
                        guint16 trans_id, guint8 flag,
                        const DFileAckEntry *entries, gsize n) {
  if (n > DFILE_MAX_ACK_ENTRIES) return -1;
  if (n > 0 && entries == NULL) return -1;

  guint16 count_field = (guint16)((v2 ? 12 : 6) + 37 * n);
  gsize frame_len = DFILE_FRAME_HEADER_LEN + count_field;
  if (out == NULL || cap < frame_len) return -1;

  /* Zero the whole payload first (entries + reserved padding). */
  memset(out + DFILE_FRAME_HEADER_LEN, 0, count_field);

  if (n > 0) {
    /* Entry 0. V2 carries the extra c/d feedback words (10 bytes used). */
    put_u16(out + 8 + 0, entries[0].file_id);
    put_u32(out + 8 + 2, entries[0].last_seq);
    if (v2) {
      put_u16(out + 8 + 6, (guint16)(entries[0].c & 0xffff));
      put_u16(out + 8 + 8, entries[0].d);
    }
  }
  if (v2) {
    /* Entries 1..N-1: {u16 fileId, u32 seq} at offset 12 + 6(i-1). */
    for (gsize i = 1; i < n; i++) {
      gsize off = 8 + 12 + 6 * (i - 1);
      put_u16(out + off, entries[i].file_id);
      put_u32(out + off + 2, entries[i].last_seq);
    }
  } else {
    /* Entries 1..N-1: {u16 fileId, u32 seq} at offset 6(i-1) + 6 = 6i. */
    for (gsize i = 1; i < n; i++) {
      gsize off = 8 + 6 * i;
      put_u16(out + off, entries[i].file_id);
      put_u32(out + off + 2, entries[i].last_seq);
    }
  }

  write_header(out, DFILE_FRAME_FILE_DATA_ACK, flag, trans_id, count_field);
  return (gssize)frame_len;
}

gssize dfile_encode_rst(guint8 *out, gsize cap, guint16 trans_id,
                        guint16 code, const guint16 *ids, gsize n) {
  gsize payload = 2 + 2 * n;
  if (n > DFILE_MAX_FILE_NUM) return -1;
  if (out == NULL || cap < DFILE_FRAME_HEADER_LEN + payload) return -1;
  if (n > 0 && ids == NULL) return -1;

  W w;
  w_init(&w, out, cap);
  w_u16(&w, code);
  for (gsize i = 0; i < n; i++) w_u16(&w, ids[i]);
  if (!w.ok) return -1;
  write_header(out, DFILE_FRAME_RST, 0, trans_id, (guint16)payload);
  return (gssize)w.pos;
}

gssize dfile_encode_backpressure(guint8 *out, gsize cap, guint16 trans_id,
                                 guint8 recv_list_over_io,
                                 guint8 recv_buf_threshold,
                                 guint32 stop_send_period) {
  if (out == NULL || cap < DFILE_FRAME_HEADER_LEN + 6) return -1;

  W w;
  w_init(&w, out, cap);
  {
    guint8 b[2] = {recv_list_over_io, recv_buf_threshold};
    w_bytes(&w, b, 2);
  }
  w_u32(&w, stop_send_period);
  if (!w.ok) return -1;
  write_header(out, DFILE_FRAME_FILE_BACK_PRESSURE, 0, trans_id, 6);
  return DFILE_FRAME_HEADER_LEN + 6;
}

/* ============================ Decoders ============================ */

gboolean dfile_decode_setting(const guint8 *frame, gsize frame_len,
                              DFileSetting *s) {
  gsize plen;
  const guint8 *p = frame_payload(frame, frame_len, DFILE_FRAME_SETTING, &plen);
  if (p == NULL || s == NULL || plen != DFILE_SETTING_PAYLOAD_LEN) return FALSE;

  R r;
  r_init(&r, p, plen);
  s->mtu = r_u16(&r);
  s->conn_type = r_u16(&r);
  s->dfile_version = r_u32(&r);
  s->abm_capability = r_u32(&r);
  s->capability = r_u32(&r);
  s->data_frame_size = r_u32(&r);
  s->caps_check = r_u32(&r);
  {
    const guint8 *pv = (const guint8 *)r_take(&r, 64);
    if (pv == NULL) return FALSE;
    memcpy(s->product_version, pv, 64);
    s->product_version[63] = '\0';
  }
  {
    const guint8 *b = (const guint8 *)r_take(&r, 4);
    if (b == NULL) return FALSE;
    s->is_support_160m = b[0];
    s->is_support_mtp = b[1];
    s->mtp_port = b[2];
    s->header_enc = b[3];
  }
  s->mtp_capability = r_u32(&r);
  s->cipher_capability = r_u32(&r);
  return r.ok;
}

gboolean dfile_decode_file_header(const guint8 *frame, gsize frame_len,
                                  guint16 *trans_id, guint16 *node_number,
                                  DFileHeaderEntry **entries_out,
                                  gsize *n_out) {
  if (entries_out == NULL || n_out == NULL) return FALSE;
  *entries_out = NULL;
  *n_out = 0;

  gsize plen;
  const guint8 *p =
      frame_payload(frame, frame_len, DFILE_FRAME_FILE_HEADER, &plen);
  if (p == NULL || plen < 2) return FALSE;
  DFileFrameHeader h;
  (void)dfile_frame_header_unpack(frame, frame_len, &h);
  if (trans_id) *trans_id = h.trans_id;

  R r;
  r_init(&r, p, plen);
  guint16 node = r_u16(&r);
  if (node_number) *node_number = node;

  gsize cap_entries = node > 0 ? node : DFILE_MAX_FILE_NUM;
  DFileHeaderEntry *entries = g_new0(DFileHeaderEntry, cap_entries);
  gsize n = 0;
  while (r.ok) {
    if (r.pos == r.len) break;
    if (r.len - r.pos < 12) { r.ok = FALSE; break; } /* truncated entry */
    guint16 id = r_u16(&r);
    guint64 size = r_u64(&r);
    guint16 name_len = r_u16(&r);
    if (id == 0) {
      /* UserDataUnit (flag 0x1): not used by the stand; the RE'd decoder
       * consumes it as a unit. Skip its (u16 pathType + data) tail. */
      if (r.len - r.pos < 2) { r.ok = FALSE; break; }
      r_take(&r, 2); /* pathType */
      r_take(&r, r.len - r.pos); /* user data to end of frame */
      break;
    }
    if (name_len == 0 || name_len > DFILE_MAX_FILE_NAME_LEN) {
      r.ok = FALSE;
      break;
    }
    const guint8 *name = (const guint8 *)r_take(&r, name_len);
    if (name == NULL) break;
    if (n >= cap_entries) {
      r.ok = FALSE;
      break;
    }
    entries[n].file_id = id;
    entries[n].file_size = size;
    entries[n].name = g_strndup((const gchar *)name, name_len);
    n++;
  }
  if (!r.ok) {
    dfile_header_entries_free(entries, n);
    return FALSE;
  }
  *entries_out = entries;
  *n_out = n;
  return TRUE;
}

void dfile_header_entries_free(DFileHeaderEntry *entries, gsize n) {
  if (entries == NULL) return;
  for (gsize i = 0; i < n; i++) g_free(entries[i].name);
  g_free(entries);
}

gboolean dfile_decode_idlist(const guint8 *frame, gsize frame_len,
                             DFileFrameType expect_type,
                             guint16 *trans_id, guint8 *flag,
                             guint16 **ids_out, gsize *n_out) {
  if (ids_out == NULL || n_out == NULL) return FALSE;
  *ids_out = NULL;
  *n_out = 0;

  gsize plen;
  const guint8 *p = frame_payload(frame, frame_len, expect_type, &plen);
  if (p == NULL) return FALSE;
  if (plen % 2 != 0) return FALSE;
  DFileFrameHeader h;
  (void)dfile_frame_header_unpack(frame, frame_len, &h);
  if (trans_id) *trans_id = h.trans_id;
  if (flag) *flag = h.flag;

  gsize n = plen / 2;
  if (n > DFILE_MAX_FILE_NUM) return FALSE;
  guint16 *ids = n ? g_new(guint16, n) : NULL;
  R r;
  r_init(&r, p, plen);
  for (gsize i = 0; i < n; i++) ids[i] = r_u16(&r);
  if (!r.ok) {
    g_free(ids);
    return FALSE;
  }
  *ids_out = ids;
  *n_out = n;
  return TRUE;
}

gboolean dfile_decode_data(const guint8 *frame, gsize frame_len,
                           guint16 *trans_id, guint8 *flag,
                           guint16 *file_id, guint32 *block_seq,
                           const guint8 **payload, gsize *payload_len) {
  gsize plen;
  const guint8 *p = frame_payload(frame, frame_len, DFILE_FRAME_FILE_DATA, &plen);
  if (p == NULL || plen < 6) return FALSE;
  DFileFrameHeader h;
  (void)dfile_frame_header_unpack(frame, frame_len, &h);
  if (trans_id) *trans_id = h.trans_id;
  if (flag) *flag = h.flag;

  R r;
  r_init(&r, p, plen);
  guint16 id = r_u16(&r);
  guint32 seq = r_u32(&r);
  if (!r.ok) return FALSE;
  if (file_id) *file_id = id;
  if (block_seq) *block_seq = seq;
  if (payload) *payload = p + r.pos;
  if (payload_len) *payload_len = r.len - r.pos;
  return TRUE;
}

gboolean dfile_decode_ack(const guint8 *frame, gsize frame_len,
                          guint16 *trans_id, guint8 *flag,
                          gboolean *v2, DFileAckEntry **entries_out,
                          gsize *n_out) {
  if (entries_out == NULL || n_out == NULL) return FALSE;
  *entries_out = NULL;
  *n_out = 0;

  gsize plen;
  const guint8 *p =
      frame_payload(frame, frame_len, DFILE_FRAME_FILE_DATA_ACK, &plen);
  if (p == NULL) return FALSE;
  DFileFrameHeader h;
  (void)dfile_frame_header_unpack(frame, frame_len, &h);
  if (trans_id) *trans_id = h.trans_id;
  if (flag) *flag = h.flag;

  /* Count encoding: length field is 6+37N (V1) or 12+37N (V2). */
  guint16 len_field = h.length;
  gboolean is_v2 = (len_field % 37) == 12;
  gboolean is_v1 = (len_field % 37) == 6;
  if (!is_v1 && !is_v2) return FALSE;
  if (len_field >= 0x5c1) return FALSE;
  gsize n = (len_field - (is_v2 ? 12 : 6)) / 37;
  if (v2) *v2 = is_v2;

  DFileAckEntry *entries = n > 0 ? g_new0(DFileAckEntry, n) : NULL;
  if (n > 0) {
    /* Entry 0. */
    entries[0].file_id = get_u16(p + 0);
    entries[0].last_seq = get_u32(p + 2);
    if (is_v2) {
      entries[0].c = get_u16(p + 6);
      entries[0].d = get_u16(p + 8);
    }
  }
  if (is_v2) {
    for (gsize i = 1; i < n; i++) {
      gsize off = 12 + 6 * (i - 1);
      if (off + 6 > plen) { g_free(entries); return FALSE; }
      entries[i].file_id = get_u16(p + off);
      entries[i].last_seq = get_u32(p + off + 2);
    }
  } else {
    for (gsize i = 1; i < n; i++) {
      gsize off = 6 * i;
      if (off + 6 > plen) { g_free(entries); return FALSE; }
      entries[i].file_id = get_u16(p + off);
      entries[i].last_seq = get_u32(p + off + 2);
    }
  }
  *entries_out = entries;
  *n_out = n;
  return TRUE;
}

gboolean dfile_decode_rst(const guint8 *frame, gsize frame_len,
                          guint16 *trans_id, guint16 *code,
                          guint16 **ids_out, gsize *n_out) {
  if (code == NULL || ids_out == NULL || n_out == NULL) return FALSE;
  *ids_out = NULL;
  *n_out = 0;

  gsize plen;
  const guint8 *p = frame_payload(frame, frame_len, DFILE_FRAME_RST, &plen);
  if (p == NULL || plen < 2 || plen % 2 != 0) return FALSE;
  DFileFrameHeader h;
  (void)dfile_frame_header_unpack(frame, frame_len, &h);
  if (trans_id) *trans_id = h.trans_id;

  R r;
  r_init(&r, p, plen);
  *code = r_u16(&r);
  gsize n = (plen - 2) / 2;
  if (n > DFILE_MAX_FILE_NUM) return FALSE;
  guint16 *ids = n ? g_new(guint16, n) : NULL;
  for (gsize i = 0; i < n; i++) ids[i] = r_u16(&r);
  if (!r.ok) {
    g_free(ids);
    return FALSE;
  }
  *ids_out = ids;
  *n_out = n;
  return TRUE;
}
