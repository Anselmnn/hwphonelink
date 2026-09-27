/*
 * dfile_frame.h - DFile (t2stack nstackx) frame codec
 *
 * Wire format (spec §7, RE'd from libnstackx_dfile.so EMUI 12 + OpenHarmony
 * communication_t2stack nstackx_core/dfile):
 *
 *   Frame header (8 bytes, packed, all integers big-endian):
 *
 *     off  len  field
 *     ---  ---  -----------------------------------------------
 *     0    1    type        (1..13)
 *     1    1    flag        per-type bits
 *     2    2    sessionId   always 0
 *     4    2    transId     per-direction transfer id (1 = first)
 *     6    2    length      payload bytes after header. EXCEPTION: type 5
 *                           (FILE_DATA_ACK) encodes the entry count here:
 *                             V1: length = 6  + 37*N
 *                             V2: length = 12 + 37*N
 *
 *   Framing reader (RE: DecodeDFileFrame @ 0x16b50) requires exactly
 *   `length` payload bytes (len - 8 == length) and sanity-checks
 *   length <= 29433 in the main loop.
 */

#pragma once

#include <glib.h>

#define DFILE_FRAME_HEADER_LEN 8
#define DFILE_FRAME_MAX_LEN 29433   /* main-loop sanity cap (0x72f9) */
#define DFILE_FRAME_MAX_SIZE 14720  /* NSTACKX_MAX_FRAME_SIZE */
#define DFILE_DEFAULT_FRAME_SIZE 1472
#define DFILE_MIN_MTU_SIZE 64

#define DFILE_MAX_FILE_NUM 500
#define DFILE_MAX_FILE_NAME_LEN 256
#define DFILE_MAX_USER_DATA_SIZE 1024
#define DFILE_MAX_FILE_SIZE 0x7FFFFFFFFFULL /* 512 GB */
#define DFILE_MAX_ACK_ENTRIES 39
#define DFILE_VERSION 1

/* ============================ Frame types ============================ */

typedef enum {
  DFILE_FRAME_FILE_HEADER = 1,
  DFILE_FRAME_FILE_HEADER_CONFIRM = 2,
  DFILE_FRAME_FILE_TRANSFER_REQ = 3,
  DFILE_FRAME_FILE_DATA = 4,
  DFILE_FRAME_FILE_DATA_ACK = 5,
  DFILE_FRAME_FILE_TRANSFER_DONE = 6,
  DFILE_FRAME_FILE_TRANSFER_DONE_ACK = 7,
  DFILE_FRAME_SETTING = 8,
  DFILE_FRAME_RST = 9,
  DFILE_FRAME_FLOW_CONTROL = 10,
  DFILE_FRAME_CONGESTION_CONTROL = 11,
  DFILE_FRAME_PEER_DOWN = 12,
  DFILE_FRAME_FILE_BACK_PRESSURE = 13,
  DFILE_FRAME_TYPE_MAX
} DFileFrameType;

/* FILE_HEADER flag bits */
#define DFILE_FLAG_HEADER_USER_DATA 0x1
#define DFILE_FLAG_HEADER_PATH_TYPE 0x2
#define DFILE_FLAG_HEADER_NO_SYNC   0x4
#define DFILE_FLAG_HEADER_VTRANS    0x8

/* FILE_DATA flag bits (bits 0-1 select the block kind, bit 2 = retrans) */
#define DFILE_FLAG_DATA_CONTINUE  0x1  /* not the first block of the file */
#define DFILE_FLAG_DATA_END       0x2  /* last block of the file */
#define DFILE_FLAG_DATA_RETRAN    0x4  /* retransmitted block */

/* FILE_DATA_ACK flag bits */
#define DFILE_FLAG_ACK_RETRAN     0x1  /* ACK_RETRAN_FILE_FLAG */

/* Setting capability word (capability field) */
#define DFILE_CAPS_UDP_GSO       (1u << 0)
#define DFILE_CAPS_LINK_SEQUENCE (1u << 1)

/* Setting capsCheck word (internal capability bits) */
#define DFILE_ICAPS_RECV_FEEDBACK (1u << 2)  /* enables V2 acks w/ feedback */

/* RST frame codes (payload first u16) */
#define DFILE_RST_NO_ERROR            200
#define DFILE_RST_WITHOUT_SETTING     201
#define DFILE_RST_FILE_WRITE_ERROR    202
#define DFILE_RST_FILE_READ_ERROR     203
#define DFILE_RST_NO_ENOUGH_STORAGE   204
#define DFILE_RST_INTERNAL_ERROR      209
#define DFILE_RST_CANCEL              210

/* SETTING payload is a fixed 100-byte struct (108 with header) */
#define DFILE_SETTING_PAYLOAD_LEN 100

/* ============================ Structures ============================ */

typedef struct {
  guint8 type;
  guint8 flag;
  guint16 session_id;
  guint16 trans_id;
  guint16 length;  /* payload bytes; count-encoding for ACK (see header) */
} DFileFrameHeader;

typedef struct {
  guint16 file_id;   /* 1..N (0 marks a UserDataUnit on the wire) */
  guint64 file_size;
  gchar  *name;      /* NUL-terminated */
} DFileHeaderEntry;

typedef struct {
  guint16 mtu;
  guint16 conn_type;
  guint32 dfile_version;
  guint32 abm_capability;
  guint32 capability;
  guint32 data_frame_size;
  guint32 caps_check;
  char    product_version[64];
  guint8  is_support_160m;
  guint8  is_support_mtp;
  guint8  mtp_port;
  guint8  header_enc;
  guint32 mtp_capability;
  guint32 cipher_capability;
} DFileSetting;

/*
 * One ACK entry. V1: only file_id + last_seq are meaningful
 * ("all blocks <= last_seq are acked for file_id", cumulative).
 * V2: entry 0 additionally carries c (u16 zero-extended) and d
 * (u16 feedback, fed to SetServerFeedbackBufferWrite on the phone).
 */
typedef struct {
  guint16 file_id;
  guint32 last_seq;
  guint32 c;   /* V2 entry 0 only */
  guint16 d;   /* V2 entry 0 only */
} DFileAckEntry;

/* ============================ Header ============================ */

/* Pack header into @out (8 bytes). 0 on success, -1 if @h->length is out
 * of range. */
int dfile_frame_header_pack(const DFileFrameHeader *h, guint8 *out);

/*
 * Parse a header from the start of @in.
 *  0 : ok (needs at least 8 bytes)
 * -1 : incomplete (fewer than 8 bytes)
 * -2 : invalid (length > DFILE_FRAME_MAX_LEN)
 */
int dfile_frame_header_unpack(const guint8 *in, gsize in_len,
                              DFileFrameHeader *h);

/* ============================ Encoders ============================
 * All encoders write a complete frame (header + payload) into @out.
 * Return total frame size, or -1 if @cap is too small / params invalid.
 */

/* type 8; @s->product_version is copied (truncated to 63 + NUL). */
gssize dfile_encode_setting(guint8 *out, gsize cap, const DFileSetting *s);

/*
 * type 1. Encodes @count entries starting at @entries[@start], as many as
 * fit in @cap (frame size budget, e.g. DFILE_DEFAULT_FRAME_SIZE).
 * @node_number is the total file count for the transfer (RE: nodeNumber
 * field). *n_written = number of entries encoded.
 */
gssize dfile_encode_file_header(guint8 *out, gsize cap, guint16 trans_id,
                                guint16 node_number,
                                const DFileHeaderEntry *entries,
                                gsize start, gsize count, gsize *n_written);

/*
 * type 2/3/6/7 (file-id list frames): payload = u16 fileId[N], length=2N.
 */
gssize dfile_encode_idlist(guint8 *out, gsize cap, DFileFrameType type,
                           guint8 flag, guint16 trans_id,
                           const guint16 *ids, gsize n);

/*
 * type 4. payload = u16 fileId + u32 blockSequence + block; length=6+len.
 */
gssize dfile_encode_data(guint8 *out, gsize cap, guint16 trans_id,
                         guint8 flag, guint16 file_id, guint32 block_seq,
                         const guint8 *payload, gsize payload_len);

/*
 * type 5. @v2 selects the layout (V1: 6B entries, V2: 12B+12B layout);
 * @n entries (0..39). Reserved padding is written as zeros.
 */
gssize dfile_encode_ack(guint8 *out, gsize cap, gboolean v2,
                        guint16 trans_id, guint8 flag,
                        const DFileAckEntry *entries, gsize n);

/*
 * type 9. payload = u16 code + u16 fileId[N].
 */
gssize dfile_encode_rst(guint8 *out, gsize cap, guint16 trans_id,
                        guint16 code, const guint16 *ids, gsize n);

/* type 13 (6B payload). Not used by the replay stand (capsCheck = 0). */
gssize dfile_encode_backpressure(guint8 *out, gsize cap, guint16 trans_id,
                                 guint8 recv_list_over_io,
                                 guint8 recv_buf_threshold,
                                 guint32 stop_send_period);

/* ============================ Decoders ============================
 * All decoders take a COMPLETE frame (header + length payload bytes as
 * delivered by the framer) and validate type/length before parsing.
 * Return FALSE on any inconsistency; outputs are untouched on failure.
 */

gboolean dfile_decode_setting(const guint8 *frame, gsize frame_len,
                              DFileSetting *s);

/*
 * type 1. *entries_out = g_new0'd array owned by the caller
 * (dfile_header_entries_free). A fileId == 0 UserDataUnit terminates the
 * file entries (the tail is ignored, matching the RE'd decoder).
 */
gboolean dfile_decode_file_header(const guint8 *frame, gsize frame_len,
                                  guint16 *trans_id, guint16 *node_number,
                                  DFileHeaderEntry **entries_out,
                                  gsize *n_out);
void dfile_header_entries_free(DFileHeaderEntry *entries, gsize n);

/*
 * type 2/3/6/7. *ids_out = g_malloc'd guint16 array owned by the caller
 * (NULL when n == 0).
 */
gboolean dfile_decode_idlist(const guint8 *frame, gsize frame_len,
                             DFileFrameType expect_type,
                             guint16 *trans_id, guint8 *flag,
                             guint16 **ids_out, gsize *n_out);

/* type 4. *payload points into @frame (borrowed). */
gboolean dfile_decode_data(const guint8 *frame, gsize frame_len,
                           guint16 *trans_id, guint8 *flag,
                           guint16 *file_id, guint32 *block_seq,
                           const guint8 **payload, gsize *payload_len);

/*
 * type 5. *entries_out = g_new0'd DFileAckEntry array owned by the caller
 * (NULL when n == 0). Validates the count encoding:
 * (length-6)%37==0 (V1) or (length-12)%37==0 (V2), length < 0x5c1.
 */
gboolean dfile_decode_ack(const guint8 *frame, gsize frame_len,
                          guint16 *trans_id, guint8 *flag,
                          gboolean *v2, DFileAckEntry **entries_out,
                          gsize *n_out);

/* type 9. *ids_out as in dfile_decode_idlist. */
gboolean dfile_decode_rst(const guint8 *frame, gsize frame_len,
                          guint16 *trans_id, guint16 *code,
                          guint16 **ids_out, gsize *n_out);
