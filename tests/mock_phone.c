/*
 * mock_phone.c - Replay-stand "phone" for the dsoftbus protocol
 *
 * Emulates the phone side of the Multi-Screen stack without a real device:
 *   1. Publishes a CoAP discovery beacon (224.0.1.187:5683, plus a unicast
 *      copy to the daemon so same-host testing is deterministic).
 *   2. Connects to the daemon's TCP session port and wraps the connection
 *      in a SoftbusSession (the PC is the accepting side).
 *   3. Runs the HiChain 4-state auth FSM as the PASSIVE side in PSK mode.
 *   4. On success, verifies the "P40-PING" echo (session data path),
 *      serves the DMSDP control session (spec §6.5): the daemon's
 *      SETUP (CSeq 0) and PLAY (CSeq 1) are byte-verified against the
 *      pinned wire strings and answered with SetupReply / CommonReply;
 *      afterwards the daemon's deterministic 12-event RemoteCtrl input
 *      sequence (spec §6.4) is verified byte-exact.
 *   5. Opens a raw-TCP DFile connection to the daemon, pushes a
 *      deterministic test file (ft-<sha>.bin, verified by the daemon)
 *      and receives the daemon's reverse push (verified by the engine
 *      from the wire name) — bidirectional E2E. Skippable with --no-ft.
 *   6. After the DFile phase, runs the fillp/VTP screen-streaming
 *      phase (spec §8) as the fillp SERVER on UDP stream_port: receives
 *      the daemon's file B and pushes file A — the H.264 mirror clip
 *      (hs-<sha>.h264; the daemon verifies it from the wire name and
 *      decodes it) — both content-verified. Skippable with --no-stream
 *      (implied by --no-ft; the daemon triggers its stream phase off
 *      the DFile phase, so both sides must agree).
 *
 * Exit codes: 0 = full handshake + DMSDP + input + FT + stream OK,
 *             1 = failure/timeout.
 */

#include <glib.h>
#include <gio/gio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "proto/softbus_defs.h"
#include "proto/softbus_device.h"
#include "proto/softbus_auth.h"
#include "proto/softbus_session.h"
#include "proto/softbus_crypto.h"
#include "proto/dfile_conn.h"
#include "proto/ft_testfile.h"
#include "proto/fillp_conn.h"
#include "proto/stream_file.h"
#include "proto/vtp_frame.h"
#include "proto/dmsdp.h"
#include "proto/remote_input.h"

#define MOCK_PING "P40-PING"
/* Wall-clock budget for the whole mock run (auth + FT + stream, incl.
 * up to 3 daemon fillp connect retries). Must stay under the E2E
 * harness `timeout` (90 s). */
#define MOCK_TIMEOUT_MS 80000
#define MOCK_FT_SEED 1
#define MOCK_FT_SIZE (1024 * 1024) /* 1 MiB = 713 blocks @ 1472, last 512 */

static GMainLoop *loop = NULL;
static gint exit_code = 1;
static SoftbusSession *session = NULL;
static SoftbusAuth *auth = NULL;
/* Pre-provisioned PSK; shared with the stream phase (VTP key derivation). */
static gchar *psk = NULL;

/* DFile phase state. The push is started from the engine thread
 * (on_ft_negotiated); results/closure fire there too and are marshalled
 * to the main loop with g_main_context_invoke. */
static DFileConn *ft_dc = NULL;
static volatile gint ft_push_done = 0;
static volatile gint ft_pull_done = 0;
static volatile gint ft_finished = 0;
static guint ft_port = 54322;
static gboolean skip_ft = FALSE;

/* Stream phase (fillp server + VTP file session, spec §8). */
static FillpEngine *stream_engine = NULL;
static FillpPeer *stream_peer = NULL;
static StreamFile *stream_sf = NULL;
static volatile gint stream_tx_done = 0; /* file A pushed + acked */
static volatile gint stream_rx_done = 0; /* file B received + verified */
static volatile gint stream_failed = 0;
static volatile gint stream_established = 0; /* fillp handshake done */
static guint stream_port = 54324;
static gboolean skip_stream = FALSE;

/*
 * M3 (spec §8.7): DMSDP control server on the session + RemoteCtrl
 * input verification + mirror clip push.
 *
 * The daemon (DMSDP client) sends SETUP (CSeq 0) right after auth
 * completes; the mock answers SetupReply (combined Transport), accepts
 * PLAY (CSeq 1) with a CommonReply, and then verifies the daemon's
 * deterministic 12-event RemoteCtrl input sequence. The pinned wire
 * strings below are byte-verified on both sides; the stand runs with
 * the default fillp ports, so the port numbers are part of the pin.
 */
#define MOCK_DMSDP_SERVICE "hwphonelink-mirror"
#define MOCK_DMSDP_ST_INIT 0
#define MOCK_DMSDP_ST_WAIT_PLAY 1
#define MOCK_DMSDP_ST_READY 2
#define MOCK_DMSDP_CLIENT_PORT 54323
#define MOCK_DMSDP_SERVER_PORT 54324
#define MOCK_INPUT_EVENTS 12

static volatile gint dmsdp_state = MOCK_DMSDP_ST_INIT;
static volatile gint input_rx_count = 0;
static volatile gint input_done = 0;
static volatile gint mock_finished = 0;
static gchar *mirror_file_opt = NULL;

/* Runs on the main thread (either directly from the timeout source, or
 * via g_main_context_invoke from the session pump thread). GSourceFunc. */
static int set_exit(gpointer code) {
  int c = GPOINTER_TO_INT(code);
  if (exit_code != 0) exit_code = c;
  g_main_loop_quit(loop);
  return 0;
}

/* Marshalled: print + fail with @msg (takes ownership of the string). */
static int mock_fail(gpointer msg) {
  g_print("mock-phone: FAILED: %s\n", (const gchar *)msg);
  g_free(msg);
  return set_exit(GINT_TO_POINTER(1));
}

static void mock_fail_invoke(const gchar *reason) {
  g_main_context_invoke_full(NULL, G_PRIORITY_DEFAULT, (GSourceFunc)mock_fail,
                             g_strdup(reason), NULL);
}

/*
 * Final success exit (M3): all verification nets are green — the DFile
 * phase (ft_mark_done), the stream phase (push + pull, on_stream_done)
 * and the input sequence (12 events, mock_input_handle). May run on the
 * fillp engine thread or the session pump thread; the exchange guard
 * makes the double call harmless.
 */
static void maybe_finish(void) {
  if (skip_stream) return; /* the FT-only path exits in ft_mark_done */
  if (!g_atomic_int_get(&stream_tx_done) ||
      !g_atomic_int_get(&stream_rx_done) || !g_atomic_int_get(&input_done))
    return;
  if (g_atomic_int_exchange(&mock_finished, 1)) return;
  g_print("mock-phone: STREAM E2E OK (push + pull verified)\n");
  g_print("mock-phone: INPUT E2E OK (%d events verified)\n",
          MOCK_INPUT_EVENTS);
  if (stream_peer != NULL) fillp_peer_close(stream_peer);
  g_main_context_invoke(NULL, set_exit, GINT_TO_POINTER(0));
}

static void print_keys(const gchar *who) {
  const guint8 *ck = softbus_auth_get_control_key(auth);
  const guint8 *dk = softbus_auth_get_data_key(auth);
  if (ck) {
    gchar *h = softbus_to_hex(ck, softbus_auth_get_key_len(auth));
    g_print("mock-phone: [%s] control-key: %s\n", who, h);
    g_free(h);
  }
  if (dk) {
    gchar *h = softbus_to_hex(dk, softbus_auth_get_key_len(auth));
    g_print("mock-phone: [%s] data-key: %s\n", who, h);
    g_free(h);
  }
}

/* ==================== M3: DMSDP control + input (spec §8.7) ====================
 *
 * DMSDP server side on the session socket: SETUP/PLAY are byte-verified
 * against the pinned wire strings and semantically checked with
 * dmsdp_parse; the replies are built with the shared builder and, for
 * the stand's default ports, self-verified against their own pinned
 * strings. All handlers run on the session pump thread.
 */

/* Pinned wire strings (spec §8.7, byte-exact; also unit-tested in
 * proto_test.c). The stand runs with the default fillp ports, so the
 * port numbers are part of the pin. */
static const gchar MOCK_EXPECT_SETUP[] =
    "SETUP * DMSDP/1.0\r\n"
    "CSeq: 0\r\n"
    "ServiceID: hwphonelink-mirror\r\n"
    "ServiceType: 0\r\n"
    "DataSessionID: 1\r\n"
    "Backup: 0\r\n"
    "Transport: RTP/AVP/UDP;unicast;client_port=54323-54323\r\n"
    "\r\n";
static const gchar MOCK_EXPECT_SETUP_REPLY[] =
    "DMSDP/1.0 200 OK\r\n"
    "CSeq: 0\r\n"
    "ServiceID: hwphonelink-mirror\r\n"
    "ServiceType: 0\r\n"
    "DataSessionID: 1\r\n"
    "Transport: RTP/AVP/UDP;unicast;client_port=54323-54323;"
    "server_port=54324-54324\r\n"
    "\r\n";
static const gchar MOCK_EXPECT_PLAY[] =
    "PLAY * DMSDP/1.0\r\n"
    "CSeq: 1\r\n"
    "ServiceID: hwphonelink-mirror\r\n"
    "ServiceType: 0\r\n"
    "DataSessionID: 1\r\n"
    "\r\n";
static const gchar MOCK_EXPECT_COMMON_REPLY[] =
    "DMSDP/1.0 200 OK\r\n"
    "CSeq: 1\r\n"
    "ServiceID: hwphonelink-mirror\r\n"
    "ServiceType: 0\r\n"
    "DataSessionID: 1\r\n"
    "\r\n";

/* Build + frame + send one DMSDP reply; the reply text is additionally
 * compared against @expect (a pinned string) when given. */
static void mock_dmsdp_reply(SoftbusSession *s, const DmsdpMsg *msg,
                             const gchar *expect) {
  gchar text[DMSDP_TEXT_MAX];
  gsize tlen = 0;
  guint8 wire[3 + DMSDP_TEXT_MAX];
  gsize n = 0;
  GError *err = NULL;
  if (dmsdp_build(msg, (guint8 *)text, sizeof(text), &tlen) != 0) {
    mock_fail_invoke("DMSDP reply build failed");
    return;
  }
  if (expect != NULL &&
      (tlen != strlen(expect) || memcmp(text, expect, tlen) != 0)) {
    g_print("mock-phone: DMSDP: built reply deviates from the pinned "
            "wire string\n");
    mock_fail_invoke("DMSDP reply wire deviation");
    return;
  }
  if (dmsdp_frame(text, tlen, wire, sizeof(wire), &n) != 0) {
    mock_fail_invoke("DMSDP reply framing failed");
    return;
  }
  if (!softbus_session_send(s, wire, n, &err)) {
    g_print("mock-phone: DMSDP reply send failed: %s\n",
            err ? err->message : "?");
    g_clear_error(&err);
    mock_fail_invoke("DMSDP reply send failed");
  }
}

/* DMSDP server state machine (session pump thread). @text is the frame
 * payload, @tlen its length. */
static void mock_dmsdp_handle(SoftbusSession *s, const guint8 *text,
                              gsize tlen) {
  DmsdpParsed p;
  dmsdp_parsed_init(&p);
  if (dmsdp_parse((const gchar *)text, tlen, &p) != 0) {
    g_print("mock-phone: DMSDP: received frame did not parse (%u bytes)\n",
            (unsigned)tlen);
    mock_fail_invoke("DMSDP request did not parse");
    return;
  }
  gint st = g_atomic_int_get(&dmsdp_state);
  if (st == MOCK_DMSDP_ST_READY) {
    g_print("mock-phone: DMSDP: ignoring type %u request after READY\n",
            (unsigned)p.type);
    dmsdp_parsed_free(&p);
    return;
  }
  if (p.type == DMSDP_TYPE_SETUP && st == MOCK_DMSDP_ST_INIT) {
    if (tlen != strlen(MOCK_EXPECT_SETUP) ||
        memcmp(text, MOCK_EXPECT_SETUP, tlen) != 0) {
      g_print("mock-phone: DMSDP: SETUP deviates from the pinned wire "
              "string\n");
      dmsdp_parsed_free(&p);
      mock_fail_invoke("SETUP wire deviation");
      return;
    }
    if (p.cseq != 0 || p.service_type != 0 || p.data_session_id != 1 ||
        p.client_port_lo != MOCK_DMSDP_CLIENT_PORT ||
        p.client_port_hi != MOCK_DMSDP_CLIENT_PORT || p.service_id == NULL ||
        strcmp(p.service_id, MOCK_DMSDP_SERVICE) != 0) {
      g_print("mock-phone: DMSDP: SETUP fields deviate (cseq %u, sid '%s')\n",
              (unsigned)p.cseq, p.service_id ? p.service_id : "(null)");
      dmsdp_parsed_free(&p);
      mock_fail_invoke("SETUP field deviation");
      return;
    }
    DmsdpMsg reply;
    dmsdp_msg_setup_reply(&reply, 0, MOCK_DMSDP_SERVICE, 0, 1,
                          MOCK_DMSDP_CLIENT_PORT, MOCK_DMSDP_CLIENT_PORT,
                          stream_port, stream_port);
    g_print("mock-phone: DMSDP: SETUP verified (pinned wire) — replying "
            "(server_port %u-%u)\n",
            (unsigned)stream_port, (unsigned)stream_port);
    g_atomic_int_set(&dmsdp_state, MOCK_DMSDP_ST_WAIT_PLAY);
    dmsdp_parsed_free(&p);
    mock_dmsdp_reply(s, &reply,
                     stream_port == MOCK_DMSDP_SERVER_PORT
                         ? MOCK_EXPECT_SETUP_REPLY
                         : NULL);
    return;
  }
  if (p.type == DMSDP_TYPE_PLAY && st == MOCK_DMSDP_ST_WAIT_PLAY) {
    if (tlen != strlen(MOCK_EXPECT_PLAY) ||
        memcmp(text, MOCK_EXPECT_PLAY, tlen) != 0) {
      g_print("mock-phone: DMSDP: PLAY deviates from the pinned wire "
              "string\n");
      dmsdp_parsed_free(&p);
      mock_fail_invoke("PLAY wire deviation");
      return;
    }
    if (p.cseq != 1 || p.service_type != 0 || p.data_session_id != 1 ||
        p.service_id == NULL ||
        strcmp(p.service_id, MOCK_DMSDP_SERVICE) != 0) {
      g_print("mock-phone: DMSDP: PLAY fields deviate (cseq %u)\n",
              (unsigned)p.cseq);
      dmsdp_parsed_free(&p);
      mock_fail_invoke("PLAY field deviation");
      return;
    }
    DmsdpMsg reply;
    dmsdp_msg_common_reply(&reply, 1, MOCK_DMSDP_SERVICE, 0, 1);
    g_print("mock-phone: DMSDP: PLAY verified (pinned wire) — replying\n");
    g_atomic_int_set(&dmsdp_state, MOCK_DMSDP_ST_READY);
    dmsdp_parsed_free(&p);
    mock_dmsdp_reply(s, &reply, MOCK_EXPECT_COMMON_REPLY);
    g_print("mock-phone: DMSDP OK (SETUP + PLAY exchanged, CSeq 0/1)\n");
    return;
  }
  g_print("mock-phone: DMSDP: unexpected request type %u in state %d\n",
          (unsigned)p.type, st);
  dmsdp_parsed_free(&p);
  mock_fail_invoke("unexpected DMSDP request");
}

/*
 * RemoteCtrl input verification (PC -> phone, spec §6.4). The daemon
 * sends 12 pinned packets right after DMSDP READY; each is checked
 * byte-exact against mock_expect, then structurally decoded with an
 * independent spec-based decoder (framing, class/action map, lenfield
 * degeneracy, per-type body layout, touch zero tail, timestamp) and
 * field-checked against the expected table.
 */

typedef struct {
  guint8 cls; /* hdr[1] */
  guint8 action; /* body[0] */
  guint16 l; /* body length */
  guint32 ts;
  guint8 cnt; /* touch */
  guint8 id; /* touch */
  guint16 px; /* touch/vkey x, zoom x */
  guint16 py; /* touch/vkey y, zoom y */
  guint16 kf16a;
  guint16 kf16b;
  guint32 kf32;
  guint8 mbtn; /* mouse */
  guint16 mx; /* mouse/wheel x */
  guint16 my; /* mouse/wheel y */
  guint16 mz;
  guint16 mw;
  guint8 saxis; /* scroll */
  gint8 sdelta; /* scroll */
  guint8 wdirf; /* wheel dir field */
  guint16 wf1; /* wheel */
  guint8 zp[2]; /* zoom pressure bytes */
  guint16 clen; /* input7 content */
  guint8 content[4];
  guint16 mlen; /* message */
  guint8 msg[4];
} MockInDec;

static const guint8 mock_expect[MOCK_INPUT_EVENTS][32] = {
    /* 0: touch down, 1 point (id 1) @ (1234, 5678), ts 1000 */
    {0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x0e, 0x00, 0x0b, 0x01, 0x01, 0x04, 0xd2, 0x16, 0x2e, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x03, 0xe8, 0x00},
    /* 1: touch move (id 1) @ (1300, 5700), ts 1016 */
    {0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x0f, 0x00, 0x0b, 0x01, 0x01, 0x05, 0x14, 0x16, 0x44, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x03, 0xf8, 0x00},
    /* 2: touch up (id 1) @ (1300, 5700), ts 1032 */
    {0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x02, 0x00, 0x0b, 0x01, 0x01, 0x05, 0x14, 0x16, 0x44, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x04, 0x08, 0x00},
    /* 3: key down (f16a 0x0001), ts 1048 */
    {0x00, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x03, 0x00, 0x09, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x04, 0x18},
    /* 4: key up (f16a 0x0001), ts 1064 */
    {0x00, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x04, 0x00, 0x09, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x04, 0x28},
    /* 5: mouse move (button 0) @ (100, 200), w 6250, ts 1080 */
    {0x00, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x0f, 0x00, 0x09, 0x00, 0x00, 0x64, 0x00, 0xc8, 0x00, 0x00, 0x18,
     0x6a, 0x00, 0x00, 0x04, 0x38},
    /* 6: scroll (axis 0, delta +3), ts 1096 */
    {0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x06, 0x00, 0x03, 0x00, 0x03, 0x00, 0x00, 0x04, 0x48, 0x00},
    /* 7: vkey (sub 0) @ (0, 0), ts 1112 */
    {0x00, 0x03, 0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x02, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x58,
     0x00},
    /* 8: wheel (dir field 1), ts 1128 */
    {0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x0c, 0x00, 0x07, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x04, 0x68},
    /* 9: input7 content "hi" (len 2), ts 1144 */
    {0x00, 0x02, 0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x05, 0x00, 0x02, 0x68, 0x69, 0x00, 0x00, 0x04, 0x78,
     0x00},
    /* 10: message (len 5, payload "hi!"), ts 1160 */
    {0x00, 0x04, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x06, 0x00, 0x07, 0x00, 0x05, 0x00, 0x00, 0x68, 0x69, 0x21, 0x00,
     0x00, 0x04, 0x88},
    /* 11: zoom (10, 20), pressure 1.0, ts 1176 */
    {0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x05, 0x00, 0x07, 0x00, 0x0a, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00,
     0x04, 0x98, 0x00},
};
static const gsize mock_expect_len[MOCK_INPUT_EVENTS] = {
    28, 28, 28, 26, 26, 26, 20, 22, 24, 22, 24, 24,
};
static const gchar *const mock_input_desc[MOCK_INPUT_EVENTS] = {
    "touch down (id 1) @ (1234, 5678)",
    "touch move (id 1) @ (1300, 5700)",
    "touch up (id 1) @ (1300, 5700)",
    "key down (f16a 0x0001)",
    "key up (f16a 0x0001)",
    "mouse move (button 0) @ (100, 200), w 6250",
    "scroll (axis 0, delta +3)",
    "vkey (sub 0) @ (0, 0)",
    "wheel (dir field 1)",
    "input7 content \"hi\" (len 2)",
    "message (len 5, payload \"hi!\")",
    "zoom (10, 20), pressure 1.0",
};

/*
 * Spec §6.4 structural decoder, independent of remote_input.c:
 * framing (total, reserved zeros, pad byte), class -> action map, the
 * lenfield degeneracy (L&1)+(L-3), per-type body layouts, the touch
 * zero tail and the timestamp.
 *
 * len = 10 + L + 4 + pad with pad = (L+4) & 1, so from len alone the
 * body length is ambiguous: L is either rem = len-14 (no pad, L even)
 * or rem-1 (pad present, L odd). Both candidates are tried; the
 * per-type L constraints decide. On success fills @out.
 */
static gboolean mock_input_decode_body(const guint8 *d, guint16 l,
                                       guint32 exp_ts, MockInDec *out) {
  guint32 ts = ((guint32)d[10 + l] << 24) | ((guint32)d[11 + l] << 16) |
               ((guint32)d[12 + l] << 8) | d[13 + l];
  guint8 cls = d[1];
  guint8 action = d[10];
  gboolean cls_ok = FALSE;
  switch (cls) {
  case 0:
    cls_ok = (action == 0x0e || action == 0x0f || action == 0x02 ||
              action == 0x10 || action == 0x03 || action == 0x04 ||
              action == 0x05 || action == 0x06 || action == 0x07 ||
              action == 0x0c || action == 0x0d);
    break;
  case 2:
    cls_ok = (action == 0x00 || action == 0x01);
    break;
  case 3:
    cls_ok = (action >= 0x02 && action <= 0x05);
    break;
  case 4:
    cls_ok = (action == 0x06 || action == 0x07);
    break;
  default:
    break;
  }
  if (!cls_ok) return FALSE;
  /* lenfield degeneracy (spec §6.4): (L & 1) + (L - 3) */
  guint16 lf = (guint16)((l & 1) + (l - 3));
  guint16 lf_be = (guint16)(((guint)d[11] << 8) | d[12]);
  if (lf_be != lf) return FALSE;

  const guint8 *b = d + 10;
  memset(out, 0, sizeof(*out));
  out->cls = cls;
  out->action = action;
  out->l = l;
  out->ts = ts;
  if (cls == 0) {
    switch (action) {
    case 0x0e:
    case 0x0f:
      if (l == 12) {
        /* mouse down/move: button + x,y,z,w (u16 BE) */
        out->mbtn = b[3];
        out->mx = (guint16)(((guint)b[4] << 8) | b[5]);
        out->my = (guint16)(((guint)b[6] << 8) | b[7]);
        out->mz = (guint16)(((guint)b[8] << 8) | b[9]);
        out->mw = (guint16)(((guint)b[10] << 8) | b[11]);
      } else {
        /* touch down/move: cnt 5-byte points, zero tail */
        guint8 cnt = b[3];
        if (cnt < 1 || cnt > 4 || l != (guint16)(9 * cnt + 4)) return FALSE;
        out->cnt = cnt;
        out->id = b[4];
        out->px = (guint16)(((guint)b[5] << 8) | b[6]);
        out->py = (guint16)(((guint)b[7] << 8) | b[8]);
        for (gsize i = 4 + 5 * cnt; i < l; i++)
          if (b[i] != 0) return FALSE;
      }
      break;
    case 0x02: /* touch up */
    case 0x10: /* mouse up */
      if (action == 0x02) {
        guint8 cnt = b[3];
        if (cnt < 1 || cnt > 4 || l != (guint16)(9 * cnt + 4)) return FALSE;
        out->cnt = cnt;
        out->id = b[4];
        out->px = (guint16)(((guint)b[5] << 8) | b[6]);
        out->py = (guint16)(((guint)b[7] << 8) | b[8]);
        for (gsize i = 4 + 5 * cnt; i < l; i++)
          if (b[i] != 0) return FALSE;
      } else {
        if (l != 12) return FALSE;
        out->mbtn = b[3];
        out->mx = (guint16)(((guint)b[4] << 8) | b[5]);
        out->my = (guint16)(((guint)b[6] << 8) | b[7]);
        out->mz = (guint16)(((guint)b[8] << 8) | b[9]);
        out->mw = (guint16)(((guint)b[10] << 8) | b[11]);
      }
      break;
    case 0x03:
    case 0x04: /* key down/up */
      if (l != 12) return FALSE;
      if (b[3] != 0) return FALSE;
      out->kf16a = (guint16)(((guint)b[4] << 8) | b[5]);
      out->kf16b = (guint16)(((guint)b[6] << 8) | b[7]);
      out->kf32 = ((guint32)b[8] << 24) | ((guint32)b[9] << 16) |
                  ((guint32)b[10] << 8) | b[11];
      break;
    case 0x05: /* zoom */
      if (l != 9) return FALSE;
      out->px = (guint16)(((guint)b[3] << 8) | b[4]);
      out->py = (guint16)(((guint)b[5] << 8) | b[6]);
      out->zp[0] = b[7];
      out->zp[1] = b[8];
      break;
    case 0x06:
    case 0x07: /* scroll */
      if (l != 5) return FALSE;
      out->saxis = b[3];
      out->sdelta = (gint8)b[4];
      break;
    case 0x0c:
    case 0x0d: /* wheel */
      if (l != 10) return FALSE;
      out->wdirf = b[3];
      out->wf1 = (guint16)(((guint)b[4] << 8) | b[5]);
      out->mx = (guint16)(((guint)b[6] << 8) | b[7]);
      out->my = (guint16)(((guint)b[8] << 8) | b[9]);
      break;
    default:
      return FALSE;
    }
  } else if (cls == 2) {
    if (action == 0x00) { /* content */
      out->clen = (guint16)(((guint)b[3] << 8) | b[4]);
      if (out->clen == 0 || out->clen > 4) return FALSE;
      if (l != (guint16)(out->clen + 5)) return FALSE;
      memcpy(out->content, b + 5, out->clen);
    } else {
      return FALSE; /* focus: not in the stand sequence */
    }
  } else if (cls == 3) { /* vkey */
    if (l != 7) return FALSE;
    out->px = (guint16)(((guint)b[3] << 8) | b[4]);
    out->py = (guint16)(((guint)b[5] << 8) | b[6]);
  } else { /* cls 4: message */
    out->mlen = (guint16)(((guint)b[3] << 8) | b[4]);
    if ((guint16)(((guint)b[5] << 8) | b[6]) != 0) return FALSE;
    if (out->mlen < 2 || out->mlen > 6) return FALSE;
    if (l != (guint16)(out->mlen + 5)) return FALSE;
    memcpy(out->msg, b + 7, out->mlen - 2);
  }
  return ts == exp_ts;
}

/* Entry point: framing checks, then the two-candidate body decode. */
static gboolean mock_input_decode(const guint8 *d, gsize len, guint32 exp_ts,
                                  MockInDec *out) {
  if (len < 14) return FALSE;
  if (d[0] != 0) return FALSE;
  guint16 total = (guint16)(((guint)d[2] << 8) | d[3]);
  if (total != len) return FALSE;
  for (gint i = 5; i < 9; i++)
    if (d[i] != 0) return FALSE;
  guint16 rem = (guint16)(len - 14); /* = L + pad */
  if (rem < 5) return FALSE;
  for (guint pad = 0; pad <= 1; pad++) {
    if (rem < pad) continue;
    guint16 l = (guint16)(rem - pad);
    if (((guint)l + 4) & 1) {
      if (pad != 1) continue;
      if (d[len - 1] != 0) continue; /* the pad byte must be zero */
    } else if (pad != 0) {
      continue;
    }
    if (mock_input_decode_body(d, l, exp_ts, out)) return TRUE;
  }
  return FALSE;
}

/* Per-index expected fields (the daemon's event table, spec §8.7). */
static gboolean mock_input_fields_ok(guint i, const MockInDec *d) {
  switch (i) {
  case 0:
    return d->cls == 0 && d->action == 0x0e && d->cnt == 1 && d->id == 1 &&
           d->px == 1234 && d->py == 5678;
  case 1:
    return d->cls == 0 && d->action == 0x0f && d->cnt == 1 && d->id == 1 &&
           d->px == 1300 && d->py == 5700;
  case 2:
    return d->cls == 0 && d->action == 0x02 && d->cnt == 1 && d->id == 1 &&
           d->px == 1300 && d->py == 5700;
  case 3:
    return d->cls == 0 && d->action == 0x03 && d->kf16a == 1 &&
           d->kf16b == 0 && d->kf32 == 0;
  case 4:
    return d->cls == 0 && d->action == 0x04 && d->kf16a == 1 &&
           d->kf16b == 0 && d->kf32 == 0;
  case 5:
    return d->cls == 0 && d->action == 0x0f && d->mbtn == 0 && d->mx == 100 &&
           d->my == 200 && d->mz == 0 && d->mw == 6250;
  case 6:
    return d->cls == 0 && d->action == 0x06 && d->saxis == 0 &&
           d->sdelta == 3;
  case 7:
    return d->cls == 3 && d->action == 0x02 && d->px == 0 && d->py == 0;
  case 8:
    return d->cls == 0 && d->action == 0x0c && d->wdirf == 1 && d->wf1 == 0 &&
           d->mx == 0 && d->my == 0;
  case 9:
    return d->cls == 2 && d->action == 0x00 && d->clen == 2 &&
           memcmp(d->content, "hi", 2) == 0;
  case 10:
    return d->cls == 4 && d->action == 0x06 && d->mlen == 5 &&
           memcmp(d->msg, "hi!", 3) == 0;
  case 11:
    return d->cls == 0 && d->action == 0x05 && d->px == 10 && d->py == 20 &&
           d->zp[0] == 0 && d->zp[1] == 0;
  default:
    return FALSE;
  }
}

/* One RemoteCtrl packet from the daemon (session pump thread). */
static void mock_input_handle(const guint8 *data, gsize len) {
  g_atomic_int_inc(&input_rx_count);
  guint i = (guint)g_atomic_int_get(&input_rx_count) - 1;
  if (i >= MOCK_INPUT_EVENTS) {
    g_print("mock-phone: INPUT: unexpected extra packet #%u\n", (unsigned)i);
    mock_fail_invoke("extra input packet");
    return;
  }
  if (len != mock_expect_len[i] || memcmp(data, mock_expect[i], len) != 0) {
    g_print("mock-phone: INPUT: packet %u deviates from the pinned bytes "
            "(len %u vs %u)\n",
            (unsigned)i, (unsigned)len, (unsigned)mock_expect_len[i]);
    mock_fail_invoke("input byte deviation");
    return;
  }
  MockInDec dec;
  if (!mock_input_decode(data, len, 1000 + 16 * i, &dec)) {
    g_print("mock-phone: INPUT: packet %u failed the structural decode\n",
            (unsigned)i);
    mock_fail_invoke("input decode failure");
    return;
  }
  if (!mock_input_fields_ok(i, &dec)) {
    g_print("mock-phone: INPUT: packet %u fields deviate from the "
            "expected table\n",
            (unsigned)i);
    mock_fail_invoke("input field deviation");
    return;
  }
  g_print("mock-phone: INPUT %2u/%d ok: %s\n", (unsigned)(i + 1),
          MOCK_INPUT_EVENTS, mock_input_desc[i]);
  if (i + 1 == MOCK_INPUT_EVENTS) {
    g_atomic_int_set(&input_done, 1);
    g_print("mock-phone: INPUT sequence verified (%d/%d events byte-exact)\n",
            MOCK_INPUT_EVENTS, MOCK_INPUT_EVENTS);
    maybe_finish();
  }
}

/*
 * Mirror clip (file A, M3): a real x264 H.264 clip committed to the
 * repo (tests/data/mirror-testsrc.h264). The wire name is
 * hs-<sha256>.h264, computed here at runtime; the daemon's stream_file
 * re-derives the sha from the name and verifies the received bytes
 * (plus the Annex-B NAL structure), then the main loop decodes the
 * clip (mirror_player). Lookup order: --mirror-file,
 * CWD/mirror-testsrc.h264, MIRROR_CLIP_DEFAULT (meson: the committed
 * source-tree path).
 */
#ifndef MIRROR_CLIP_DEFAULT
#define MIRROR_CLIP_DEFAULT "mirror-testsrc.h264"
#endif

static gboolean resolve_clip(gchar **out_path, gchar **out_wire,
                             guint64 *out_size) {
  gchar *path = NULL;
  if (mirror_file_opt != NULL) {
    path = g_strdup(mirror_file_opt);
  } else {
    gchar *cwd = g_build_filename(g_get_current_dir(), "mirror-testsrc.h264",
                                  NULL);
    if (g_file_test(cwd, G_FILE_TEST_IS_REGULAR)) {
      path = cwd;
    } else {
      g_free(cwd);
      path = g_strdup(MIRROR_CLIP_DEFAULT);
    }
  }
  if (!g_file_test(path, G_FILE_TEST_IS_REGULAR)) {
    g_print("mock-phone: mirror clip not found: %s\n", path);
    g_free(path);
    return FALSE;
  }
  gchar *text = NULL;
  gsize len = 0;
  if (!g_file_get_contents(path, &text, &len, NULL) || len == 0) {
    g_print("mock-phone: cannot read the mirror clip: %s\n", path);
    g_free(path);
    g_free(text);
    return FALSE;
  }
  GChecksum *sum = g_checksum_new(G_CHECKSUM_SHA256);
  g_checksum_update(sum, (const guint8 *)text, (gssize)len);
  gchar *digest = g_strdup(g_checksum_get_string(sum));
  g_checksum_free(sum);
  g_free(text);
  *out_path = path;
  *out_wire = g_strdup_printf("hs-%s.h264", digest);
  *out_size = (guint64)len;
  return TRUE;
}

/* ============================ Stream phase (fillp + VTP) ============================
 *
 * After the DFile phase, the mock runs the fillp SERVER engine on
 * stream_port (the daemon connects as the fillp client). One
 * bidirectional StreamFile: push file A (the H.264 mirror clip,
 * verified by the daemon from the wire name) and receive the daemon's
 * file B (verified here).
 *
 * Engine callbacks fire on the fillp engine thread; they only marshal
 * to the main loop via g_main_context_invoke().
 */

/* Marshalled: print + fail with @msg (takes ownership of the string). */
static int stream_fail(gpointer msg) {
  g_print("mock-phone: STREAM FAILED: %s\n", (const gchar *)msg);
  g_free(msg);
  return set_exit(GINT_TO_POINTER(1));
}

static void stream_fail_invoke(const gchar *reason) {
  g_main_context_invoke_full(NULL, G_PRIORITY_DEFAULT, (GSourceFunc)stream_fail,
                             g_strdup(reason), NULL);
}

/* One direction finished (fillp engine thread). */
static void on_stream_done(StreamFile *sf, gboolean is_send, gboolean ok,
                           const gchar *message, gpointer user_data) {
  (void)sf;
  (void)user_data;
  g_print("mock-phone: STREAM %s %s: %s\n", is_send ? "push" : "pull",
          ok ? "OK" : "FAILED", message);
  g_free((gchar *)message);
  if (!ok) {
    g_atomic_int_set(&stream_failed, 1);
    stream_fail_invoke("one-direction stream transfer failed");
    return;
  }
  if (is_send)
    g_atomic_int_set(&stream_tx_done, 1);
  else
    g_atomic_int_set(&stream_rx_done, 1);
  maybe_finish();
}

/* Handshake complete (fillp engine thread): start pushing file A and
 * attach the receive side for the daemon's file B. */
static void on_stream_established(FillpEngine *engine, FillpPeer *peer,
                                  gpointer user_data) {
  (void)engine;
  (void)user_data;
  g_atomic_int_set(&stream_established, 1);
  stream_peer = peer;

  /* File A (M3): the H.264 mirror clip. The DMSDP control session must
   * be READY before the stream phase — the stand flow is broken
   * otherwise (the daemon reaches the stream phase after DMSDP, and
   * the clip push is gated on READY). */
  if (g_atomic_int_get(&dmsdp_state) != MOCK_DMSDP_ST_READY) {
    g_print("mock-phone: DMSDP control session not READY before the "
            "stream phase\n");
    stream_fail_invoke("DMSDP flow incomplete");
    return;
  }
  gchar *path = NULL;
  gchar *wire_name = NULL;
  guint64 clip_size = 0;
  if (!resolve_clip(&path, &wire_name, &clip_size)) {
    stream_fail_invoke("mirror clip unavailable");
    return;
  }
  g_print("mock-phone: STREAM pushing %s (%" G_GUINT64_FORMAT " bytes)\n",
          wire_name, clip_size);

  guint8 key[VTP_KEY_LEN];
  vtp_derive_key((const guint8 *)psk, strlen(psk), key);
  stream_sf = stream_file_new(peer, key);
  gchar *rxdir =
      g_build_filename(g_get_tmp_dir(), "hwphonelink-mock-stream-rx", NULL);
  g_mkdir_with_parents(rxdir, 0755);
  stream_file_set_recv_dir(stream_sf, rxdir);
  g_free(rxdir);
  stream_file_set_callbacks(stream_sf, NULL, on_stream_done, NULL);

  GError *err = NULL;
  if (!stream_file_start_send(stream_sf, path, wire_name, &err)) {
    g_print("mock-phone: stream push start failed: %s\n",
            err ? err->message : "?");
    g_clear_error(&err);
    stream_file_close(stream_sf);
    stream_sf = NULL;
    stream_fail_invoke("stream push start failed");
  }
  g_free(path);
  g_free(wire_name);
}

/* Peer teardown (fillp engine thread); the peer is dead after this. */
static void on_stream_closed(FillpEngine *engine, FillpPeer *peer,
                             const gchar *reason, gpointer user_data) {
  (void)engine;
  (void)user_data;
  g_print("mock-phone: fillp peer closed: %s\n", reason);
  if (stream_sf != NULL) {
    stream_file_close(stream_sf);
    stream_sf = NULL;
  }
  if (stream_peer == peer) stream_peer = NULL;
  if (stream_failed) return; /* failure already reported */
  if (stream_tx_done && stream_rx_done) return; /* normal completion */
  if (!stream_established) {
    /* The handshake never completed (lost datagram, server bring-up
     * race, ...): the daemon retries the connect, so keep the fillp
     * server listening. The overall timeout still bounds the wait. */
    g_print("mock-phone: fillp handshake incomplete — waiting for the "
            "daemon to retry\n");
    return;
  }
  stream_fail_invoke("fillp session closed before stream completed");
}

/* Main loop thread (from ft_mark_done): bring up the fillp server. */
static void start_stream(void) {
  GError *err = NULL;
  stream_engine = fillp_engine_new(stream_port, &err);
  if (stream_engine == NULL) {
    g_print("mock-phone: fillp engine start failed: %s\n",
            err ? err->message : "unknown");
    g_clear_error(&err);
    stream_fail_invoke("fillp engine start failed");
    return;
  }
  fillp_engine_set_callbacks(stream_engine, on_stream_established, NULL, NULL,
                             on_stream_closed, NULL);
  g_print("mock-phone: fillp server on UDP port %u (waiting for the "
          "daemon)\n",
          (unsigned)stream_port);
}

/* ============================ DFile phase ============================
 *
 * After the echo check the mock opens a raw-TCP DFile client connection
 * to the daemon (proto/dfile_conn.h), pushes a deterministic test file
 * (ft-<sha256>.bin) and receives the daemon's reverse push. The wire
 * name convention lets the receiver verify content without extra
 * metadata.
 *
 * Engine callbacks fire on the DFile engine thread; they only marshal
 * to the main loop via g_main_context_invoke().
 */

/* Marshalled: print + fail with @msg (takes ownership of the string). */
static int ft_fail(gpointer msg) {
  g_print("mock-phone: FT FAILED: %s\n", (const gchar *)msg);
  g_free(msg);
  return set_exit(GINT_TO_POINTER(1));
}

static void ft_fail_invoke(const gchar *reason) {
  g_main_context_invoke_full(NULL, G_PRIORITY_DEFAULT, (GSourceFunc)ft_fail,
                             g_strdup(reason), NULL);
}

/* Both directions verified → stream phase (or exit 0 if skipped). */
static int ft_mark_done(gpointer p) {
  (void)p;
  if (g_atomic_int_exchange(&ft_finished, 1)) return 0;
  if (skip_stream) {
    g_print("mock-phone: FT E2E OK (push + pull verified)\n");
    return set_exit(GINT_TO_POINTER(0));
  }
  g_print("mock-phone: FT E2E OK (push + pull verified) — starting the "
          "stream phase\n");
  start_stream();
  return 0;
}

static void on_ft_negotiated(DFileConn *dc, gpointer user_data) {
  (void)user_data;
  g_print("mock-phone: DFile session negotiated (block size %u)\n",
          dfile_conn_block_size(dc));

  /* Push file A: deterministic test content, self-describing name. */
  gchar *dir = g_build_filename(g_get_tmp_dir(), "hwphonelink-mock-ft",
                                NULL);
  gchar *path = NULL;
  gchar *wire_name = NULL;
  if (g_mkdir_with_parents(dir, 0755) < 0 ||
      !ft_testfile_generate(dir, MOCK_FT_SEED, MOCK_FT_SIZE, &path,
                            &wire_name)) {
    g_print("mock-phone: test file generation failed\n");
    g_free(dir);
    ft_fail_invoke("cannot generate test file");
    return;
  }
  g_print("mock-phone: pushing %s (%u bytes)\n", wire_name,
          (unsigned)MOCK_FT_SIZE);
  DFileSendItem item = {path, wire_name, 0};
  GError *err = NULL;
  if (!dfile_conn_send_files(dc, &item, 1, &err)) {
    g_print("mock-phone: push start failed: %s\n", err ? err->message : "?");
    g_clear_error(&err);
    ft_fail_invoke("push start failed");
  }
  g_free(path);
  g_free(wire_name);
  g_free(dir);
}

static void on_ft_file_list(DFileConn *dc, const DFileHeaderEntry *entries,
                            gsize n, gpointer user_data) {
  (void)dc;
  (void)user_data;
  for (gsize i = 0; i < n; i++)
    g_print("mock-phone: incoming file %u: %s (%" G_GUINT64_FORMAT
            " bytes)\n", (unsigned)entries[i].file_id, entries[i].name,
            entries[i].file_size);
}

static void on_ft_result(DFileConn *dc, gboolean is_sender, gboolean ok,
                         const gchar *msg, gpointer user_data) {
  (void)dc;
  (void)user_data;
  if (!ok) {
    ft_fail_invoke(msg);
    return;
  }
  g_print("mock-phone: FT %s done: %s\n", is_sender ? "push" : "pull", msg);
  if (is_sender)
    g_atomic_int_set(&ft_push_done, 1);
  else
    g_atomic_int_set(&ft_pull_done, 1);
  if (ft_push_done && ft_pull_done)
    g_main_context_invoke(NULL, ft_mark_done, NULL);
}

static void on_ft_closed(DFileConn *dc, gpointer user_data) {
  (void)dc;
  (void)user_data;
  g_print("mock-phone: DFile session closed\n");
  if (!(ft_push_done && ft_pull_done))
    ft_fail_invoke("FT session closed before both transfers completed");
  /* The mock keeps its external ref until main() cleanup. */
}

/* Called on the session pump thread after the echo check. A blocking
 * connect here is fine — the daemon's FT listener is already up. */
static void start_ft(const gchar *server_ip) {
  GError *err = NULL;
  DFileConn *dc = dfile_conn_new_client(server_ip, ft_port, &err);
  if (dc == NULL) {
    g_print("mock-phone: DFile connect failed: %s\n",
            err ? err->message : "?");
    g_clear_error(&err);
    ft_fail_invoke("DFile connect failed");
    return;
  }
  gchar *rxdir = g_build_filename(g_get_tmp_dir(), "hwphonelink-mock-ft-rx",
                                  NULL);
  g_mkdir_with_parents(rxdir, 0755);
  dfile_conn_set_recv_dir(dc, rxdir);
  g_free(rxdir);
  dfile_conn_set_callbacks(dc, on_ft_negotiated, on_ft_file_list,
                           on_ft_result, on_ft_closed, NULL);
  ft_dc = dc;
}

/* Session data callback (pump thread). */
static void on_data(SoftbusSession *s, const guint8 *data, gsize len,
                    gpointer user_data) {
  if (softbus_auth_get_state(auth) == SOFTBUS_AUTH_STATE_DONE) {
    /*
     * Post-auth (M3). The session delivers discrete logical messages,
     * so the three message kinds are structurally distinguishable:
     *   - the exact 8-byte P40-PING: the echo of our ping (M2 net);
     *   - [0x00][u16 BE N][text] with 3+N == len: a DMSDP NoCrypto
     *     frame (SETUP / PLAY from the daemon's control client);
     *   - u16be(data[2..4]) == len with data[0] == 0: a RemoteCtrl
     *     input packet (the daemon's 12-event sequence).
     */
    if (len == strlen(MOCK_PING) && memcmp(data, MOCK_PING, len) == 0) {
      g_print("mock-phone: echo of %s received — session data path OK\n",
              MOCK_PING);
      if (skip_ft)
        g_main_context_invoke(NULL, set_exit, GINT_TO_POINTER(0));
      else
        start_ft((const gchar *)user_data);
      return;
    }
    if (len >= 3 && data[0] == DMSDP_FRAME_TYPE_NOCRYPTO) {
      guint16 n = (guint16)(((guint)data[1] << 8) | data[2]);
      if (n <= DMSDP_FRAME_MAX_PAYLOAD && (gsize)(3 + n) == len) {
        mock_dmsdp_handle(s, data + 3, n);
        return;
      }
    }
    if (len >= 14 && data[0] == 0) {
      guint16 total = (guint16)(((guint)data[2] << 8) | data[3]);
      if (total == len) {
        mock_input_handle(data, len);
        return;
      }
    }
    g_print("mock-phone: unexpected post-auth payload (%u bytes) — "
            "ignored\n",
            (unsigned)len);
    return;
  }

  gchar *reply = NULL;
  GError *err = NULL;
  SoftbusAuthResult result = softbus_auth_feed(auth, (const gchar *)data,
                                               len, &reply, &err);
  if (err) {
    g_print("mock-phone: auth error: %s\n", err->message);
    g_clear_error(&err);
  }
  if (reply) {
    GError *serr = NULL;
    if (!softbus_session_send_json(s, reply, &serr)) {
      g_print("mock-phone: reply send failed: %s\n",
              serr ? serr->message : "?");
      g_clear_error(&serr);
    }
    g_free(reply);
  }

  switch (result) {
    case SOFTBUS_AUTH_RESULT_COMPLETE: {
      const SoftbusDevice *peer = softbus_auth_get_peer(auth);
      g_print("mock-phone: AUTH COMPLETE (PSK) with %s\n",
              peer ? softbus_device_get_id(peer) : "pc");
      print_keys("phone");
      GError *serr = NULL;
      if (!softbus_session_send(s, (const guint8 *)MOCK_PING,
                                strlen(MOCK_PING), &serr)) {
        g_print("mock-phone: ping send failed: %s\n",
                serr ? serr->message : "?");
        g_clear_error(&serr);
        g_main_context_invoke(NULL, set_exit, GINT_TO_POINTER(1));
      }
      break;
    }
    case SOFTBUS_AUTH_RESULT_FAILED:
      g_print("mock-phone: AUTH FAILED\n");
      g_main_context_invoke(NULL, set_exit, GINT_TO_POINTER(1));
      break;
    default:
      break;
  }
}

/* Send the discovery beacon: multicast + unicast to the daemon. */
static void send_beacon(SoftbusDevice *dev, const gchar *server_ip) {
  GError *err = NULL;
  gchar *beacon = softbus_device_pack_beacon(dev, &err);
  if (!beacon) {
    g_print("mock-phone: beacon pack failed: %s\n", err ? err->message : "?");
    g_clear_error(&err);
    return;
  }

  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    g_print("mock-phone: cannot open UDP socket: %s\n", g_strerror(errno));
    g_free(beacon);
    return;
  }

  struct sockaddr_in dst;
  memset(&dst, 0, sizeof(dst));
  dst.sin_family = AF_INET;
  dst.sin_port = htons(SOFTBUS_COAP_PORT);
  inet_pton(AF_INET, SOFTBUS_COAP_MCAST_ADDR, &dst.sin_addr);
  if (sendto(fd, beacon, strlen(beacon), 0,
             (struct sockaddr *)&dst, sizeof(dst)) < 0) {
    g_print("mock-phone: multicast beacon failed: %s\n", g_strerror(errno));
  } else {
    g_print("mock-phone: beacon published to %s:%d (%zu bytes)\n",
            SOFTBUS_COAP_MCAST_ADDR, SOFTBUS_COAP_PORT, strlen(beacon));
  }

  /* Unicast copy to the daemon (deterministic for same-host testing). */
  struct sockaddr_in dst2 = dst;
  inet_pton(AF_INET, server_ip, &dst2.sin_addr);
  if (sendto(fd, beacon, strlen(beacon), 0,
             (struct sockaddr *)&dst2, sizeof(dst2)) < 0) {
    g_print("mock-phone: unicast beacon failed: %s\n", g_strerror(errno));
  } else {
    g_print("mock-phone: beacon also sent to %s:%d\n",
            server_ip, SOFTBUS_COAP_PORT);
  }

  close(fd);
  g_free(beacon);
}

static gboolean on_timeout(gpointer data) {
  (void)data;
  g_print("mock-phone: timed out waiting for handshake/echo/FT/stream\n");
  set_exit(GINT_TO_POINTER(1));
  return G_SOURCE_REMOVE;
}

int main(int argc, char *argv[]) {
  g_autoptr(GError) error = NULL;
  g_autoptr(GOptionContext) context = NULL;

  gchar *server_ip = NULL;
  guint server_port = 54321;
  gint ft_port_opt = 54322;
  gint stream_port_opt = 54324;
  gchar *device_id = "mock-phone-001";

  GOptionEntry entries[] = {
    {"server-ip", 0, 0, G_OPTION_ARG_STRING, &server_ip, "Daemon IP to connect to", "IP"},
    {"server-port", 0, 0, G_OPTION_ARG_INT, &server_port, "Daemon session TCP port (default 54321)", "PORT"},
    {"ft-port", 0, 0, G_OPTION_ARG_INT, &ft_port_opt, "Daemon DFile (file transfer) TCP port (default 54322)", "PORT"},
    {"stream-port", 0, 0, G_OPTION_ARG_INT, &stream_port_opt, "fillp (stream) UDP server port (default 54324)", "PORT"},
    {"no-ft", 0, G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE, &skip_ft, "Skip the DFile transfer phase (session test only; also skips the stream phase)", NULL},
    {"no-stream", 0, G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE, &skip_stream, "Skip the fillp/VTP stream phase (FT test only)", NULL},
    {"psk", 0, 0, G_OPTION_ARG_STRING, &psk, "Pre-provisioned PSK (default: test PSK)", "SECRET"},
    {"id", 0, 0, G_OPTION_ARG_STRING, &device_id, "Mock phone device id", "ID"},
    {"mirror-file", 0, 0, G_OPTION_ARG_STRING, &mirror_file_opt, "H.264 clip to push as the stream file A (default: tests/data/mirror-testsrc.h264)", "PATH"},
    {NULL}
  };

  context = g_option_context_new("hwphonelink-mock-phone [OPTIONS]");
  g_option_context_add_main_entries(context, entries, NULL);
  if (!g_option_context_parse(context, &argc, &argv, &error)) {
    g_printerr("Option parsing failed: %s\n", error->message);
    return 1;
  }
  if (server_ip == NULL) {
    g_printerr("--server-ip is required\n");
    g_printerr("%s", g_option_context_get_help(context, TRUE, NULL));
    return 1;
  }
  if (ft_port_opt < 0) {
    g_printerr("--ft-port must be >= 0\n");
    return 1;
  }
  ft_port = (guint)ft_port_opt;
  if (stream_port_opt < 0) {
    g_printerr("--stream-port must be >= 0\n");
    return 1;
  }
  stream_port = (guint)stream_port_opt;
  if (skip_ft)
    skip_stream = TRUE; /* the daemon triggers its stream off the FT phase */
  if (psk == NULL) {
    psk = g_strdup(g_getenv("HWPONELINK_PSK"));
    if (psk == NULL || psk[0] == '\0') {
      g_free(psk);
      psk = g_strdup("hwphonelink-test-psk");
    }
  }
  if (!skip_stream) {
    gchar *cp = NULL;
    gchar *cw = NULL;
    guint64 csz = 0;
    if (!resolve_clip(&cp, &cw, &csz))
      return 1;
    g_print("mock-phone: mirror clip ready: %s (%" G_GUINT64_FORMAT
            " bytes, wire name %s)\n",
            cp, csz, cw);
    g_free(cp);
    g_free(cw);
  }

  /* 1. Local device record (what the phone would advertise). */
  SoftbusDevice *dev = softbus_device_new();
  dev->device_id = g_strdup(device_id);
  dev->device_name = g_strdup("HUAWEI P40 Pro (mock)");
  dev->device_type = SOFTBUS_DEVTYPE_PHONE;
  dev->capabilities = SOFTBUS_CAP_CASTPLUS | SOFTBUS_CAP_DVKIT |
                      SOFTBUS_CAP_OSD | SOFTBUS_CAP_MULTISCREEN;
  dev->auth_port = 45678;
  dev->session_port = 45679;
  dev->proxy_port = 45680;
  dev->ble_mac = g_strdup("aa:bb:cc:dd:ee:ff");

  gchar *dstr = softbus_device_to_string(dev);
  g_print("mock-phone: %s\n", dstr);
  g_free(dstr);

  /* 2. Publish the discovery beacon. */
  send_beacon(dev, server_ip);

  /* 3. Connect to the daemon's session listener (retry: it may be starting). */
  GSocketClient *client = g_socket_client_new();
  g_socket_client_set_timeout(client, 5);
  GSocketConnection *conn = NULL;
  for (int attempt = 1; attempt <= 10 && conn == NULL; attempt++) {
    GError *cerr = NULL;
    conn = g_socket_client_connect_to_host(client, server_ip, server_port,
                                           NULL, &cerr);
    if (!conn) {
      g_print("mock-phone: connect %s:%u attempt %d failed: %s\n",
              server_ip, server_port, attempt, cerr->message);
      g_clear_error(&cerr);
      g_usleep(500 * 1000);
    }
  }
  g_object_unref(client);
  if (!conn) {
    g_print("mock-phone: could not connect to daemon at %s:%u\n",
            server_ip, server_port);
    softbus_device_unref(dev);
    return 1;
  }
  g_print("mock-phone: connected to %s:%u\n", server_ip, server_port);

  /* 4. Session + passive auth. */
  session = softbus_session_new(conn, SOFTBUS_SESSION_MESSAGE);
  if (!session) {
    g_print("mock-phone: session creation failed\n");
    g_object_unref(conn);
    softbus_device_unref(dev);
    return 1;
  }
  g_object_unref(conn);  /* the session owns its ref */

  auth = softbus_auth_new(dev, NULL, (const guint8 *)psk, strlen(psk));
  /* user_data carries the daemon IP for the post-echo DFile phase. */
  softbus_session_set_data_cb(session, on_data, (gpointer)server_ip, NULL);

  /* 5. Main loop (timeout guards the whole handshake). */
  loop = g_main_loop_new(NULL, FALSE);
  g_timeout_add(MOCK_TIMEOUT_MS, on_timeout, NULL);
  g_main_loop_run(loop);

  /* Cleanup */
  g_print("mock-phone: exiting with code %d\n", exit_code);
  if (stream_engine != NULL) {
    fillp_engine_close(stream_engine);
    fillp_engine_unref(stream_engine);
    stream_engine = NULL;
  }
  if (ft_dc) {
    dfile_conn_close(ft_dc);
    dfile_conn_unref(ft_dc);
    ft_dc = NULL;
  }
  softbus_session_stop(session);
  g_object_unref(session);
  softbus_auth_free(auth);
  softbus_device_unref(dev);
  g_main_loop_unref(loop);
  g_free(psk);
  return exit_code;
}
