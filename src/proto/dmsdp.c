/*
 * dmsdp.c - DMSDP control plane (session control text)
 *
 * Implements the RE'd builder and parser (spec 6.5):
 *
 *   builder  BuildPkt/BuildHeader (spec 6.5.4-6.5.6): fixed header
 *            order, ports printed lo-hi, the combined Transport line
 *            (b14) overriding the client-only line (b13).
 *   parser   AnalyzePkt (spec 6.5.7): prefix keyword match, integer
 *            parsing with the documented degenerates, silent unknown
 *            keys, soft-ignored Codec/KaRetry (flag bit cleared),
 *            trigger-method body check.
 *
 * Wire text is emitted byte-exactly; the M3 stand vectors are in
 * spec 6.5.12.
 */

#include "proto/dmsdp.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------- constants ---------- */

static const gchar *const dmsdp_method_lines[8] = {
    "OPTIONS * DMSDP/1.0\r\n",      "SETUP * DMSDP/1.0\r\n",
    "PLAY * DMSDP/1.0\r\n",         "TEARDOWN * DMSDP/1.0\r\n",
    "SET_PARAMETER * DMSDP/1.0\r\n", "GET_PARAMETER * DMSDP/1.0\r\n",
    "RESETUP * DMSDP/1.0\r\n",      "TRIGGER_RECONN * DMSDP/1.0\r\n",
};

static const gchar *const dmsdp_trigger_bodies[5] = {
    "msdp_trigger_method: SETUP\r\n",
    "msdp_trigger_method: TEARDOWN\r\n",
    "msdp_trigger_method: OPTIONS\r\n",
    "msdp_trigger_method: CLOSE\r\n",
    "msdp_trigger_method: RESETUP\r\n",
};

/* Name table: GKW idx 0..29 = table positions 1..30 (spec 6.5.3).
 * Match rule: strncmp(trimmed key, name, strlen(trimmed key)) — a key
 * shorter than a name matches on its own length. */
static const gchar *const dmsdp_names[30] = {
    "CSeq",             "Content-Length", "Content-Type",
    "ServiceID",        "ServiceType",    "DataSessionID",
    "CryptoVer",        "CryptoSwitch",   "CryptoAlg",
    "CryptoAbility",    "UdpKA",          "UdpKAport",
    "Fillp",            "Codec",          "TCP",
    "VideoParameter",   "AudioParameter", "GpsParameter",
    "VideoMetaParameter", "Transport",    "TimeServerPort",
    "TimeUsHigh",       "TimeUsLow",      "DeviceTraceId",
    "KaRetry",          "MultiTrans",     "Backup",
    "ReplyType",        "Simple",         "PolyPackage",
};

static const guint32 dmsdp_flag1[30] = {
    0x00000001u, 0u,         0u,           0x00000400u, 0x00000800u,
    0x00001000u, 0x00000002u, 0x00000004u, 0x00000008u, 0x00000010u,
    0x00000020u, 0x00000040u, 0x00000080u, 0x00000100u, 0x00000200u,
    0x00008000u, 0x00010000u, 0x00020000u, 0x00040000u, 0x00080000u,
    0x00100000u, 0u,          0u,          0x00200000u, 0x00400000u,
    0u, 0u, 0u, 0u, 0u,
};

static const guint32 dmsdp_flag2[30] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1u, 0x2u, 0x4u, 0x8u, 0x10u,
};

/* 1 = string path (AnalyzeStringPara), 0 = integer path */
static const guint8 dmsdp_special[30] = {
    0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
};

/* ---------- small helpers ---------- */

static gchar *dmsdp_strndup(const gchar *s, gsize len) {
  gchar *r = g_malloc(len + 1);
  memcpy(r, s, len);
  r[len] = '\0';
  return r;
}

/*
 * ParseInteger (0x180019b40, spec 6.5.7): copy at most 16 bytes into a
 * zeroed buffer (len > 16 or len != 0 with str == NULL -> -9, the
 * errno 34/22 paths), empty result or out == NULL -> -1. Skip leading
 * spaces; if the first non-space byte c satisfies (c - 0x2b) & 0xfd ==
 * 0 -- with the 0xfd mask this holds exactly for x = 0 or 2, i.e.
 * c in {'+', '-'} -- treat it as a sign slot (a lone such char,
 * strlen == 1, -> -1). Every remaining byte must be an ASCII digit,
 * else -1. The value is atoi() of the whole buffer from byte 0 (atoi
 * re-skips spaces; negative results wrap to the low 32 bits).
 * Degenerates: "3" -> 3, " 3" -> 3, "+3" -> 3, "-3" -> 0xfffffffd,
 * "/3" -> -1 ('/' is not a sign slot), "+" -> -1, " " -> 0.
 */
static int dmsdp_parse_integer(const gchar *str, gsize len, guint32 *out) {
  gchar buf[17] = {0};
  if (len != 0) {
    if (str == NULL) return -9; /* errno 22 path */
    if (len > 16) return -9;    /* errno 34 path */
    memcpy(buf, str, len);
  }
  gsize sl = strlen(buf);
  if (sl < 1) return -1;
  if (out == NULL) return -1;
  gsize sp = 0;
  while (sp < sl && buf[sp] == ' ') sp++;
  if ((((guint8)buf[sp] - 0x2b) & 0xfd) == 0) { /* '+' or '/' */
    sp++;
    if (sl == 1) return -1;
  }
  for (gsize i = sp; i < sl; i++) {
    if (buf[i] < '0' || buf[i] > '9') return -1;
  }
  *out = (guint32)atoi(buf); /* whole buffer, from byte 0 */
  return 0;
}

static int dmsdp_parse_port_range(const gchar *s, gsize len, guint32 *lo,
                                  guint32 *hi) {
  gchar buf[32] = {0};
  if (len >= sizeof(buf)) return -5;
  memcpy(buf, s, len);
  int a, b;
  if (sscanf(buf, "%d-%d", &a, &b) == 2) {
    *lo = (guint32)a;
    *hi = (guint32)b;
    return 0;
  }
  if (sscanf(buf, "%d", &a) == 1) {
    *lo = (guint32)a;
    *hi = 0;
    return 0;
  }
  return -5;
}

/* FindAttr (RE 0x18001a149/0x1a247): scan ';'-separated segments; a
 * segment matches when len >= 12, seg[11] == '=' and the first 11
 * bytes equal "client_port"/"server_port". The first match wins; the
 * loop stops after it. Returns 1 when a match was found but the port
 * range is malformed (the original then jumps straight to the
 * silent-return epilogue, skipping the server pass), 0 otherwise. */
static int dmsdp_parse_transport_attr(const gchar *val, gsize len,
                                      const gchar *name, guint32 *lo,
                                      guint32 *hi) {
  const gchar *p = val;
  gsize rem = len;
  while (rem > 0) {
    gsize seg_len = rem;
    for (gsize k = 0; k < rem; k++) {
      if (p[k] == ';') {
        seg_len = k;
        break;
      }
    }
    if (seg_len >= 12 && p[11] == '=' && strncmp(p, name, 11) == 0) {
      return dmsdp_parse_port_range(p + 12, seg_len - 12, lo, hi) != 0 ? 1
                                                                       : 0;
    }
    if (seg_len < rem) {
      p += seg_len + 1;
      rem -= seg_len + 1;
    } else {
      break;
    }
  }
  return 0;
}

/* AnalyzeTransportPara (RE 0x18001a050): the value arrives with the
 * leading space already skipped (AnalyzeStringPara). Prefix
 * "RTP/AVP/UDP;unicast;" on 20 bytes, else silent 0. Then two
 * sequential passes -- client_port first, then server_port, each
 * taking its first match; a bad client range aborts before the server
 * pass (silent 0 either way). -4 in the original is only a strdup
 * (malloc) failure, logged as "parse transport strdup fail"; there is
 * no duplicate check (a repeated Transport line re-parses and the
 * last line's first match wins). */
static int dmsdp_parse_transport(const gchar *val, gsize len,
                                 DmsdpParsed *out) {
  if (len < 20 || strncmp(val, "RTP/AVP/UDP;unicast;", 20) != 0) return 0;
  if (dmsdp_parse_transport_attr(val, len, "client_port", &out->client_port_lo,
                                 &out->client_port_hi) != 0)
    return 0;
  dmsdp_parse_transport_attr(val, len, "server_port", &out->server_port_lo,
                             &out->server_port_hi);
  return 0;
}

/* AnalyzeGpsServerPort (RE 0x18001a350, tag "DMSDPAnalyzeGpsServerPort"):
 * the value arrives with the leading space already stripped. The copy
 * must contain "ServerUdpPort" (strstr); after the 13-char needle the
 * scan advances over whitespace (' ' \t \n \r) and '=' (bitmask
 * 0x2000000100002600), stops at the first other byte, and takes the
 * segment up to ';' (or end). Segment >= 20 chars -> -5
 * ("udp port is invalid"); atoi must be > 0 -> out+0x30 (gps_server_port).
 * Needle missing -> -5 ("udp port not found in input params"); a strdup
 * (malloc) failure is -9 in the original (not representable here).
 * No duplicate check. */
static int dmsdp_parse_gps(const gchar *val, gsize len, DmsdpParsed *out) {
  const gchar *needle = "ServerUdpPort";
  const gchar *end = val + len;
  const gchar *p = NULL;
  for (const gchar *q = val; q + 13 <= end; q++) {
    if (memcmp(q, needle, 13) == 0) {
      p = q;
      break;
    }
  }
  if (p == NULL) return -5;
  p += 13;
  while (p < end && (guchar)*p <= 0x3d &&
         (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == '='))
    p++;
  const gchar *q = p;
  while (q < end && *q != ';') q++;
  gsize seg = (gsize)(q - p);
  if (seg >= 20) return -5;
  gchar buf[21] = {0};
  memcpy(buf, p, seg);
  int v = atoi(buf);
  if (v <= 0) return -5;
  out->gps_server_port = (guint32)v;
  return 0;
}

/* AnalyzeStringPara (jt 0x18001a710): the copy helper is a plain
 * strndup (no dup check). Values arrive with the leading space already
 * skipped by dmsdp_analyze_line (the RE does the skip once here, before
 * dispatching to the jt targets). */
static int dmsdp_analyze_string(int idx, const gchar *val, gsize vlen,
                                DmsdpParsed *out) {
  switch (idx) {
  case 2: /* Content-Type: no-op */
    return 0;
  case 3:
    out->service_id = dmsdp_strndup(val, vlen);
    return 0;
  case 8:
    out->crypto_alg = dmsdp_strndup(val, vlen);
    return 0;
  case 15: /* VideoParameter */
  case 16: /* AudioParameter overwrites */
    out->av_param = dmsdp_strndup(val, vlen);
    return 0;
  case 17:
    return dmsdp_parse_gps(val, vlen, out);
  case 18:
    out->video_meta = dmsdp_strndup(val, vlen);
    return 0;
  case 19:
    return dmsdp_parse_transport(val, vlen, out);
  case 23:
    out->device_trace_id = dmsdp_strndup(val, vlen);
    return 0;
  default:
    return -10; /* unreachable: not in the special table */
  }
}

/* Integer path (jt 0x18001aa44). Codec (13) and KaRetry (24) jt
 * entries return -10 (soft-ignore). */
static int dmsdp_analyze_integer(int idx, const gchar *val, gsize vlen,
                                 DmsdpParsed *out) {
  guint32 v = 0;
  int rc;
  switch (idx) {
  case 0:
    return dmsdp_parse_integer(val, vlen, &out->cseq);
  case 1:
    return dmsdp_parse_integer(val, vlen, &out->content_length);
  case 4:
    return dmsdp_parse_integer(val, vlen, &out->service_type);
  case 5:
    return dmsdp_parse_integer(val, vlen, &out->data_session_id);
  case 6:
    if ((rc = dmsdp_parse_integer(val, vlen, &v)) != 0) return rc;
    out->crypto_ver = (guint8)v;
    return 0;
  case 7:
    if ((rc = dmsdp_parse_integer(val, vlen, &v)) != 0) return rc;
    out->crypto_switch = (guint8)v;
    return 0;
  case 9:
    if ((rc = dmsdp_parse_integer(val, vlen, &v)) != 0) return rc;
    out->crypto_ability = (guint8)v;
    return 0;
  case 10:
    if ((rc = dmsdp_parse_integer(val, vlen, &v)) != 0) return rc;
    out->udp_ka = (guint8)v;
    return 0;
  case 11:
    return dmsdp_parse_integer(val, vlen, &out->udp_ka_port);
  case 12:
    if ((rc = dmsdp_parse_integer(val, vlen, &v)) != 0) return rc;
    out->fillp = (guint8)v;
    return 0;
  case 13: /* Codec */
    return -10;
  case 14:
    if ((rc = dmsdp_parse_integer(val, vlen, &v)) != 0) return rc;
    out->tcp = (guint8)v;
    return 0;
  case 20:
    return dmsdp_parse_integer(val, vlen, &out->time_server_port);
  case 21:
    return dmsdp_parse_integer(val, vlen, &out->time_us_high);
  case 22:
    return dmsdp_parse_integer(val, vlen, &out->time_us_low);
  case 24: /* KaRetry */
    return -10;
  case 25:
    return dmsdp_parse_integer(val, vlen, &out->multi_trans);
  case 26:
    if ((rc = dmsdp_parse_integer(val, vlen, &v)) != 0) return rc;
    out->backup = (guint8)v;
    return 0;
  case 27:
    if ((rc = dmsdp_parse_integer(val, vlen, &v)) != 0) return rc;
    out->reply_type = (guint8)v;
    return 0;
  case 28:
    if ((rc = dmsdp_parse_integer(val, vlen, &v)) != 0) return rc;
    out->simple = (guint8)v;
    return 0;
  case 29:
    if ((rc = dmsdp_parse_integer(val, vlen, &v)) != 0) return rc;
    out->poly_package = (guint8)v;
    return 0;
  default:
    return -10; /* unreachable: no jt entry */
  }
}

/* GetKeyWord (0x180019d30): trim surrounding spaces, then prefix-match
 * the trimmed key against names 1..30. Not found -> -8. */
static int dmsdp_get_keyword(const gchar *key, gsize keylen) {
  gsize s = 0, e = keylen;
  while (s < e && key[s] == ' ') s++;
  while (e > s && key[e - 1] == ' ') e--;
  gsize tl = e - s;
  if (tl == 0) return -8;
  for (int i = 0; i < 30; i++) {
    if (strncmp(key + s, dmsdp_names[i], tl) == 0) return i;
  }
  return -8;
}

/* AnalyzeLine: no ':' -> -5; empty/short key or empty value -> -5;
 * unknown key -> silently ignored; sub-parse -10 -> clear the OR'd
 * flag bits and continue. The string path strips the leading space(s)
 * after the colon once here (RE: AnalyzeStringPara); the integer path
 * receives the raw value and ParseInteger skips its spaces internally. */
static int dmsdp_analyze_line(const gchar *line, gsize len, DmsdpParsed *out) {
  const gchar *colon = memchr(line, ':', len);
  if (colon == NULL) return -5;
  gsize keylen = (gsize)(colon - line);
  if (keylen == 0 || len <= 1 || keylen >= len - 1) return -5;
  int idx = dmsdp_get_keyword(line, keylen);
  if (idx == -8) return 0;
  guint32 f1 = dmsdp_flag1[idx];
  guint32 f2 = dmsdp_flag2[idx];
  out->flags1 |= f1;
  out->flags2 |= f2;
  const gchar *val = colon + 1;
  gsize vlen = len - keylen - 1;
  int rc;
  if (dmsdp_special[idx]) {
    gsize sp = 0;
    while (sp < vlen && val[sp] == ' ') sp++;
    rc = dmsdp_analyze_string(idx, val + sp, vlen - sp, out);
  } else {
    rc = dmsdp_analyze_integer(idx, val, vlen, out);
  }
  if (rc == -10) {
    out->flags1 &= ~f1;
    out->flags2 &= ~f2;
    return 0;
  }
  return rc;
}

/* ---------- public: parsed struct ---------- */

void dmsdp_parsed_init(DmsdpParsed *p) { memset(p, 0, sizeof(*p)); }

void dmsdp_parsed_free(DmsdpParsed *p) {
  if (p == NULL) return;
  g_free((gchar *)p->crypto_alg);
  g_free((gchar *)p->service_id);
  g_free((gchar *)p->av_param);
  g_free((gchar *)p->video_meta);
  g_free((gchar *)p->device_trace_id);
  dmsdp_parsed_init(p);
}

/* ---------- public: parser ---------- */

/*
 * AnalyzePkt (0x18001aac0):
 *   line 1: one of the 8 method lines -> type 0..7; otherwise the
 *   response form `DMSDP/1.0 <status> <reason>` (reason <= 12 chars
 *   after the 10-char prefix, digits must stop before end-of-line)
 *   -> type 8, response_fail = (status != 200).
 *   headers: CRLF-terminated lines until the blank line (a missing
 *   final blank is lenient).
 *   body: if Content-Length > 0 it must exactly match one of the 5
 *   trigger strings -> trigger_idx 1..5; final pos + CL == len.
 */
gint dmsdp_parse(const gchar *buf, gsize len, DmsdpParsed *out) {
  if (buf == NULL || out == NULL || len == 0) return -2;
  dmsdp_parsed_init(out);

  const gchar *crlf = memmem(buf, len, "\r\n", 2);
  if (crlf == NULL) return -2; /* line 1 must be CRLF-terminated */
  gsize line1 = (gsize)(crlf - buf);
  gsize pos = line1 + 2;

  int is_method = -1;
  for (int i = 0; i < 8; i++) {
    gsize mlen = strlen(dmsdp_method_lines[i]);
    /* line1 excludes the CRLF; the table entries include it. */
    if (line1 == mlen - 2 && memcmp(buf, dmsdp_method_lines[i], line1) == 0) {
      is_method = i;
      break;
    }
  }
  if (is_method >= 0) {
    out->type = (guint32)is_method;
  } else {
    if (line1 < 10 || memcmp(buf, "DMSDP/1.0 ", 10) != 0 ||
        line1 - 10 > 12) {
      return -2;
    }
    gsize d = 10;
    while (d < line1 && buf[d] >= '0' && buf[d] <= '9') d++;
    if (d == 10 || d == line1 || buf[d] != ' ') return -2;
    guint32 status = 0;
    if (dmsdp_parse_integer(buf + 10, d - 10, &status) != 0) return -2;
    out->type = DMSDP_TYPE_RESPONSE;
    out->response_fail = (status != 200) ? 1u : 0u;
  }

  gsize body_start = 0;
  gboolean finalised = FALSE;
  while (pos < len) {
    crlf = memmem(buf + pos, len - pos, "\r\n", 2);
    if (crlf != NULL) {
      gsize ll = (gsize)(crlf - (buf + pos));
      if (ll == 0) { /* blank line finalises the header block */
        body_start = pos + 2;
        finalised = TRUE;
        break;
      }
      int rc = dmsdp_analyze_line(buf + pos, ll, out);
      if (rc != 0) return rc;
      pos = (gsize)(crlf - buf) + 2;
      continue;
    }
    /* No CRLF left: lenient only for a complete final header line
     * (missing final blank); a dangling 1-byte fragment is malformed. */
    gsize ll = len - pos;
    if (ll < 2) return -2;
    int rc = dmsdp_analyze_line(buf + pos, ll, out);
    if (rc != 0) return rc;
    body_start = len;
    finalised = TRUE;
    break;
  }
  if (!finalised) body_start = pos; /* == len */

  if (out->content_length > 0) {
    gsize body_len = len - body_start;
    if (body_len != out->content_length) return -2;
    int matched = -1;
    for (int i = 0; i < 5; i++) {
      gsize tl = strlen(dmsdp_trigger_bodies[i]);
      if (body_len == tl &&
          memcmp(buf + body_start, dmsdp_trigger_bodies[i], tl) == 0) {
        matched = i + 1;
        break;
      }
    }
    if (matched < 0) return -2;
    out->trigger_idx = (guint32)matched;
  } else {
    if (body_start == 0) return -2; /* require parsed content */
  }
  return 0;
}

/* ---------- public: builder ---------- */

gint dmsdp_build(const DmsdpMsg *msg, guint8 *out, gsize cap, gsize *out_len) {
  if (msg == NULL || out == NULL || out_len == NULL) return -1;
  if (msg->type > 8) return -1;
  if (msg->type == 8 && msg->status != 200) return -1;

  gchar buf[DMSDP_TEXT_MAX]; /* matches the BuildPkt fixed 1400 B buffer */
  gchar *p = buf;
  const gchar *end = buf + sizeof(buf);

#define EMIT(fmt, ...)                                        \
  do {                                                        \
    int _n = g_snprintf(p, (gsize)(end - p), fmt, ##__VA_ARGS__); \
    if (_n < 0 || (gsize)_n >= (gsize)(end - p)) return -1;   \
    p += _n;                                                  \
  } while (0)

  if (msg->type == 8) {
    EMIT("DMSDP/1.0 200 OK\r\n"); /* the only status the PC emits */
  } else {
    EMIT("%s", dmsdp_method_lines[msg->type]);
  }

  guint32 f = msg->flags1;
  guint32 f2 = msg->flags2;

  if (f & DMSDP_FLAG_CSEQ) EMIT("CSeq: %u\r\n", msg->cseq);
  if (f & DMSDP_FLAG_SERVICE_ID) {
    if (msg->service_id == NULL) return -1;
    EMIT("ServiceID: %s\r\n", msg->service_id);
  }
  if (f & DMSDP_FLAG_SERVICE_TYPE)
    EMIT("ServiceType: %u\r\n", msg->service_type);
  if (f & DMSDP_FLAG_DATA_SESSION_ID)
    EMIT("DataSessionID: %u\r\n", msg->data_session_id);
  if (f & DMSDP_FLAG_CRYPTO_VER) EMIT("CryptoVer: %u\r\n", msg->crypto_ver);
  if (f & DMSDP_FLAG_CRYPTO_SWITCH)
    EMIT("CryptoSwitch: %u\r\n", msg->crypto_switch);
  if (f & DMSDP_FLAG_CRYPTO_ABILITY)
    EMIT("CryptoAbility: %u\r\n", msg->crypto_ability);
  if (f & DMSDP_FLAG_CRYPTO_ALG) {
    if (msg->crypto_alg == NULL) return -1;
    EMIT("CryptoAlg: %s\r\n", msg->crypto_alg);
  }
  if (f & DMSDP_FLAG_FILLP) EMIT("Fillp: %u\r\n", msg->fillp);
  if (f & DMSDP_FLAG_CODEC) EMIT("Codec: %u\r\n", msg->codec);
  if (f & DMSDP_FLAG_TCP) EMIT("TCP: %u\r\n", msg->tcp);
  if (f2 & DMSDP_FLAG2_BACKUP) EMIT("Backup: %u\r\n", msg->backup);
  if (f2 & DMSDP_FLAG2_SIMPLE) EMIT("Simple: %u\r\n", msg->simple);
  if (f2 & DMSDP_FLAG2_POLY_PACKAGE)
    EMIT("PolyPackage: %u\r\n", msg->poly_package);
  if (f & DMSDP_FLAG_UDP_KA) EMIT("UdpKA: %u\r\n", msg->udp_ka);
  if (f & DMSDP_FLAG_KA_RETRY) EMIT("KaRetry: %u\r\n", msg->ka_retry);
  if (f & DMSDP_FLAG_TRANSPORT_COMBINED) {
    EMIT("Transport: RTP/AVP/UDP;unicast;client_port=%u-%u;"
         "server_port=%u-%u\r\n",
         msg->client_port_lo, msg->client_port_hi, msg->server_port_lo,
         msg->server_port_hi);
  } else if (f & DMSDP_FLAG_TRANSPORT_CLIENT) {
    EMIT("Transport: RTP/AVP/UDP;unicast;client_port=%u-%u\r\n",
         msg->client_port_lo, msg->client_port_hi);
  }
  EMIT("\r\n");

#undef EMIT

  gsize text_len = (gsize)(p - buf);
  if (cap < text_len) return -1;
  memcpy(out, buf, text_len);
  *out_len = text_len;
  return 0;
}

gint dmsdp_frame(const gchar *text, gsize len, guint8 *out, gsize cap,
                 gsize *out_len) {
  if (text == NULL || out == NULL || out_len == NULL) return -1;
  if (len > DMSDP_FRAME_MAX_PAYLOAD) return -1;
  if (cap < 3 + len) return -1;
  out[0] = DMSDP_FRAME_TYPE_NOCRYPTO;
  out[1] = (guint8)(len >> 8);
  out[2] = (guint8)(len & 0xff);
  if (len) memcpy(out + 3, text, len);
  *out_len = 3 + len;
  return 0;
}

/* ---------- public: per-case helpers ---------- */

void dmsdp_msg_setup(DmsdpMsg *m, guint32 cseq, const gchar *service_id,
                     guint32 service_type, guint32 data_session_id,
                     guint32 backup, guint32 client_port_lo,
                     guint32 client_port_hi) {
  memset(m, 0, sizeof(*m));
  m->type = DMSDP_TYPE_SETUP;
  m->flags1 = 0x3c01; /* CSeq + service triple + client Transport */
  m->flags2 = DMSDP_FLAG2_BACKUP;
  m->cseq = cseq;
  m->service_id = service_id;
  m->service_type = service_type;
  m->data_session_id = data_session_id;
  m->backup = backup;
  m->client_port_lo = client_port_lo;
  m->client_port_hi = client_port_hi;
}

void dmsdp_msg_setup_reply(DmsdpMsg *m, guint32 cseq,
                           const gchar *service_id, guint32 service_type,
                           guint32 data_session_id, guint32 client_port_lo,
                           guint32 client_port_hi, guint32 server_port_lo,
                           guint32 server_port_hi) {
  memset(m, 0, sizeof(*m));
  m->type = DMSDP_TYPE_RESPONSE;
  m->status = 200;
  m->flags1 = 0x5c01; /* CSeq + service triple + combined Transport */
  m->cseq = cseq;
  m->service_id = service_id;
  m->service_type = service_type;
  m->data_session_id = data_session_id;
  m->client_port_lo = client_port_lo;
  m->client_port_hi = client_port_hi;
  m->server_port_lo = server_port_lo;
  m->server_port_hi = server_port_hi;
}

void dmsdp_msg_play(DmsdpMsg *m, guint32 cseq, const gchar *service_id,
                    guint32 service_type, guint32 data_session_id) {
  memset(m, 0, sizeof(*m));
  m->type = DMSDP_TYPE_PLAY;
  m->flags1 = 0x1c01; /* CSeq + service triple, pure */
  m->cseq = cseq;
  m->service_id = service_id;
  m->service_type = service_type;
  m->data_session_id = data_session_id;
}

void dmsdp_msg_common_reply(DmsdpMsg *m, guint32 cseq,
                            const gchar *service_id, guint32 service_type,
                            guint32 data_session_id) {
  memset(m, 0, sizeof(*m));
  m->type = DMSDP_TYPE_RESPONSE;
  m->status = 200;
  m->flags1 = 0x1c01;
  m->cseq = cseq;
  m->service_id = service_id;
  m->service_type = service_type;
  m->data_session_id = data_session_id;
}

/* ---------- public: client FSM ---------- */

struct _DmsdpClient {
  DmsdpClientState state;
  guint32 pending_cseq;
};

DmsdpClient *dmsdp_client_new(void) {
  DmsdpClient *c = g_new0(DmsdpClient, 1);
  c->state = DMSDP_CL_INIT;
  return c;
}

void dmsdp_client_free(DmsdpClient *c) { g_free(c); }

DmsdpClientState dmsdp_client_state(const DmsdpClient *c) {
  return c == NULL ? DMSDP_CL_ERROR : c->state;
}

gint dmsdp_client_send(DmsdpClient *c, const DmsdpMsg *msg, guint8 *out,
                       gsize cap, gsize *out_len) {
  if (c == NULL || msg == NULL) return -1;
  if (c->state == DMSDP_CL_INIT) {
    if (msg->type != DMSDP_TYPE_SETUP || msg->cseq != 0) {
      c->state = DMSDP_CL_ERROR;
      return -1;
    }
    c->state = DMSDP_CL_WAIT_SETUP_REPLY;
    c->pending_cseq = 0;
  } else if (c->state == DMSDP_CL_SEND_PLAY) {
    if (msg->type != DMSDP_TYPE_PLAY || msg->cseq != 1) {
      c->state = DMSDP_CL_ERROR;
      return -1;
    }
    c->state = DMSDP_CL_WAIT_PLAY_REPLY;
    c->pending_cseq = 1;
  } else {
    return -1; /* no sends in WAIT_* states, READY or ERROR */
  }
  gchar text[DMSDP_TEXT_MAX];
  gsize text_len = 0;
  if (dmsdp_build(msg, (guint8 *)text, sizeof(text), &text_len) != 0) {
    c->state = DMSDP_CL_ERROR;
    return -1;
  }
  if (dmsdp_frame(text, text_len, out, cap, out_len) != 0) {
    c->state = DMSDP_CL_ERROR;
    return -1;
  }
  return 0;
}

gint dmsdp_client_recv(DmsdpClient *c, const DmsdpParsed *p) {
  if (c == NULL || p == NULL) return -1;
  if (c->state == DMSDP_CL_READY) return 0; /* ignore further replies */
  if (c->state == DMSDP_CL_WAIT_SETUP_REPLY ||
      c->state == DMSDP_CL_WAIT_PLAY_REPLY) {
    if (p->type == DMSDP_TYPE_RESPONSE && p->response_fail == 0 &&
        p->cseq == c->pending_cseq) {
      c->state = (c->state == DMSDP_CL_WAIT_SETUP_REPLY)
                     ? DMSDP_CL_SEND_PLAY
                     : DMSDP_CL_READY;
      return 0;
    }
    c->state = DMSDP_CL_ERROR;
    return -1;
  }
  if (c->state == DMSDP_CL_ERROR) return -1;
  c->state = DMSDP_CL_ERROR; /* INIT / SEND_PLAY: reply not expected */
  return -1;
}

/* ---------- layout checks ---------- */

/* DmsdpParsed field offsets must match the RE'd layout (spec 6.5.3). */
_Static_assert(offsetof(DmsdpParsed, type) == 0x00, "type");
_Static_assert(offsetof(DmsdpParsed, flags1) == 0x04, "flags1");
_Static_assert(offsetof(DmsdpParsed, flags2) == 0x08, "flags2");
_Static_assert(offsetof(DmsdpParsed, trigger_idx) == 0x0c, "trigger_idx");
_Static_assert(offsetof(DmsdpParsed, response_fail) == 0x10, "response_fail");
_Static_assert(offsetof(DmsdpParsed, cseq) == 0x14, "cseq");
_Static_assert(offsetof(DmsdpParsed, content_length) == 0x18,
               "content_length");
_Static_assert(offsetof(DmsdpParsed, crypto_ver) == 0x1c, "crypto_ver");
_Static_assert(offsetof(DmsdpParsed, crypto_switch) == 0x1d,
               "crypto_switch");
_Static_assert(offsetof(DmsdpParsed, crypto_alg) == 0x20, "crypto_alg");
_Static_assert(offsetof(DmsdpParsed, crypto_ability) == 0x28,
               "crypto_ability");
_Static_assert(offsetof(DmsdpParsed, udp_ka) == 0x29, "udp_ka");
_Static_assert(offsetof(DmsdpParsed, udp_ka_port) == 0x2c, "udp_ka_port");
_Static_assert(offsetof(DmsdpParsed, gps_server_port) == 0x30,
               "gps_server_port");
_Static_assert(offsetof(DmsdpParsed, fillp) == 0x34, "fillp");
_Static_assert(offsetof(DmsdpParsed, tcp) == 0x35, "tcp");
_Static_assert(offsetof(DmsdpParsed, service_id) == 0x38, "service_id");
_Static_assert(offsetof(DmsdpParsed, service_type) == 0x40, "service_type");
_Static_assert(offsetof(DmsdpParsed, data_session_id) == 0x44,
               "data_session_id");
_Static_assert(offsetof(DmsdpParsed, client_port_lo) == 0x48,
               "client_port_lo");
_Static_assert(offsetof(DmsdpParsed, client_port_hi) == 0x4c,
               "client_port_hi");
_Static_assert(offsetof(DmsdpParsed, server_port_lo) == 0x50,
               "server_port_lo");
_Static_assert(offsetof(DmsdpParsed, server_port_hi) == 0x54,
               "server_port_hi");
_Static_assert(offsetof(DmsdpParsed, time_server_port) == 0x58,
               "time_server_port");
_Static_assert(offsetof(DmsdpParsed, time_us_high) == 0x5c, "time_us_high");
_Static_assert(offsetof(DmsdpParsed, time_us_low) == 0x60, "time_us_low");
_Static_assert(offsetof(DmsdpParsed, av_param) == 0x68, "av_param");
_Static_assert(offsetof(DmsdpParsed, video_meta) == 0x70, "video_meta");
_Static_assert(offsetof(DmsdpParsed, device_trace_id) == 0x78,
               "device_trace_id");
_Static_assert(offsetof(DmsdpParsed, multi_trans) == 0x80, "multi_trans");
_Static_assert(offsetof(DmsdpParsed, backup) == 0x84, "backup");
_Static_assert(offsetof(DmsdpParsed, reply_type) == 0x85, "reply_type");
_Static_assert(offsetof(DmsdpParsed, simple) == 0x86, "simple");
_Static_assert(offsetof(DmsdpParsed, poly_package) == 0x87, "poly_package");
_Static_assert(sizeof(DmsdpParsed) == 0x88, "size (8-aligned, no tail pad)");
