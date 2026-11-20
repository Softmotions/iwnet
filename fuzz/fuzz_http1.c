// Fuzzy testing harness for the HTTP/1.1 request parser.
//
// Two entry points share the same checks:
//   * libFuzzer target - compile without `IWN_FUZZ_STANDALONE` and link with `-fsanitize=fuzzer`.
//     The library should be instrumented with `-fsanitize=fuzzer-no-link` (`ENABLE_FUZZ=1`).
//   * Standalone randomized driver - compile with `-DIWN_FUZZ_STANDALONE`. It replays a seed corpus
//     and runs mutated/random inputs for a configurable number of rounds. The driver is an
//     `iwtests.h` suite, so campaigns can be selected by case name; rounds and the PRNG seed are
//     taken from the `IWN_FUZZ_ROUNDS`/`IWN_FUZZ_SEED` environment variables.
//
// The parser is driven from memory by `iwn_http_request_parse_buf()`, no network IO is involved.
// The checks are:
//   * the parser must not violate its own invariants (a token pointing outside the parse buffer,
//     a negative or inconsistent request body length, a non progressing parse) - those are reported
//     by `iwn_http_request_parse_buf()` and treated as a bug here;
//   * the request framing (`Content-Length`, `Transfer-Encoding` or none) is decoded independently
//     and the parser must report exactly that body length, or reject the request when the framing
//     is ambiguous/invalid exactly as RFC 9112 requires;
//   * the parse must be deterministic and every truncated prefix of the input must be parsed
//     without violating the invariants (the parser is a streaming state machine).
#define IW_TEST_HARNESS "iwnet"
#include "iwn_http_server_internal.h"
#include "iwtests.h"

#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef IWN_FUZZ_STANDALONE
#include <inttypes.h>
#endif

/// Longest accepted input, longer inputs are skipped by the driver.
#define FUZZ_MAX_INPUT 8192

/// Parser limits enforced by `iwn_http_server_create()` defaults.
#define FUZZ_MAX_HEADERS   127
#define FUZZ_MAX_TOKEN_LEN 8191

/// Input currently checked by the harness, dumped by ::fuzz_bug() for triage.
static const uint8_t *g_input;
static size_t g_input_len;

static void fuzz_dump_input(void) {
  fprintf(stderr, "fuzz_http1: input (%zu bytes):", g_input_len);
  for (size_t i = 0; i < g_input_len; ++i) {
    uint8_t c = g_input[i];
    if (c == '\r') {
      fprintf(stderr, "\\r");
    } else if (c == '\n') {
      fprintf(stderr, "\\n\n");
    } else if (c >= 0x20 && c < 0x7f) {
      fputc(c, stderr);
    } else {
      fprintf(stderr, "\\x%02x", c);
    }
  }
  fprintf(stderr, "\n");
  fflush(stderr);
}

/// Reports an oracle violation.
/// Inside a running `iwtests.h` case the case is aborted; outside of it (the libFuzzer target)
/// the process exits with a failure, which is what libFuzzer expects from a crash.
static _Noreturn void fuzz_bug(const char *fmt, ...) {
  char buf[512];
  va_list args;
  va_start(args, fmt);
  vsnprintf(buf, sizeof(buf), fmt, args);
  va_end(args);
  iw_test_fail(__FILE__, __LINE__, "fuzz oracle: %s", buf);
  fuzz_dump_input();
  iw_test_abort_case();
}

///////////////////////////////////////////////////////////////////////////
//                     Request framing model                             //
///////////////////////////////////////////////////////////////////////////

#define FRAME_SKIP    0 ///< The framing could not be determined independently
#define FRAME_NONE    1 ///< No `Content-Length`, no `Transfer-Encoding`
#define FRAME_LENGTH  2 ///< Single `Content-Length`
#define FRAME_CHUNKED 3 ///< `Transfer-Encoding: chunked`
/// Invalid or ambiguous framing, a duplicated `Content-Length`, a repeated `chunked`
/// coding or a transfer coding which is not implemented. The exact rejection status
/// (`400` or `501`) depends on the header field order, both are accepted here; the
/// deterministic `src/http/tests/http_parser1.c` cases pin the exact statuses.
#define FRAME_REJECT 4

enum chunk_result_e {
  CHUNK_OK,
  CHUNK_TRUNCATED,
  CHUNK_INVALID,
};

struct fuzz_frame {
  int     kind;
  ssize_t body_len; ///< Decoded body length of a fully present `FRAME_LENGTH`/`FRAME_CHUNKED` body
  bool    present;  ///< The framed request body is fully present in the input
};

/// Checks `tchar` of RFC 9110 §5.6.2.
static bool fuzz_tchar(uint8_t c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
         || (c && strchr("!#$%&'*+-.^_`|~", (int) c) && c != 0);
}

static bool fuzz_caseeq(const uint8_t *p, size_t len, const char *s) {
  size_t slen = strlen(s);
  if (len != slen) {
    return false;
  }
  for (size_t i = 0; i < len; ++i) {
    uint8_t c = p[i];
    if (c >= 'A' && c <= 'Z') {
      c = (uint8_t) (c + 32);
    }
    if (c != (uint8_t) s[i]) {
      return false;
    }
  }
  return true;
}

/// Decodes the chunked request body framing (RFC 9112 §7.1).
static enum chunk_result_e fuzz_chunked_decode(const uint8_t *p, size_t len, ssize_t *out_len) {
  size_t pos = 0;
  ssize_t total = 0;
  *out_len = 0;
  for ( ; ; ) {
    // Chunk size
    size_t start = pos;
    ssize_t size = 0;
    for ( ; ; ) {
      if (pos >= len) {
        return CHUNK_TRUNCATED;
      }
      uint8_t c = p[pos];
      int digit;
      if (c >= '0' && c <= '9') {
        digit = c - '0';
      } else if (c >= 'a' && c <= 'f') {
        digit = c - 'a' + 10;
      } else if (c >= 'A' && c <= 'F') {
        digit = c - 'A' + 10;
      } else {
        break;
      }
      if (size > (SSIZE_MAX - digit) / 0x10) {
        return CHUNK_INVALID;
      }
      size = size * 0x10 + digit;
      ++pos;
    }
    if (pos == start) {
      return CHUNK_INVALID; // Chunk size is 1*HEXDIG, leading zeroes are allowed
    }
    // Optional chunk extensions are not decoded: *( BWS ";" ... ), no trailing whitespace
    size_t bws = pos;
    while (bws < len && (p[bws] == ' ' || p[bws] == '\t')) {
      ++bws;
    }
    if (bws >= len) {
      return CHUNK_TRUNCATED; // Undecided: the whitespace may precede a chunk extension
    }
    if (p[bws] == ';') {
      pos = bws;
      while (pos < len && p[pos] != '\r') {
        // HTAB is allowed in a chunk extension, other control bytes and obs-text are not
        if (p[pos] == '\n' || (p[pos] < 0x20 && p[pos] != '\t') || p[pos] >= 0x7f) {
          return CHUNK_INVALID;
        }
        ++pos;
      }
    }
    if (pos >= len) {
      return CHUNK_TRUNCATED;
    }
    if (p[pos] != '\r') {
      return CHUNK_INVALID;
    }
    if (pos + 1 >= len) {
      return CHUNK_TRUNCATED;
    }
    if (p[pos + 1] != '\n') {
      return CHUNK_INVALID;
    }
    pos += 2;
    if (size == 0) {
      // Trailer section: header fields terminated by an empty line
      for ( ; ; ) {
        if (pos + 1 >= len) {
          return CHUNK_TRUNCATED;
        }
        if (p[pos] == '\r' && p[pos + 1] == '\n') {
          *out_len = total;
          return CHUNK_OK;
        }
        while (pos < len && p[pos] != '\r') {
          if (p[pos] == '\n') {
            return CHUNK_INVALID;
          }
          ++pos;
        }
        if (pos + 1 >= len) {
          return CHUNK_TRUNCATED;
        }
        if (p[pos + 1] != '\n') {
          return CHUNK_INVALID;
        }
        pos += 2;
      }
    }
    if (size > (ssize_t) len - (ssize_t) pos) {
      return CHUNK_TRUNCATED;
    }
    total += size;
    pos += (size_t) size;
    if (pos + 1 >= len) {
      return CHUNK_TRUNCATED;
    }
    if (p[pos] != '\r' || p[pos + 1] != '\n') {
      return CHUNK_INVALID;
    }
    pos += 2;
  }
}

/// Decodes one `Transfer-Encoding` field value list.
/// `chunked` tracks the `chunked` coding across the request header fields.
/// @return ::FRAME_CHUNKED or ::FRAME_REJECT.
static int fuzz_te_decode(const uint8_t *p, size_t len, bool *chunked_seen) {
  size_t pos = 0;
  bool chunked = false;
  bool unsupported = false;
  while (pos < len) {
    while (pos < len && (p[pos] == ' ' || p[pos] == '\t' || p[pos] == ',')) {
      ++pos;
    }
    if (pos >= len) {
      break;
    }
    size_t start = pos;
    while (pos < len && fuzz_tchar(p[pos])) {
      ++pos;
    }
    if (pos == start) {
      return FRAME_REJECT; // Not a transfer coding token
    }
    bool is_chunked = fuzz_caseeq(p + start, pos - start, "chunked");
    while (pos < len && (p[pos] == ' ' || p[pos] == '\t')) {
      ++pos;
    }
    if (pos < len && p[pos] == ';') {
      // Parameterized transfer codings are not implemented, the parser reports 501 right away
      return FRAME_REJECT;
    } else if (!is_chunked) {
      unsupported = true;
    } else if (chunked || *chunked_seen) {
      return FRAME_REJECT; // The chunked coding applied more than once
    } else {
      chunked = true;
      *chunked_seen = true;
    }
    while (pos < len && (p[pos] == ' ' || p[pos] == '\t')) {
      ++pos;
    }
    if (pos < len && p[pos] != ',') {
      return FRAME_REJECT;
    }
  }
  if (unsupported) {
    return FRAME_REJECT;
  }
  return chunked ? FRAME_CHUNKED : FRAME_REJECT;
}

/// Scans the request head and determines the request body framing.
/// @return `false` if the framing cannot be determined independently (the input is not a complete
///         request head, or it exceeds the parser limits), no semantic checks are performed then.
static bool fuzz_frame_scan(const uint8_t *data, size_t size, struct fuzz_frame *fr) {
  memset(fr, 0, sizeof(*fr));
  fr->kind = FRAME_SKIP;
  if (size == 0) {
    return false;
  }
  // Header section terminator
  size_t hdr_end = 0;
  for (size_t i = 0; i + 3 < size; ++i) {
    if (data[i] == '\r' && data[i + 1] == '\n' && data[i + 2] == '\r' && data[i + 3] == '\n') {
      hdr_end = i + 4;
      break;
    }
  }
  if (!hdr_end) {
    return false;
  }

  size_t cl_count = 0;
  size_t te_count = 0;
  ssize_t cl_value = -1;
  bool cl_digits = true;
  uint8_t te_buf[4][256];
  size_t te_len[4];
  int te_n = 0;
  int headers = 0;

  size_t line = 0;
  int line_no = 0;
  while (line + 3 < hdr_end) {
    size_t end = line;
    while (end + 1 < hdr_end && !(data[end] == '\r' && data[end + 1] == '\n')) {
      ++end;
    }
    if (end + 1 >= hdr_end) {
      return false;
    }
    size_t line_len = end - line;
    if (line_no == 0) {
      // Request line: `METHOD SP request-target SP HTTP-version`
      size_t i = line;
      while (i < end && data[i] != ' ') {
        if (!fuzz_tchar(data[i])) {
          return false;
        }
        ++i;
      }
      if (i == end || i == line) {
        return false;
      }
      if (data[line] >= '0' && data[line] <= '9') {
        return false; // The parser requires a method to start with a non digit
      }
      ++i;
      size_t target = i;
      while (i < end && data[i] != ' ') {
        if (data[i] < 0x21 || data[i] > 0x7e) {
          return false;
        }
        ++i;
      }
      if (i == end || i == target) {
        return false;
      }
      if (data[target] == ':' || data[target] == ';' || data[target] == '\t') {
        return false; // Request-target forms which the parser rejects on the first byte
      }
      ++i;
      if (  end - i != 8 || memcmp(data + i, "HTTP/1.", 7) != 0
         || data[i + 7] < '0' || data[i + 7] > '9') {
        return false;
      }
    } else if (line_len == 0) {
      break;
    } else {
      if (++headers > FUZZ_MAX_HEADERS || line_len > FUZZ_MAX_TOKEN_LEN) {
        return false;
      }
      size_t colon = line;
      while (colon < end && data[colon] != ':') {
        ++colon;
      }
      if (colon == end) {
        return false;
      }
      size_t name_len = colon - line;
      if (name_len == 0) {
        return false; // Empty field name
      }
      for (size_t k = line; k < colon; ++k) {
        if (!fuzz_tchar(data[k])) {
          return false;
        }
      }
      size_t val = colon + 1;
      while (val < end && (data[val] == ' ' || data[val] == '\t')) {
        ++val;
      }
      size_t val_end = end;
      while (val_end > val && (data[val_end - 1] == ' ' || data[val_end - 1] == '\t')) {
        --val_end;
      }
      size_t val_len = val_end - val;
      for (size_t k = val; k < val_end; ++k) {
        if (data[k] < 0x20 || data[k] > 0x7e) {
          return false; // Field values with CTL/obs-text are not analyzed
        }
      }
      if (fuzz_caseeq(data + line, name_len, "content-length")) {
        ++cl_count;
        cl_digits = val_len > 0;
        ssize_t v = 0;
        for (size_t k = val; k < val_end; ++k) {
          if (data[k] < '0' || data[k] > '9' || v > (SSIZE_MAX - (data[k] - '0')) / 10) {
            cl_digits = false;
            break;
          }
          v = v * 10 + (data[k] - '0');
        }
        cl_value = v;
      } else if (fuzz_caseeq(data + line, name_len, "transfer-encoding")) {
        ++te_count;
        if (te_n >= (int) (sizeof(te_buf) / sizeof(te_buf[0])) || val_len >= sizeof(te_buf[0])) {
          return false;
        }
        memcpy(te_buf[te_n], data + val, val_len);
        te_len[te_n] = val_len;
        ++te_n;
      }
    }
    ++line_no;
    line = end + 2;
  }
  if (headers > FUZZ_MAX_HEADERS) {
    return false;
  }

  if (cl_count == 0 && te_count == 0) {
    fr->kind = FRAME_NONE;
    fr->body_len = 0;
    fr->present = true;
    return true;
  }
  if (cl_count > 1 || (cl_count && te_count)) {
    // Rejected as a malformed or as a not implemented transfer coding request
    fr->kind = FRAME_REJECT;
    return true;
  }
  if (te_count) {
    bool chunked_seen = false;
    for (int i = 0; i < te_n; ++i) {
      // The parser rejects the request on the first offending field value
      int kind = fuzz_te_decode(te_buf[i], te_len[i], &chunked_seen);
      if (kind != FRAME_CHUNKED) {
        fr->kind = kind;
        return true;
      }
    }
    ssize_t body_len = 0;
    switch (fuzz_chunked_decode(data + hdr_end, size - hdr_end, &body_len)) {
      case CHUNK_OK:
        fr->kind = FRAME_CHUNKED;
        fr->body_len = body_len;
        fr->present = true;
        return true;
      case CHUNK_TRUNCATED:
        fr->kind = FRAME_CHUNKED; // Incomplete body, the parser can't report a body length
        return true;
      case CHUNK_INVALID:
      default:
        fr->kind = FRAME_REJECT;
        return true;
    }
  }
  // A single `Content-Length`
  if (!cl_digits) {
    fr->kind = FRAME_REJECT;
    return true;
  }
  fr->kind = FRAME_LENGTH;
  fr->body_len = cl_value;
  fr->present = (size_t) cl_value <= size - hdr_end;
  return true;
}

///////////////////////////////////////////////////////////////////////////
//                          Oracles                                      //
///////////////////////////////////////////////////////////////////////////

/// Parses the input and checks the parser level invariants.
static void fuzz_parse(const uint8_t *data, size_t size, struct iwn_http_parse_result *res) {
  iwrc rc = iwn_http_request_parse_buf((const char*) data, size, res);
  if (rc) {
    fuzz_bug("parser invariant violated: %s (rc=%lu)", res->violation ? res->violation : "unknown", (unsigned long) rc);
  }
  if (res->status != 0 && res->status != 400 && res->status != 501) {
    fuzz_bug("unexpected request rejection status: %d", res->status);
  }
  if (res->body_len < -1) {
    fuzz_bug("invalid body length reported: %zd", res->body_len);
  }
  if (res->status == 0 && res->body_len > (ssize_t) size) {
    fuzz_bug("body length %zd exceeds the input length %zu", res->body_len, size);
  }
}

/// Checks the parse outcome against the independently decoded request framing.
static void fuzz_check_framing(const uint8_t *data, size_t size, const struct iwn_http_parse_result *res) {
  struct fuzz_frame fr;
  if (!fuzz_frame_scan(data, size, &fr)) {
    return;
  }
  switch (fr.kind) {
    case FRAME_NONE:
      if (res->status != 0 || res->body_len != 0 || !res->complete) {
        fuzz_bug("a request without a body framing must be accepted with an empty body "
                 "(status=%d body_len=%zd complete=%d)", res->status, res->body_len, (int) res->complete);
      }
      break;
    case FRAME_LENGTH:
      if (fr.present) {
        if (res->status != 0 || res->body_len != fr.body_len || !res->complete) {
          fuzz_bug("declared body of %zd bytes must be accepted "
                   "(status=%d body_len=%zd complete=%d)", fr.body_len, res->status, res->body_len,
                   (int) res->complete);
        }
      } else if (res->complete) {
        fuzz_bug("truncated body of %zd bytes reported as complete", fr.body_len);
      }
      break;
    case FRAME_CHUNKED:
      if (fr.present) {
        if (res->status != 0 || res->body_len != fr.body_len || !res->complete) {
          fuzz_bug("chunked body of %zd bytes must be accepted "
                   "(status=%d body_len=%zd complete=%d)", fr.body_len, res->status, res->body_len,
                   (int) res->complete);
        }
      } else if (res->complete) {
        fuzz_bug("truncated chunked body reported as complete");
      }
      break;
    case FRAME_REJECT:
      if (res->status != 400 && res->status != 501) {
        fuzz_bug("an ambiguous or unsupported request framing must be rejected with 400 or 501 "
                 "(status=%d)", res->status);
      }
      break;
    default:
      break;
  }
}

/// Runs all checks of the harness over a single input.
static void fuzz_run(const uint8_t *data, size_t size) {
  struct iwn_http_parse_result res, again;
  if (size > FUZZ_MAX_INPUT) {
    return;
  }
  g_input = data;
  g_input_len = size;
  memset(&res, 0, sizeof(res));
  fuzz_parse(data, size, &res);
  fuzz_check_framing(data, size, &res);

  // The parser is a pure state machine: the same input must produce the same outcome
  fuzz_parse(data, size, &again);
  if (memcmp(&res, &again, sizeof(res)) != 0) {
    fuzz_bug("non deterministic parse: status %d/%d, body_len %zd/%zd",
             res.status, again.status, res.body_len, again.body_len);
  }

  // Every prefix of the input is parsed as a possibly incomplete request
  size_t step = size > 64 ? size / 16 : 1;
  for (size_t n = 1; n < size; n += step) {
    fuzz_parse(data, n, &again);
  }
}

#ifndef IWN_FUZZ_STANDALONE

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  fuzz_run(data, size);
  return 0;
}

#else // IWN_FUZZ_STANDALONE

/// Request seeds: valid requests of all supported body framings and their edge cases.
static const char *fuzz_seeds[] = {
  "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
  "GET /a?b=c HTTP/1.1\r\nHost: localhost\r\nUser-Agent: fuzz\r\nAccept: */*\r\n\r\n",
  "GET / HTTP/1.0\r\n\r\n",
  "POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nabcde",
  "POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
  "POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5 \r\n\r\nabcde",
  "POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 007\r\n\r\nabcdefg",
  "POST /echo HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
  "POST /echo HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n"
  "4\r\nabcd\r\n3\r\nefg\r\n0\r\n\r\n",
  "POST /echo HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n"
  "3\r\nabc\r\n0\r\nX-Trailer: v\r\n\r\n",
  "POST /echo HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: CHUNKED\r\n\r\n0\r\n\r\n",
  "POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc",
  "POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\nabc",
  "POST /echo HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\nabc",
  "POST /echo HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: gzip\r\n\r\n",
  "POST /echo HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n",
  "POST /echo HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked, gzip\r\n\r\n0\r\n\r\n",
  "POST /echo HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked, chunked\r\n\r\n0\r\n\r\n",
  "POST /echo HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked;q=1\r\n\r\n0\r\n\r\n",
  "POST /echo HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: \r\n\r\n",
  "POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 18446744073709551606\r\n\r\nabc",
  "POST /echo HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n"
  "fffffffffffffff6\r\nabc\r\n0\r\n\r\n",
  "POST /echo HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nab",
  "POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: -1\r\n\r\n",
  "POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: +1\r\n\r\n",
  "POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1 1\r\n\r\nab",
  "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n"
  "GET /next HTTP/1.1\r\nHost: localhost\r\n\r\n",
  "GET / HTTP/1.1\r\n\r\n",
  "OPTIONS * HTTP/1.1\r\nHost: localhost\r\n\r\n",
  "POST / HTTP/1.1\r\nHost: localhost\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\nhi",
  "POST /echo HTTP/1.1\r\nHost: localhost\r\nConte: 5\r\n\r\n",
  "POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: \r\n\r\n",
  "POST /echo HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nabc\r\n0\r\n\r\n",
  "POST /echo HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n"
  "3 ;ext=1\r\nabc\r\n0\r\n\r\n",
  "POST /echo HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n3;x\r\nabc\r\n0\r\n\r\n",
};

#define FUZZ_SEED_COUNT (sizeof(fuzz_seeds) / sizeof(fuzz_seeds[0]))

static uint64_t g_rng;

static uint32_t fuzz_rand(void) {
  g_rng ^= g_rng << 13;
  g_rng ^= g_rng >> 7;
  g_rng ^= g_rng << 17;
  return (uint32_t) (g_rng >> 32);
}

static unsigned long g_rounds = 100000;
static uint64_t g_seed = 0x9E3779B97F4A7C15ull;

static int suite_init(void) {
  const char *v = getenv("IWN_FUZZ_ROUNDS");
  if (v && *v) {
    g_rounds = strtoul(v, 0, 0);
  }
  v = getenv("IWN_FUZZ_SEED");
  if (v && *v) {
    g_seed = strtoull(v, 0, 0);
  }
  g_rng = g_seed ? g_seed : 1;
  return 0;
}

/// Feeds every seed unmutated through the harness.
static void test_corpus(void) {
  for (size_t i = 0; i < FUZZ_SEED_COUNT; ++i) {
    fuzz_run((const uint8_t*) fuzz_seeds[i], strlen(fuzz_seeds[i]));
  }
}

/// Runs `IWN_FUZZ_ROUNDS` random and seed mutated inputs.
static void test_random_rounds(void) {
  uint8_t buf[FUZZ_MAX_INPUT];

  for (unsigned long r = 0; r < g_rounds; ++r) {
    size_t len;
    int mode = (int) (fuzz_rand() % 4);
    if (mode == 0) {
      len = fuzz_rand() % sizeof(buf);
      for (size_t i = 0; i < len; ++i) {
        buf[i] = (uint8_t) fuzz_rand();
      }
    } else if (mode == 1) {
      // Request shaped input: a random request line followed by random header bytes
      static const char *methods[] = { "GET", "POST", "PUT", "OPTIONS", "HEAD" };
      static const char *versions[] = { "HTTP/1.1", "HTTP/1.0", "HTTP/1.2", "HTTP/2.0", "HTTP/1" };
      len = (size_t) snprintf((char*) buf, sizeof(buf), "%s /%s %s\r\n",
                              methods[fuzz_rand() % 5], (fuzz_rand() & 1) ? "x" : "",
                              versions[fuzz_rand() % 5]);
      size_t n = fuzz_rand() % 200;
      for (size_t i = 0; i < n && len < sizeof(buf); ++i) {
        buf[len++] = (uint8_t) (fuzz_rand() & 1 ? (char) fuzz_rand() : "\r\n: -0123456789abcxyz"[fuzz_rand() % 18]);
      }
      if (len + 4 < sizeof(buf)) {
        memcpy(buf + len, "\r\n\r\n", 4);
        len += 4;
      }
    } else {
      const char *seed = fuzz_seeds[fuzz_rand() % FUZZ_SEED_COUNT];
      len = strlen(seed);
      if (len > sizeof(buf)) {
        len = sizeof(buf);
      }
      memcpy(buf, seed, len);
      int muts = 1 + (int) (fuzz_rand() % 8);
      for (int m = 0; m < muts; ++m) {
        int op = (int) (fuzz_rand() % 5);
        if (len == 0) {
          buf[0] = (uint8_t) fuzz_rand();
          len = 1;
          continue;
        }
        if (op == 0) {
          buf[fuzz_rand() % len] ^= (uint8_t) (1u << (fuzz_rand() % 8));
        } else if (op == 1) {
          buf[fuzz_rand() % len] = (uint8_t) fuzz_rand();
        } else if (op == 2) {
          len = fuzz_rand() % len;
        } else if (op == 3 && len < sizeof(buf)) {
          size_t at = fuzz_rand() % len;
          memmove(buf + at + 1, buf + at, len - at);
          buf[at] = (uint8_t) (fuzz_rand() & 1 ? "\r\n"[fuzz_rand() % 2] : (char) fuzz_rand());
          ++len;
        } else if (len < sizeof(buf)) {
          buf[len++] = (uint8_t) fuzz_rand();
        }
      }
    }
    fuzz_run(buf, len);
  }

  fprintf(stderr, "fuzz_http1: %lu rounds ok (seed=%" PRIu64 ")\n", g_rounds, g_seed);
}

int main(int argc, char *argv[]) {
  static const struct iw_test_case cases[] = {
    IW_TEST_CASE_AS("corpus", test_corpus),
    IW_TEST_CASE_AS("random_rounds", test_random_rounds),
  };
  return iw_test_run(argc, argv, IW_TEST_SUITE("fuzz_http1", cases, suite_init, 0));
}

#endif // IWN_FUZZ_STANDALONE
