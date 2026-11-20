/*
 * Regression tests of the HTTP/1.1 request parser numeric body length handling.
 *
 * The parser accumulates `Content-Length` (decimal) and chunk sizes (hex) in an
 * `ssize_t` without bounds checking. An overflowing value wrapped to a negative
 * length, which made the body scanner jump backwards over already consumed bytes
 * of the connection buffer: an echo style handler returned request bytes (of the
 * same connection) the client never sent in that request, and the request body
 * no longer matched the received data.
 *
 * The tests run a real server on `127.0.0.1:9294` in a separate poller thread and
 * talk to it over plain blocking sockets so arbitrary (malformed) requests can be
 * sent:
 *
 *  - `overflown_content_length`: a valid request plants a marker in the connection
 *    buffer, then a request with an overflowing `Content-Length` is sent over the
 *    same connection. The response must be `400 Bad Request` and must not contain
 *    the marker.
 *  - `overflown_chunk_size`: the same scenario with a chunked request carrying an
 *    overflowing hex chunk size, followed by a well formed chunked request that
 *    proves the server is still healthy.
 *  - `duplicate_content_length`/`te_with_content_length`: ambiguous request framing
 *    (`Content-Length` duplicated or combined with `Transfer-Encoding`) is rejected.
 *  - `transfer_encoding_value`: a transfer coding which is not implemented is
 *    reported as `501`, an invalid `Transfer-Encoding` value is rejected.
 *  - `ignored_streamed_body`/`streamed_keep_alive`: a streamed request body that the
 *    handler does not consume closes the connection, a consumed one keeps it reusable.
 *
 * Streamed (chunked) request bodies are collected by the server handler, so the
 * chunk size accumulation path is actually reached before the response is written.
 */

#include "iwtests.h"
#include "iwn_http_server.h"

#include <iowow/iwlog.h>
#include <iowow/iwxstr.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define TEST_PORT    9294
#define TEST_HOST    "127.0.0.1"
#define RECV_TIMEOUT 5 /* seconds */
#define MARKER       "MARKER-Q1W2E3R4T5Y6"

static struct iwn_poller *poller;

///////////////////////////////////////////////////////////////////////////
//                        Server under test                               //
///////////////////////////////////////////////////////////////////////////

static void _on_request_dispose(struct iwn_http_req *req) {
  iwxstr_destroy(req->user_data);
  req->user_data = 0;
}

/// Collects the whole streamed (chunked) request body and echoes it back.
static bool _chunk_cb(struct iwn_http_req *req, bool *again) {
  struct iwxstr *xstr = req->user_data;
  struct iwn_val val = iwn_http_request_chunk_get(req);
  if (val.len > 0) {
    iwrc rc = iwxstr_cat(xstr, val.buf, val.len);
    if (rc) {
      iwlog_ecode_error3(rc);
      return false;
    }
    iwn_http_request_chunk_next(req, _chunk_cb);
    return true;
  }
  iwrc rc = iwn_http_response_header_set(req, "content-type", "text/plain", -1);
  if (!rc) {
    iwn_http_response_body_set(req, iwxstr_ptr(xstr), iwxstr_size(xstr), 0);
    rc = iwn_http_response_end(req);
  }
  if (rc) {
    iwlog_ecode_error3(rc);
    return false;
  }
  return true;
}

static bool _request_handler(struct iwn_http_req *req) {
  iwrc rc = 0;
  if (iwn_http_request_is_streamed(req)) {
    if (iwn_http_request_target_is(req, "/nobody", -1)) {
      // Responds without consuming the streamed request body
      return iwn_http_response_end(req) == 0;
    }
    struct iwxstr *xstr = iwxstr_create_empty();
    if (!xstr) {
      return false;
    }
    req->user_data = xstr;
    req->on_request_dispose = _on_request_dispose;
    iwn_http_request_chunk_next(req, _chunk_cb);
    return true;
  }
  struct iwn_val body = iwn_http_request_body(req);
  RCC(rc, finish, iwn_http_response_header_set(req, "content-type", "text/plain", -1));
  iwn_http_response_body_set(req, body.buf, body.len, 0);
  rc = iwn_http_response_end(req);
finish:
  if (rc) {
    iwlog_ecode_error3(rc);
    return false;
  }
  return true;
}

static int _suite_init(void) {
  iwrc rc = iwn_poller_create(1, 1, &poller);
  if (rc) {
    iwlog_ecode_error3(rc);
    return 1;
  }
  struct iwn_http_server_spec spec = {
    .listen = TEST_HOST,
    .port = TEST_PORT,
    .poller = poller,
    .request_handler = _request_handler,
    .request_timeout_sec = -1,
    .request_timeout_keepalive_sec = -1,
  };
  rc = iwn_http_server_create(&spec, 0);
  if (rc) {
    iwlog_ecode_error3(rc);
    iwn_poller_destroy(&poller);
    return 1;
  }
  pthread_t thr;
  rc = iwn_poller_poll_in_thread(poller, "http_parser1", &thr);
  if (rc) {
    iwlog_ecode_error3(rc);
    iwn_poller_destroy(&poller);
    return 1;
  }
  return 0;
}

static void _suite_cleanup(void) {
  iwn_poller_shutdown_request(poller);
  iwn_poller_destroy(&poller);
}

///////////////////////////////////////////////////////////////////////////
//                        Raw HTTP client                                //
///////////////////////////////////////////////////////////////////////////

static int _connect(void) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    return -1;
  }
  struct timeval tv = { .tv_sec = RECV_TIMEOUT, .tv_usec = 0 };
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  struct sockaddr_in addr = {
    .sin_family = AF_INET,
    .sin_port = htons(TEST_PORT),
  };
  if (  inet_pton(AF_INET, TEST_HOST, &addr.sin_addr) != 1
     || connect(fd, (struct sockaddr*) &addr, sizeof(addr))) {
    close(fd);
    return -1;
  }
  return fd;
}

static bool _write_all(int fd, const char *buf, size_t len) {
  while (len > 0) {
    ssize_t bytes = write(fd, buf, len);
    if (bytes < 0) {
      if (errno == EINTR) {
        continue;
      }
      return false;
    }
    buf += bytes;
    len -= bytes;
  }
  return true;
}

static bool _writef(int fd, const char *fmt, ...) {
  char buf[512];
  va_list args;
  va_start(args, fmt);
  int len = vsnprintf(buf, sizeof(buf), fmt, args);
  va_end(args);
  if (len < 0 || len >= (int) sizeof(buf)) {
    return false;
  }
  return _write_all(fd, buf, len);
}

/// Reads `len` bytes from `fd` into `buf`. Returns `false` on IO error.
static bool _read_all(int fd, char *buf, size_t len) {
  while (len > 0) {
    ssize_t bytes = read(fd, buf, len);
    if (bytes <= 0) {
      if (bytes < 0 && errno == EINTR) {
        continue;
      }
      return false;
    }
    buf += bytes;
    len -= bytes;
  }
  return true;
}

/// Reads a single HTTP response from `fd`.
/// The response status code is stored in `status`, up to `body_cap` bytes of the
/// response body (NUL terminated) in `body`, and the full body length in `body_len`.
/// Returns `false` on IO error or a malformed response.
static bool _read_response(int fd, int *status, char *body, size_t body_cap, size_t *body_len) {
  char buf[4096];
  size_t len = 0;
  char *hdr_end = 0;
  while (len < sizeof(buf) - 1 && !hdr_end) {
    ssize_t bytes = read(fd, buf + len, sizeof(buf) - len - 1);
    if (bytes <= 0) {
      return false;
    }
    len += bytes;
    buf[len] = '\0';
    hdr_end = strstr(buf, "\r\n\r\n");
  }
  if (!hdr_end || strncmp(buf, "HTTP/1.1 ", 9) != 0) {
    return false;
  }
  *status = (int) strtol(buf + 9, 0, 10);
  long content_length = -1;
  for (char *p = strstr(buf, "\r\n"); p && p < hdr_end; p = strstr(p, "\r\n")) {
    p += 2;
    if (strncasecmp(p, "content-length:", 15) == 0) {
      content_length = strtol(p + 15, 0, 10);
      break;
    }
  }
  if (content_length < 0) {
    return false;
  }
  char *hdr_body = hdr_end + 4;
  size_t got = len - (size_t) (hdr_body - buf);
  size_t want = (size_t) content_length;
  size_t nb = got < want ? got : want;
  nb = nb < body_cap ? nb : body_cap - 1;
  memcpy(body, hdr_body, nb);
  size_t copied = nb;
  while (got < want) {
    char tmp[512];
    size_t chunk = want - got > sizeof(tmp) ? sizeof(tmp) : want - got;
    if (!_read_all(fd, tmp, chunk)) {
      return false;
    }
    size_t space = body_cap - 1 - copied;
    size_t ncopy = chunk < space ? chunk : space;
    memcpy(body + copied, tmp, ncopy);
    copied += ncopy;
    got += chunk;
  }
  body[copied] = '\0';
  *body_len = want;
  return true;
}

static size_t _occurrences(const char *haystack, const char *needle) {
  size_t n = 0;
  for (const char *p = haystack; (p = strstr(p, needle)); p += strlen(needle)) {
    ++n;
  }
  return n;
}

/// Sends a plain (non chunked) `POST /echo` request with the `MARKER` body and
/// the given raw `Content-Length` value.
static bool _send_echo(int fd, const char *content_length_str) {
  return _writef(fd,
                 "POST /echo HTTP/1.1\r\n"
                 "Host: localhost\r\n"
                 "Content-Length: %s\r\n"
                 "Connection: keep-alive\r\n"
                 "\r\n" MARKER, content_length_str);
}

/// Sends a well formed chunked `POST /echo` request with the `MARKER` body.
static bool _send_chunked_echo(int fd, const char *chunk_size_str) {
  return _writef(fd,
                 "POST /echo HTTP/1.1\r\n"
                 "Host: localhost\r\n"
                 "Transfer-Encoding: chunked\r\n"
                 "\r\n"
                 "%s\r\n" MARKER "\r\n0\r\n\r\n", chunk_size_str);
}

/// Returns `true` when the server closed the connection.
static bool _wait_eof(int fd) {
  struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  char c;
  return read(fd, &c, 1) == 0;
}

///////////////////////////////////////////////////////////////////////////
//                        Test cases                                     //
///////////////////////////////////////////////////////////////////////////

static void test_overflown_content_length(void) {
  int status = 0;
  size_t body_len = 0;
  char body[1024];
  char clen[32];
  snprintf(clen, sizeof(clen), "%zu", strlen(MARKER));

  int fd = _connect();
  IW_TEST_ASSERT_FATAL(fd >= 0);

  // Valid request, the echoed body stays in the connection buffer
  IW_TEST_ASSERT(_send_echo(fd, clen));
  IW_TEST_ASSERT(_read_response(fd, &status, body, sizeof(body), &body_len));
  IW_TEST_ASSERT_EQUAL(status, 200);
  IW_TEST_ASSERT_STR_EQUAL(body, MARKER);

  // 2^64 - 10: wraps to a negative `ssize_t`
  IW_TEST_ASSERT(_send_echo(fd, "18446744073709551606"));
  IW_TEST_ASSERT(_read_response(fd, &status, body, sizeof(body), &body_len));
  IW_TEST_ASSERT_EQUAL(status, 400);
  IW_TEST_ASSERT_EQUAL(_occurrences(body, MARKER), 0);
  IW_TEST_ASSERT_EQUAL(body_len, strlen(body));
  close(fd);
}

static void test_overflown_chunk_size(void) {
  int status = 0;
  size_t body_len = 0;
  char body[1024];
  char clen[32];
  snprintf(clen, sizeof(clen), "%zu", strlen(MARKER));

  int fd = _connect();
  IW_TEST_ASSERT_FATAL(fd >= 0);

  IW_TEST_ASSERT(_send_echo(fd, clen));
  IW_TEST_ASSERT(_read_response(fd, &status, body, sizeof(body), &body_len));
  IW_TEST_ASSERT_EQUAL(status, 200);
  IW_TEST_ASSERT_STR_EQUAL(body, MARKER);

  // Chunk size 0xfffffffffffffff6 wraps to a negative `ssize_t`
  IW_TEST_ASSERT(_send_chunked_echo(fd, "fffffffffffffff6"));
  IW_TEST_ASSERT(_read_response(fd, &status, body, sizeof(body), &body_len));
  IW_TEST_ASSERT_EQUAL(status, 400);
  IW_TEST_ASSERT_EQUAL(_occurrences(body, MARKER), 0);
  close(fd);

  // Non hex chunk size
  fd = _connect();
  IW_TEST_ASSERT_FATAL(fd >= 0);
  IW_TEST_ASSERT(_send_chunked_echo(fd, "1g"));
  IW_TEST_ASSERT(_read_response(fd, &status, body, sizeof(body), &body_len));
  IW_TEST_ASSERT_EQUAL(status, 400);
  IW_TEST_ASSERT_EQUAL(_occurrences(body, MARKER), 0);
  close(fd);

  // The server still accepts well formed chunked requests
  snprintf(clen, sizeof(clen), "%zx", strlen(MARKER));
  fd = _connect();
  IW_TEST_ASSERT_FATAL(fd >= 0);
  IW_TEST_ASSERT(_send_chunked_echo(fd, clen));
  IW_TEST_ASSERT(_read_response(fd, &status, body, sizeof(body), &body_len));
  IW_TEST_ASSERT_EQUAL(status, 200);
  IW_TEST_ASSERT_STR_EQUAL(body, MARKER);
  close(fd);
}

/// Duplicated `Content-Length` headers must be rejected (RFC 9112).
static void test_duplicate_content_length(void) {
  int status = 0;
  size_t body_len = 0;
  char body[1024];

  int fd = _connect();
  IW_TEST_ASSERT_FATAL(fd >= 0);
  IW_TEST_ASSERT(_writef(fd,
                         "POST /echo HTTP/1.1\r\n"
                         "Host: localhost\r\n"
                         "Content-Length: 19\r\n"
                         "Content-Length: 19\r\n"
                         "\r\n" MARKER));
  IW_TEST_ASSERT(_read_response(fd, &status, body, sizeof(body), &body_len));
  IW_TEST_ASSERT_EQUAL(status, 400);
  IW_TEST_ASSERT_EQUAL(_occurrences(body, MARKER), 0);
  close(fd);

  fd = _connect();
  IW_TEST_ASSERT_FATAL(fd >= 0);
  IW_TEST_ASSERT(_writef(fd,
                         "POST /echo HTTP/1.1\r\n"
                         "Host: localhost\r\n"
                         "Content-Length: 1\r\n"
                         "Content-Length: 9\r\n"
                         "\r\n" MARKER));
  IW_TEST_ASSERT(_read_response(fd, &status, body, sizeof(body), &body_len));
  IW_TEST_ASSERT_EQUAL(status, 400);
  IW_TEST_ASSERT_EQUAL(_occurrences(body, MARKER), 0);
  close(fd);
}

/// A streamed request body ignored by the handler must not desync the connection:
/// the response must not inherit the previous response body length and the
/// connection has to be closed instead of being reused.
static void test_ignored_streamed_body(void) {
  int status = 0;
  size_t body_len = 0;
  char body[1024];

  int fd = _connect();
  IW_TEST_ASSERT_FATAL(fd >= 0);

  IW_TEST_ASSERT(_send_echo(fd, "19"));
  IW_TEST_ASSERT(_read_response(fd, &status, body, sizeof(body), &body_len));
  IW_TEST_ASSERT_EQUAL(status, 200);
  IW_TEST_ASSERT_STR_EQUAL(body, MARKER);

  // `/nobody` responds without reading the chunked body
  IW_TEST_ASSERT(_writef(fd,
                         "POST /nobody HTTP/1.1\r\n"
                         "Host: localhost\r\n"
                         "Transfer-Encoding: chunked\r\n"
                         "\r\n"
                         "13\r\n" MARKER "\r\n0\r\n\r\n"));
  IW_TEST_ASSERT(_read_response(fd, &status, body, sizeof(body), &body_len));
  IW_TEST_ASSERT_EQUAL(status, 200);
  IW_TEST_ASSERT_EQUAL(body_len, 0);
  IW_TEST_ASSERT_EQUAL(body[0], '\0');
  IW_TEST_ASSERT(_wait_eof(fd));
  close(fd);
}

/// A fully consumed streamed request keeps the connection reusable.
static void test_streamed_keep_alive(void) {
  int status = 0;
  size_t body_len = 0;
  char body[1024];
  char clen[32];
  snprintf(clen, sizeof(clen), "%zx", strlen(MARKER));

  int fd = _connect();
  IW_TEST_ASSERT_FATAL(fd >= 0);

  IW_TEST_ASSERT(_send_chunked_echo(fd, clen));
  IW_TEST_ASSERT(_read_response(fd, &status, body, sizeof(body), &body_len));
  IW_TEST_ASSERT_EQUAL(status, 200);
  IW_TEST_ASSERT_STR_EQUAL(body, MARKER);

  IW_TEST_ASSERT(_send_chunked_echo(fd, clen));
  IW_TEST_ASSERT(_read_response(fd, &status, body, sizeof(body), &body_len));
  IW_TEST_ASSERT_EQUAL(status, 200);
  IW_TEST_ASSERT_STR_EQUAL(body, MARKER);
  close(fd);
}

/// Requests with ambiguous framing: `Transfer-Encoding` combined with
/// `Content-Length` (RFC 9112 section 6.1).
static const char _te_then_cl_req[]
  = "POST /echo HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nContent-Length: 19\r\n\r\n"
    "13\r\n" MARKER "\r\n0\r\n\r\n";
static const char _cl_then_te_req[]
  = "POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 19\r\nTransfer-Encoding: chunked\r\n\r\n"
    "13\r\n" MARKER "\r\n0\r\n\r\n";
// An unsupported transfer coding must not fall back to `Content-Length`
static const char _te_unsupported_cl_req[]
  = "POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 19\r\nTransfer-Encoding: gzip\r\n\r\n"
    MARKER;

/// `Transfer-Encoding` together with `Content-Length` must be rejected, since the
/// message framing is ambiguous for intermediaries (RFC 9112 section 6.1).
static void test_te_with_content_length(void) {
  int status = 0;
  size_t body_len = 0;
  char body[1024];

  static const char *reqs[] = {
    _te_then_cl_req,
    _cl_then_te_req,
    _te_unsupported_cl_req,
  };

  for (size_t i = 0; i < sizeof(reqs) / sizeof(reqs[0]); ++i) {
    int fd = _connect();
    IW_TEST_ASSERT_FATAL(fd >= 0);
    IW_TEST_ASSERT(_write_all(fd, reqs[i], strlen(reqs[i])));
    IW_TEST_ASSERT(_read_response(fd, &status, body, sizeof(body), &body_len));
    IW_TEST_ASSERT_EQUAL(status, 400);
    IW_TEST_ASSERT_EQUAL(_occurrences(body, MARKER), 0);
    close(fd);
  }

  // Both headers are still accepted on their own
  int fd = _connect();
  IW_TEST_ASSERT_FATAL(fd >= 0);
  IW_TEST_ASSERT(_send_echo(fd, "19"));
  IW_TEST_ASSERT(_read_response(fd, &status, body, sizeof(body), &body_len));
  IW_TEST_ASSERT_EQUAL(status, 200);
  IW_TEST_ASSERT_STR_EQUAL(body, MARKER);
  close(fd);

  fd = _connect();
  IW_TEST_ASSERT_FATAL(fd >= 0);
  IW_TEST_ASSERT(_send_chunked_echo(fd, "13"));
  IW_TEST_ASSERT(_read_response(fd, &status, body, sizeof(body), &body_len));
  IW_TEST_ASSERT_EQUAL(status, 200);
  IW_TEST_ASSERT_STR_EQUAL(body, MARKER);
  close(fd);
}

/// `Transfer-Encoding` field values of the request (RFC 9112 section 6.1).
/// The `chunked` coding is the only one implemented, any other coding is reported
/// as `501 Not Implemented`, while an invalid field value (a repeated `chunked`
/// coding, or no coding at all) is a malformed request.
static void test_transfer_encoding_value(void) {
  int status = 0;
  size_t body_len = 0;
  char body[1024];

  static const struct {
    const char *request;
    int status;
  } cases[] = {
    { "POST /echo HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: gzip\r\n\r\n", 501 },
    { "POST /echo HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked, gzip\r\n\r\n", 501 },
    { "POST /echo HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: gzip, chunked\r\n\r\n", 501 },
    { "POST /echo HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked;foo=bar\r\n\r\n", 501 },
    { "POST /echo HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked, chunked\r\n\r\n", 400 },
    {
      "POST /echo HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n"
      "Transfer-Encoding: chunked\r\n\r\n", 400
    },
    { "POST /echo HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: \r\n\r\n", 400 },
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    int fd = _connect();
    IW_TEST_ASSERT_FATAL(fd >= 0);
    IW_TEST_ASSERT(_write_all(fd, cases[i].request, strlen(cases[i].request)));
    IW_TEST_ASSERT(_read_response(fd, &status, body, sizeof(body), &body_len));
    IW_TEST_ASSERT_EQUAL(status, cases[i].status);
    IW_TEST_ASSERT_EQUAL(_occurrences(body, MARKER), 0);
    close(fd);
  }

  // The `chunked` coding is recognized case insensitively and around optional whitespace
  static const char *chunked_reqs[] = {
    "POST /echo HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n"
    "13\r\n" MARKER "\r\n0\r\n\r\n",
    "POST /echo HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: Chunked\r\n\r\n"
    "13\r\n" MARKER "\r\n0\r\n\r\n",
    "POST /echo HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: \tchunked \t\r\n\r\n"
    "13\r\n" MARKER "\r\n0\r\n\r\n",
  };

  for (size_t i = 0; i < sizeof(chunked_reqs) / sizeof(chunked_reqs[0]); ++i) {
    int fd = _connect();
    IW_TEST_ASSERT_FATAL(fd >= 0);
    IW_TEST_ASSERT(_write_all(fd, chunked_reqs[i], strlen(chunked_reqs[i])));
    IW_TEST_ASSERT(_read_response(fd, &status, body, sizeof(body), &body_len));
    IW_TEST_ASSERT_EQUAL(status, 200);
    IW_TEST_ASSERT_STR_EQUAL(body, MARKER);
    close(fd);
  }
}

/// Request head and body framing edge cases found by the fuzzing harness.
static void test_request_head_quirks(void) {
  int status = 0;
  size_t body_len = 0;
  char body[1024];

  // A request without header fields is valid
  int fd = _connect();
  IW_TEST_ASSERT_FATAL(fd >= 0);
  IW_TEST_ASSERT(_write_all(fd, "GET / HTTP/1.0\r\n\r\n", IW_LLEN("GET / HTTP/1.0\r\n\r\n")));
  IW_TEST_ASSERT(_read_response(fd, &status, body, sizeof(body), &body_len));
  IW_TEST_ASSERT_EQUAL(status, 200);
  IW_TEST_ASSERT_EQUAL(body_len, 0);
  close(fd);

  // Trailing OWS of the `Content-Length` value is ignored
  fd = _connect();
  IW_TEST_ASSERT_FATAL(fd >= 0);
  IW_TEST_ASSERT(_send_echo(fd, "19 "));
  IW_TEST_ASSERT(_read_response(fd, &status, body, sizeof(body), &body_len));
  IW_TEST_ASSERT_EQUAL(status, 200);
  IW_TEST_ASSERT_STR_EQUAL(body, MARKER);
  close(fd);

  // An empty `Content-Length` value is malformed
  fd = _connect();
  IW_TEST_ASSERT_FATAL(fd >= 0);
  IW_TEST_ASSERT(_writef(fd,
                         "POST /echo HTTP/1.1\r\n"
                         "Host: localhost\r\n"
                         "Content-Length: \r\n"
                         "\r\n" MARKER));
  IW_TEST_ASSERT(_read_response(fd, &status, body, sizeof(body), &body_len));
  IW_TEST_ASSERT_EQUAL(status, 400);
  close(fd);

  // A header field name which is a prefix of `content-length` is not a content length
  fd = _connect();
  IW_TEST_ASSERT_FATAL(fd >= 0);
  IW_TEST_ASSERT(_writef(fd,
                         "POST /echo HTTP/1.1\r\n"
                         "Host: localhost\r\n"
                         "Conte: 19\r\n"
                         "\r\n"));
  IW_TEST_ASSERT(_read_response(fd, &status, body, sizeof(body), &body_len));
  IW_TEST_ASSERT_EQUAL(status, 200);
  IW_TEST_ASSERT_EQUAL(body_len, 0);
  close(fd);

  // Chunked trailer section is accepted and ignored
  fd = _connect();
  IW_TEST_ASSERT_FATAL(fd >= 0);
  IW_TEST_ASSERT(_writef(fd,
                         "POST /echo HTTP/1.1\r\n"
                         "Host: localhost\r\n"
                         "Transfer-Encoding: chunked\r\n"
                         "\r\n"
                         "13\r\n" MARKER "\r\n0\r\nX-Trailer: v\r\n\r\n"));
  IW_TEST_ASSERT(_read_response(fd, &status, body, sizeof(body), &body_len));
  IW_TEST_ASSERT_EQUAL(status, 200);
  IW_TEST_ASSERT_STR_EQUAL(body, MARKER);
  close(fd);
}

int main(int argc, char *argv[]) {
  iwlog_init();
  static const struct iw_test_case cases[] = {
    IW_TEST_CASE(test_overflown_content_length),
    IW_TEST_CASE(test_overflown_chunk_size),
    IW_TEST_CASE(test_duplicate_content_length),
    IW_TEST_CASE(test_te_with_content_length),
    IW_TEST_CASE(test_transfer_encoding_value),
    IW_TEST_CASE(test_request_head_quirks),
    IW_TEST_CASE(test_ignored_streamed_body),
    IW_TEST_CASE(test_streamed_keep_alive),
  };
  return iw_test_run(argc, argv, IW_TEST_SUITE("http_parser1", cases, _suite_init, _suite_cleanup));
}
