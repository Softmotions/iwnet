#include "iwn_wf_files.h"

#include <iowow/iwp.h>
#include <iowow/iwlog.h>
#include <iowow/iwxstr.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>

#define BOUNDARY_MAX 32
#define CTYPE_MAX    128
#define ETAG_MAX     64
#define BUF_MAX      4096

struct range {
  int64_t       start;
  int64_t       end;
  int64_t       to_read;
  struct range *next;
};

struct ctx {
  struct iwn_wf_req *req;
  FILE *file;
  struct range *ranges;
  IWP_FILE_STAT fs;
  bool range_processed;
  char boundary[BOUNDARY_MAX];
  char ctype[CTYPE_MAX];
  char buf[BUF_MAX];
};

static void _ctx_destroy(struct ctx *ctx) {
  if (ctx) {
    ctx->req->http->user_data = 0;
    ctx->req->http->on_request_dispose = 0;
    if (ctx->file) {
      fclose(ctx->file);
    }
    for (struct range *r = ctx->ranges; r; ) {
      struct range *n = r->next;
      free(r);
      r = n;
    }
    free(ctx);
  }
}

static void _on_request_dispose(struct iwn_http_req *req) {
  struct ctx *ctx = req->user_data;
  _ctx_destroy(ctx);
}

static const char* _ranges_parse_next(const char *rp, const char *ep, struct range *range) {
  const char *ret = 0;
  range->next = 0;
  range->to_read = INT64_MAX;
  range->start = range->end = INT64_MAX;

  int64_t *rv = &range->start;
  while (rp < ep) {
    switch (*rp) {
      case ' ':
        ++rp;
        if (*rv != INT64_MAX) {
          range->start = range->end = INT64_MIN; // invalid
          return 0;
        }
        break;
      case ',':
        ++rp;
        ret = rp;
        goto finish;
      case '-':
        ++rp;
        if (rv == &range->start) {
          rv = &range->end;
          break;
        } else {
          range->start = range->end = INT64_MIN; // invalid
          return 0;
        }
      case '0':
      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
      case '6':
      case '7':
      case '8':
      case '9':
        if (*rv == INT64_MAX) {
          *rv = 0;
        }
        *rv = *rv * 10 + *rp - '0';
        ++rp;
        break;
      default:
        range->start = range->end = INT64_MIN; // invalid
        return 0;
    }
  }

finish:
  if (rv == &range->start) {
    range->start = range->end = INT64_MIN;
  }
  return ret;
}

static bool _ranges_parse(struct ctx *ctx, const char *rp, const char *ep) {
  // TODO: Check overlapping of ranges
  struct range range;
  while (rp) {
    rp = _ranges_parse_next(rp, ep, &range);
    if (  (range.start == INT64_MIN || range.end == INT64_MIN)
       || (range.start == INT64_MAX && range.end == INT64_MAX)) {
      return false;
    }
    if (  range.start != INT64_MAX && range.end != INT64_MAX
       && (range.start > range.end || range.start < 0 || range.end < 0)) {
      return false;
    }
    if (range.start == INT64_MAX && range.end < 1) {
      return false;
    }
    struct range *nr = malloc(sizeof(*nr));
    if (!nr) {
      return false;
    }
    *nr = range;
    struct range *r = ctx->ranges;
    while (r && r->next) {
      r = r->next;
    }
    if (r) {
      r->next = nr;
    } else {
      ctx->ranges = nr;
    }
  }
  return true;
}

static iwrc _boundary_fill(char fout[BOUNDARY_MAX]) {
  static const char cset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  FILE *f = fopen("/dev/urandom", "r");
  if (!f) {
    return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
  }
  if (fread(fout, BOUNDARY_MAX, 1, f) != 1) {
    fclose(f);
    return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
  }
  fclose(f);
  int i = 0;
  for ( ; i < BOUNDARY_MAX - 1; ++i) {
    fout[i] = cset[fout[i] % (sizeof(cset) - 1)];
  }
  fout[i] = '\0';
  return 0;
}

IW_INLINE size_t _etag_fill(struct ctx *ctx, char fout[64]) {
  return snprintf(fout, 64, "%04X-%04X",
                  (int32_t) ctx->fs.size, (int32_t) ctx->fs.mtime);
}

static bool _file_serve_ranges_multiple_part(struct iwn_http_req *req, bool *again);

static bool _file_serve_ranges_multiple_part_body(struct iwn_http_req *req, bool *again) {
  struct ctx *ctx = req->user_data;
  struct range *r = ctx->ranges;

  ctx->range_processed = r != 0;

  size_t to_read = MIN(sizeof(ctx->buf), r->to_read);
  size_t len = fread(ctx->buf, 1, to_read, ctx->file);
  bool stop = len == 0 || len != to_read || len == r->to_read;

  r->to_read -= len;

  if (stop) {
    //  Move to the next part
    ctx->ranges = r->next;
    free(r);
  }

  iwn_http_response_stream_write(
    req, ctx->buf, len, 0,
    stop ? _file_serve_ranges_multiple_part : _file_serve_ranges_multiple_part_body,
    again);

  return true;
}

static bool _file_server_accept_range(int64_t *start_, int64_t *end_, struct range *r, struct ctx *ctx) {
  iwrc rc = 0;
  int64_t start = 0, end = ctx->fs.size - 1;

  if (r->start == INT64_MAX) {
    RCN(finish, fseek(ctx->file, -r->end, SEEK_END));
    start = ctx->fs.size - r->end;
    r->to_read = end - start + 1;
  } else {
    start = r->start;
    RCN(finish, fseek(ctx->file, r->start, IWP_SEEK_SET));
    if (r->end != INT64_MAX) {
      end = r->end;
      r->to_read = end - start + 1;
    } else {
      r->to_read = ctx->fs.size - start;
    }
  }

  if (start < 0 || end < 0 || start > end || r->to_read < 1) {
    return false;
  }

  *start_ = start;
  *end_ = end;

finish:
  return rc == 0;
}

static bool _file_serve_ranges_multiple_part(struct iwn_http_req *req, bool *again) {
  iwrc rc = 0;

  struct ctx *ctx = req->user_data;
  struct range *r = ctx->ranges;

  char *buf = 0;
  size_t buf_len = 0;
  iwn_http_server_chunk_handler ch = 0;

  IWXSTR *xstr = iwxstr_new();
  if (!xstr) {
    return false;
  }

  if (ctx->range_processed) {
    RCC(rc, finish, iwxstr_printf(xstr, "\r\n"));
  }

  if (r) {
    int64_t start, end;
    if (!_file_server_accept_range(&start, &end, r, ctx)) {
      rc = IW_ERROR_FAIL;
      goto finish;
    }
    RCC(rc, finish, iwxstr_printf(xstr, "--%s\r\n", ctx->boundary));
    RCC(rc, finish, iwxstr_printf(xstr, "content-type: %s\r\n", ctx->ctype));
    RCC(rc, finish, iwxstr_printf(xstr, "content-range: "
                                  "bytes %" PRId64 "-%" PRId64 "/%" PRId64 "\r\n\r\n",
                                  start, end, ctx->fs.size));

    ch = _file_serve_ranges_multiple_part_body;
  } else {
    RCC(rc, finish, iwxstr_printf(xstr, "--%s--\r\n", ctx->boundary));
  }

  buf_len = iwxstr_size(xstr);
  buf = iwxstr_ptr(xstr);
  iwxstr_destroy_keep_ptr(xstr);
  xstr = 0;

  iwn_http_response_stream_write(req, buf, buf_len, free, ch, again);

finish:
  if (rc) {
    free(buf);
    iwxstr_destroy(xstr);
    return false;
  }
  return true;
}

static iwrc _file_serve_ranges_multiple(struct ctx *ctx) {
  iwrc rc = 0;
  RCC(rc, finish, _boundary_fill(ctx->boundary));
  RCC(rc, finish, iwn_http_response_code_set(ctx->req->http, 206));
  iwn_http_connection_set_keep_alive(ctx->req->http, false);
  RCC(rc, finish, iwn_http_response_header_printf(
        ctx->req->http, "content-type", "multipart/byteranges; boundary=\"%s\"", ctx->boundary));

  if (IW_UNLIKELY(ctx->req->flags & IWN_WF_HEAD)) {
    iwn_http_response_write(ctx->req->http, 206, "", 0, 0);
  } else {
    rc = iwn_http_response_stream_start(ctx->req->http, _file_serve_ranges_multiple_part);
  }

finish:
  return rc;
}

static bool _file_serve_range_single_cb(struct iwn_http_req *req, bool *again) {
  struct ctx *ctx = req->user_data;
  struct range *r = ctx->ranges;

  size_t to_read = MIN(sizeof(ctx->buf), r->to_read);
  size_t len = fread(ctx->buf, 1, to_read, ctx->file);
  bool stop = len == 0 || len != to_read || len == r->to_read;

  r->to_read -= len;

  iwn_http_response_stream_write(req, ctx->buf, len, 0, stop ? 0 : _file_serve_range_single_cb, again);
  return true;
}

static iwrc _file_serve_range_single(struct ctx *ctx) {
  iwrc rc = 0;
  int64_t start, end;
  struct range *r = ctx->ranges;

  if (!_file_server_accept_range(&start, &end, r, ctx)) {
    iwn_http_response_by_code(ctx->req->http, 416);
    goto finish;
  }

  RCC(rc, finish, iwn_http_response_header_set(ctx->req->http, "content-type", ctx->ctype, -1));
  RCC(rc, finish, iwn_http_response_header_i64_set(ctx->req->http, "content-length", r->to_read));
  RCC(rc, finish, iwn_http_response_code_set(ctx->req->http, 206)); // Partial content
  RCC(rc, finish, iwn_http_response_header_printf(
        ctx->req->http, "content-range",
        "bytes %" PRId64 "-%" PRId64 "/%" PRIu64, start, end, ctx->fs.size));

  if (IW_UNLIKELY(ctx->req->flags & IWN_WF_HEAD)) {
    iwn_http_response_write(ctx->req->http, 206, "", 0, 0);
  } else {
    rc = iwn_http_response_stream_start(ctx->req->http, _file_serve_range_single_cb);
  }

finish:
  return rc;
}

static bool _file_serve_norange_cb(struct iwn_http_req *req, bool *again) {
  struct ctx *ctx = req->user_data;
  size_t len = fread(ctx->buf, 1, sizeof(ctx->buf), ctx->file);
  iwn_http_response_stream_write(req, ctx->buf, len, 0,
                                 len != sizeof(ctx->buf) ? 0 : _file_serve_norange_cb,
                                 again);
  return true;
}

static iwrc _file_serve_norange(struct ctx *ctx) {
  iwrc rc = 0;
  RCC(rc, finish, iwn_http_response_header_set(ctx->req->http, "content-type", ctx->ctype, -1));
  RCC(rc, finish, iwn_http_response_header_i64_set(ctx->req->http, "content-length", ctx->fs.size));

  if (IW_UNLIKELY(ctx->req->flags & IWN_WF_HEAD)) {
    iwn_http_response_write(ctx->req->http, 200, "", 0, 0);
  } else {
    rc = iwn_http_response_stream_start(ctx->req->http, _file_serve_norange_cb);
  }

finish:
  return rc;
}

static iwrc _file_serve(struct ctx *ctx) {
  ctx->req->http->user_data = ctx;
  ctx->req->http->on_request_dispose = _on_request_dispose;
  if (IW_UNLIKELY(ctx->ranges)) {
    if (IW_UNLIKELY(ctx->ranges->next)) {
      return _file_serve_ranges_multiple(ctx);
    } else {
      return _file_serve_range_single(ctx);
    }
  } else {
    return _file_serve_norange(ctx);
  }
}

int iwn_wf_file_serve(struct iwn_wf_req *req, const char *ctype, const char *path) {
  iwrc rc = 0;
  int ret = 0;
  struct ctx *ctx;

  RCA(ctx = calloc(1, sizeof(*ctx)), finish);
  ctx->req = req;
  rc = iwp_fstat(path, &ctx->fs);
  if (rc || ctx->fs.ftype != IWP_TYPE_FILE) {
    rc = 0;
    goto finish;
  }

  if (ctype && *ctype != '\0') {
    strncpy(ctx->ctype, ctype, sizeof(ctx->ctype));
    ctx->ctype[sizeof(ctx->ctype) - 1] = '\0';
  } else {
    memcpy(ctx->ctype, "application/octet-stream", sizeof("application/octet-stream"));
  }

  struct iwn_pair pv = iwn_wf_header_part_find(req, "range", "bytes");
  if (ctx->fs.size > 0 && pv.val_len) { // Use ranges only for non-empty files
    if (!_ranges_parse(ctx, pv.val, pv.val + pv.val_len)) {
      ret = 416; // Bad ranges
      goto finish;
    }
  } else {
    char etag[64];
    size_t etag_len = _etag_fill(ctx, etag);
    RCC(rc, finish, iwn_http_response_header_set(req->http, "etag", etag, etag_len));
    struct iwn_val val = iwn_http_request_header_get(req->http, "if-none-match", IW_LLEN("if-none-match"));
    if (val.len == etag_len && strncmp(val.buf, etag, etag_len) == 0) {
      ret = 304; // Not modified
      goto finish;
    }
  }
  RCC(rc, finish, iwn_http_response_header_set(req->http, "accept-ranges", "bytes", IW_LLEN("bytes")));

  ctx->file = fopen(path, "r");
  if (!ctx->file) {
    goto finish;
  }

  RCC(rc, finish, _file_serve(ctx));
  ret = 1; // We handled this request

finish:
  if (rc) {
    ret = -1;
  }
  if (ret != 1) {
    _ctx_destroy(ctx);
  }
  return ret;
}
