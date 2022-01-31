#include "wf_files.h"

#include <iowow/iwp.h>
#include <iowow/iwlog.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define BOUNDARY_LEN 32

struct range {
  int start;
  int end;
  int pos; // Position winin a range
  struct range *next;
};

struct ctx {
  FILE *file;
  struct range *ranges;
  IWP_FILE_STAT fs;
  char boundary[BOUNDARY_LEN];
  char ctype[128];
};

static void _ctx_destroy(struct ctx *ctx) {
  if (ctx) {
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

static iwrc _ranges_parse(struct ctx *ctx, const char *ranges, const char *ep) {
  iwrc rc = 0;

  return rc;
}

static iwrc _boundary_fill(char fout[BOUNDARY_LEN]) {
  static const char cset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  FILE *f = fopen("/dev/urandom", "r");
  if (!f) {
    return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
  }
  if (fread(fout, BOUNDARY_LEN, 1, f) != 1) {
    fclose(f);
    return iwrc_set_errno(IW_ERROR_IO_ERRNO, errno);
  }
  fclose(f);
  for (int i = 0; i < BOUNDARY_LEN; ++i) {
    fout[i] = cset[fout[i] % (sizeof(cset) - 1)];
  }
  return 0;
}

IW_INLINE void _etag_fill(struct ctx *ctx, char fount[64]) {
  snprintf(fount, 64, "%04X-%04X",
           (int32_t) ctx->fs.size, (int32_t) ctx->fs.mtime);
}

int iwn_wf_files_serve(struct iwn_wf_req *req, const char *ctype, const char *path) {
  iwrc rc = 0;
  int ret = 0;

  char etag[64];
  struct ctx *ctx;

  RCA(ctx = calloc(1, sizeof(*ctx)), finish);
  rc = iwp_fstat(path, &ctx->fs);
  if (rc || ctx->fs.ftype != IWP_TYPE_FILE) {
    goto finish;
  }
  _etag_fill(ctx, etag);
  size_t etag_len = strlen(etag);

  struct iwn_val val = iwn_http_request_header_get(req->http, "range", IW_LLEN("range"));
  if (val.len) {
    RCC(rc, finish, _ranges_parse(ctx, val.buf, val.buf + val.len));
  }
  if (ctype) {
    strncpy(ctx->ctype, ctype, strlen(ctype));
    ctx->ctype[sizeof(ctx->ctype) - 1] = '\0';
  }

  RCC(rc, finish, iwn_http_response_header_set(req->http, "accept-ranges", "bytes", IW_LLEN("bytes")));
  RCC(rc, finish, iwn_http_response_header_set(req->http, "etag", etag, etag_len));

  if (ctx->ranges == 0) {
    val = iwn_http_request_header_get(req->http, "if-none-match", IW_LLEN("if-none-match"));
    if (val.len == etag_len && strncmp(val.buf, etag, etag_len) == 0) {
      _ctx_destroy(ctx);
      if (iwn_http_response_write(req->http, 304, ctx->ctype, 0, 0)) {
        return 1;
      } else {
        return -1;
      }
    }
  } else if (ctx->ranges->next) { // We have multiple ranges
    RCC(rc, finish, _boundary_fill(ctx->boundary));
  }

  ctx->file = fopen(path, "r");
  if (!ctx->file) {
    goto finish;
  }

finish:
  if (rc || ret == 0) {
    _ctx_destroy(ctx);
  }
  return ret;
}

struct iwn_wf_route* iwn_wf_files_attach(
  struct iwn_wf_route            *route,
  const struct iwn_wf_files_spec *spec_
  ) {
  // TODO:


  return route;
}
