#pragma once

#include "iwn_wf.h"

#include <iowow/iwlog.h>
#include <iowow/iwxstr.h>
#include <iowow/iwarr.h>
#include <iowow/iwconv.h>

#include <curl/curl.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

IW_EXTERN_C_START

// Curl return code check
#define XCC(cc_, label_, op_)               \
  cc_ = op_;                                \
  if (cc_) {                                \
    iwlog_error2(curl_easy_strerror(cc_));  \
    rc = WF_ERROR_CURL_API;                 \
    goto label_;                            \
  }

#define XUCC(cc_, label_, op_)              \
  cc_ = xcurlcode(op_);                     \
  if (cc_) {                                \
    iwlog_error2(curl_easy_strerror(cc_));  \
    rc = WF_ERROR_CURL_API;                 \
    goto label_;                            \
  }

struct xcurl_cursor {
  const char *rp;
  const char *end;
};

#define XCURLREQ_POST 0x01U
#define XCURLREQ_PUT  0x02U
#define XCURLREQ_DEL  0x04U
#define XCURLREQ_JSON 0x08U
#define XCURLREQ_HEAD 0x10U
#define XCURLREQ_OPTS 0x20U

struct xcurlreq {
  const char *path;
  const char *qs;
  const char *payload;
  size_t      payload_len;
  struct curl_slist *headers;
  IWXSTR  *_xstr;
  IWXSTR  *_qxstr;
  uint64_t flags;
};

static CURLcode xcurlcode(CURLUcode uc) {
  switch (uc) {
    case CURLUE_OK:
      return CURLE_OK;
    case CURLUE_UNSUPPORTED_SCHEME:
      return CURLE_UNSUPPORTED_PROTOCOL;
    case CURLUE_OUT_OF_MEMORY:
      return CURLE_OUT_OF_MEMORY;
    case CURLUE_USER_NOT_ALLOWED:
      return CURLE_LOGIN_DENIED;
    default:
      return CURLE_URL_MALFORMAT;
  }
}

static size_t xcurl_read_cursor(char *buffer, size_t size, size_t nitems, void *op) {
  struct xcurl_cursor *dcur = op;
  ssize_t avail = dcur->end - dcur->rp;
  ssize_t toread = size * nitems;
  if (toread > avail) {
    toread = avail;
  }
  memcpy(buffer, dcur->rp, toread);
  dcur->rp += toread;
  return toread;
}

static size_t xcurl_body_write_xstr(void *contents, size_t size, size_t nmemb, void *op) {
  IWXSTR *xstr = op;
  if (!xstr) {
    return 0;
  }
  if (iwxstr_cat(xstr, contents, size * nmemb)) {
    return 0;
  }
  return size * nmemb;
}

static size_t xcurl_hdr_write_iwlist(char *buffer, size_t size, size_t nmemb, void *op) {
  if (strchr(buffer, ':') == 0) {
    return size * nmemb;
  }
  IWLIST *headers = op;
  size_t sz = size * nmemb;
  iwrc rc = iwlist_push(headers, buffer, sz);
  if (rc) {
    iwlog_ecode_error3(rc);
    return 0;
  }
  locale_t lc = newlocale(LC_CTYPE_MASK, "C", 0);
  if (lc == 0) {
    return 0;
  }
  int i = 0;
  char *wp = iwlist_at2(headers, iwlist_length(headers) - 1, &sz);
  for ( ; i < sz && wp[i] != ':'; ++i) {
    wp[i] = (char) tolower_l(wp[i], lc);
  }
  for (i = (int) strlen(wp) - 1; i >= 0 && isspace_l(wp[i], lc); --i) {
    wp[i] = '\0';
  }
  freelocale(lc);
  return size * nmemb;
}

static const char* xcurl_hdr_find(const char *name, IWLIST *headers) {
  const char *ret = 0;
  locale_t lc = newlocale(LC_CTYPE_MASK, "C", 0);
  if (lc == 0) {
    return 0;
  }
  for (int i = 0, l = iwlist_length(headers); i < l && !ret; ++i) {
    const char *hp = name;
    const char *rp = iwlist_at2(headers, i, 0);
    for ( ; *rp; ++rp, ++hp) {
      if ((*rp == ':') && (*hp == '\0')) {
        ++rp;
        while (*rp && isblank_l(*rp, lc)) ++rp;
        ret = rp;
        break;
      } else if (*rp != *hp) {
        break;
      }
      if (*hp == '\0') {
        break;
      }
    }
  }
  if (lc != 0) {
    freelocale(lc);
  }
  return ret;
}

static iwrc xcurlreq_query_add(
  CURL *curl,
  struct xcurlreq *data, const char *name, size_t name_len,
  const char *value, size_t value_len) {

  if (!data || !name || !value) {
    return IW_ERROR_INVALID_ARGS;
  }
  if (name_len == (size_t) -1) {
    name_len = strlen(name);
  }
  if (value_len == (size_t) -1) {
    value_len = strlen(value);
  }

  iwrc rc = 0;
  char *aname = 0, *avalue = 0;
  if (!data->_qxstr) {
    RCA(data->_qxstr = iwxstr_new(), finish);
  }
  RCA(aname = curl_easy_escape(curl, name, name_len), finish);
  RCA(avalue = curl_easy_escape(curl, value, value_len), finish);
  if (iwxstr_size(data->_qxstr)) {
    RCC(rc, finish, iwxstr_cat2(data->_qxstr, "&"));
  }
  RCC(rc, finish, iwxstr_printf(data->_qxstr, "%s=%s", aname, avalue));
  data->qs = iwxstr_ptr(data->_qxstr);

finish:
  curl_free(aname);
  curl_free(avalue);
  return rc;
}

static iwrc xcurlreq_query_add_i64(
  CURL            *curl,
  struct xcurlreq *data,
  const char      *name,
  size_t           name_len,
  int64_t          value) {

  char buf[32];
  size_t len = iwitoa(value, buf, sizeof(buf));
  return xcurlreq_query_add(curl, data, name, name_len, buf, len);
}

static iwrc xcurlreq_add(
  CURL *curl,
  struct xcurlreq *data, const char *name, size_t name_len,
  const char *value, size_t value_len) {

  if (!data || !name || !value) {
    return IW_ERROR_INVALID_ARGS;
  }
  if (name_len == (size_t) -1) {
    name_len = strlen(name);
  }
  if (value_len == (size_t) -1) {
    value_len = strlen(value);
  }

  iwrc rc = 0;
  char *aname = 0, *avalue = 0;
  if (!data->_xstr) {
    RCA(data->_xstr = iwxstr_new(), finish);
  }
  RCA(aname = curl_easy_escape(curl, name, name_len), finish);
  RCA(avalue = curl_easy_escape(curl, value, value_len), finish);
  if (iwxstr_size(data->_xstr)) {
    RCC(rc, finish, iwxstr_cat2(data->_xstr, "&"));
  }
  RCC(rc, finish, iwxstr_printf(data->_xstr, "%s=%s", aname, avalue));
  data->payload = iwxstr_ptr(data->_xstr);
  data->payload_len = iwxstr_size(data->_xstr);

finish:
  curl_free(aname);
  curl_free(avalue);
  return rc;
}

static iwrc xcurlreq_add_i64(
  CURL            *curl,
  struct xcurlreq *data,
  const char      *name,
  size_t           name_len,
  int64_t          value) {

  char buf[32];
  size_t len = iwitoa(value, buf, sizeof(buf));
  return xcurlreq_add(curl, data, name, name_len, buf, len);
}

static void xcurlreq_hdr_add(
  struct xcurlreq *req,
  const char      *name,
  size_t           name_len,
  const char      *value,
  size_t           value_len) {

  if (name_len == (size_t) -1) {
    name_len = strlen(name);
  }
  if (value_len == (size_t) -1) {
    value_len = strlen(value);
  }
  char buf[name_len + value_len + 1 /* : */ + 1 /* 0 */];
  snprintf(buf, sizeof(buf), "%.*s:%.*s", (int) name_len, name, (int) value_len, value);
  req->headers = curl_slist_append(req->headers, buf);
}

static void xcurlreq_destroy_keep(struct xcurlreq *req) {
  if (!req) {
    return;
  }
  if (req->_xstr) {
    if (req->payload == iwxstr_ptr(req->_xstr)) {
      req->payload = 0;
      req->payload_len = 0;
    }
    iwxstr_destroy(req->_xstr);
    req->_xstr = 0;
  }
  if (req->_qxstr) {
    if (req->qs == iwxstr_ptr(req->_qxstr)) {
      req->qs = 0;
    }
    iwxstr_destroy(req->_qxstr);
    req->_qxstr = 0;
  }
  curl_slist_free_all(req->headers);
  req->headers = 0;
}

IW_EXTERN_C_END
