/*
 * HTTP protocol parser is based on https://github.com/jeremycw/httpserver.h MIT code.
 */

#include "http_server_internal.h"
#include "poller_adapter.h"
#include "poller/direct_poller_adapter.h"
#include "ssl/brssl_poller_adapter.h"

#include <iowow/iwlog.h>
#include <iowow/iwutils.h>
#include <iowow/iwpool.h>
#include <iowow/iwxstr.h>

#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <inttypes.h>

struct server {
  struct iwn_http_server      server;
  struct iwn_http_server_spec spec;
  long stime;  ///< Server time second since epoch.
  int  fd;
  int  refs;
  pthread_mutex_t mtx;
  IWPOOL *pool;
  char    stime_text[32]; ///< Formatted as: `%a, %d %b %Y %T GMT`
  volatile bool https;
};

struct token {
  int index;
  int len;
  int type;
};

struct tokens_buf {
  struct token *buf;
  ssize_t       capacity;
  ssize_t       size;
};

struct stream {
  char *buf;
  void  (*buf_free)(void*);
  struct token token;
  ssize_t      bytes_total;
  ssize_t      capacity;
  ssize_t      length;
  ssize_t      index;
  ssize_t      anchor;
  uint8_t      flags;
};

struct parser {
  ssize_t content_length;
  ssize_t body_consumed;
  int16_t match_index;
  int16_t header_count;
  int8_t  state;
  int8_t  meta;
};

struct header {
  char *name;
  char *value;
  struct header *next;
  bool exclude;
};

struct response {
  struct header *headers;
  IWPOOL     *pool;
  const char *body;
  void   (*body_free)(void*);
  size_t body_len;
  int    code;
};

struct client {
  struct iwn_http_req request;
  iwn_http_server_chunk_handler chunk_cb;
  IWPOOL *pool;
  iwn_on_poller_adapter_event injected_poller_evh;
  struct server    *server;
  struct tokens_buf tokens;
  struct stream     stream;
  struct parser     parser;
  struct response   response;

  // Web-framework implementation hooks (do not use these in app)
  // TODO: Review it
  void *_ws_data;
  void *_wf_data;
  void  (*_wf_on_request_dispose)(struct iwn_http_req*);
  void  (*_wf_on_response_headers_write)(struct iwn_http_req*);

  int     fd;
  uint8_t state;     ///< HTTP_SESSION_{INIT,READ,WRITE,NOP}
  uint8_t flags;     ///< HTTP_END_SESSION,HTTP_AUTOMATIC,HTTP_CHUNKED_RESPONSE
};

// stream flags
#define HS_SF_CONSUMED 0x01U

// parser flags
#define HS_PF_IN_CONTENT_LEN  0x01U
#define HS_PF_IN_TRANSFER_ENC 0x02U
#define HS_PF_CHUNKED         0x04U
#define HS_PF_CKEND           0x08U
#define HS_PF_REQ_END         0x10U

// http session states
#define HTTP_SESSION_INIT  0
#define HTTP_SESSION_READ  1
#define HTTP_SESSION_WRITE 2
#define HTTP_SESSION_NOP   3

// http session flags
#define HTTP_KEEP_ALIVE       0x01U
#define HTTP_STREAMED         0x02U
#define HTTP_END_SESSION      0x04U
#define HTTP_AUTOMATIC        0x08U
#define HTTP_CHUNKED_RESPONSE 0x10U
#define HTTP_STREAM_RESPONSE  0x20U
#define HTTP_UPGRADE          0x40U
#define HTTP_HAS_CONTENT_LEN  0x80U

// http version indicators
#define HTTP_1_0 0
#define HTTP_1_1 1

#define HS_META_NOT_CHUNKED  0
#define HS_META_NON_ZERO     0
#define HS_META_END_CHK_SIZE 1
#define HS_META_END_CHUNK    2
#define HS_META_NEXT         0

// *INDENT-OFF*
enum token_e {
  HS_TOK_NONE,        HS_TOK_METHOD,     HS_TOK_TARGET,     HS_TOK_VERSION,
  HS_TOK_HEADER_KEY,  HS_TOK_HEADER_VAL, HS_TOK_CHUNK_BODY, HS_TOK_BODY,
  HS_TOK_BODY_STREAM, HS_TOK_REQ_END,    HS_TOK_EOF,        HS_TOK_ERROR
};

enum char_type_e {
  HS_SPC,   HS_NL,  HS_CR,    HS_COLN,  HS_TAB,   HS_SCOLN,
  HS_DIGIT, HS_HEX, HS_ALPHA, HS_TCHAR, HS_VCHAR, HS_ETC,   HS_CHAR_TYPE_LEN
};

enum meta_state_e {
  M_WFK, M_ANY, M_MTE, M_MCL, M_CLV, M_MCK, M_SML, M_CHK, M_BIG, M_ZER, M_CSZ,
  M_CBD, M_LST, M_STR, M_SEN, M_BDY, M_END, M_ERR
};

enum meta_type_e {
  HS_META_NOT_CONTENT_LEN, HS_META_NOT_TRANSFER_ENC, HS_META_END_KEY,
  HS_META_END_VALUE,       HS_META_END_HEADERS,      HS_META_LARGE_BODY,
  HS_META_TYPE_LEN
};

enum state_e {
  ST, MT, MS, TR, TS, VN, RR, RN, HK, HS, HV, HR, HE,
  ER, HN, BD, CS, CB, CE, CR, CN, CD, C1, C2, BR, HS_STATE_LEN
};

static const int8_t _transitions[] = {
//                                            A-Z G-Z
//                spc \n  \r  :   \t  ;   0-9 a-f g-z tch vch etc
/* ST start */    BR, BR, BR, BR, BR, BR, BR, MT, MT, MT, BR, BR,
/* MT method */   MS, BR, BR, BR, BR, BR, MT, MT, MT, MT, BR, BR,
/* MS methodsp */ BR, BR, BR, BR, BR, BR, TR, TR, TR, TR, TR, BR,
/* TR target */   TS, BR, BR, TR, BR, TR, TR, TR, TR, TR, TR, BR,
/* TS targetsp */ BR, BR, BR, BR, BR, BR, VN, VN, VN, VN, VN, BR,
/* VN version */  BR, BR, RR, BR, BR, BR, VN, VN, VN, VN, VN, BR,
/* RR rl \r */    BR, RN, BR, BR, BR, BR, BR, BR, BR, BR, BR, BR,
/* RN rl \n */    BR, BR, BR, BR, BR, BR, HK, HK, HK, HK, BR, BR,
/* HK headkey */  BR, BR, BR, HS, BR, BR, HK, HK, HK, HK, BR, BR,
/* HS headspc */  HS, HS, HS, HV, HS, HV, HV, HV, HV, HV, HV, BR,
/* HV headval */  HV, BR, HR, HV, HV, HV, HV, HV, HV, HV, HV, BR,
/* HR head\r */   BR, HE, BR, BR, BR, BR, BR, BR, BR, BR, BR, BR,
/* HE head\n */   BR, BR, ER, BR, BR, BR, HK, HK, HK, HK, BR, BR,
/* ER hend\r */   BR, HN, BR, BR, BR, BR, BR, BR, BR, BR, BR, BR,
/* HN hend\n */   BD, BD, BD, BD, BD, BD, BD, BD, BD, BD, BD, BD,
/* BD body */     BD, BD, BD, BD, BD, BD, BD, BD, BD, BD, BD, BD,
/* CS chksz */    BR, BR, CR, BR, BR, CE, CS, CS, BR, BR, BR, BR,
/* CB chkbd */    CB, CB, CB, CB, CB, CB, CB, CB, CB, CB, CB, CB,
/* CE chkext */   BR, BR, CR, CE, CE, CE, CE, CE, CE, CE, CE, BR,
/* CR chksz\r */  BR, CN, BR, BR, BR, BR, BR, BR, BR, BR, BR, BR,
/* CN chksz\n */  CB, CB, CB, CB, CB, CB, CB, CB, CB, CB, CB, CB,
/* CD chkend */   BR, BR, C1, BR, BR, BR, BR, BR, BR, BR, BR, BR,
/* C1 chkend\r */ BR, C2, BR, BR, BR, BR, BR, BR, BR, BR, BR, BR,
/* C2 chkend\n */ BR, BR, BR, BR, BR, BR, CS, CS, BR, BR, BR, BR
};

static const int8_t _meta_transitions[] = {
//                 no chk
//                 not cl not te endkey endval end h  toobig
/* WFK wait */     M_WFK, M_WFK, M_WFK, M_ANY, M_END, M_ERR,
/* ANY matchkey */ M_MTE, M_MCL, M_WFK, M_ERR, M_END, M_ERR,
/* MTE matchte */  M_MTE, M_WFK, M_MCK, M_ERR, M_ERR, M_ERR,
/* MCL matchcl */  M_WFK, M_MCL, M_CLV, M_ERR, M_ERR, M_ERR,
/* CLV clvalue */  M_ERR, M_ERR, M_ERR, M_SML, M_ERR, M_ERR,
/* MCK matchchk */ M_WFK, M_ERR, M_ERR, M_CHK, M_ERR, M_ERR,
/* SML smallbdy */ M_SML, M_SML, M_SML, M_SML, M_BDY, M_BIG,
/* CHK chunkbdy */ M_CHK, M_CHK, M_CHK, M_CHK, M_ZER, M_ERR,
/* BIG bigbody */  M_BIG, M_BIG, M_BIG, M_BIG, M_STR, M_ERR,

//                         *** chunked body ***

//                 nonzer endsz  endchk
/* ZER zerochk */  M_CSZ, M_LST, M_ERR, M_ERR, M_ERR, M_ERR,
/* CSZ chksize */  M_CSZ, M_CBD, M_ERR, M_ERR, M_ERR, M_ERR,
/* CBD readchk */  M_CBD, M_CBD, M_ZER, M_ERR, M_ERR, M_ERR,
/* LST lastchk */  M_LST, M_END, M_END, M_ERR, M_ERR, M_ERR,

//                         *** streamed body ***

//                 next
/* STR readstr */  M_SEN, M_ERR, M_ERR, M_ERR, M_ERR, M_ERR,
/* SEN strend */   M_END, M_ERR, M_ERR, M_ERR, M_ERR, M_ERR,

//                         *** small body ***

//                 next
/* BDY readbody */ M_END, M_ERR, M_ERR, M_ERR, M_ERR, M_ERR,
/* END reqend */   M_WFK, M_ERR, M_ERR, M_ERR, M_ERR, M_ERR
};

static const int8_t _ctype[] = {
  HS_ETC,   HS_ETC,   HS_ETC,   HS_ETC,   HS_ETC,   HS_ETC,   HS_ETC,
  HS_ETC,   HS_ETC,   HS_TAB,   HS_NL,    HS_ETC,   HS_ETC,   HS_CR,
  HS_ETC,   HS_ETC,   HS_ETC,   HS_ETC,   HS_ETC,   HS_ETC,   HS_ETC,
  HS_ETC,   HS_ETC,   HS_ETC,   HS_ETC,   HS_ETC,   HS_ETC,   HS_ETC,
  HS_ETC,   HS_ETC,   HS_ETC,   HS_ETC,   HS_SPC,   HS_TCHAR, HS_VCHAR,
  HS_TCHAR, HS_TCHAR, HS_TCHAR, HS_TCHAR, HS_TCHAR, HS_VCHAR, HS_VCHAR,
  HS_TCHAR, HS_TCHAR, HS_TCHAR, HS_TCHAR, HS_TCHAR, HS_VCHAR, HS_DIGIT,
  HS_DIGIT, HS_DIGIT, HS_DIGIT, HS_DIGIT, HS_DIGIT, HS_DIGIT, HS_DIGIT,
  HS_DIGIT, HS_DIGIT, HS_COLN,  HS_SCOLN, HS_VCHAR, HS_VCHAR, HS_VCHAR,
  HS_VCHAR, HS_VCHAR, HS_HEX,   HS_HEX,   HS_HEX,   HS_HEX,   HS_HEX,
  HS_HEX,   HS_ALPHA, HS_ALPHA, HS_ALPHA, HS_ALPHA, HS_ALPHA, HS_ALPHA,
  HS_ALPHA, HS_ALPHA, HS_ALPHA, HS_ALPHA, HS_ALPHA, HS_ALPHA, HS_ALPHA,
  HS_ALPHA, HS_ALPHA, HS_ALPHA, HS_ALPHA, HS_ALPHA, HS_ALPHA, HS_ALPHA,
  HS_VCHAR, HS_VCHAR, HS_VCHAR, HS_TCHAR, HS_TCHAR, HS_TCHAR, HS_HEX,
  HS_HEX,   HS_HEX,   HS_HEX,   HS_HEX,   HS_HEX,   HS_ALPHA, HS_ALPHA,
  HS_ALPHA, HS_ALPHA, HS_ALPHA, HS_ALPHA, HS_ALPHA, HS_ALPHA, HS_ALPHA,
  HS_ALPHA, HS_ALPHA, HS_ALPHA, HS_ALPHA, HS_ALPHA, HS_ALPHA, HS_ALPHA,
  HS_ALPHA, HS_ALPHA, HS_ALPHA, HS_ALPHA, HS_VCHAR, HS_TCHAR, HS_VCHAR,
  HS_TCHAR, HS_ETC
};

static int8_t const _token_start_states[] = {
//ST MT             MS TR             TS VN              RR RN HK
  0, HS_TOK_METHOD, 0, HS_TOK_TARGET, 0, HS_TOK_VERSION, 0, 0, HS_TOK_HEADER_KEY,
//HS HV                 HR HE ER HN BD           CS CB                 CE CR CN
  0, HS_TOK_HEADER_VAL, 0, 0, 0, 0, HS_TOK_BODY, 0, HS_TOK_CHUNK_BODY, 0, 0, 0,
//CD C1 C2
  0, 0, 0,
};

static char const *_status_text[] = {
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",

  //100s
  "Continue", "Switching Protocols", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",

  //200s
  "OK", "Created", "Accepted", "Non-Authoritative Information", "No Content",
  "Reset Content", "Partial Content", "", "", "",

  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",

  //300s
  "Multiple Choices", "Moved Permanently", "Found", "See Other", "Not Modified",
  "Use Proxy", "", "Temporary Redirect", "", "",

  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",

  //400s
  "Bad Request", "Unauthorized", "Payment Required", "Forbidden", "Not Found",
  "Method Not Allowed", "Not Acceptable", "Proxy Authentication Required",
  "Request Timeout", "Conflict",

  "Gone", "Length Required", "", "Payload Too Large", "", "", "", "", "", "",

  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",

  //500s
  "Internal Server Error", "Not Implemented", "Bad Gateway", "Service Unavailable",
  "Gateway Timeout", "", "", "", "", "",

  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", "",
  "", "", "", "", "", "", "", "", "", ""
};
// *INDENT-ON*

static iwrc _server_ref(struct server *server, struct server **out);
static void _server_unref(struct server *server);

static void _noop_free(void *ptr) {
  ;
}

static void _server_time(struct server *server, char out_buf[32]) {
  static_assert(sizeof(server->stime_text) == 32, "sizeof(server->stime) == 32");
  time_t rawtime;
  time(&rawtime);
  pthread_mutex_lock(&server->mtx);
  if (server->stime != rawtime) {
    server->stime = rawtime;
    struct tm *timeinfo = gmtime(&rawtime);
    if (timeinfo) {
      strftime(server->stime_text, sizeof(server->stime_text), "%a, %d %b %Y %T %Z", timeinfo);
    } else {
      out_buf[0] = '\0';
    }
  }
  memcpy(out_buf, server->stime_text, sizeof(server->stime_text));
  pthread_mutex_unlock(&server->mtx);
}

IW_INLINE void _stream_free_buffer(struct client *client) {
  if (IW_UNLIKELY(client->stream.buf_free)) {
    client->stream.buf_free(client->stream.buf);
  } else {
    free(client->stream.buf);
  }
  memset(&client->stream, 0, sizeof(client->stream));
}

IW_INLINE void _tokens_free_buffer(struct client *client) {
  if (client->tokens.buf) {
    free(client->tokens.buf);
  }
  memset(&client->tokens, 0, sizeof(client->tokens));
}

IW_INLINE void _request_data_free(struct client *client) {
  if (client->request.on_request_dispose) {
    client->request.on_request_dispose(&client->request);
    client->request.on_request_dispose = 0;
  }
  if (client->_wf_on_request_dispose) {
    client->_wf_on_request_dispose(&client->request);
    client->_wf_on_request_dispose = 0;
  }
  client->_wf_data = 0;
  client->_ws_data = 0;
  client->request.user_data = 0;
  client->request.user_flags = 0;
}

static bool _stream_next(struct stream *stream, char *c) {
  stream->flags &= ~HS_SF_CONSUMED;
  if (stream->index >= stream->length) {
    return false;
  }
  *c = stream->buf[stream->index];
  return true;
}

static void _stream_consume(struct stream *stream) {
  if (stream->flags & HS_SF_CONSUMED) {
    return;
  }
  stream->flags |= HS_SF_CONSUMED;
  stream->index++;
  int nlen = stream->token.len + 1;
  stream->token.len = stream->token.type ? nlen : 0;
}

static void _stream_shift(struct stream *stream) {
  if (stream->token.index == stream->anchor) {
    return;
  }
  if (stream->token.len > 0) {
    char *dst = stream->buf + stream->anchor;
    char *src = stream->buf + stream->token.index;
    ssize_t bytes = stream->length - stream->token.index;
    memcpy(dst, src, bytes);
  }
  stream->token.index = stream->anchor;
  stream->index = stream->anchor + stream->token.len;
  stream->length = stream->index;
}

IW_INLINE void _stream_anchor(struct stream *stream) {
  stream->anchor = stream->index;
}

IW_INLINE void _stream_begin_token(struct stream *stream, int token_type) {
  stream->token.type = token_type;
  stream->token.index = stream->index;
}

IW_INLINE struct token _stream_emit(struct stream *stream) {
  struct token token = stream->token;
  memset(&stream->token, 0, sizeof(stream->token));
  return token;
}

IW_INLINE bool _stream_can_contain(struct client *client, int64_t size) {
  return client->server->spec.request_buf_max_size - client->stream.index + 1 >= size;
}

static bool _stream_jump(struct stream *stream, int offset) {
  stream->flags |= HS_SF_CONSUMED;
  if (stream->index + offset > stream->length) {
    return false;
  }
  stream->index += offset;
  int nlen = stream->token.len + offset;
  stream->token.len = stream->token.type == 0 ? 0 : nlen;
  return true;
}

static ssize_t _stream_jumpall(struct stream *stream) {
  stream->flags |= HS_SF_CONSUMED;
  ssize_t offset = stream->length - stream->index;
  stream->index += offset;
  int nlen = (int) (stream->token.len + offset);
  stream->token.len = stream->token.type == 0 ? 0 : nlen;
  return offset;
}

///////////////////////////////////////////////////////////////////////////
//								              Client                                   //
///////////////////////////////////////////////////////////////////////////

IW_INLINE void _response_body_free(struct response *response) {
  if (response->body) {
    if (response->body_free) {
      response->body_free((void*) response->body);
      response->body_free = 0;
    }
    response->body = 0;
  }
}

IW_INLINE void _response_free(struct client *client) {
  struct response *response = &client->response;
  if (response->pool) {
    iwpool_destroy(response->pool);
    response->pool = 0;
  }
  _response_body_free(response);
  response->headers = 0;
  response->code = 200;
}

static bool _client_response_error(struct client *client, int code, char *response) {
  return iwn_http_response_write(&client->request, code, "text/plain", response, -1);
}

static void _client_reset(struct client *client) {
  client->state = HTTP_SESSION_INIT;
  _request_data_free(client);
  _stream_free_buffer(client);
  _tokens_free_buffer(client);
  _response_free(client);
}

static void _client_destroy(struct client *client) {
  if (!client) {
    return;
  }
  _client_reset(client);
  if (client->server) {
    _server_unref(client->server);
  }
  iwpool_destroy(client->pool);
}

static iwrc _client_init(struct client *client) {
  iwrc rc = 0;
  _client_reset(client);
  client->flags = HTTP_AUTOMATIC;
  memset(&client->parser, 0, sizeof(client->parser));
  client->chunk_cb = 0;
  client->tokens.capacity = 32;
  client->tokens.size = 0;
  client->tokens.buf = malloc(sizeof(client->tokens.buf[0]) * client->tokens.capacity);
  if (!client->tokens.buf) {
    client->tokens.capacity = 0;
    rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);
    goto finish;
  }
  if (client->server->spec.request_timeout_sec > 0) {
    iwn_poller_set_timeout(client->server->spec.poller, client->fd, client->server->spec.request_timeout_sec);
  }

finish:
  return rc;
}

IW_INLINE bool _client_write_bytes(struct client *client) {
  struct iwn_poller_adapter *pa = client->request.poller_adapter;
  struct stream *stream = &client->stream;
  if (stream->length > stream->bytes_total) {
    ssize_t bytes = pa->write(pa,
                              (uint8_t*) stream->buf + stream->bytes_total,
                              stream->length - stream->bytes_total);
    if (bytes > 0) {
      stream->bytes_total += bytes;
    }
    return errno != EPIPE;
  } else {
    return true;
  }
}

static void _client_write(struct client *client) {
  iwrc rc = 0;
  struct stream *stream = &client->stream;
  struct iwn_poller_adapter *pa = client->request.poller_adapter;

again:
  if (!_client_write_bytes(client)) {
    client->flags |= HTTP_END_SESSION;
    return;
  }
  if (stream->bytes_total != stream->length) {
    rc = iwn_poller_arm_events(client->server->spec.poller, client->fd, IWN_POLLOUT);
  } else if (pa->has_pending_write_bytes && pa->has_pending_write_bytes(pa)) {
    ; // NOOP
  } else if (client->flags & (HTTP_CHUNKED_RESPONSE | HTTP_STREAM_RESPONSE)) {
    _stream_free_buffer(client);
    if (client->server->spec.request_timeout_sec > 0) {
      iwn_poller_set_timeout(client->server->spec.poller, client->fd, client->server->spec.request_timeout_sec);
    }
    bool again = false;
    if (!client->chunk_cb || !client->chunk_cb((void*) client, &again)) {
      client->flags |= HTTP_END_SESSION;
    } else if (again) {
      goto again;
    }
  } else {
    bool (*on_response_completed)(struct iwn_http_req*) = client->request.on_response_completed;
    if (IW_UNLIKELY(on_response_completed)) {
      client->request.on_response_completed = 0;
      if (!on_response_completed(&client->request)) {
        client->flags |= HTTP_END_SESSION;
      }
    } else if (client->flags & HTTP_KEEP_ALIVE) {
      if (client->server->spec.request_timeout_keepalive_sec > 0) {
        iwn_poller_set_timeout(client->server->spec.poller, client->fd,
                               client->server->spec.request_timeout_keepalive_sec);
      }
      _client_reset(client);
    } else {
      client->flags |= HTTP_END_SESSION;
    }
  }

  if (rc) {
    iwlog_ecode_error3(rc);
    client->flags |= HTTP_END_SESSION;
  }
}

static bool _client_read_bytes(struct client *client) {
  struct iwn_poller_adapter *pa = client->request.poller_adapter;
  struct stream *stream = &client->stream;
  struct server *server = client->server;
  if (stream->index < stream->length) {
    return true;
  }
  if (!stream->buf) {
    stream->length = 0;
    stream->capacity = 0;
    stream->buf = malloc(server->spec.request_buf_size + 1 /* \0 */);
    if (!stream->buf) {
      return false;
    }
    stream->capacity = server->spec.request_buf_size;
  }
  ssize_t bytes;
  do {
    bytes = pa->read(pa, (uint8_t*) stream->buf + stream->length, stream->capacity - stream->length);
    if (bytes > 0) {
      stream->length += bytes;
      stream->bytes_total += bytes;
    }
    if (stream->length == stream->capacity) {
      if (stream->capacity != server->spec.request_buf_max_size) {
        ssize_t ncap = stream->capacity * 2;
        if (ncap > server->spec.request_buf_max_size) {
          ncap = server->spec.request_buf_max_size;
        }
        char *nbuf = realloc(stream->buf, ncap + 1 /* \0 */);
        if (!nbuf) {
          bytes = 0;
          break;
        }
        stream->capacity = ncap;
        stream->buf = nbuf;
      } else {
        break;
      }
    }
  } while (bytes > 0);

  return bytes != 0;
}

IW_INLINE void _meta_trigger(struct parser *parser, int event) {
  int8_t to = _meta_transitions[parser->meta * HS_META_TYPE_LEN + event];
  parser->meta = to;
}

struct token _meta_emit_token(struct parser *parser) {
  struct token token = { 0 };
  switch (parser->meta) {
    case M_SEN:
      token.type = HS_TOK_CHUNK_BODY;
      _meta_trigger(parser, HS_META_NEXT);
      break;
    case M_END:
      token.type = HS_TOK_REQ_END;
      memset(parser, 0, sizeof(*parser));
      break;
  }
  return token;
}

struct token _transition(struct client *client, char c, int8_t from, int8_t to) {
  struct server *server = client->server;
  struct parser *parser = &client->parser;
  struct stream *stream = &client->stream;
  struct token emitted = { 0 };

  if (from == HN) {
    _stream_anchor(stream);
  }
  if (from != to) {
    int8_t type = _token_start_states[to];
    if (type != HS_TOK_NONE) {
      _stream_begin_token(stream, type);
    }
    if (from == CS) {
      _meta_trigger(parser, HS_META_END_CHK_SIZE);
    }
    if (to == HK) {
      ++parser->header_count;
      if (parser->header_count > server->spec.request_max_headers_count) {
        emitted.type = HS_TOK_ERROR;
      }
    } else if (to == HS) {
      _meta_trigger(parser, HS_META_END_KEY);
      emitted = _stream_emit(stream);
    }
    parser->match_index = 0;
  }

  char low, m = '\0';
  int in_bounds = 0;
  ssize_t body_left = 0;

#define MATCH(str__, meta__) \
  in_bounds = parser->match_index < (int) sizeof(str__) - 1; \
  m = in_bounds ? str__[parser->match_index] : m; \
  low = c >= 'A' && c <= 'Z' ? c + 32 : c; \
  if (low != m) _meta_trigger(parser, meta__)

  switch (to) {
    case MS:
    case TS:
      emitted = _stream_emit(stream);
      break;
    case RR:
    case HR:
      _meta_trigger(parser, HS_META_END_VALUE);
      emitted = _stream_emit(stream);
      break;
    case HK:
      MATCH("transfer-encoding", HS_META_NOT_TRANSFER_ENC);
      MATCH("content-length", HS_META_NOT_CONTENT_LEN);
      parser->match_index++;
      break;
    case HV:
      if (parser->meta == M_MCK) {
        MATCH("chunked", HS_META_NOT_CHUNKED);
        parser->match_index++;
      } else if (parser->meta == M_CLV) {
        parser->content_length *= 10;
        parser->content_length += c - '0';
      }
      break;
    case HN:
      if (parser->meta == M_SML && !_stream_can_contain(client, parser->content_length)) {
        _meta_trigger(parser, HS_META_LARGE_BODY);
      }
      if (parser->meta == M_BIG || parser->meta == M_CHK) {
        emitted.type = HS_TOK_BODY_STREAM;
      }
      _meta_trigger(parser, HS_META_END_HEADERS);
      if (parser->content_length == 0 && parser->meta == M_BDY) {
        parser->meta = M_END;
      }
      if (parser->meta == M_END) {
        emitted.type = HS_TOK_BODY;
      }
      break;
    case CS:
      if (c != '0') {
        _meta_trigger(parser, HS_META_NON_ZERO);
      }
      if (c >= 'A' && c <= 'F') {
        parser->content_length *= 0x10;
        parser->content_length += c - 55;
      } else if (c >= 'a' && c <= 'f') {
        parser->content_length *= 0x10;
        parser->content_length += c - 87;
      } else if (c >= '0' && c <= '9') {
        parser->content_length *= 0x10;
        parser->content_length += c - '0';
      }
      break;
    case CB:
    case BD:
      if (parser->meta == M_STR) {
        _stream_begin_token(stream, HS_TOK_CHUNK_BODY);
      }
      body_left = parser->content_length - parser->body_consumed;
      if (_stream_jump(stream, body_left)) {
        emitted = _stream_emit(stream);
        _meta_trigger(parser, HS_META_NEXT);
        if (to == CB) {
          parser->state = CD;
        }
        parser->content_length = 0;
        parser->body_consumed = 0;
      } else {
        parser->body_consumed += _stream_jumpall(stream);
        if (parser->meta == M_STR) {
          emitted = _stream_emit(stream);
          _stream_shift(stream);
        }
      }
      break;
    case C2:
      _meta_trigger(parser, HS_META_END_CHUNK);
      break;
    case BR:
      emitted.type = HS_TOK_ERROR;
      break;
  }
#undef MATCH

  return emitted;
}

struct token _token_parse(struct client *client) {
  struct server *server = client->server;
  struct parser *parser = &client->parser;
  struct stream *stream = &client->stream;
  struct token token = _meta_emit_token(parser);

  if (token.type != HS_TOK_NONE) {
    return token;
  }

  char c = 0;
  while (_stream_next(stream, &c)) {
    int8_t type = c < 0 ? HS_ETC : _ctype[(size_t) c];
    int8_t to = _transitions[parser->state * HS_CHAR_TYPE_LEN + type];
    if (parser->meta == M_ZER && parser->state == HN && to == BD) {
      to = CS;
    }
    int8_t from = parser->state;
    parser->state = to;
    struct token emitted = _transition(client, c, from, to);
    _stream_consume(stream);
    if (emitted.type != HS_TOK_NONE) {
      return emitted;
    }
  }
  if (parser->state == CB) {
    _stream_shift(stream);
  }
  token = _meta_emit_token(parser);
  struct token *ct = &stream->token;
  if (  ct->type != HS_TOK_CHUNK_BODY
     && ct->type != HS_TOK_BODY
     && ct->len > server->spec.request_token_max_len) {
    token.type = HS_TOK_ERROR;
  }
  return token;
}

static struct iwn_val _token_get_string(struct client *client, int token_type) {
  struct iwn_val ret = { 0 };
  if (client->tokens.buf == 0) {
    return ret;
  }
  for (int i = 0; i < client->tokens.size; ++i) {
    struct token token = client->tokens.buf[i];
    if (token.type == token_type) {
      ret.buf = &client->stream.buf[token.index];
      ret.len = token.len;
      return ret;
    }
  }
  return ret;
}

static void _client_read(struct client *client) {
  struct token token;

again:
  client->state = HTTP_SESSION_READ;
  if (client->server->spec.request_timeout_sec > 0) {
    iwn_poller_set_timeout(client->server->spec.poller, client->fd, client->server->spec.request_timeout_sec);
  }
  if (!_client_read_bytes(client)) {
    client->flags |= HTTP_END_SESSION;
    return;
  }
  do {
    token = _token_parse(client);
    if (token.type != HS_TOK_NONE) {
      if (IW_UNLIKELY(client->tokens.size == client->tokens.capacity)) {
        ssize_t ncap = client->tokens.capacity * 2;
        struct token *nbuf = realloc(client->tokens.buf, ncap * sizeof(client->tokens.buf[0]));
        if (!nbuf) {
          client->flags |= HTTP_END_SESSION;
          return;
        }
        client->tokens.buf = nbuf;
        client->tokens.capacity = ncap;
      }
      client->tokens.buf[client->tokens.size++] = token;
    }
    switch (token.type) {
      case HS_TOK_ERROR:
        _client_response_error(client, 400, "Bad request");
        break;
      case HS_TOK_BODY:
        client->state = HTTP_SESSION_NOP;
        if (token.len > 0) {
          // We have allocated one extra byte behind client->stream-capacity
          client->stream.buf[token.index + token.len] = '\0';
        }
        if (!client->server->spec.request_handler(&client->request)) {
          client->flags |= HTTP_END_SESSION;
          return;
        }
        break;
      case HS_TOK_BODY_STREAM:
        client->state = HTTP_SESSION_NOP;
        client->flags |= HTTP_STREAMED;
        if (!client->server->spec.request_handler(&client->request)) {
          client->flags |= HTTP_END_SESSION;
          return;
        }
        break;
      case HS_TOK_CHUNK_BODY:
        client->state = HTTP_SESSION_NOP;
        bool again = false;
        if (!client->chunk_cb || !client->chunk_cb(&client->request, &again)) {
          client->flags |= HTTP_END_SESSION;
          return;
        } else if (again) {
          goto again;
        }
        break;
    }
  } while (token.type != HS_TOK_NONE && client->state == HTTP_SESSION_READ);
}

static int64_t _client_on_poller_adapter_event(struct iwn_poller_adapter *pa, void *user_data, uint32_t events) {
  struct client *client = user_data;

  if (client->request.poller_adapter != pa) {
    client->request.poller_adapter = pa;
  }
  if (client->injected_poller_evh) {
    return client->injected_poller_evh(pa, &client->request, events);
  }

  iwrc rc = 0;
  int64_t resp = 0;

  switch (client->state) {
    case HTTP_SESSION_INIT:
      RCC(rc, finish, _client_init(client));
      client->state = HTTP_SESSION_READ;
    // NOTE: Fallthrough
    case HTTP_SESSION_READ:
      _client_read(client);
      break;
    case HTTP_SESSION_WRITE:
      _client_write(client);
      break;
  }
  if (client->flags & HTTP_END_SESSION) {
    resp = -1;
  }

finish:
  if (rc) {
    iwlog_ecode_error3(rc);
    resp = -1;
  }
  return resp;
}

void iwn_http_inject_poller_events_handler(struct iwn_http_req *request, iwn_on_poller_adapter_event eh) {
  struct client *client = (void*) request;
  client->injected_poller_evh = eh;
}

static void _client_on_poller_adapter_dispose(struct iwn_poller_adapter *pa, void *user_data) {
  struct client *client = user_data;
  _client_destroy(client);
}

static iwrc _client_accept(struct server *server, int fd) {
  iwrc rc = 0;
  IWPOOL *pool = iwpool_create_empty();
  if (!pool) {
    rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);
    close(fd);
    return rc;
  }
  struct client *client = iwpool_calloc(sizeof(*client), pool);
  if (!client) {
    rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);
    goto finish;
  }
  client->pool = pool;
  client->fd = fd;
  RCC(rc, finish, _server_ref(server, &client->server));
  client->request.server_user_data = client->server->spec.user_data;

  int flags = fcntl(fd, F_GETFL, 0);
  RCN(finish, flags);
  RCN(finish, fcntl(fd, F_SETFL, flags | O_NONBLOCK));

  if (server->https) {
    pthread_mutex_lock(&server->mtx);
    RCC(rc, finish, iwn_brssl_server_poller_adapter(&(struct iwn_brssl_server_poller_adapter_spec) {
      .certs = server->spec.ssl.certs,
      .certs_in_buffer = server->spec.ssl.certs_in_buffer,
      .certs_len = server->spec.ssl.certs_len,
      .events = IWN_POLLIN,
      .events_mod = IWN_POLLET,
      .fd = fd,
      .on_dispose = _client_on_poller_adapter_dispose,
      .on_event = _client_on_poller_adapter_event,
      .poller = server->spec.poller,
      .private_key = server->spec.ssl.private_key,
      .private_key_in_buffer = server->spec.ssl.private_key_in_buffer,
      .private_key_len = server->spec.ssl.private_key_len,
      .timeout_sec = server->spec.request_timeout_sec,
      .user_data = client,
    }));
    pthread_mutex_unlock(&server->mtx);
  } else {
    RCC(rc, finish,
        iwn_direct_poller_adapter(
          server->spec.poller, fd,
          _client_on_poller_adapter_event,
          _client_on_poller_adapter_dispose,
          client, IWN_POLLIN, IWN_POLLET,
          server->spec.request_timeout_sec));
  }

finish:
  if (rc) {
    close(fd);
    if (client) {
      _client_destroy(client);
    } else {
      iwpool_destroy(pool);
    }
  }

  return rc;
}

///////////////////////////////////////////////////////////////////////////
//								      Client Public API                                //
///////////////////////////////////////////////////////////////////////////

bool iwn_http_request_is_streamed(struct iwn_http_req *request) {
  struct client *client = (void*) request;
  return (client->flags & HTTP_STREAMED);
}

bool iwn_http_request_is_secure(struct iwn_http_req *request) {
  struct client *client = (void*) request;
  return client->server->https;
}

void iwn_http_request_free(struct iwn_http_req *request) {
  struct client *client = (void*) request;
  _request_data_free(client);
  _stream_free_buffer(client);
  _tokens_free_buffer(client);
}

struct iwn_val iwn_http_request_target(struct iwn_http_req *request) {
  return _token_get_string((void*) request, HS_TOK_TARGET);
}

bool iwn_http_request_target_is(struct iwn_http_req *request, const char *target, ssize_t target_len) {
  struct iwn_val val = iwn_http_request_target(request);
  if (target_len < 0) {
    target_len = strlen(target);
  }
  return val.len == target_len && memcmp(val.buf, target, target_len) == 0;
}

struct iwn_val iwn_http_request_method(struct iwn_http_req *request) {
  return _token_get_string((void*) request, HS_TOK_METHOD);
}

struct iwn_val iwn_http_request_body(struct iwn_http_req *request) {
  return _token_get_string((void*) request, HS_TOK_BODY);
}

void iwn_http_request_chunk_next(struct iwn_http_req *request, iwn_http_server_chunk_handler chunk_cb) {
  struct client *client = (void*) request;
  client->chunk_cb = chunk_cb;
  _client_read(client);
}

struct iwn_val iwn_http_request_chunk_get(struct iwn_http_req *request) {
  struct client *client = (void*) request;
  struct token *token = &client->tokens.buf[client->tokens.size - 1];
  return (struct iwn_val) {
           .buf = &client->stream.buf[token->index],
           .len = token->len
  };
}

void iwn_http_connection_set_automatic(struct iwn_http_req *request) {
  struct client *client = (void*) request;
  client->flags |= HTTP_AUTOMATIC;
  client->flags &= ~HTTP_KEEP_ALIVE;
}

void iwn_http_connection_set_keep_alive(struct iwn_http_req *request, bool keep_alive) {
  struct client *client = (void*) request;
  client->flags &= ~HTTP_AUTOMATIC;
  if (keep_alive) {
    client->flags |= HTTP_KEEP_ALIVE;
  } else {
    client->flags &= ~HTTP_KEEP_ALIVE;
  }
}

void iwn_http_connection_set_upgrade(struct iwn_http_req *request) {
  struct client *client = (void*) request;
  client->flags &= ~HTTP_AUTOMATIC;
  client->flags &= ~HTTP_KEEP_ALIVE;
  client->flags |= HTTP_UPGRADE;
}

bool iwn_http_connection_is_upgrade(struct iwn_http_req *request) {
  struct client *client = (void*) request;
  return client->flags & HTTP_UPGRADE;
}

struct iwn_val iwn_http_request_header_get(
  struct iwn_http_req *request,
  const char          *header_name,
  ssize_t              header_name_len
  ) {
  struct client *client = (void*) request;
  if (header_name_len < 0) {
    header_name_len = strlen(header_name);
  }
  for (int i = 0; i < client->tokens.size; ++i) {
    struct token token = client->tokens.buf[i];
    if (token.type == HS_TOK_HEADER_KEY && token.len == header_name_len) {
      if (strncasecmp(&client->stream.buf[token.index], header_name, header_name_len) == 0) {
        token = client->tokens.buf[i + 1];
        return (struct iwn_val) {
                 .buf = &client->stream.buf[token.index],
                 .len = token.len
        };
      }
    }
  }
  return (struct iwn_val) {};
}

static bool _iteration_headers_assign(
  struct client  *client,
  struct iwn_val *key,
  struct iwn_val *val,
  int            *iter
  ) {
  struct token token = client->tokens.buf[*iter];
  if (client->tokens.buf[*iter].type == HS_TOK_BODY) {
    return false;
  }
  *key = (struct iwn_val) {
    .buf = &client->stream.buf[token.index],
    .len = token.len
  };
  (*iter)++;
  token = client->tokens.buf[*iter];
  *val = (struct iwn_val) {
    .buf = &client->stream.buf[token.index],
    .len = token.len
  };
  return true;
}

bool iwn_http_request_headers_iterate(
  struct iwn_http_req *request,
  struct iwn_val      *key,
  struct iwn_val      *val,
  int                 *iter
  ) {
  struct client *client = (void*) request;
  if (*iter == 0) {
    for ( ; *iter < client->tokens.size; (*iter)++) {
      struct token token = client->tokens.buf[*iter];
      if (token.type == HS_TOK_HEADER_KEY) {
        return _iteration_headers_assign(client, key, val, iter);
      }
    }
    return false;
  } else {
    (*iter)++;
    return _iteration_headers_assign(client, key, val, iter);
  }
}

int iwn_http_response_code_get(struct iwn_http_req *request) {
  return ((struct client*) request)->response.code;
}

iwrc iwn_http_response_code_set(struct iwn_http_req *request, int code) {
  if (code < 0 || code > 599) {
    return IW_ERROR_INVALID_ARGS;
  }
  if (code == 0) {
    code = 200;
  }
  struct client *client = (void*) request;
  client->response.code = code;
  return 0;
}

struct iwn_val iwn_http_response_header_get(struct iwn_http_req *request, const char *header_name) {
  struct client *client = (void*) request;
  for (struct header *h = client->response.headers; h; h = h->next) {
    if (strcasecmp(h->name, header_name) == 0) {
      return (struct iwn_val) {
               .buf = h->value,
               .len = strlen(h->value)
      };
    }
  }
  return (struct iwn_val) {};
}

iwrc iwn_http_response_header_add(
  struct iwn_http_req *request,
  const char          *header_name,
  const char          *header_value,
  ssize_t              header_value_len
  ) {
  iwrc rc = 0;
  struct client *client = (void*) request;
  struct response *response = &client->response;
  struct header *header = 0;

  if (header_value_len < 0) {
    header_value_len = strlen(header_value);
  }
  if (!response->pool) {
    RCA(response->pool = iwpool_create_empty(), finish);
  }
  RCA(header = iwpool_alloc(sizeof(*header), response->pool), finish);
  RCA(header->name = iwpool_strdup2(response->pool, header_name), finish);
  for (char *p = header->name; *p != '\0'; ++p) {
    *p = (char) tolower((unsigned char) *p);
  }
  RCA(header->value = iwpool_strndup2(response->pool, header_value, header_value_len), finish);
  header->next = response->headers;
  response->headers = header;

finish:
  return rc;
}

iwrc iwn_http_response_header_set(
  struct iwn_http_req *request,
  const char          *header_name,
  const char          *header_value,
  ssize_t              header_value_len
  ) {
  iwrc rc = 0;
  struct client *client = (void*) request;
  struct response *response = &client->response;
  struct header *header = 0;

  if (header_value_len < 0) {
    header_value_len = strlen(header_value);
  }

  if (!response->pool) {
    RCA(response->pool = iwpool_create_empty(), finish);
  }
  for (struct header *h = response->headers; h; h = h->next) {
    if (strcasecmp(h->name, header_name) == 0) {
      header = h;
      break;
    }
  }
  if (IW_LIKELY(header == 0)) {
    RCA(header = iwpool_alloc(sizeof(*header), response->pool), finish);
    RCA(header->name = iwpool_strdup2(response->pool, header_name), finish);
    for (char *p = header->name; *p != '\0'; ++p) {
      *p = (char) tolower((unsigned char) *p);
    }
    RCA(header->value = iwpool_strndup2(response->pool, header_value, header_value_len), finish);
    header->next = response->headers;
    response->headers = header;
  } else {
    RCA(header->value = iwpool_strndup2(response->pool, header_value, header_value_len), finish);
  }

finish:
  return rc;
}

iwrc iwn_http_response_header_i64_set(
  struct iwn_http_req *req,
  const char          *header_name,
  int64_t              header_value
  ) {
  char buf[64];
  int len = snprintf(buf, sizeof(buf), "%" PRId64, header_value);
  return iwn_http_response_header_set(req, header_name, buf, len);
}

iwrc iwn_http_response_header_printf_va(
  struct iwn_http_req *req,
  const char          *header_name,
  const char          *fmt,
  va_list              va
  ) {
  iwrc rc = 0;
  char buf[1024];
  char *wp = buf;

  va_list cva;
  va_copy(cva, va);

  int size = vsnprintf(wp, sizeof(buf), fmt, va);
  if (size < 0) {
    rc = IW_ERROR_FAIL;
    goto finish;
  }
  if (size >= sizeof(buf)) {
    RCA(wp = malloc(size + 1), finish);
    size = vsnprintf(wp, size + 1, fmt, cva);
    if (size < 0) {
      rc = IW_ERROR_FAIL;
      goto finish;
    }
  }

  rc = iwn_http_response_header_set(req, header_name, wp, size);

finish:
  va_end(cva);
  if (wp != buf) {
    free(wp);
  }
  return rc;
}

iwrc iwn_http_response_header_printf(
  struct iwn_http_req *req,
  const char          *header_name,
  const char          *fmt,
  ...
  ) {
  va_list va;
  va_start(va, fmt);
  iwrc rc = iwn_http_response_header_printf_va(req, header_name, fmt, va);
  va_end(va);
  return rc;
}

void iwn_http_response_header_exclude(struct iwn_http_req *request, const char *header_name) {
  struct client *client = (void*) request;
  struct response *response = &client->response;
  for (struct header *h = response->headers; h; h = h->next) {
    if (header_name[0] == '\0' || strcasecmp(h->name, header_name) == 0) {
      h->exclude = true;
    }
  }
}

void iwn_http_response_body_clear(struct iwn_http_req *request) {
  struct client *client = (void*) request;
  if (client->response.body) {
    if (client->response.body_free) {
      client->response.body_free((void*) client->response.body);
      client->response.body_free = 0;
    }
    client->response.body = 0;
  }
}

void iwn_http_response_body_set(
  struct iwn_http_req *request,
  const char          *body,
  ssize_t              body_len,
  void (              *body_free )(void*)
  ) {
  if (!body || body_len == 0) {
    iwn_http_response_body_clear(request);
    return;
  }
  struct client *client = (void*) request;
  if (body_len < 0) {
    body_len = strlen(body);
  }
  iwn_http_response_body_clear(request);
  client->response.body = body;
  client->response.body_len = body_len;
  client->response.body_free = body_free;
}

static void _client_autodetect_keep_alive(struct client *client) {
  struct iwn_val val = _token_get_string(client, HS_TOK_VERSION);
  if (val.buf == 0) {
    return;
  }
  int version = val.buf[val.len - 1] == '1';
  val = iwn_http_request_header_get(&client->request, "connection", IW_LLEN("connection"));
  if (  (val.len == IW_LLEN("close") && strncasecmp(val.buf, "close", IW_LLEN("close")) == 0)
     || (val.len == 0 && version == HTTP_1_0)) {
    client->flags &= ~HTTP_KEEP_ALIVE;
  } else {
    client->flags |= HTTP_KEEP_ALIVE;
  }
}

static iwrc _client_response_headers_write(struct client *client, IWXSTR *xstr) {
  iwrc rc = 0;
  for (struct header *h = client->response.headers; h; h = h->next) {
    RCC(rc, finish, iwxstr_printf(xstr, "%s: %s\r\n", h->name, h->value));
  }
  if (!(client->flags & (HTTP_CHUNKED_RESPONSE | HTTP_STREAM_RESPONSE | HTTP_HAS_CONTENT_LEN))) {
    RCC(rc, finish, iwxstr_printf(xstr, "content-length: %d\r\n", (int) client->response.body_len));
  }
  rc = iwxstr_cat(xstr, "\r\n", sizeof("\r\n") - 1);

finish:
  return rc;
}

static iwrc _client_response_headers_write_http(struct client *client, IWXSTR *xstr) {
  iwrc rc = 0;
  struct iwn_val val = iwn_http_response_header_get(&client->request, "content-length");
  if (val.len) {
    client->flags |= HTTP_HAS_CONTENT_LEN;
  }
  if (client->flags & HTTP_AUTOMATIC) {
    _client_autodetect_keep_alive(client);
  }

  if (client->request.on_response_headers_write) {
    client->request.on_response_headers_write(&client->request);
  }
  if (client->_wf_on_response_headers_write) {
    client->_wf_on_response_headers_write(&client->request);
  }

  if (IW_UNLIKELY(client->flags & HTTP_UPGRADE)) {
    iwn_http_response_header_set(&client->request, "connection", "upgrade", IW_LLEN("upgrade"));
  } else if (client->flags & HTTP_KEEP_ALIVE) {
    iwn_http_response_header_set(&client->request, "connection", "keep-alive", IW_LLEN("keep-alive"));
  } else {
    iwn_http_response_header_set(&client->request, "connection", "close", IW_LLEN("close"));
  }

  if (client->response.code == 0) {
    client->response.code = 200;
  }
  char dbuf[32];
  _server_time(client->server, dbuf);
  RCC(rc, finish, iwxstr_printf(xstr, "HTTP/1.1 %d %s\r\ndate: %s\r\n",
                                client->response.code,
                                _status_text[client->response.code],
                                dbuf));

  rc = _client_response_headers_write(client, xstr);

finish:
  return rc;
}

iwrc iwn_http_response_headers_flush_into(struct iwn_http_req *request, IWXSTR *xstr) {
  struct client *client = (void*) request;
  return _client_response_headers_write_http(client, xstr);
}

IW_INLINE void _client_response_setbuf(struct client *client, IWXSTR *xstr) {
  _stream_free_buffer(client);
  struct stream *s = &client->stream;
  s->buf = iwxstr_ptr(xstr);
  s->length = iwxstr_size(xstr);
  s->capacity = s->length;
  client->state = HTTP_SESSION_WRITE;
  iwxstr_destroy_keep_ptr(xstr);
  _response_free(client);
}

IW_INLINE void _client_response_setbuf2(struct client *client, char *buf, ssize_t buf_len, void (*buf_free)(void*)) {
  _stream_free_buffer(client);
  struct stream *s = &client->stream;
  s->buf = buf;
  s->buf_free = buf_free;
  s->length = buf_len;
  s->capacity = s->length;
  client->state = HTTP_SESSION_WRITE;
  _response_free(client);
}

iwrc iwn_http_response_end(struct iwn_http_req *request) {
  iwrc rc = 0;
  struct client *client = (void*) request;
  struct response *response = &client->response;
  IWXSTR *xstr = iwxstr_new();
  if (!xstr) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  RCC(rc, finish, _client_response_headers_write_http(client, xstr));
  if (response->body) {
    RCC(rc, finish, iwxstr_cat(xstr, response->body, response->body_len));
  }

  _client_response_setbuf(client, xstr);
  _client_write(client);

finish:
  if (rc) {
    iwxstr_destroy(xstr);
  }
  return rc;
}

iwrc iwn_http_response_stream_start(
  struct iwn_http_req          *request,
  iwn_http_server_chunk_handler chunk_cb
  ) {
  iwrc rc = 0;
  struct client *client = (void*) request;
  IWXSTR *xstr = iwxstr_new();
  if (!xstr) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  client->chunk_cb = chunk_cb;
  if (!(client->flags & HTTP_STREAM_RESPONSE)) {
    client->flags |= HTTP_STREAM_RESPONSE;
    RCC(rc, finish, _client_response_headers_write_http(client, xstr));
  }

  _client_response_setbuf(client, xstr);
  _client_write(client);

finish:
  if (rc) {
    iwxstr_destroy(xstr);
  }
  return rc;
}

void iwn_http_response_stream_write(
  struct iwn_http_req          *request,
  char                         *buf,
  ssize_t                       buf_len,
  void (                       *buf_free )(void*),
  iwn_http_server_chunk_handler chunk_cb,
  bool                         *again
  ) {
  if (!buf_free) {
    buf_free = _noop_free;
  }
  if (buf_len < 0) {
    buf_len = strlen(buf);
  }
  struct client *client = (void*) request;
  client->chunk_cb = chunk_cb;
  if (chunk_cb) {
    if (again) {
      *again = true;
    }
  } else {
    client->flags &= ~HTTP_STREAM_RESPONSE;
  }
  _client_response_setbuf2(client, buf, buf_len, buf_free);
  if (!again || *again != true) {
    _client_write(client);
  }
}

void iwn_http_response_stream_end(struct iwn_http_req *request) {
  iwn_http_response_stream_write(request, 0, 0, 0, 0, 0);
}

iwrc iwn_http_response_chunk_write(
  struct iwn_http_req          *request,
  char                         *body,
  ssize_t                       body_len,
  iwn_http_server_chunk_handler chunk_cb,
  bool                         *again
  ) {
  iwrc rc = 0;
  struct client *client = (void*) request;
  if (body_len < 0) {
    body_len = strlen(body);
  }
  IWXSTR *xstr = iwxstr_new();
  if (!xstr) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  client->chunk_cb = chunk_cb;
  if (chunk_cb && again) {
    *again = true;
  }

  if (!(client->flags & HTTP_CHUNKED_RESPONSE)) {
    client->flags |= HTTP_CHUNKED_RESPONSE;
    iwn_http_response_header_set(request, "transfer-encoding", "chunked", IW_LLEN("chunked"));
    RCC(rc, finish, _client_response_headers_write_http(client, xstr));
  }
  RCC(rc, finish, iwxstr_printf(xstr, "%X\r\n", (unsigned int) body_len));
  RCC(rc, finish, iwxstr_cat(xstr, body, body_len));
  RCC(rc, finish, iwxstr_cat(xstr, "\r\n", sizeof("\r\n") - 1));

  _client_response_setbuf(client, xstr);
  if (!again || *again != true) {
    _client_write(client);
  }

finish:
  if (rc) {
    iwxstr_destroy(xstr);
  }
  return rc;
}

iwrc iwn_http_response_chunk_end(struct iwn_http_req *request) {
  iwrc rc = 0;
  struct client *client = (void*) request;
  IWXSTR *xstr = iwxstr_new();
  if (!xstr) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  RCC(rc, finish, iwxstr_cat(xstr, "0\r\n", sizeof("0\r\n") - 1));
  RCC(rc, finish, _client_response_headers_write(client, xstr));
  RCC(rc, finish, iwxstr_cat(xstr, "\r\n", sizeof("\r\n") - 1));
  client->flags &= ~HTTP_CHUNKED_RESPONSE;

  _client_response_setbuf(client, xstr);
  _client_write(client);

finish:
  if (rc) {
    iwxstr_destroy(xstr);
  }
  return rc;
}

bool iwn_http_response_write(
  struct iwn_http_req *request,
  int                  status_code,
  const char          *content_type,
  const char          *body,
  ssize_t              body_len
  ) {
  iwrc rc = 0;
  RCC(rc, finish, iwn_http_response_code_set(request, status_code));
  if (!content_type) {
    content_type = "text/plain";
  }
  if (*content_type != '\0') {
    // Content-type header disabled if empty
    RCC(rc, finish, iwn_http_response_header_set(request, "content-type", content_type, -1));
  }
  iwn_http_response_body_set(request, body, body_len, 0);
  rc = iwn_http_response_end(request);

finish:
  if (rc) {
    iwlog_ecode_error3(rc);
    return false;
  }
  return true;
}

bool iwn_http_response_by_code(struct iwn_http_req *request, int code) {
  const char *text = _status_text[code];
  return iwn_http_response_write(request, code, "text/plain", text, -1);
}

bool iwn_http_response_printf_va(
  struct iwn_http_req *req,
  int status_code, const char *content_type,
  const char *fmt, va_list va
  ) {
  iwrc rc = 0;
  bool ret = false;
  char buf[1024];
  char *wp = buf;

  va_list cva;
  va_copy(cva, va);

  int size = vsnprintf(wp, sizeof(buf), fmt, va);
  if (size < 0) {
    rc = IW_ERROR_FAIL;
    goto finish;
  }
  if (size >= sizeof(buf)) {
    RCA(wp = malloc(size + 1), finish);
    size = vsnprintf(wp, size + 1, fmt, cva);
    if (size < 0) {
      rc = IW_ERROR_FAIL;
      goto finish;
    }
  }

  ret = iwn_http_response_write(req, status_code, content_type, wp, size);

finish:
  va_end(cva);
  if (wp != buf) {
    free(wp);
  }
  return ret && rc == 0;
}

bool iwn_http_response_printf(
  struct iwn_http_req *req,
  int status_code, const char *content_type,
  const char *fmt, ...
  ) {
  va_list va;
  va_start(va, fmt);
  bool res = iwn_http_response_printf_va(req, status_code, content_type, fmt, va);
  va_end(va);
  return res;
}

///////////////////////////////////////////////////////////////////////////
//								             Server                                    //
///////////////////////////////////////////////////////////////////////////

static void _server_destroy(struct server *server) {
  if (!server) {
    return;
  }
  if (server->spec.on_server_dispose) {
    server->spec.on_server_dispose((void*) server);
  }
  if (server->fd > -1) {
    close(server->fd);
    server->fd = -1;
  }
  free((void*) server->spec.ssl.certs);
  free((void*) server->spec.ssl.private_key);
  pthread_mutex_destroy(&server->mtx);
  iwpool_destroy(server->pool);
}

static int64_t _server_on_ready(const struct iwn_poller_task *t, uint32_t events) {
  struct server *server = t->user_data;
  int client_fd = 0;

  do {
    client_fd = accept(t->fd, 0, 0);
    if (client_fd == -1) {
      break;
    }
    iwrc rc = _client_accept(server, client_fd);
    if (rc) {
      iwlog_ecode_error(rc, "Failed to initiate client connection fd: %d", client_fd);
    }
  } while (1);

  return 0;
}

static iwrc _server_ref(struct server *server, struct server **out) {
  iwrc rc = 0;
  pthread_mutex_lock(&server->mtx);
  if (server->refs == 0) {
    *out = 0;
    rc = IW_ERROR_ASSERTION;
    iwlog_ecode_error(rc, "Server instance fd: %d is already disposed", server->fd);
    assert(server->refs);
  } else {
    *out = server;
    ++server->refs;
  }
  pthread_mutex_unlock(&server->mtx);
  return rc;
}

static void _server_unref(struct server *server) {
  int refs;
  pthread_mutex_lock(&server->mtx);
  refs = --server->refs;
  pthread_mutex_unlock(&server->mtx);
  if (refs < 1) {
    _server_destroy(server);
  }
}

static void _server_on_dispose(const struct iwn_poller_task *t) {
  struct server *server = t->user_data;
  _server_unref(server);
}

void iwn_http_request_wf_set(
  struct iwn_http_req *request, void *user_data,
  void (*wf_on_request_dispose)(struct iwn_http_req*),
  void (*wf_on_response_headers_write)(struct iwn_http_req*)
  ) {
  struct client *client = (void*) request;
  client->_wf_data = user_data;
  client->_wf_on_request_dispose = wf_on_request_dispose;
  client->_wf_on_response_headers_write = wf_on_response_headers_write;
}

void* iwn_http_request_wf_data(struct iwn_http_req *request) {
  struct client *client = (void*) request;
  return client->_wf_data;
}

void iwn_http_request_ws_set(struct iwn_http_req *request, void *user_data) {
  struct client *client = (void*) request;
  client->_ws_data = user_data;
}

void* iwn_http_request_ws_data(struct iwn_http_req *request) {
  struct client *client = (void*) request;
  return client->_ws_data;
}

static void _probe_ssl_set(struct iwn_poller *p, void *slot_data, void *fn_data) {
  struct server *server = slot_data;
  const struct iwn_http_server_ssl_spec *ssl = fn_data;
  pthread_mutex_lock(&server->mtx);
  free((void*) server->spec.ssl.certs);
  free((void*) server->spec.ssl.private_key);
  server->spec.ssl.certs_len = ssl->certs_len;
  server->spec.ssl.private_key_len = ssl->private_key_len;
  if (ssl->certs) {
    if (ssl->certs_len < 0) {
      server->spec.ssl.certs_len = strlen(ssl->certs);
    }
    server->spec.ssl.certs = strndup(ssl->certs, server->spec.ssl.certs_len);
  } else {
    server->spec.ssl.certs = 0;
  }
  if (ssl->private_key) {
    if (ssl->private_key_len < 0) {
      server->spec.ssl.private_key_len = strlen(ssl->private_key);
    }
    server->spec.ssl.private_key = strndup(ssl->private_key, server->spec.ssl.private_key_len);
  } else {
    server->spec.ssl.private_key = 0;
  }
  server->spec.ssl.certs_in_buffer = ssl->certs_in_buffer;
  server->spec.ssl.private_key_in_buffer = ssl->private_key_in_buffer;
  server->https = ssl->certs && ssl->certs_len && ssl->private_key && ssl->private_key_len;
  pthread_mutex_unlock(&server->mtx);
}

bool iwn_http_server_ssl_set(
  struct iwn_poller                     *poller,
  int                                    server_fd,
  const struct iwn_http_server_ssl_spec *ssl
  ) {
  return iwn_poller_probe(poller, server_fd, _probe_ssl_set, (void*) ssl);
}

iwrc iwn_http_server_create(const struct iwn_http_server_spec *spec_, int *out_fd) {
  iwrc rc = 0;
  if (out_fd) {
    *out_fd = -1;
  }
  int optval;
  struct server *server;
  struct iwn_http_server_spec *spec;

  IWPOOL *pool = iwpool_create_empty();
  if (!pool) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  RCA(server = iwpool_calloc(sizeof(*server), pool), finish);
  pthread_mutex_init(&server->mtx, 0);

  server->pool = pool;
  server->refs = 1;
  spec = &server->spec;
  memcpy(spec, spec_, sizeof(*spec));

  if (!spec->request_handler) {
    rc = IW_ERROR_INVALID_ARGS;
    iwlog_ecode_error2(rc, "No request_handler specified");
    goto finish;
  }
  if (!spec->poller) {
    rc = IW_ERROR_INVALID_ARGS;
    iwlog_ecode_error2(rc, "No poller specified");
    goto finish;
  }
  if (spec->socket_queue_size < 1) {
    spec->socket_queue_size = 64;
  }
  if (spec->request_buf_size < 1023) {
    spec->request_buf_size = 1023;
  }
  if (spec->request_timeout_sec == 0) {
    spec->request_timeout_sec = 20;
  }
  if (spec->request_timeout_keepalive_sec == 0) {
    spec->request_timeout_keepalive_sec = 120;
  }
  if (spec->request_token_max_len < 8191) {
    spec->request_token_max_len = 8191;
  }
  if (spec->request_max_headers_count < 1) {
    spec->request_max_headers_count = 127;
  }
  if (spec->request_buf_max_size < 1024 * 1024) {
    spec->request_buf_max_size = 8 * 1024 * 1024;
  }

  server->https = spec->ssl.certs && spec->ssl.certs_len && spec->ssl.private_key && spec->ssl.private_key_len;
  if (server->https) {
    if (spec->ssl.certs_len < 0) {
      spec->ssl.certs_len = strlen(spec->ssl.certs);
    }
    if (spec->ssl.private_key_len < 0) {
      spec->ssl.private_key_len = strlen(spec->ssl.private_key);
    }
    RCA(spec->ssl.certs = strndup(spec->ssl.certs, spec->ssl.certs_len), finish);
    RCA(spec->ssl.private_key = strndup(spec->ssl.private_key, spec->ssl.private_key_len), finish);
  }

  if (!spec->port) {
    spec->port = server->https ? 8443 : 8080;
  }
  if (!spec->listen) {
    spec->listen = "localhost";
  }
  RCA(spec->listen = iwpool_strdup2(pool, spec->listen), finish);

  struct iwn_poller_task task = {
    .user_data  = server,
    .on_ready   = _server_on_ready,
    .on_dispose = _server_on_dispose,
    .events     = IWN_POLLIN,
    .events_mod = IWN_POLLET,
    .poller     = spec->poller
  };

  struct addrinfo hints = {
    .ai_socktype = SOCK_STREAM,
    .ai_family   = AF_INET,
    .ai_flags    = AI_PASSIVE
  };

  struct addrinfo *result, *rp;
  char port[32];
  snprintf(port, sizeof(port), "%d", spec->port);

  int rci = getaddrinfo(spec->listen, port, &hints, &result);
  if (rci) {
    rc = IW_ERROR_FAIL;
    iwlog_error("Error getting local address and port: %s", gai_strerror(rci));
    goto finish;
  }

  optval = 1;
  for (rp = result; rp; rp = rp->ai_next) {
    task.fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    server->fd = task.fd;
    if (task.fd < 0) {
      continue;
    }
    fcntl(task.fd, F_SETFD, FD_CLOEXEC);
    setsockopt(task.fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
    if (bind(task.fd, rp->ai_addr, rp->ai_addrlen) == 0) {
      break;
    }
    close(task.fd);
  }

  freeaddrinfo(result);
  if (!rp) {
    rc = iwrc_set_errno(IW_ERROR_ERRNO, errno);
    iwlog_ecode_error2(rc, "Could not find any suitable address to bind");
    goto finish;
  }
  RCN(finish, optval = fcntl(task.fd, F_GETFL, 0));
  RCN(finish, fcntl(task.fd, F_SETFL, optval | O_NONBLOCK));

  server->server.listen = spec->listen;
  server->server.fd = task.fd;
  server->server.port = spec->port;
  server->server.user_data = spec->user_data;

  RCC(rc, finish, iwn_poller_add(&task));
  if (listen(task.fd, spec->socket_queue_size) == -1) {
    rc = iwrc_set_errno(IW_ERROR_ERRNO, errno);
    iwn_poller_remove(task.poller, task.fd);
    return rc;
  }

finish:
  if (rc) {
    if (server) {
      _server_destroy(server);
    } else {
      iwpool_destroy(pool);
    }
  } else if (out_fd) {
    *out_fd = server->fd;
  }
  return rc;
}
