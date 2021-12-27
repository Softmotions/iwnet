/*
 * Based on https://github.com/jeremycw/httpserver.h
 */

#include "http_server.h"
#include "poller_adapter.h"
#include "poller/direct_poller_adapter.h"
#include "ssl/brssl_poller_adapter.h"

#include <iowow/iwlog.h>
#include <iowow/iwpool.h>

#include <assert.h>
#include <arpa/inet.h>
#include <stdatomic.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>

struct server {
  struct iwn_http_server_spec spec;
  int fd;
  int refs;
  pthread_mutex_t mtx;
  IWPOOL *pool;
  atomic_int_fast64_t memused;
  bool https;
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
  uint8_t     *buf;
  struct token token;
  ssize_t      bytes_total;
  ssize_t      capacity;
  ssize_t      length;
  ssize_t      index;
  ssize_t      anchor;
  uint8_t      flags;
};

struct parser {
  int64_t content_length;
  int64_t body_consumed;
  int16_t match_index;
  int16_t header_count;
  int8_t  state;
  int8_t  meta;
};

struct client {
  struct iwn_http_request req;
  IWPOOL *pool;
  struct server    *server;
  struct tokens_buf tokens;
  struct stream     stream;
  struct parser     parser;
  int     fd;
  uint8_t state;     ///< HTTP_SESSION_{INIT,READ,WRITE,NOP}
  uint8_t flags;     ///< HTTP_END_SESSION,HTTP_AUTOMATIC,HTTP_CHUNKED_RESPONSE
};

// stream flags
#define HS_SF_CONSUMED 0x1

// parser flags
#define HS_PF_IN_CONTENT_LEN  0x1
#define HS_PF_IN_TRANSFER_ENC 0x2
#define HS_PF_CHUNKED         0x4
#define HS_PF_CKEND           0x8
#define HS_PF_REQ_END         0x10

// http session states
#define HTTP_SESSION_INIT  0
#define HTTP_SESSION_READ  1
#define HTTP_SESSION_WRITE 2
#define HTTP_SESSION_NOP   3

// http session flags
#define HTTP_END_SESSION      0x2
#define HTTP_AUTOMATIC        0x8
#define HTTP_CHUNKED_RESPONSE 0x20

// http version indicators
#define HTTP_1_0 0
#define HTTP_1_1 1

// *INDENT-OFF*
enum hs_token {
  HS_TOK_NONE,        HS_TOK_METHOD,     HS_TOK_TARGET,     HS_TOK_VERSION,
  HS_TOK_HEADER_KEY,  HS_TOK_HEADER_VAL, HS_TOK_CHUNK_BODY, HS_TOK_BODY,
  HS_TOK_BODY_STREAM, HS_TOK_REQ_END,    HS_TOK_EOF,        HS_TOK_ERROR
};

enum hs_state {
  ST, MT, MS, TR, TS, VN, RR, RN, HK, HS, HV, HR, HE,
  ER, HN, BD, CS, CB, CE, CR, CN, CD, C1, C2, BR, HS_STATE_LEN
};

enum hs_char_type {
  HS_SPC,   HS_NL,  HS_CR,    HS_COLN,  HS_TAB,   HS_SCOLN,
  HS_DIGIT, HS_HEX, HS_ALPHA, HS_TCHAR, HS_VCHAR, HS_ETC,   HS_CHAR_TYPE_LEN
};

enum meta_state {
  M_WFK, M_ANY, M_MTE, M_MCL, M_CLV, M_MCK, M_SML, M_CHK, M_BIG, M_ZER, M_CSZ,
  M_CBD, M_LST, M_STR, M_SEN, M_BDY, M_END, M_ERR
};

enum meta_type {
  HS_META_NOT_CONTENT_LEN, HS_META_NOT_TRANSFER_ENC, HS_META_END_KEY,
  HS_META_END_VALUE,       HS_META_END_HEADERS,      HS_META_LARGE_BODY,
  HS_META_TYPE_LEN
};
// *INDENT-ON*

#define HS_META_NOT_CHUNKED  0
#define HS_META_NON_ZERO     0
#define HS_META_END_CHK_SIZE 1
#define HS_META_END_CHUNK    2
#define HS_META_NEXT         0

// *INDENT-OFF*
char const * hs_status_text[] = {
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

static int const _transitions[] = {
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

static int const _meta_transitions[] = {
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

static int const _ctype[] = {
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

static int const _token_start_states[] = {
//ST MT             MS TR             TS VN              RR RN HK
  0, HS_TOK_METHOD, 0, HS_TOK_TARGET, 0, HS_TOK_VERSION, 0, 0, HS_TOK_HEADER_KEY,
//HS HV                 HR HE ER HN BD           CS CB                 CE CR CN
  0, HS_TOK_HEADER_VAL, 0, 0, 0, 0, HS_TOK_BODY, 0, HS_TOK_CHUNK_BODY, 0, 0, 0,
//CD C1 C2
  0, 0, 0,
};

// *INDENT-ON*

static struct server* _server_ref(struct server *server);
static void _server_unref(struct server *server);

///////////////////////////////////////////////////////////////////////////
//								              Client                                   //
///////////////////////////////////////////////////////////////////////////

static void _client_response_error(struct client *client, int code, const char *response) {
  // TODO:
}

static iwrc _client_init(struct client *client) {
  iwrc rc = 0;
  client->flags = HTTP_AUTOMATIC;
  client->parser = (struct parser) {};
  client->stream = (struct stream) {};
  if (client->tokens.buf) {
    free(client->tokens.buf);
  }
  client->tokens.capacity = 32;
  client->tokens.size = 0;
  client->tokens.buf = malloc(sizeof(struct token) * client->tokens.capacity);
  if (!client->tokens.buf) {
    client->tokens.capacity = 0;
    rc = iwrc_set_errno(IW_ERROR_ALLOC, errno);
    goto finish;
  }

finish:
  return rc;
}

static void _client_write(struct client *client, struct iwn_poller_adapter *pa) {
}

static int _client_read_pa(struct client *client, struct iwn_poller_adapter *pa) {
  struct stream *stream = &client->stream;
  struct server *server = client->server;
  if (stream->index < stream->length) {
    return 1;
  }
  if (!stream->buf) {
    stream->buf = calloc(1, server->spec.request_buf_size);
    if (!stream->buf) {
      return 0;
    }
    stream->capacity = server->spec.request_buf_size;
    server->memused += stream->capacity;
  }
  ssize_t bytes;
  do {
    bytes = pa->read(pa, stream->buf + stream->length, stream->capacity - stream->length);
    if (bytes > 0) {
      stream->length += bytes;
      stream->bytes_total += bytes;
    }
    if (stream->length == stream->capacity && stream->capacity != server->spec.request_buf_max_size) {
      server->memused -= stream->capacity;
      ssize_t ncap = stream->capacity * 2;
      if (ncap > server->spec.request_buf_max_size) {
        ncap = server->spec.request_buf_max_size;
      }
      uint8_t *nbuf = realloc(stream->buf, ncap);
      if (!nbuf) {
        bytes = 0;
        break;
      }
      stream->capacity = ncap;
      stream->buf = nbuf;
      server->memused += stream->capacity;
    }
  } while (bytes > 0 && stream->capacity < server->spec.request_buf_max_size);
  return bytes ? 1 : 0;
}

IW_INLINE void _meta_trigger(struct parser *parser, int event) {
  int to = _meta_transitions[parser->meta * HS_META_TYPE_LEN + event];
  parser->meta = to;
}

struct token _token_meta_emit(struct parser *parser) {
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

struct token _token_parse(struct parser *parser, struct stream *stream) {
  struct token token = _token_meta_emit(parser);

  return token;
}

static void _client_read(struct client *client, struct iwn_poller_adapter *pa) {
  client->state = HTTP_SESSION_READ;
  struct token token;
  int rci = _client_read_pa(client, pa);
  if (rci == 0) {
    client->flags |= HTTP_END_SESSION;
    return;
  }
  do {
    token = _token_parse(&client->parser, &client->stream);
    if (token.type != HS_TOK_NONE) {
      if (client->tokens.size == client->tokens.capacity) {
        ssize_t ncap = client->tokens.capacity * 2;
        struct token *nbuf = realloc(client->tokens.buf, ncap * sizeof(client->tokens.buf[0]));
        if (!nbuf) {
          client->flags = HTTP_END_SESSION;
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
      case HS_TOK_BODY_STREAM:

        break;
    }
  } while (token.type != HS_TOK_NONE && client->state == HTTP_SESSION_READ);
}

static int64_t _client_on_poller_adapter_event(struct iwn_poller_adapter *pa, void *user_data, uint32_t events) {
  iwrc rc = 0;
  int64_t resp = 0;
  struct client *client = user_data;

  switch (client->state) {
    case HTTP_SESSION_INIT:
      RCC(rc, finish, _client_init(client));
      client->state = HTTP_SESSION_READ;
      if (client->server->memused > client->server->spec.http_max_total_mem_usage) {
        _client_response_error(client, 503, "Service Unavailable");
        return -1;
      }
    case HTTP_SESSION_READ:
      _client_read(client, pa);
      break;
    case HTTP_SESSION_WRITE:
      _client_write(client, pa);
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

static void _client_destroy(struct client *client) {
  if (!client) {
    return;
  }
  if (client->fd > -1) {
    close(client->fd);
  }
  if (client->stream.buf) {
    client->server->memused -= client->stream.capacity;
    free(client->stream.buf);
  }
  if (client->server) {
    _server_unref(client->server);
  }
  iwpool_destroy(client->pool);
}

static void _client_on_poller_adapter_dispose(struct iwn_poller_adapter *pa, void *user_data) {
  struct client *client = user_data;
  _client_destroy(client);
}

static iwrc _client_accept(struct server *server, int fd) {
  iwrc rc = 0;
  IWPOOL *pool = iwpool_create_empty();
  if (!pool) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  struct client *client;
  RCA(client = iwpool_alloc(sizeof(*client), pool), finish);
  client->pool = pool;
  client->fd = fd;
  client->server = _server_ref(server);

  int flags = fcntl(fd, F_GETFL, 0);
  RCN(finish, flags);
  RCN(finish, fcntl(fd, F_SETFL, flags | O_NONBLOCK));

  if (server->https) {
    RCC(rc, finish, iwn_brssl_server_poller_adapter(&(struct iwn_brssl_server_poller_adapter_spec) {
      .certs_data = server->spec.certs_data,
      .certs_data_in_buffer = server->spec.certs_data_in_buffer,
      .certs_data_len = server->spec.certs_data_len,
      .events = IWN_POLLIN,
      .events_mod = IWN_POLLET,
      .fd = fd,
      .on_dispose = _client_on_poller_adapter_dispose,
      .on_event = _client_on_poller_adapter_event,
      .poller = server->spec.poller,
      .private_key = server->spec.private_key,
      .private_key_in_buffer = server->spec.private_key_in_buffer,
      .private_key_len = server->spec.private_key_len,
      .timeout_sec = server->spec.request_timeout_sec,
      .user_data = client,
    }));
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
    if (client) {
      _client_destroy(client);
    } else {
      iwpool_destroy(pool);
    }
  }

  return rc;
}

///////////////////////////////////////////////////////////////////////////
//								             Server                                    //
///////////////////////////////////////////////////////////////////////////

static void _server_destroy(struct server *server) {
  if (!server) {
    return;
  }
  if (server->fd > -1) {
    close(server->fd);
  }
  pthread_mutex_destroy(&server->mtx);
  iwpool_destroy(server->pool);
}

static int64_t _server_on_ready(const struct iwn_poller_task *t, uint32_t events) {
  struct server *server = t->user_data;
  int sfd = 0;

  do {
    sfd = accept(t->fd, 0, 0);
    if (sfd == -1) {
      break;
    }
    iwrc rc = _client_accept(server, sfd);
    if (rc) {
      iwlog_ecode_error3(rc);
    }
  } while (1);

  return 0;
}

static struct server* _server_ref(struct server *server) {
  pthread_mutex_lock(&server->mtx);
  if (server->refs == 0) {
    iwlog_ecode_error(IW_ERROR_ASSERTION, "Server instance fd: %d is already disposed", server->fd);
    assert(server->refs);
  } else {
    ++server->refs;
  }
  pthread_mutex_unlock(&server->mtx);
  return server;
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
  // TODO:
  _server_unref(server);
}

iwrc iwn_http_server_create(const struct iwn_http_server_spec *spec_, iwn_http_server_fd_t *out_fd) {
  iwrc rc = 0;
  *out_fd = 0;
  int optval;
  struct server *server;
  struct iwn_http_server_spec *spec;

  IWPOOL *pool = iwpool_create_empty();
  if (!pool) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  RCA(server = iwpool_calloc(sizeof(*server), pool), finish);
  memcpy(&server->mtx, &(pthread_mutex_t) PTHREAD_MUTEX_INITIALIZER, sizeof(server->mtx));
  server->pool = pool;
  spec = &server->spec;
  memcpy(spec, spec_, sizeof(*spec));
    
  if (!spec->request_handler) {
    rc = IW_ERROR_INVALID_ARGS;
    iwlog_ecode_error2(rc, "No request_handler specified");
  }
  if (!spec->poller) {
    rc = IW_ERROR_INVALID_ARGS;
    iwlog_ecode_error2(rc, "No poller specified");
    goto finish;
  }

  if (spec->request_buf_size < 1024) {
    spec->request_buf_size = 1024;
  }
  if (spec->response_buf_size < 1024) {
    spec->response_buf_size = 1024;
  }
  if (spec->request_timeout_sec < 1) {
    spec->request_timeout_sec = 20;
  }
  if (spec->request_timeout_keepalive_sec < 1) {
    spec->request_timeout_keepalive_sec = 120;
  }
  if (spec->request_token_max_len < 8192) {
    spec->request_token_max_len = 8192;
  }
  if (spec->http_max_total_mem_usage < 1024 * 1024 * 10) {    // 10M
    spec->http_max_total_mem_usage = 4L * 1024 * 1024 * 1024; // 4Gb
  }
  if (spec->request_buf_max_size < 1024 * 1024) {
    spec->request_buf_max_size = 8 * 1024 * 1024;
  }

  server->https = spec->certs_data && spec->certs_data_len && spec->private_key && spec->private_key_len;
  if (server->https) {
    spec->certs_data = iwpool_strndup(pool, spec->certs_data, spec->certs_data_len, &rc);
    RCGO(rc, finish);
    spec->private_key = iwpool_strndup(pool, spec->private_key, spec->private_key_len, &rc);
    RCGO(rc, finish);
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
    .ai_family   = AF_UNSPEC,
    .ai_flags    = AI_PASSIVE | AI_NUMERICSERV
  };

  struct addrinfo *result, *rp;
  char port[32];
  snprintf(port, sizeof(port), "%d", spec->port);

  int rci = getaddrinfo(spec->listen, port, &hints, &result);
  if (rci != 0) {
    rc = IW_ERROR_FAIL;
    iwlog_error("Error getting local address and port: %s", gai_strerror(rci));
    goto finish;
  }

  optval = 1;
  for (rp = result; rp; rp = rp->ai_next) {
    task.fd = socket(rp->ai_family, rp->ai_socktype | SOCK_CLOEXEC, rp->ai_protocol);
    server->fd = task.fd;
    if (task.fd < 0) {
      continue;
    }
    if (setsockopt(task.fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &optval, sizeof(optval)) < 0) {
      iwlog_error("Error setsockopt: %s", strerror(errno));
    }
    if (bind(task.fd, rp->ai_addr, rp->ai_addrlen) == 0) {
      break;
    } else {
      iwlog_error("Error binding socket: %s", strerror(errno));
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
  RCN(finish, listen(task.fd, 64)); // TODO: Make configurable

  rc = iwn_poller_add(&task);

finish:
  if (rc) {
    if (server) {
      _server_destroy(server);
    } else {
      iwpool_destroy(pool);
    }
  } else {
    *out_fd = server->fd;
  }
  return rc;
}

iwrc iwn_http_server_request_dispose(iwn_http_server_fd_t h) {
  iwrc rc = 0;

  return rc;
}
