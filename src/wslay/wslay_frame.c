/*
 * Wslay - The WebSocket Library
 *
 * Copyright (c) 2011, 2012 Tatsuhiro Tsujikawa
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#include "wslay_frame.h"

#include <stddef.h>
#include <string.h>
#include <assert.h>

#include "wslay_net.h"

#include <stdio.h>

#define wslay_min(A, B) (((A) < (B)) ? (A) : (B))

int wslay_frame_context_init(
  wslay_frame_context_ptr            *ctx,
  const struct wslay_frame_callbacks *callbacks,
  void                               *user_data
  ) {
  *ctx = malloc(sizeof(struct wslay_frame_context));
  if (*ctx == NULL) {
    return -1;
  }
  memset(*ctx, 0, sizeof(struct wslay_frame_context));
  (*ctx)->istate = RECV_HEADER1;
  (*ctx)->ireqread = 2;
  (*ctx)->ostate = PREP_HEADER;
  (*ctx)->user_data = user_data;
  (*ctx)->ibufmark = (*ctx)->ibuflimit = (*ctx)->ibuf;
  (*ctx)->callbacks = *callbacks;
  return 0;
}

void wslay_frame_context_free(wslay_frame_context_ptr ctx) {
  free(ctx);
}

ssize_t wslay_frame_send(
  wslay_frame_context_ptr  ctx,
  struct wslay_frame_iocb *iocb
  ) {
  if (ctx->ostate == PREP_HEADER) {
    uint8_t buf[WSLAY_FRAME_HDR_SIZ] = { 0 };
    uint8_t *wp = buf;

    *wp |= (uint8_t) ((uint8_t) (iocb->fin << 7) & 0x80u);
    *wp |= (uint8_t) ((uint8_t) (iocb->rsv << 4) & 0x70u);

    /* Suppress stubborn gcc-10 warning */
    *wp |= (uint8_t) ((uint8_t) (iocb->opcode << 0) & 0xfu);
    ++wp;
    *wp |= (uint8_t) ((uint8_t) (iocb->mask << 7) & 0x80u);
    if (wslay_is_ctrl_frame(iocb->opcode) && iocb->payload_length > 125) {
      return WSLAY_ERR_INVALID_ARGUMENT;
    }
    if (iocb->payload_length < 126) {
      *wp |= (uint8_t) iocb->payload_length;
      ++wp;
    } else if (iocb->payload_length < (1 << 16)) {
      uint16_t len = htons((uint16_t) iocb->payload_length);
      *wp |= 126;
      ++wp;
      memcpy(wp, &len, 2);
      wp += 2;
    } else if (iocb->payload_length < (1ull << 63)) {
      uint64_t len = hton64(iocb->payload_length);
      *wp |= 127;
      ++wp;
      memcpy(wp, &len, 8);
      wp += 8;
    } else {
      /* Too large payload length */
      return WSLAY_ERR_INVALID_ARGUMENT;
    }
    if (iocb->mask) {
      if (ctx->callbacks.genmask_callback(ctx->omaskkey, 4, ctx->user_data) !=
          0) {
        return WSLAY_ERR_INVALID_CALLBACK;
      } else {
        ctx->omask = 1;
        memcpy(wp, ctx->omaskkey, 4);
        wp += 4;
      }
    }

    ctx->hdrtow = wp - buf;
    assert(ctx->hdrtow <= sizeof(buf));

    iocb->data -= ctx->hdrtow;
    iocb->data_length += ctx->hdrtow;
    memcpy(iocb->data, buf, ctx->hdrtow);

    ctx->opayloadlen = iocb->data_length;
    ctx->opayloadoff = 0;
    ctx->opayloadmaskoff = 0;

    ctx->ostate = SEND_PAYLOAD;
  } else if (ctx->hdrtow) {
    iocb->data -= ctx->hdrtow;
    iocb->data_length += ctx->hdrtow;
  }
  if (ctx->ostate == SEND_HEADER) {
    ptrdiff_t len = ctx->oheaderlimit - ctx->oheadermark;
    ssize_t r;
    int flags = 0;
    if (iocb->data_length > 0) {
      flags |= WSLAY_MSG_MORE;
    };
    r = ctx->callbacks.send_callback(ctx->oheadermark, (size_t)len, flags,
                                     ctx->user_data);
    if (r > 0) {
      if (r > len) {
        return WSLAY_ERR_INVALID_CALLBACK;
      } else {
        ctx->oheadermark += r;
        if (ctx->oheadermark == ctx->oheaderlimit) {
          ctx->ostate = SEND_PAYLOAD;
        } else {
          return WSLAY_ERR_WANT_WRITE;
        }
      }
    } else {
      return WSLAY_ERR_WANT_WRITE;
    }
  }
  if (ctx->ostate == SEND_PAYLOAD) {
    ssize_t totallen = 0;

    if (iocb->data_length > 0) {
      if (ctx->omask) {
        uint8_t temp[4096];
        const uint8_t *datamark = iocb->data,
                      *datalimit = iocb->data + iocb->data_length;
        while (datamark < datalimit) {
          size_t i, datalen = (size_t) (datalimit - datamark);
          const uint8_t *writelimit
            = datamark + wslay_min(sizeof(temp), datalen);
          size_t writelen = (size_t) (writelimit - datamark);

          /* header part */
          for (i = 0; i < writelen && i < ctx->hdrtow; ++i) {
            temp[i] = datamark[i];
          }
          r = ctx->callbacks.send_callback(temp, writelen, 0, ctx->user_data);
          if (r > 0) {
            datamark += r;
            ctx->opayloadoff += (uint64_t) r;
            totallen += (ssize_t) r;

            ctx->opayloadmaskoff += r;
            if (ctx->hdrtow) {
              uint64_t hp = wslay_min(ctx->hdrtow, r);
              ctx->opayloadmaskoff -= hp;
              ctx->hdrtow -= hp;
              iocb->data += hp;
              iocb->data_length -= hp;
              totallen -= hp;
            }
          } else {
            if (totallen > 0) {
              break;
            } else {
              return WSLAY_ERR_WANT_WRITE;
            }
          }
        }
      } else {
        ssize_t r = ctx->callbacks.send_callback(iocb->data, iocb->data_length, 0, ctx->user_data);
        if (r > 0) {
          ctx->opayloadoff += (uint64_t) r;
          totallen = (ssize_t) r;
          if (ctx->hdrtow) {
            uint64_t hp = wslay_min(ctx->hdrtow, r);
            ctx->hdrtow -= hp;
            iocb->data += hp;
            iocb->data_length -= hp;
            totallen -= hp;
          }
        } else {
          return WSLAY_ERR_WANT_WRITE;
        }
      }
    }

    if (ctx->hdrtow) {
      /* Only part of header was sent */
      return WSLAY_ERR_WANT_WRITE;
    }

    if (ctx->opayloadoff == ctx->opayloadlen) {
      ctx->ostate = PREP_HEADER;
    }

    return totallen;
  }

  return WSLAY_ERR_INVALID_ARGUMENT;
}

static void wslay_shift_ibuf(wslay_frame_context_ptr ctx) {
  ptrdiff_t len = ctx->ibuflimit - ctx->ibufmark;
  memmove(ctx->ibuf, ctx->ibufmark, (size_t) len);
  ctx->ibuflimit = ctx->ibuf + len;
  ctx->ibufmark = ctx->ibuf;
}

static ssize_t wslay_recv(wslay_frame_context_ptr ctx) {
  ssize_t r;
  if (ctx->ibufmark != ctx->ibuf) {
    wslay_shift_ibuf(ctx);
  }
  r = ctx->callbacks.recv_callback(
    ctx->ibuflimit, (size_t) (ctx->ibuf + sizeof(ctx->ibuf) - ctx->ibuflimit),
    0, ctx->user_data);
  if (r > 0) {
    ctx->ibuflimit += r;
  } else {
    r = WSLAY_ERR_WANT_READ;
  }
  return r;
}

#define WSLAY_AVAIL_IBUF(ctx) ((size_t) (ctx->ibuflimit - ctx->ibufmark))

ssize_t wslay_frame_recv(
  wslay_frame_context_ptr  ctx,
  struct wslay_frame_iocb *iocb
  ) {
  ssize_t r;
  if (ctx->istate == RECV_HEADER1) {
    uint8_t fin, opcode, rsv, payloadlen;
    if (WSLAY_AVAIL_IBUF(ctx) < ctx->ireqread) {
      if ((r = wslay_recv(ctx)) <= 0) {
        return r;
      }
    }
    if (WSLAY_AVAIL_IBUF(ctx) < ctx->ireqread) {
      return WSLAY_ERR_WANT_READ;
    }
    fin = (ctx->ibufmark[0] >> 7) & 1;
    rsv = (ctx->ibufmark[0] >> 4) & 7;
    opcode = ctx->ibufmark[0] & 0xfu;
    ctx->iom.opcode = opcode;
    ctx->iom.fin = fin;
    ctx->iom.rsv = rsv;
    ++ctx->ibufmark;
    ctx->imask = (ctx->ibufmark[0] >> 7) & 1;
    payloadlen = ctx->ibufmark[0] & 0x7fu;
    ++ctx->ibufmark;
    if (wslay_is_ctrl_frame(opcode) && (payloadlen > 125 || !fin)) {
      return WSLAY_ERR_PROTO;
    }
    if (payloadlen == 126) {
      ctx->istate = RECV_EXT_PAYLOADLEN;
      ctx->ireqread = 2;
    } else if (payloadlen == 127) {
      ctx->istate = RECV_EXT_PAYLOADLEN;
      ctx->ireqread = 8;
    } else {
      ctx->ipayloadlen = payloadlen;
      ctx->ipayloadoff = 0;
      if (ctx->imask) {
        ctx->istate = RECV_MASKKEY;
        ctx->ireqread = 4;
      } else {
        ctx->istate = RECV_PAYLOAD;
      }
    }
  }
  if (ctx->istate == RECV_EXT_PAYLOADLEN) {
    if (WSLAY_AVAIL_IBUF(ctx) < ctx->ireqread) {
      if ((r = wslay_recv(ctx)) <= 0) {
        return r;
      }
      if (WSLAY_AVAIL_IBUF(ctx) < ctx->ireqread) {
        return WSLAY_ERR_WANT_READ;
      }
    }
    ctx->ipayloadlen = 0;
    ctx->ipayloadoff = 0;
    memcpy((uint8_t*) &ctx->ipayloadlen + (8 - ctx->ireqread), ctx->ibufmark,
           ctx->ireqread);
    ctx->ipayloadlen = ntoh64(ctx->ipayloadlen);
    ctx->ibufmark += ctx->ireqread;
    if (ctx->ireqread == 8) {
      if (ctx->ipayloadlen < (1 << 16) || ctx->ipayloadlen & (1ull << 63)) {
        return WSLAY_ERR_PROTO;
      }
    } else if (ctx->ipayloadlen < 126) {
      return WSLAY_ERR_PROTO;
    }
    if (ctx->imask) {
      ctx->istate = RECV_MASKKEY;
      ctx->ireqread = 4;
    } else {
      ctx->istate = RECV_PAYLOAD;
    }
  }
  if (ctx->istate == RECV_MASKKEY) {
    if (WSLAY_AVAIL_IBUF(ctx) < ctx->ireqread) {
      if ((r = wslay_recv(ctx)) <= 0) {
        return r;
      }
      if (WSLAY_AVAIL_IBUF(ctx) < ctx->ireqread) {
        return WSLAY_ERR_WANT_READ;
      }
    }
    memcpy(ctx->imaskkey, ctx->ibufmark, 4);
    ctx->ibufmark += 4;
    ctx->istate = RECV_PAYLOAD;
  }
  if (ctx->istate == RECV_PAYLOAD) {
    uint8_t *readlimit, *readmark;
    uint64_t rempayloadlen = ctx->ipayloadlen - ctx->ipayloadoff;
    if (WSLAY_AVAIL_IBUF(ctx) == 0 && rempayloadlen > 0) {
      if ((r = wslay_recv(ctx)) <= 0) {
        return r;
      }
    }
    readmark = ctx->ibufmark;
    readlimit = WSLAY_AVAIL_IBUF(ctx) < rempayloadlen
                ? ctx->ibuflimit
                : ctx->ibufmark + rempayloadlen;
    if (ctx->imask) {
      for ( ; ctx->ibufmark != readlimit; ++ctx->ibufmark, ++ctx->ipayloadoff) {
        ctx->ibufmark[0] ^= ctx->imaskkey[ctx->ipayloadoff % 4];
      }
    } else {
      ctx->ibufmark = readlimit;
      ctx->ipayloadoff += (uint64_t) (readlimit - readmark);
    }
    iocb->fin = ctx->iom.fin;
    iocb->rsv = ctx->iom.rsv;
    iocb->opcode = ctx->iom.opcode;
    iocb->payload_length = ctx->ipayloadlen;
    iocb->mask = ctx->imask;
    iocb->data = readmark;
    iocb->data_length = (size_t) (ctx->ibufmark - readmark);
    if (ctx->ipayloadlen == ctx->ipayloadoff) {
      ctx->istate = RECV_HEADER1;
      ctx->ireqread = 2;
    }
    return (ssize_t) iocb->data_length;
  }
  return WSLAY_ERR_INVALID_ARGUMENT;
}
