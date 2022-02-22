
#include "bre_asn1.h"
#include "bre_utils.h"
#include "bre_internal.h"

static size_t _tag_write(asn1_tag_t tag, void *out_buf) {
  if (out_buf) {
    *((unsigned char*) out_buf) = tag;
  }
  // todo: aware multibyte tags
  return 1;
}

static struct asn1_node *_node_register(struct asn1_node *parent, struct asn1_node *child) {
  if (parent) {
    if (parent->child) {
      struct asn1_node *s = parent->child;
      while (s->next) {
        s = s->next;
      }
      s->next = child;
    } else {
      parent->child = child;
    }
  }
  return child;
}

static size_t _node_header_write(struct asn1_node *n, size_t len, void *out_buf) {
  int c = 0;
  asn1_tag_t tag = n->tag;
  if (len > 127) {
    c = 1;
    while (len >> (c << 3)) {
      c++;
    }
  }
  if (!out_buf) {
    return _tag_write(tag, 0) + c + 1;
  }
  uint8_t *sp = out_buf, *wp = sp;
  wp += _tag_write(tag, wp);
  if (c > 0) {
    *wp++ = 0x80 | c;
    while (c--) {
      *wp++ = (len >> (c << 3)) & 0xff;
    }
  } else {
    *wp++ = len & 0x7f;
  }
  return wp - sp;
}

static size_t _integer_write(struct asn1_node *n, void *out_buf) {
  int64_t vi64 = n->vi64;
  uint8_t nbuf[sizeof(vi64) + 1];
  uint8_t *wp = nbuf, bv;
  int i = sizeof(vi64) * 8, skip_zero, skip_sign;

  if (vi64 < 0) {
    skip_sign = 1;
    skip_zero = 0;
  } else {
    skip_sign = 0;
    skip_zero = 1;
  }

  do {
    i -= 8;
    bv = vi64 >> i;
    if (skip_sign) {
      if (bv != 0xff) {
        skip_sign = 0;
      }
      if (bv & 0x80) {
        *wp = bv;
        if (bv == 0xff) {
          continue;
        }
      } else {
        wp++;
        skip_sign = 0;
      }
    }
    if ((bv == 0) && skip_zero) {
      continue;
    }
    if (skip_zero) {
      skip_zero = 0;
      if (((bv & 0x80) != 0) && (vi64 > 0)) {
        *wp++ = 0;
      }
    }
    *wp++ = bv;
  } while (i > 0);
  if (skip_sign) {
    wp++;
  }
  size_t sz = wp - nbuf;
  if (sz == 0) {
    sz = 1;
    nbuf[0] = 0;
  }
  size_t ret = _node_header_write(n, sz, out_buf);
  if (out_buf) {
    memcpy((uint8_t*) out_buf + ret, nbuf, sz);
  }
  return ret + sz;
}

struct asn1_node *asn1_integer_add(struct asn1 *asn1, int64_t val, struct asn1_node *parent) {
  struct asn1_node *n = pool_alloc(sizeof(*n), asn1->pool);
  if (!n) {
    asn1->error = BRE_ERROR(ALLOC);
    return 0;
  }
  *n = (struct asn1_node) {
    .tag = 0x02,
    .asn1 = asn1,
    .vi64 = val,
    .write = _integer_write
  };
  return _node_register(parent, n);
}

static size_t _bitstring_write(struct asn1_node *n, void *out_buf) {
  int bits_left = n->vlen;
  int vlen = (bits_left + 7) / 8 + 1;
  if (!out_buf) {
    return _node_header_write(n, vlen, 0) + vlen;
  }
  int unused = 0;
  uint8_t *sp = out_buf, *wp = sp;
  const char *rp = n->vptr;
  wp += _node_header_write(n, vlen, wp);
  uint8_t *bsp = wp;
  wp++;
  while (bits_left) {
    int bits = 8;
    *wp = 0;
    if (bits_left < 8) {
      bits = bits_left;
      unused = 8 - bits_left;
      for (int i = 0; i < bits; ++i) {
        *wp |= ((*rp >> i) & 1) << i;
      }
    } else {
      *wp = *rp;
    }
    bits_left -= bits;
    wp++, rp++;
  }
  bsp[0] = unused;
  return wp - sp;
}

static size_t _string_write(struct asn1_node *n, void *out_buf) {
  if (!out_buf) {
    return _node_header_write(n, n->vlen, 0) + n->vlen;
  }
  size_t ret = _node_header_write(n, n->vlen, out_buf);
  memcpy((uint8_t*) out_buf + ret, n->vptr, n->vlen);
  return ret + n->vlen;
}

struct asn1_node *asn1_string_add(
  struct asn1 *asn1, asn1_tag_t tag, const void *data, size_t len,
  uint32_t flags, struct asn1_node *parent) {

  struct asn1_node *n = pool_alloc(sizeof(*n), asn1->pool);
  if (!n) {
    asn1->error = BRE_ERROR(ALLOC);
    return 0;
  }

  *n = (struct asn1_node) {
    .tag = tag,
    .asn1 = asn1,
    .flags = flags,
    .vptr = data,
    .vlen = len
  };

  switch (tag) {
    case 0x0c: // UTF8 String
    case 0x04: // Octet string
    case 0x13: // Printable string
    case 0x16: // IA5 String
      n->write = _string_write;
      break;
    case 0x03: // Bit string
      n->write = _bitstring_write;
      break;
    default:
      if ((tag >> 7) & 1) {
        // Content specific / private tag
        n->write = _string_write;
        break;
      } else {
        asn1->error = BRE_ERROR(INVALID_ARGUMENT);
        return 0;
      }
  }

  if (flags & ASN1_STRING_COPY) {
    size_t vlen = len;
    if (tag == 0x03) {
      vlen = (len + 7) / 8 + 1;
    }
    void *nb = pool_alloc(vlen, asn1->pool);
    if (!nb) {
      asn1->error = BRE_ERROR(ALLOC);
      return 0;
    }
    memcpy(nb, n->vptr, vlen);
    n->vptr = nb;
  }

  return _node_register(parent, n);
}

static size_t _oid_write(struct asn1_node *n, void *out_buf) {

  uint8_t buf[ASN1_MAX_OBJECT_ID_OCTETS * 5], *wp = buf;
  struct asn1_oid *oid = &n->vid;

  if ((oid->value[0] == -1) || (oid->value[1] == -1)) {
    n->asn1->error = BRE_ERROR(INVALID_ARGUMENT);
  }

  for (int i = 0; i < ASN1_MAX_OBJECT_ID_OCTETS && oid->value[i] != -1; ++i) {
    unsigned shift, k = oid->value[i];
    switch (i) {
      case 0:
        if (k > 2) {
          n->asn1->error = BRE_ERROR(INVALID_ARGUMENT);
          return 0;
        }
        *wp = k * 40;
        break;
      case 1:
        if ((k > 39) && (oid->value[0] < 2)) {
          n->asn1->error = BRE_ERROR(INVALID_ARGUMENT);
          return 0;
        }
        k += *wp;
      /* fall through */
      default:
        shift = 28;
        while (shift && (k >> shift) == 0) {
          shift -= 7;
        }
        while (shift) {
          *wp++ = 0x80 | ((k >> shift) & 0x7f);
          shift -= 7;
        }
        *wp++ = k & 0x7F;
        break;
    }
  }
  size_t ret = _node_header_write(n, wp - buf, out_buf);
  if (!out_buf) {
    return ret + wp - buf;
  }
  memcpy((uint8_t*) out_buf + ret, buf, wp - buf);
  return ret + wp - buf;
}

static struct asn1_node *_asn1_add_oid(struct asn1 *asn1, struct asn1_oid *oid, struct asn1_node *parent) {
  struct asn1_node *n = pool_alloc(sizeof(*n), asn1->pool);
  if (!n) {
    asn1->error = BRE_ERROR(ALLOC);
    return 0;
  }
  *n = (struct asn1_node) {
    .tag = 0x6,
    .asn1 = asn1,
    .vid = *oid,
    .write = _oid_write
  };
  return _node_register(parent, n);
}

struct asn1_node *asn1_oid_add(struct asn1 *asn1, const char *oid, struct asn1_node *parent) {
  struct asn1_oid aoid;
  const char *sp = oid, *rp = sp;
  int i = 0;
  while (i < ASN1_MAX_OBJECT_ID_OCTETS - 1) {
    if ((*rp == '.') || (*rp == '\0')) {
      if (rp == sp) {
        asn1->error = BRE_ERROR(INVALID_ARGUMENT);
        return 0;
      }
      aoid.value[i++] = (int) bre_atoi(sp, rp - sp);
      if (*rp == '\0') {
        break;
      }
      rp++;
      sp = rp;
    } else {
      rp++;
    }
  }
  aoid.value[i] = -1;
  return _asn1_add_oid(asn1, &aoid, parent);
}

static size_t _container_write(struct asn1_node *n, void *out_buf) {
  size_t sz = 0, ret;
  uint8_t *wp = out_buf;
  for (struct asn1_node *nn = n->child; nn; nn = nn->next) {
    sz += ZRET(0, nn->write(nn, 0));
  }
  ret = _node_header_write(n, sz, wp);
  if (!out_buf) {
    return ret + sz;
  }
  wp += ret;
  for (struct asn1_node *nn = n->child; nn; nn = nn->next) {
    wp += ZRET(0, nn->write(nn, wp));
  }
  return ret + sz;
}

struct asn1_node *asn1_container_add(struct asn1 *asn1, asn1_tag_t tag, struct asn1_node *parent) {
  struct asn1_node *n = pool_alloc(sizeof(*n), asn1->pool);
  if (!n) {
    asn1->error = BRE_ERROR(ALLOC);
    return 0;
  }
  *n = (struct asn1_node) {
    .tag = tag,
    .asn1 = asn1,
    .write = _container_write
  };
  return _node_register(parent, n);
}

void *asn1_der_allocated(struct asn1 *asn1, struct asn1_node *n, size_t *out_size) {
  *out_size = 0;
  size_t sz = n->write(n, 0);
  if (!sz) {
    asn1->error = BRE_ERROR(FAILED);
    return 0;
  }
  uint8_t *buf = asn1->pool->alloc(sz);
  if (!buf) {
    asn1->error = BRE_ERROR(ALLOC);
    return 0;
  }
  size_t sz2 = n->write(n, buf);
  if (sz != sz2) {
    asn1->pool->dealloc(buf);
    asn1->error = BRE_ERROR(FAILED);
    return 0;
  }
  *out_size = sz;
  return buf;
}
