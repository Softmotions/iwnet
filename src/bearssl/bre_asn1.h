#pragma once

#include <stdint.h>
#include "bre_pool.h"

#define ASN1_MAX_OBJECT_ID_OCTETS 16

typedef unsigned char asn1_tag_t;

struct asn1_node;
struct asn1_oid;

struct asn1 {
  struct pool      *pool;
  struct asn1_node *root;
  const char       *error;
};

typedef size_t (*asn1_node_write)(struct asn1_node *n, void *out_buf);

struct asn1_oid {
  int value[ASN1_MAX_OBJECT_ID_OCTETS];
};

struct asn1_node {
  asn1_tag_t       tag;
  struct asn1      *asn1;
  struct asn1_node *child;
  struct asn1_node *next;
  asn1_node_write  write;
  uint32_t flags;
  int      vlen;
  union {
    int64_t    vi64;
    const void *vptr;
    struct asn1_oid vid;
  };
};

#define ASN1_STRING_COPY 0x01U

struct asn1_node *asn1_integer_add(struct asn1 *asn1, int64_t val, struct asn1_node *parent);

struct asn1_node *asn1_oid_add(struct asn1 *asn1, const char *oid, struct asn1_node *parent);

struct asn1_node *asn1_string_add(
  struct asn1 *asn1, asn1_tag_t tag, const void *data, size_t len,
  uint32_t flags, struct asn1_node *parent);

struct asn1_node *asn1_container_add(struct asn1 *asn1, asn1_tag_t tag, struct asn1_node *parent);

void *asn1_der_allocated(struct asn1 *asn1, struct asn1_node *n, size_t *out_size);
