
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <stdint.h>

#define NSIZE 1024
#define STR(x_) #x_
#define Q(x_)   STR(x_)

struct node {
  char *name;
  struct node *ctype;
  struct node *nnext;
  struct node *hnext;
} *enodes[NSIZE], *nnode;

static inline uint32_t _h(const char *str) {
  unsigned char c;
  uint32_t hash = 5381;
  while ((c = *str++)) {
    hash = ((hash << 5) + hash) + c;
  }
  return hash;
}

static void _line(char *sp) {
  char *p1 = sp, *p2 = p1;
  if (*p1 == '#' || *p1 <= 32) {
    return;
  }
  while (*p1 > 32 && *p1 < 127) ++p1;

  p2 = p1;
  while (*p2 == ' ' || *p2 == '\t') ++p2;
  if (*p2 == '\0') {
    return;
  }

  struct node *n = malloc(sizeof(*n));
  n->name = strndup(sp, p1 - sp);
  n->hnext = 0;
  n->ctype = 0;

  p1 = p2;

  while (*p2 != '\0') {
    while (*p2 > 32 && *p2 < 127) ++p2;
    if (p2 > p1) {
      struct node *e = malloc(sizeof(*e));
      e->name = strndup(p1, p2 - p1);
      uint32_t b = _h(e->name) % NSIZE;
      e->ctype = n;

      if (!enodes[b]) {
        enodes[b] = e;
      } else {
        for (struct node *ee = enodes[b]; ee; ee = ee->hnext) {
          if (strcmp(ee->name, e->name) == 0) {
            break;
          }
          if (ee->hnext == 0) {
            ee->hnext = e;
            break;
          }
        }
      }
    } else {
      break;
    }
    while (*p2 == ' ' || *p2 == '\t' || *p2 == '\n' || *p2 == '\r') ++p2;
    p1 = p2;
  }

  n->nnext = nnode;
  nnode = n;
}

static void _code(FILE *f) {
  char fbuf[1024];

  #define WF(f_, ...) \
  do { \
    int n = snprintf(fbuf, sizeof(fbuf), f_, __VA_ARGS__); \
    fwrite(fbuf, n, 1, f); \
  } while (0)

  #define WW(f_) fwrite(f_, sizeof(f_) - 1, 1, f)

  WW("#include <string.h>\n");
  WW("#include <stdint.h>\n\n");
  const char hf[]
    = "static inline uint32_t _hash(const char *str) {\n"
      "  unsigned char c;\n"
      "  uint32_t hash = 5381;\n"
      "  while ((c = *str++)) {\n"
      "    hash = ((hash << 5) + hash) + c;\n"
      "  }\n"
      "  return hash;\n"
      "}\n";
  WW(hf);
  WW("static const char* _mimetype_find(const char *ext) {\n");
  WW("  uint32_t b = _hash(ext) % " Q(NSIZE) ";\n");
  WW("  switch(b) {\n");

  for (int i = 0; i < NSIZE; ++i) {
    if (!enodes[i]) {
      continue;
    }
    {
      WF("    case %d:\n", i);
    }
    struct node *e = enodes[i];
    while (e) {
      WF("      if (strcmp(ext, \"%s\") == 0) return \"%s\";\n", e->name, e->ctype->name);
      e = e->hnext;
    }
    {
      WW("      break;\n");
    }
  }

  WW("  }\n");
  WW("  return 0;\n");
  WW("}\n\n");

  #undef W
  #undef WF
}

int main(int argc, char *argv[]) {
  const char *path = argc > 1 ? argv[1] : "/etc/mime.types";
  char buf[4096];
  FILE *f = fopen(path, "r");
  if (!f) {
    fprintf(stderr, "Error reading file %s\n", path);
    return EXIT_FAILURE;
  }
  char *l;
  while ((l = fgets(buf, sizeof(buf), f))) {
    _line(l);
  }

  _code(stdout);

  fclose(f);
  return EXIT_SUCCESS;
}
