
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <stdint.h>

#define NSIZE 255

struct node {
  char *name;
  struct node *ctype;
  struct node *nnext;
  struct node *hnext;
  int h;
} *enodes[NSIZE], *nnode, *enode;

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
  n->h = 0;
  n->ctype = 0;
  n->hnext = 0;

  p1 = p2;

  while (*p2 != '\0') {
    while (*p2 > 32 && *p2 < 127) ++p2;
    if (p2 > p1) {
      struct node *e = malloc(sizeof(*e));
      e->name = strndup(p1, p2 - p1);
      e->ctype = n;
      e->h = _h(e->name);
      e->hnext = enodes[e->h % NSIZE];
      enodes[e->h % NSIZE] = n;
      if (enode) {
        e->nnext = enode;
      } else {
        enode = e;
        e->nnext = 0;
      }
    }
    p1 = p2;
  }

  if (nnode) {
    n->nnext = nnode;
  } else {
    nnode = n;
    n->nnext = 0;
  }
}

const char* _mime(const char *m) {
  int h = _h(m);
  switch (h) {
    case 112:
    case 223:
      return "zzz";
    case 222:
      return "aaa";
  }
  return 0;
}

static void _code(FILE *f) {
  const char *inc = "#include <stdint.h>\n\n";
  const char *hf
    = "static inline uint32_t _h(const char *str) {\n"
      "  unsigned char c;\n"
      "  uint32_t hash = 5381;\n"
      "  while ((c = *str++)) {\n"
      "    hash = ((hash << 5) + hash) + c;\n"
      "  }\n"
      "  return hash;\n"
      "}\n";
  fwrite(inc, sizeof(inc) - 1, 1, f);
  fwrite(hf, sizeof(hf) - 1, 1, f);
}

int main(int argc, char *argv[]) {
  const char *path = argc ? argv[0] : "/etc/mime.types";
  char buf[4096];
  FILE *f = fopen(path, "r");
  if (!f) {
    fprintf(stderr, "Error reading file %s\n", path);
  }
  char *l;
  while ((l = fgets(buf, sizeof(buf), f))) {
    _line(l);
  }

  _code(stdout);

  fclose(f);
  return EXIT_SUCCESS;
}
