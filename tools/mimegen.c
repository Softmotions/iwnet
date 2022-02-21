
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

struct node {
  char *name;
  struct node *ext;
  struct node *next;
} *nodes;

static void on_line(const char *line) {
  char *sp = line;
  if (*sp == '#' || isspace(*sp)) {
    return;
  }
  while (*sp && isspace(*sp)) ++sp;
}

static void code_write(FILE *f) {

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
    on_line(l);
  }

  code_write(stdout);

  fclose(f);
  return EXIT_SUCCESS;
}
