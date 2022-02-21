
#include <stdlib.h>
#include <string.h>
#include <stdio.h>


static void on_line(const char *line) {

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
