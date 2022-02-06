#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char const *argv[]) {
  FILE *in = stdin;
  FILE *out = stdout;

  for (int c = 1; c < argc; ++c) {
    if (strcmp(argv[c], "-stderr") == 0) {
      out = stderr;
    }
  }

  int ch = 0;
  while ((ch = fgetc(in)) != EOF) {
    fputc(ch, out);
  }
  fflush(out);
  //sleep(1);
  return 0;
}
