#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

static void make_identifier(char *str) {
  char c;
  size_t i;
  for (i = 0; (c = str[i]) != '\0'; ++i) {
    if (!(
          ((c >= '0') && (c <= '9'))
          || ((c >= 'a') && (c <= 'z') )
          || ((c >= 'A') && (c <= 'Z') ))) {
      str[i] = '_';
    }
  }
}

/* strdup is actually a POSIX thing, not a C thing, so don't use it */
static char *dupstr(char *str) {
  size_t len = strlen(str);
  char *dup = malloc(len + 1);
  strcpy(dup, str);
  dup[len] = '\0';
  return dup;
}

static void usage(const char *argv0) {
  printf("Usage: %s [options] [infile] [outfile]\n", argv0);
  puts(
    "Options:\n"
    "\t-h, --help                  Show this help text\n"
    "\t--no-const                  Output mutable variables instead of consts\n"
    "\t--always-escape             Unconditionally escape every character\n"
    "\t-l, --line-length <length>  Specify how long a line should be\n"
    "\t-i, --ident <ident>         Overwrite the identifier instead of using the file name");
}

int main(int argc, char **argv) {
  int ret = 0;
  char *inp = "stdin", *outp = "stdout";
  FILE *inf = stdin, *outf = stdout;
  char *ident = NULL;
  char *buffer = NULL;
  char *conststr = "static const ";
  int alwaysescape = 0;
  size_t maxlength = 120;

  int argidx;
  for (argidx = 1; argidx < argc; ++argidx) {
    char *arg = argv[argidx];
    if ((arg[0] != '-') || (strcmp(arg, "--") == 0)) {
      break;
    }

    if ((strcmp(arg, "--help") == 0) || (strcmp(arg, "-h") == 0)) {
      usage(argv[0]);
      goto exit;
    } else if (strcmp(arg, "--no-const") == 0) {
      conststr = "";
    } else if (strcmp(arg, "--always-escape") == 0) {
      alwaysescape = 1;
    } else if ((strcmp(arg, "--line-length") == 0) || (strcmp(arg, "-l") == 0)) {
      if (argidx + 1 >= argc) {
        fprintf(stderr, "%s requires an argument\n", arg);
        goto fail;
      }
      maxlength = (size_t) atoi(argv[++argidx]);
    } else if ((strcmp(arg, "--ident") == 0) || (strcmp(arg, "-i") == 0)) {
      if (argidx + 1 >= argc) {
        fprintf(stderr, "%s requires an argument\n", arg);
        goto fail;
      }
      ident = dupstr(argv[++argidx]);
      make_identifier(ident);
    } else {
      fprintf(stderr, "Unknown option: %s\n", arg);
      usage(argv[0]);
      goto fail;
    }
  }

  if (argc - argidx == 0) {
    if (ident == NULL) {
      ident = dupstr("stdin");
    }
  } else if ((argc - argidx == 1) || (argc - argidx == 2)) {
    inp = argv[argidx];
    inf = fopen(inp, "rb");
    if (inf == NULL) {
      perror(inp);
      goto fail;
    }

    if (ident == NULL) {
      ident = dupstr(inp);
      make_identifier(ident);
    }

    if (argc - argidx == 2) {
      outp = argv[argidx + 1];
      outf = fopen(outp, "w");
      if (outf == NULL) {
        perror(outp);
        goto fail;
      }
    }
  } else {
    fprintf(stderr, "Unexpected number of non-option arguments: %i\n", argc - argidx);
    goto fail;
  }

  if (fprintf(outf, "%sunsigned char %s[] =\n\t\"", conststr, ident) < 0) {
    perror("write d");
    goto fail;
  }

  buffer = malloc(maxlength + 4);

  size_t linechar = 0;
  size_t length = 0;
  int c;
  while ((c = fgetc(inf)) != EOF) {
    if (alwaysescape) {
      buffer[linechar++] = '\\';
      buffer[linechar++] = '0' + ((c & 0700) >> 6);
      buffer[linechar++] = '0' + ((c & 0070) >> 3);
      buffer[linechar++] = '0' + ((c & 0007) >> 0);
    } else if ((c >= 32) && (c <= 126) && (c != '"') && (c != '\\') && (c != '?') && (c != ':') && (c != '%')) {
      buffer[linechar++] = (char) c;
    } else if (c == '\r') {
      buffer[linechar++] = '\\';
      buffer[linechar++] = 'r';
    } else if (c == '\n') {
      buffer[linechar++] = '\\';
      buffer[linechar++] = 'n';
    } else if (c == '\t') {
      buffer[linechar++] = '\\';
      buffer[linechar++] = 't';
    } else if (c == '\"') {
      buffer[linechar++] = '\\';
      buffer[linechar++] = '"';
    } else if (c == '\\') {
      buffer[linechar++] = '\\';
      buffer[linechar++] = '\\';
    } else {
      buffer[linechar++] = '\\';
      buffer[linechar++] = '0' + ((c & 0700) >> 6);
      buffer[linechar++] = '0' + ((c & 0070) >> 3);
      buffer[linechar++] = '0' + ((c & 0007) >> 0);
    }

    length += 1;

    if (linechar >= maxlength) {
      if (fwrite(buffer, 1, linechar, outf) != linechar) {
        perror("write");
        goto fail;
      }

      if (fwrite("\"\n\t\"", 1, 4, outf) != 4) {
        perror("write");
        goto fail;
      }

      linechar = 0;
    }
  }

  if (linechar >= 1) {
    if (fwrite(buffer, 1, linechar, outf) != linechar) {
      perror("write b");
      goto fail;
    }
  }

  if (ferror(inf)) {
    perror("read");
    goto fail;
  }

  if (fprintf(outf, "\";\n%sunsigned int %s_len = %u;\n",
              conststr, ident, (unsigned int) length) < 0) {
    perror("write c");
    goto fail;
  }

  if (fclose(inf) == EOF) {
    perror("close");
    goto fail;
  }

  if (fclose(outf) == EOF) {
    perror("close");
    goto fail;
  }

exit:
  free(ident);
  free(buffer);
  return ret;

fail:
  ret = 1;
  goto exit;
}
