
#include "utils/tests.h"
#include "http_server.h"

int main(int argc, char *argv[]) {
  iwrc rc = 0;
  iwlog_init();


  return iwn_asserts_failed > 0 ? 1 : 0;
}

