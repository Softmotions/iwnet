#include "iwn_tests.h"
#include "iwn_grpc_client.h"

#include <iowow/iwarr.h>
#include <iowow/iwconv.h>
#include <iowow/iwpool.h>
#include <getopt.h>
#include <string.h>

static struct _ctx {
  struct iwpool *pool;
  char *connect_url;
  struct iwulist messages; /// struct iwn_val
} ctx;

static void _ctx_destroy(void) {
  iwulist_destroy_keep(&ctx.messages);
  iwpool_destroy(ctx.pool);
}

int main(int argc, char *argv[]) {
  iwrc rc = 0;
  ssize_t len;
  struct iwpool *pool = iwpool_create_empty();
  RCB(finish, pool);

  ctx.pool = pool;
  iwulist_init(&ctx.messages, 3, sizeof(struct iwn_val));

  static const struct option long_options[] = {
    "message", 1, 0, 'm',
    "connect", 1, 0, 'c',
    0
  };

  for (int ch; (ch = getopt_long(argc, argv, "m:c:", long_options, 0)) != -1; ) {
    switch (ch) {
      case 'm': {
        struct iwn_val v = { 0 };
        len = v.len = strlen(optarg);
        if (v.len & 0x01) {
          v.len++;
        }
        v.len /= 2;
        IWN_ASSERT_FATAL(v.len > 0);
        RCB(finish, v.buf = iwpool_calloc(v.len, pool));
        v.len = iwhex2bin(optarg, len, v.buf, len);
        RCC(rc, finish, iwulist_push(&ctx.messages, &v));
      }
      break;
      case 'c':
        RCB(finish, ctx.connect_url = iwpool_strdup2(pool, optarg));
        break;
      default:
        fprintf(stderr, "Invalid option provided\n");
        rc = IW_ERROR_INVALID_ARGS;
        goto finish;
    }
  }


finish:
  if (rc) {
    iwlog_ecode_error3(rc);
  }
  IWN_ASSERT(rc == 0);
  iwpool_destroy(pool);
  return iwn_assertions_failed > 0 ? 1 : 0;
}
