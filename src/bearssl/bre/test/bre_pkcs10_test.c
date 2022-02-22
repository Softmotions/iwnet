#include "bre.h"
#include "bre_internal.h"

#include <stdio.h>

#define IERR 1

int main(int argc, char *argv[]) {
  int irc = 0;
  br_hmac_drbg_context rng;
  unsigned char skey_buf[BR_EC_KBUF_PRIV_MAX_SIZE];

  bre_ec_csr csr = {
    .signature_hc = &br_sha512_vtable,
    .subj         = {
      .cn         = "greenrooms.softmotions.com",
      .dns_name   = "greenrooms.softmotions.com",
      .email      = "info@softmotions.com"
    }
  };

  br_hmac_drbg_init(&rng, &br_sha256_vtable, "898a5fe5-f643-4900-be77-39abcdb69c08", 36);
  br_hmac_drbg_update(&rng, "b19cc4b7-0072-41ce-9b42-f361ac8cc82d", 36);
  br_ec_keygen(&rng.vtable, &br_ec_prime_i31, &csr.sk, skey_buf, BR_EC_secp256r1);

  size_t len;
  const char *err = 0;

  void *buf = bre_csr_ec_pem_create(malloc, free, &csr, &len, &err);
  if (!buf) {
    irc = IERR;
    goto finish;
  }

  FILE *out = fopen("pkcs10.pem", "w");
  if (!out) {
    irc = IERR;
    goto finish;
  }
  if (fwrite(buf, len, 1, out) != 1) {
    irc = IERR;
  }
  fclose(out);

finish:
  free(buf);
  if (irc) {
    fprintf(stderr, "%s\n", err ? err : "Error");
  }
  return irc;
}
