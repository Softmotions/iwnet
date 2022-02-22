#include "bre_asn1.h"
#include "bre_pkcs10.h"
#include "bre_base64.h"
#include "bre_internal.h"

/*
   CertificationRequestInfo ::= SEQUENCE {
        version       INTEGER { v1(0) } (v1,...),
        subject       Name,
        subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
        attributes    [0] Attributes{{ CRIAttributes }}
   }

   SubjectPublicKeyInfo { ALGORITHM : IOSet} ::= SEQUENCE {
        algorithm        AlgorithmIdentifier {{IOSet}},
        subjectPublicKey BIT STRING
   }

   CertificationRequest ::= SEQUENCE {
        certificationRequestInfo CertificationRequestInfo,
        signatureAlgorithm AlgorithmIdentifier{{ SignatureAlgorithms }},
        signature          BIT STRING
   }
 */

static struct asn1_node *_cri_subject_add(const bre_ec_csr *csr, struct asn1_node *cri) {
  struct asn1 *asn = cri->asn1;
  struct asn1_node *root = ZRET(0, asn1_container_add(asn, 0x30, cri));
  struct asn1_node *cont = ZRET(0, asn1_container_add(asn, 0x31, root));
  cont = ZRET(0, asn1_container_add(asn, 0x30, cont));

  ZRET(0, asn1_oid_add(asn, "2.5.4.3", cont));
  ZRET(0, asn1_string_add(asn, 0x0c, csr->subj.cn, strlen(csr->subj.cn), 0, cont));
  if (csr->subj.email) {
    cont = ZRET(0, asn1_container_add(asn, 0x31, root));
    cont = ZRET(0, asn1_container_add(asn, 0x30, cont));
    ZRET(0, asn1_oid_add(asn, "1.2.840.113549.1.9.1", cont));
    ZRET(0, asn1_string_add(asn, 0x16, csr->subj.email, strlen(csr->subj.email), 0, cont));
  }
  return root;
}

static struct asn1_node *_cri_ec_key_add(const bre_ec_csr *csr, struct asn1_node *cri) {

  br_ec_public_key pk;
  unsigned char pkbuf[255];

  ZRET(0, br_ec_compute_pub(br_ec_get_default(), &pk, pkbuf, &csr->sk));

  struct asn1 *asn = cri->asn1;
  struct asn1_node *root = ZRET(0, asn1_container_add(asn, 0x30, cri));
  struct asn1_node *n = ZRET(0, asn1_container_add(asn, 0x30, root));

  ZRET(0, asn1_oid_add(asn, "1.2.840.10045.2.1", n));

  switch (pk.curve) {
    case BR_EC_secp256r1:
      ZRET(0, asn1_oid_add(asn, "1.2.840.10045.3.1.7", n));
      break;
    case BR_EC_secp384r1:
      ZRET(0, asn1_oid_add(asn, "1.3.132.0.34", n));
      break;
    case BR_EC_secp521r1:
      ZRET(0, asn1_oid_add(asn, "1.3.132.0.35", n));
      break;
    default:
      asn->error = BRE_ERROR(UNSUPPORTED_EC_PK);
      return 0;
  }

  ZRET(0, asn1_string_add(asn, 0x03, pk.q, pk.qlen * 8, ASN1_STRING_COPY, root));
  return root;
}

static struct asn1_node *_cri_extension_add(const bre_ec_csr *csr, struct asn1_node *cri) {

  struct asn1 *asn = cri->asn1;
  struct asn1_node *root = ZRET(0, asn1_container_add(asn, 0xa0, cri)); // C-[0]
  struct asn1_node *cont = ZRET(0, asn1_container_add(asn, 0x30, root));

  ZRET(0, asn1_oid_add(asn, "1.2.840.113549.1.9.14", cont));
  cont = ZRET(0, asn1_container_add(asn, 0x31, cont));

  if (csr->subj.dns_name) {
    // See https://tools.ietf.org/html/rfc5280#section-4.2.1.6

    struct asn1_node *ext = ZRET(0, asn1_container_add(asn, 0x30, cont));
    ext = ZRET(0, asn1_container_add(asn, 0x30, ext));
    ZRET(0, asn1_oid_add(asn, "2.5.29.17", ext));

    // 04 Octet String  1e (30)
    cont = ZRET(0, asn1_container_add(asn, 0x04, ext));
    // C-Sequence
    cont = ZRET(0, asn1_container_add(asn, 0x30, cont));
    // Content specific tag [2]
    ZRET(0, asn1_string_add(asn, 0x82, csr->subj.dns_name, strlen(csr->subj.dns_name), 0, cont));
  }

  return root;
}

static struct asn1_node *_cri_sign(void *cri_der, size_t cri_der_len, const bre_ec_csr *csr, struct asn1_node *cr) {

  struct asn1 *asn = cr->asn1;

  // Comment from br_ecdsa_raw_to_asn1()
  // Internal buffer is large enough to accommodate a signature
  // such that r and s fit on 125 bytes each (signed encoding),
  // meaning a curve order of up to 999 bits. This is the limit
  // that ensures "simple" length encodings.

  unsigned char sig[257];

  br_hash_compat_context hc;
  hc.vtable = csr->signature_hc;

  // Compute hash of CertificationRequest
  size_t hash_len = (hc.vtable->desc >> BR_HASHDESC_OUT_OFF) & BR_HASHDESC_OUT_MASK;
  unsigned char hash_cri[hash_len];

  hc.vtable->init(&hc.vtable);
  hc.vtable->update(&hc.vtable, cri_der, cri_der_len);
  hc.vtable->out(&hc.vtable, hash_cri);

  br_ecdsa_sign s = br_ecdsa_sign_asn1_get_default();
  size_t sig_len = s(br_ec_get_default(), csr->signature_hc, hash_cri, &csr->sk, sig);
  if (sig_len == 0) {
    asn->error = BRE_ERROR0("Failed to generate EC signature");
    return 0;
  }

  const char *oid_ecsda;
  switch ((hc.vtable->desc >> BR_HASHDESC_ID_OFF) & BR_HASHDESC_ID_MASK) {
    case br_sha512_ID:
      oid_ecsda = "1.2.840.10045.4.3.4";
      break;
    case br_sha384_ID:
      oid_ecsda = "1.2.840.10045.4.3.3";
      break;
    case br_sha256_ID:
      oid_ecsda = "1.2.840.10045.4.3.2";
      break;
    case br_sha224_ID:
      oid_ecsda = "1.2.840.10045.4.3.1";
      break;
    default:
      asn->error = "Unsupported ECDSA hash function";
      return 0;
  }

  struct asn1_node *n = ZRET(0, asn1_container_add(asn, 0x30, cr));
  ZRET(0, asn1_oid_add(asn, oid_ecsda, n));
  ZRET(0, asn1_string_add(asn, 0x03, sig, sig_len * 8, ASN1_STRING_COPY, cr));

  return cr;
}

uint8_t *bre_csr_ec_der_create(
  bre_alloc         alloc,
  bre_dealloc       dealloc,
  const bre_ec_csr *csr,
  size_t           *out_len,
  const char      **out_err) {

  *out_err = 0;
  *out_len = 0;

  void *der = 0, *der_ret = 0;
  size_t der_len;

  struct asn1 asn = {
    .pool = pool_create(alloc, dealloc, 0)
  };
  if (!asn.pool) {
    *out_err = BRE_ERROR(ALLOC);
    goto finish;
  }


  // CertificationRequest ::= SEQUENCE {
  //       certificationRequestInfo CertificationRequestInfo,
  //       signatureAlgorithm AlgorithmIdentifier{{ SignatureAlgorithms }},
  //       signature          BIT STRING
  struct asn1_node *cr = ZGO(finish, asn1_container_add(&asn, 0x30, 0));

  // CertificationRequestInfo ::= SEQUENCE {
  //       version       INTEGER { v1(0) } (v1,...),
  //       subject       Name,
  //       subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
  //       attributes    [0] Attributes{{ CRIAttributes }}
  //  }
  struct asn1_node *cri = ZGO(finish, asn1_container_add(&asn, 0x30, cr));

  // CertificationRequestInfo::version
  ZGO(finish, asn1_integer_add(&asn, 0, cri));

  // CertificationRequestInfo::subject
  ZGO(finish, _cri_subject_add(csr, cri));

  // CertificationRequestInfo::subjectPKInfo
  ZGO(finish, _cri_ec_key_add(csr, cri));

  // CertificationRequestInfo::attributes
  if (csr->subj.dns_name) {
    ZGO(finish, _cri_extension_add(csr, cri));
  }

  // Convert CertificationRequestInfo into DER in order to sign
  der = ZGO(finish, asn1_der_allocated(&asn, cri, &der_len));
  ZGO(finish, _cri_sign(der, der_len, csr, cr));
  dealloc(der), der = 0;

  // Compute final CSR DER
  der_ret = asn1_der_allocated(&asn, cr, out_len);

finish:
  *out_err = asn.error;
  dealloc(der);
  pool_destroy(asn.pool);
  return der_ret;
}

uint8_t *bre_csr_ec_pem_create(
  bre_alloc         alloc,
  bre_dealloc       dealloc,
  const bre_ec_csr *csr,
  size_t           *out_len,
  const char      **out_err) {

  *out_len = 0;
  *out_err = 0;
  uint8_t *b64 = 0;

  size_t olen;

  void *der = bre_csr_ec_der_create(alloc, dealloc, csr, &olen, out_err);
  if (!der) {
    return 0;
  }

  b64 = base64_encode(alloc, der, olen, out_len,
                      "-----BEGIN CERTIFICATE REQUEST-----",
                      "-----END CERTIFICATE REQUEST-----", 0);
  if (!b64) {
    *out_err = BRE_ERROR(ALLOC);
    goto finish;
  }

finish:
  dealloc(der);
  if (*out_err) {
    dealloc(b64);
  }
  return b64;
}
