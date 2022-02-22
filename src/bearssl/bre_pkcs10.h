#pragma once

#include "bre_base.h"

/**
 * @brief Certificate request
 */
typedef struct {
  bre_subject       subj;
  br_ec_private_key sk;
  const br_hash_class *signature_hc;
} bre_ec_csr;

/**
 * @brief Generate CSR in DER format.
 * @note Returned DER buffer should be freed by `br_deallocate`
 * @see pkcs10.c
 *
 * @param alloc Dynamic memory allocator.
 * @param csr Certificate request specification.
 * @param out_len Length of resulting DER buffer.
 * @param out_err Placeholde for error string. Can be zero.
 * @return DER encoded CSR or zero in the case of error.
 */
uint8_t *bre_csr_ec_der_create(
  bre_alloc        alloc,
  bre_dealloc      dealloc,
  const bre_ec_csr *csr,
  size_t           *out_len,
  const char       **out_err);


uint8_t *bre_csr_ec_pem_create(
  bre_alloc        alloc,
  bre_dealloc      dealloc,
  const bre_ec_csr *csr,
  size_t           *out_len,
  const char       **out_err);
