#pragma once

#include "bearssl.h"

#include <stddef.h>
#include <stdint.h>

#define BRE_ERROR_ALLOC "Allocation failed "

#define BRE_ERROR_FAILED "Operation failed "

#define BRE_ERROR_OVERFLOW "Overflow "

#define BRE_ERROR_INVALID_ARGUMENT "Invalid argument "

#define BRE_ERROR_ASN_NOT_UTF8_STRING "Not an UTF8 string "

#define BRE_ERROR_ASN_NOT_IA5_STRING "Not an IA5 string "

#define BRE_ERROR_UNSUPPORTED_EC_PK "Unsupported EC Public key "

#define BRE_STRINGIFY(a_) #a_

#define __BRE_ERROR(err_, file_, line_) \
  (err_ file_ ":"  BRE_STRINGIFY(line_))

#define BRE_ERROR0(err_) \
  __BRE_ERROR(err_, __FILE__, __LINE__)

#define BRE_ERROR(err_) \
  __BRE_ERROR(BRE_ERROR_ ## err_, __FILE__, __LINE__)

#define BRE_ERROR_SET(err_, var_) \
  if (var_) *var_ = BRE_ERROR0(BRE_ERROR_ ## err_)

/**
 * @brief Abstract memory allocation function.
 */
typedef void* (*bre_alloc)(size_t);

/**
 * @brief Memory deallocation function.
 */
typedef void (*bre_dealloc)(void*);

/**
 * @brief Subject
 */
typedef struct {
  const char *cn;         /**< X520 Common Name. Required. */
  const char *email;      /**< PKCS #9 Email Address. */
  const char *dns_name;   /**< Certificate Subject Alt Name. DNS name. */
} bre_subject;
