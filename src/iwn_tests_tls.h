#pragma once
#ifndef IWN_TESTS_TLS_H
#define IWN_TESTS_TLS_H

/// Helpers used by iwnet test cases to select the TLS implementation under test.
///
/// The implementation is chosen by the `IWN_TEST_TLS` environment variable:
/// `s2n` selects ::IWN_TLS_IMPL_S2N, any other value or an unset variable
/// selects the default ::IWN_TLS_IMPL_BEARSSL.

#include "iwn_tls.h"

#include <stdlib.h>
#include <string.h>

static inline iwn_tls_impl_e iwn_test_tls_impl(void) {
  const char *impl = getenv("IWN_TEST_TLS");
  if (impl && strcmp(impl, "s2n") == 0) {
    return IWN_TLS_IMPL_S2N;
  }
  return IWN_TLS_IMPL_BEARSSL;
}

#endif
