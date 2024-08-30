#pragma once

/// In-memory session store.
/// This is a default store used by `iwn_wf_create()`
/// @warning Avoid use it in production.

#include "iwn_wf.h"

IW_EXTERN_C_START;

/// Initialize iwn_wf_session_store `fout_sst` configuration.
iwrc sst_inmem_create(struct iwn_wf_session_store *fout_sst);

IW_EXTERN_C_END;
