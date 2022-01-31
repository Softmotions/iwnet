#pragma once
#include "wf.h"

IW_EXTERN_C_START;

struct iwn_wf_files_spec {
  const char *root_dir;
};

IW_EXPORT struct iwn_wf_route* iwn_wf_files_attach(
  struct iwn_wf_route            *route,
  const struct iwn_wf_files_spec *spec);

IW_EXTERN_C_END;
