#pragma once
#include "wf.h"

IW_EXTERN_C_START;

struct iwn_wf_files_spec {
  const char *root_dir;
  void (*content_type_resolver)(const char *path, char fout_ctype[255]);
};

IW_EXPORT int iwn_wf_file_serve(struct iwn_wf_req *req, const char *ctype, const char *path);

IW_EXPORT struct iwn_wf_route* iwn_wf_files_attach(
  struct iwn_wf_route            *route,
  const struct iwn_wf_files_spec *spec);

IW_EXTERN_C_END;
