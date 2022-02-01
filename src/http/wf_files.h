#pragma once
#include "wf.h"

IW_EXTERN_C_START;

IW_EXPORT int iwn_wf_file_serve(struct iwn_wf_req *req, const char *ctype, const char *path);

IW_EXTERN_C_END;
