#pragma once
#include "iwn_wf.h"

IW_EXTERN_C_START

IW_EXPORT int iwn_wf_file_serve(struct iwn_wf_req *req, const char *ctype, const char *path);

IW_EXPORT struct iwn_wf_route* iwn_wf_route_dir_attach(struct iwn_wf_route *route, const char *dir);

IW_EXTERN_C_END
