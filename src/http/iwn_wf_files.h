#pragma once

/// Files serving module.

#include "iwn_wf.h"

IW_EXTERN_C_START;

/// Sends file as response of given `req` with content type `ctype` located at given `path`.
///
/// Range HTTP requests are supported as well.
///
/// @return - `1`  File was served successfully.
///         - `-1` Error during file serving.
///         - `0`  File not found.
///         - `416` Bad file request ranges.
///         - `304` Not modified.
///
IW_EXPORT int iwn_wf_file_serve(struct iwn_wf_req *req, const char *ctype, const char *path);

IW_EXPORT int iwn_wf_fileobj_serve(
  struct iwn_wf_req *req, const char *ctype, FILE *file,
  void (*on_completed)(void*), void *on_completed_data);

/// Creates route configuration what servers files located under specified `dir` and parent `route`.
IW_EXPORT struct iwn_wf_route* iwn_wf_route_dir_attach(struct iwn_wf_route *route, const char *dir);

IW_EXTERN_C_END;
