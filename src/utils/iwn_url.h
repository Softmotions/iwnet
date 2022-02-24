#pragma once

#include <iowow/basedefs.h>
#include <stdlib.h>
#include <stdio.h>

/**
 * The struct where the parsed values will be stored:
 *
 * scheme ":" [ "//" ] [ username ":" password "@" ] host [ ":" port ] [ "/" ] [ path ] [ "?" query ]
 *
 * Note: to make sure that no strings are copied, the first slash "/" in the
 * path will be used to null terminate the hostname if no port is supplied.
 */
struct iwn_url {
  char *scheme;   /* scheme, without ":" and "//" */
  char *username; /* username, default: NULL */
  char *password; /* password, default: NULL */
  char *host;     /* hostname or IP address */
  int   port;     /* port, default: 0 */
  char *path;     /* path, without leading "/", default: NULL */
  char *query;    /* query, default: NULL */
  char *fragment; /* fragment, default: NULL */
};

/**
 * Parse a URL to a struct.
 *
 * The URL string should be in one of the following formats:
 *
 * Absolute URL:
 * scheme ":" [ "//" ] [ username ":" password "@" ] host [ ":" port ] [ "/" ] [ path ] [ "?" query ] [ "#" fragment ]
 *
 * Relative URL:
 * path [ "?" query ] [ "#" fragment ]
 *
 * The following parts will be parsed to the corresponding struct member.
 *
 * *url:     a pointer to the struct where to store the parsed values.
 * *url_str: a pointer to the url to be parsed (null terminated). The string
 *           will be modified.
 *
 * Returns 0 on success, otherwise -1.
 */
IW_EXPORT int iwn_url_parse(struct iwn_url *url, char *url_str);
