#include "iwn_url.h"
#include <string.h>

/**
 * Parse a non null terminated string into an integer.
 *
 * str: the string containing the number.
 * len: Number of characters to parse.
 */
static inline int natoi(const char *str, size_t len) {
  int i, r = 0;
  for (i = 0; i < len; i++) {
    r *= 10;
    r += str[i] - '0';
  }

  return r;
}

/**
 * Check if a URL is relative (no scheme and hostname).
 *
 * url: the string containing the URL to check.
 *
 * Returns 1 if relative, otherwise 0.
 */
static inline int is_relative(const char *url) {
  return (*url == '/') ? 1 : 0;
}

/**
 * Parse the scheme of a URL by inserting a null terminator after the scheme.
 *
 * str: the string containing the URL to parse. Will be modified.
 *
 * Returns a pointer to the hostname on success, otherwise NULL.
 */
static inline char* parse_scheme(char *str) {
  char *s;

  /* If not found or first in string, return error */
  s = strchr(str, ':');
  if (s == NULL || s == str) {
    return NULL;
  }

  /* If not followed by two slashes, return error */
  if (s[1] != '/' || s[2] == '\0' || s[2] != '/') {
    return NULL;
  }

  *s = '\0'; // Replace ':' with NULL

  return s + 3;
}

/**
 * Find a character in a string, replace it with '\0' and return the next
 * character in the string.
 *
 * str: the string to search in.
 * find: the character to search for.
 *
 * Returns a pointer to the character after the one to search for. If not
 * found, NULL is returned.
 */
static inline char* find_and_terminate(char *str, char find) {
  str = strchr(str, find);
  if (NULL == str) {
    return NULL;
  }

  *str = '\0';
  return str + 1;
}

/* Yes, the following functions could be implemented as preprocessor macros
     instead of inline functions, but I think that this approach will be more
     clean in this case. */
static inline char* find_fragment(char *str) {
  return find_and_terminate(str, '#');
}

static inline char* find_query(char *str) {
  return find_and_terminate(str, '?');
}

static inline char* find_path(char *str) {
  return find_and_terminate(str, '/');
}

/**
 * Parse a URL string to a struct.
 *
 * url: pointer to the struct where to store the parsed URL parts.
 * u:   the string containing the URL to be parsed.
 *
 * Returns 0 on success, otherwise -1.
 */
int iwn_url_parse(struct iwn_url *url, char *u) {
  if (NULL == url || NULL == u) {
    return -1;
  }

  memset(url, 0, sizeof(struct iwn_url));

  /* (Fragment) */
  url->fragment = find_fragment(u);

  /* (Query) */
  url->query = find_query(u);

  /* Relative URL? Parse scheme and hostname */
  if (!is_relative(u)) {
    /* Scheme */
    url->scheme = u;
    u = parse_scheme(u);
    if (u == NULL) {
      return -1;
    }

    /* Host */
    if ('\0' == *u) {
      return -1;
    }
    url->host = u;

    /* (Path) */
    url->path = find_path(u);

    /* (Credentials) */
    u = strchr(url->host, '@');
    if (NULL != u) {
      /* Missing credentials? */
      if (u == url->host) {
        return -1;
      }

      url->username = url->host;
      url->host = u + 1;
      *u = '\0';

      u = strchr(url->username, ':');
      if (NULL == u) {
        return -1;
      }

      url->password = u + 1;
      *u = '\0';
    }

    /* Missing hostname? */
    if ('\0' == *url->host) {
      return -1;
    }

    /* (Port) */
    u = strchr(url->host, ':');
    if (NULL != u && (NULL == url->path || u < url->path)) {
      *(u++) = '\0';
      if ('\0' == *u) {
        return -1;
      }

      if (url->path) {
        url->port = natoi(u, url->path - u - 1);
      } else {
        url->port = atoi(u);
      }
    }

    /* Missing hostname? */
    if ('\0' == *url->host) {
      return -1;
    }
  } else {
    /* (Path) */
    url->path = find_path(u);
  }

  return 0;
}



