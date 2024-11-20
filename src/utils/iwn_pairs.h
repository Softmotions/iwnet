#pragma once

#include <iowow/basedefs.h>
#include <iowow/iwpool.h>

IW_EXTERN_C_START;

struct iwn_pairs;

/// A Data buffer container.
struct iwn_val {
  size_t len;           ///< Length of the buffer.
  char  *buf;           ///< Pointer to the buffer data.
  struct iwn_val *next; ///< Optional pointer to the next container in chain. Used in various scenarios.
};

/// A chain of iwn_val containers.
struct iwn_vals {
  struct iwn_val *first;
  struct iwn_val *last;
};

/// A key/value pair.
struct iwn_pair {
  const char *key;         ///< Key data pointer.
  char       *val;         ///< Value data pointer.
  size_t      key_len;     ///< Key data length.
  size_t      val_len;     ///< Value data length.
  struct iwn_pair  *next;  ///< Next pair in pairs chain.
  struct iwn_pairs *extra; ///< Optional extra pairs associated with this pair.
};

/// A chain of key/value pairs.
struct iwn_pairs {
  struct iwn_pair *first;
  struct iwn_pair *last;
};

/// Applies `free()` to the `val` buffer and rest val length to zero.
IW_EXPORT void iwn_val_buf_free(struct iwn_val *val);

/// Adds a value specified by `v` into chain of `vals`.
IW_EXPORT void iwn_val_add(struct iwn_vals *vals, struct iwn_val *v);

/// Allocates new `iwn_val` instance and adds it to the and of `vals` list.
/// @param vals Values list
/// @param buf Data wrapped by new `iwn_val`
/// @param len Length of `buf` data
IW_EXPORT iwrc iwn_val_add_new(struct iwn_vals *vals, char *buf, size_t len);

/// Converts a provided `vals` to array form, where a `pool` used for array allocation.
IW_EXPORT struct iwn_val** iwn_vals_to_array(struct iwpool *pool, const struct iwn_vals *vals, size_t *out_size);

/// Adds given `p` pair to the `pairs` list.
IW_EXPORT void iwn_pair_add(struct iwn_pairs *pairs, struct iwn_pair *p);

/// Converts a provided `pairs` to array form, where a `pool` used for array allocation.
IW_EXPORT struct iwn_pair** iwn_pairs_to_array(struct iwpool *pool, const struct iwn_pairs *pairs, size_t *out_size);

/// Finds a first pair matched the given `key`. Returns zero pointer if no matched pair found.
IW_EXPORT struct iwn_pair* iwn_pair_find(const struct iwn_pairs *pairs, const char *key, ssize_t key_len);

/// Find a first pair value matched the given `key`. If not pair found then zero initialized `iwn_val`
/// will be returned.
IW_EXPORT struct iwn_val iwn_pair_find_val(const struct iwn_pairs *pairs, const char *key, ssize_t key_len);

/// Converts pair value to integer number if possible.
IW_EXPORT iwrc iwn_val_i64(const struct iwn_val *v, int64_t def, int64_t *out);

/// Add a new `iwn_pair` instance allocated in given `pool` to the list of `pairs` chain.
IW_EXPORT iwrc iwn_pair_add_pool(
  struct iwpool    *pool,
  struct iwn_pairs *pairs,
  const char       *key,
  ssize_t           key_len,
  char             *val,
  ssize_t           val_len);


/// Add a new `iwn_pair` with all of data including key and value allocated in given `pool`.
IW_EXPORT iwrc iwn_pair_add_pool_all(
  struct iwpool    *pool,
  struct iwn_pairs *pairs,
  const char       *key,
  ssize_t           key_len,
  const char       *val,
  ssize_t           val_len);


IW_EXTERN_C_END;
