# Fuzzy testing

Two fuzzing front-ends share the same checks in [`fuzz_http1.c`](fuzz_http1.c):

* **`fuzzdriver`** - portable randomized driver. No extra dependencies; builds with any compiler.
  It is an [`iwtests.h`](../TESTS.md) suite, so single campaigns can be selected by case name.
* **`fuzzlib`** - coverage guided [libFuzzer](https://llvm.org/docs/LibFuzzer.html) target (clang only).

Fuzzing is disabled by default and enabled with `IWNET_BUILD_FUZZ=1` (`IWNET_RUN_FUZZ=1` builds it
and runs the portable driver as part of the build).

## What is checked

The HTTP/1.1 request parser is driven from memory by `iwn_http_request_parse_buf()`
(`src/http/iwn_http_server_internal.h`), the very same parser that serves requests: the request
line, header fields, streamed (chunked) bodies, trailer sections and the request framing
validation. No network IO is involved and the request handler is not called.

The harness reports an oracle violation as a failed test case (`iwtests.h` assertion) and aborts the
case, so ASAN/UBSAN reports are meaningful. Every input is checked for:

* **Parser invariants**: no token may point outside the parse buffer, the request body length must
  be consistent with the bytes consumed and the parser must make progress (reported by the library
  as `IW_ERROR_ASSERTION` with a `violation` description).
* **Request framing**, decoded independently by the harness and compared to the parser outcome:
  - no `Content-Length`/`Transfer-Encoding`: accepted with an empty body;
  - a single `Content-Length`: the parser must report exactly that body length, or an incomplete
    request when the body is truncated;
  - `Transfer-Encoding: chunked`: the chunked framing (including chunk extensions and the trailer
    section) is decoded and the decoded body length must match, malformed framing must be rejected;
  - a duplicated `Content-Length`, `Content-Length` combined with `Transfer-Encoding`,
    `chunked` applied twice, an invalid or unsupported `Transfer-Encoding` value: the request
    must be rejected. The exact status (`400 Bad Request` or `501 Not Implemented`) depends on
    the header field order, the deterministic `src/http/tests/http_parser1.c` cases pin it.
* **Determinism**: the same input must always produce the same outcome.
* **Streaming**: every prefix of the input is parsed as a possibly truncated request without
  violating the invariants.

## Build

```sh
# Random driver + libFuzzer target, instrumented library.
./build.sh -c -DIWNET_BUILD_FUZZ=1 -DENABLE_FUZZ=1 \
           -DENABLE_ASAN=1 -DENABLE_UBSAN=1 -DBUILD_TYPE=Debug
```

`ENABLE_FUZZ` adds `-fsanitize=fuzzer-no-link` to the library build so libFuzzer sees coverage
inside it. Use `IWNET_RUN_FUZZ=1` instead of `IWNET_BUILD_FUZZ=1` to also execute the portable
driver as part of the build (the libFuzzer target is built but never started by the build).
The targets are produced in `autark-cache/fuzz/`:

```sh
autark-cache/fuzz/fuzzdriver [iwtests.h options] [case ...]
autark-cache/fuzz/fuzzlib -max_total_time=300 -dict=fuzz/http1.dict corpus_dir
```

## Running campaigns

The portable driver runs two cases: `corpus` (every seed, unmutated) and `random_rounds`
(mutation/random loop). The campaign parameters come from the environment:

| Variable          | Meaning                                    |
| ----------------- | ------------------------------------------ |
| `IWN_FUZZ_ROUNDS` | Number of random rounds, default `100000`. |
| `IWN_FUZZ_SEED`   | PRNG seed, default `0x9E3779B97F4A7C15`.   |

```sh
# Portable driver, e.g. 2M rounds with a fixed seed.
IWN_FUZZ_ROUNDS=2000000 IWN_FUZZ_SEED=1 autark-cache/fuzz/fuzzdriver random_rounds

# Only the seed replay, without the random rounds.
autark-cache/fuzz/fuzzdriver corpus --no-log

# Coverage guided campaign, seeds and generated inputs accumulate in the corpus directory.
mkdir -p /tmp/iwnet-corpus
autark-cache/fuzz/fuzzlib -max_total_time=300 -max_len=2048 -use_value_profile=1 \
    -dict=fuzz/http1.dict /tmp/iwnet-corpus
```

A violated oracle prints the offending input (escaped, `\r\n` readable) before aborting the case,
libFuzzer writes its crashes to `autark-cache/fuzz/crash-*`.
