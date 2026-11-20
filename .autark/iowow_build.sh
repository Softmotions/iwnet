#!/bin/sh
# Builds and installs the in-tree iowow dependency of iwnet.
#
# Runs as an Autark check, that is before the Autark script of iwnet is
# evaluated: the iwnet build flags are resolved with `pkg-config libiowow`, so
# libiowow.pc must already be installed. The nested build is incremental.
#
# Usage: iowow_build.sh <install-prefix> <iowow-src-dir> <build-type>
set -e

PREFIX="$1"
SRC="$2"
BUILD_TYPE="$3"

[ -n "$PREFIX" ] || { echo "iowow_build.sh: empty install prefix" >&2; exit 1; }
[ -n "$SRC" ] || { echo "iowow_build.sh: empty iowow source dir" >&2; exit 1; }

export BUILD_TYPE
autark --prefix "$PREFIX" "$SRC"
