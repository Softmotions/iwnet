#!/bin/bash

set -e
# set -x
SCRIPT_DIR=$(
  cd "$(dirname "$0")"
  pwd -P
)

if [ -z "$1" ]; then
  echo "Missing generator program"
  exit 1
fi

if [ -z "$2" ]; then
  echo "Missing output prefix"
  exit 1
fi

GEN="$1"
NAME=$(basename $2)
TARGET_DIR=$(dirname $2)

OUT="${TARGET_DIR}/${NAME}.inc"
INPUT="${SCRIPT_DIR}/${NAME}.js"

if [ ! -f ${INPUT} ]; then
  echo "Missing input file: ${INPUT}"
  exit 1
fi

test -d ${TARGET_DIR} || mkdir -p ${TARGET_DIR}

echo "Generating ${OUT}"
echo '' >$OUT
node "${INPUT}" | "${GEN}" -i "${NAME}" >>$OUT
