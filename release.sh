#!/bin/bash

set -e
# set -x

SCRIPTPATH="$(
  cd "$(dirname "$0")"
  pwd -P
)"
cd $SCRIPTPATH

readme() {
  echo "Generating README.md";
  cat "./BASE.md" > "./README.md"
  echo -e "\n\n" >> "./README.md"
  cat "./src/http/README.md" >> "./README.md"
  echo -e '\n# License\n\n```\n' >> "./README.md"
  cat "./LICENSE" >> "./README.md"
  echo -e '\n```\n' >> "./README.md"
}

while [ "$1" != "" ]; do
  case $1 in
    "-d"  )  readme
             exit
             ;;
  esac
  shift
done
