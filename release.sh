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

release_tag() {
  echo "Creating IWNET release"
  readme

  git pull origin master
  dch --distribution testing --no-force-save-on-release --release "" -c ./Changelog
  VERSION=`dpkg-parsechangelog -l./Changelog -SVersion`
  TAG="v${VERSION}"
  CHANGESET=`dpkg-parsechangelog -l./Changelog -SChanges | sed '/^iwnet.*/d' | sed '/^\s*$/d'`
  git add ./Changelog
  git add ./README.md

  if ! git diff-index --quiet HEAD --; then
    git commit -a -m"${TAG} landed"
    git push origin master
  fi

  echo "${CHANGESET}" | git tag -f -a -F - "${TAG}"
  git push origin -f --tags
}

while [ "$1" != "" ]; do
  case $1 in
    "-d"  )  readme
             exit
             ;;
    "-r" )   release_tag
             exit
             ;;
  esac
  shift
done
