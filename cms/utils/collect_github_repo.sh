#!/bin/bash
url=$1
branch=$2
repo=$3
mkdir -p cms/data/repo/github
cd cms/data/repo/github
if [ -d $repo ]; then
  cd $repo
  git pull
  if [ $? != 0 ]; then
    cd ..
    rm -rf $repo
    git clone -b $branch $url $repo
  else
    cd ..
  fi
else
  git clone -b $branch $url $repo
fi
if [ ! -d ../../json ]; then
  mkdir -p ../../json
fi
trivy fs $repo --list-all-pkgs --format json --output ../../json/$repo
