#!/bin/bash
url=$1
branch=$2
repo=$3
mkdir -p cms/data/repo/github
cd cms/data/repo/github
if [ -d $repo ]; then
  rm -rf $repo
fi

while [ ! -d $repo ]
do
  git clone -b $branch $url $repo
done

if [ ! -d ../../json ]; then
  mkdir -p ../../json
fi
trivy fs $repo --list-all-pkgs --format json --output ../../json/$repo
