#!/bin/bash

read -r VERSION < ../VERSION

VERSION=$(echo "$VERSION" | xargs)

BASE=$(git merge-base HEAD origin/main)

git reset "$BASE"

git add -A

git commit -m "version = \"v$VERSION\""