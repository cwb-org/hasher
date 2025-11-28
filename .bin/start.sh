#!/bin/bash

read -r VERSION < ../VERSION

VERSION=$(echo "$VERSION" | xargs)

git push -f origin main

git tag "v$VERSION"

git push origin "v$VERSION"