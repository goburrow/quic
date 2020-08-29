#!/bin/sh
set -e
cd ../cmd/quiwi
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -v "$@"
cd -
cp ../cmd/quiwi/quiwi .
cp ../testdata/*.pem .
docker build -t "nqviet/quic-interop:latest" .
