#!/bin/sh
set -e
cd ../cmd/quince
GOOS=linux GOARCH=amd64 go build -v "$@"
cd -
cp ../cmd/quince/quince .
cp ../testdata/*.pem .
docker build -t "nqviet/quic-interop:latest" .
