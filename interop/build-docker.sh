#!/bin/sh
set -e
# XXX: Many implementations using much lower Initial RTT
patch -d .. -p1 < 0001-lower_initial_rtt.patch
(cd ../cmd/quiwi && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -v "$@")
patch -d .. -p1 -R < 0001-lower_initial_rtt.patch

cp ../cmd/quiwi/quiwi .
docker build -t "nqviet/quic-interop:latest" .
