# Quince
[![GoDoc](https://godoc.org/github.com/goburrow/quic?status.svg)](https://godoc.org/github.com/goburrow/quic)
![](https://github.com/goburrow/quic/workflows/Go/badge.svg)

QUIC transport protocol (https://github.com/quicwg/base-drafts/) implementation in Go, inspired by Cloudflare Quiche.
The goal is to provide low level APIs for applications or protocols using QUIC as a transport. 

TLS 1.3 support is based on standard Go TLS package (https://github.com/golang/go/tree/master/src/crypto/tls),
licensed under the 3-clause BSD license.

## Testing

Build command:
```
cd cmd/quince
go build

# To enable tracing
go build -tags debug

# Check heap allocations
go build -tags debug -gcflags '-m' > debug.txt 2>&1
```

```
# Client
./quince client quic.tech:4433

# Server
./quince server
```

Add `SSLKEYLOGFILE=key.log` to have TLS keys logged to file.

Testing with Quiche:

```
cd /path/to/quiche/tools/apps
cargo build --release
# Client
RUST_LOG=trace ./target/release/quiche-client --no-verify https://127.0.0.1:4433
# Server
RUST_LOG=trace ./target/release/quiche-server
```

## Fuzzing

See https://github.com/goburrow/quic-fuzz
