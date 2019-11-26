# Quince
[![GoDoc](https://godoc.org/github.com/goburrow/quic?status.svg)](https://godoc.org/github.com/goburrow/quic)

QUIC transport protocol (https://github.com/quicwg/base-drafts/) implementation in Go, inspired by Cloudflare Quiche.
The goal is to provide low level APIs for applications or protocols using QUIC as a transport. 

TLS 1.3 support is based on standard Go TLS package (https://github.com/golang/go/tree/master/src/crypto/tls),
licensed under the 3-clause BSD license.

## Debugging

```
# To enable tracing
go build -tags debug

# Check heap allocations
go build -tags debug -gcflags '-m' > debug.txt 2>&1
```

## Testing

```
# Test server with Quiche client
SSLKEYLOGFILE=quince_key.log ./quince server
SSLKEYLOGFILE=keys.log RUST_LOG=trace ./target/release/examples/client --wire-version ff000018 --no-verify https://127.0.0.1:4433

# Test client
./quince client quic.tech:4433
```

## Fuzzing

See https://github.com/goburrow/quic-fuzz
