# Quiwi 🥝
[![GoDoc](https://godoc.org/github.com/goburrow/quic?status.svg)](https://godoc.org/github.com/goburrow/quic)
![](https://github.com/goburrow/quic/workflows/Go/badge.svg)

QUIC transport protocol (https://github.com/quicwg/base-drafts/) implementation in Go, inspired by Cloudflare Quiche.
The goal is to provide low level APIs for applications or protocols using QUIC as a transport. 

TLS 1.3 support is based on standard Go TLS package (https://github.com/golang/go/tree/master/src/crypto/tls),
licensed under the 3-clause BSD license.

## Testing

Build command:
```
cd cmd/quiwi
go build

# To enable tracing
go build -tags debug

# Check heap allocations
go build -gcflags '-m' 2>&1 | sort -V > debug.txt
```

```
# Client
./quiwi client https://quic.tech:4433/

# Server
./quiwi server
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

Test coverage:
```
go test -coverprofile=coverage.out
go tool cover -html=coverage.out
```

Generating test certificate:
```
go run $GOROOT/src/crypto/tls/generate_cert.go -ecdsa-curve P256 --host localhost,127.0.0.1
```

Interop:
```
cd /path/to/quic-interop-runner
python3 -m venv venv
. venv/bin/activate
pip install -r requirements.txt
./run.py -s quiwi -c quiwi
```

## Fuzzing

See https://github.com/goburrow/quic-fuzz
