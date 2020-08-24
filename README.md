# Quiwi 🥝
[![GoDoc](https://godoc.org/github.com/goburrow/quic?status.svg)](https://godoc.org/github.com/goburrow/quic)
![](https://github.com/goburrow/quic/workflows/Go/badge.svg)

QUIC transport protocol (https://github.com/quicwg/base-drafts/) implementation in Go, inspired by Cloudflare Quiche.
The goal is to provide low level APIs for applications or protocols using QUIC as a transport. 

TLS 1.3 support is based on standard Go TLS package (https://github.com/golang/go/tree/master/src/crypto/tls),
licensed under the 3-clause BSD license.

## Development

Build command:
```
cd cmd/quiwi
go build

# To enable tracing
go build -tags debug

# Check heap allocations
go build -gcflags '-m' 2>&1 | sort -V > debug.txt
```

### Client

```
Usage: quiwi client [arguments] <url>
  -cipher string
    	TLS 1.3 cipher suite, e.g. TLS_CHACHA20_POLY1305_SHA256
  -insecure
    	skip verifying server certificate
  -listen string
    	listen on the given IP:port (default "0.0.0.0:0")
  -qlog string
    	write logs to qlog file
  -root string
    	root download directory
  -v int
    	log verbose: 0=off 1=error 2=info 3=debug 4=trace (default 2)
```

Example
```
./quiwi client https://quic.tech:4433/
```

### Server

```
Usage: quiwi server [arguments]
  -cert string
    	TLS certificate path (default "cert.pem")
  -key string
    	TLS certificate key path (default "key.pem")
  -listen string
    	listen on the given IP:port (default ":4433")
  -qlog string
    	write logs to qlog file
  -retry
    	enable address validation using Retry packet
  -root string
    	root directory (default "www")
  -v int
    	log verbose: 0=off 1=error 2=info 3=debug 4=trace (default 2)
```

Example:
```
./quiwi server -cert ../../testdata/cert.pem -key ../../testdata/key.pem
```

Add `SSLKEYLOGFILE=key.log` to have TLS keys logged to file.

## Datagram

```
Usage: quiwi datagram [arguments] [url]
  -cert string
    	TLS certificate path (server only) (default "cert.pem")
  -insecure
    	skip verifying server certificate (client only)
  -key string
    	TLS certificate key path (server only) (default "key.pem")
  -listen string
    	listen on the given IP:port (default "0.0.0.0:0")
  -v int
    	log verbose: 0=off 1=error 2=info 3=debug 4=trace (default 2)
```

Example:
```
# Server
./quiwi datagram -listen 127.0.0.1:4433
# Client
./quiwi datagram -insecure https://127.0.0.1:4433
```

## Testing

See interop/README.md

## Fuzzing

See https://github.com/goburrow/quic-fuzz
