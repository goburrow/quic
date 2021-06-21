# Quiwi 🥝
[![Go Reference](https://pkg.go.dev/badge/github.com/goburrow/quic.svg)](https://pkg.go.dev/github.com/goburrow/quic)
![](https://github.com/goburrow/quic/workflows/Go/badge.svg)

QUIC transport protocol (https://quicwg.org/) implementation in Go.
The goal is to provide low level APIs for applications or protocols using QUIC as a transport. 

TLS 1.3 support is based on standard Go TLS package (https://github.com/golang/go/tree/master/src/crypto/tls),
licensed under the 3-clause BSD license.

## Features

- [X] Handshake with TLS 1.3
- [X] Version negotiation
- [X] Address validation
- [X] Loss detection
- [X] Congestion control
- [X] Streams
- [X] Flow control
- [X] ChaCha20 header protection
- [X] TLS session resumption
- [X] Anti-amplification
- [X] Unreliable datagram
- [X] qlog
- [X] Key update
- [ ] Connection migration
- [ ] Path MTU discovery
- [ ] Zero RTT
- [ ] HTTP/3

## Development

Run tests:
```
go test ./...
```

Build command:
```
cd cmd/quiwi
go build

# To enable tracing
go build -tags quicdebug

# Check heap allocations
go build -gcflags '-m' 2>&1 | sort -V > debug.txt

# Raspberry Pi Zero
GOOS=linux GOARCH=arm GOARM=6 CGO_ENABLED=0 go build
```

### APIs

Package [transport](https://pkg.go.dev/github.com/goburrow/quic@main/transport) provides
low-level APIs to control QUIC connections.
Applications write input data to the connection and read output data for sending to peer.

```go
config := transport.NewConfig()
server, err := transport.Accept(scid, odcid, config)
```
```go
config := transport.NewConfig()
client, err := transport.Connect(scid, config)
```
```go
for !conn.IsClosed() { // Loop until the connection is closed
	timeout := conn.Timeout()
	// (A negative timeout means that the timer should be disarmed)
	select {
		case data := <-dataChanel:  // Got data from peer
			n, err := conn.Write(data)
		case <-time.After(timeout): // Got receiving timeout
			n, err := conn.Write(nil)
	}
	// Get and process connection events
	events = conn.Events(events)
	for { // Loop until err != nil or n == 0
		n, err := conn.Read(buf)
		// Send buf[:n] to peer
	}
}
```

The root package [quic](https://pkg.go.dev/github.com/goburrow/quic@main) instead provides
high-level APIs where QUIC data are transferred over UDP.
It also handles version negotiation, address validation and logging.

```go
server := quic.NewServer(config)
server.SetHandler(handler)
err := server.ListenAndServe(address)
```

```go
client := quic.NewClient(config)
client.SetHandler(handler)
err := client.ListenAndServe(address)
err = client.Connect(serverAddress)
// wait
client.Close()
```

Applications get connection events in the handler to control QUIC connections:

```go
func (handler) Serve(conn *quic.Conn, events []transport.Event) {
	for _, e := range events {
		switch e.Type {
		case transport.EventConnOpen:
		case transport.EventConnClosed:
		}
	}
}
```

### Server
See [cmd/quiwi/server.go](cmd/quiwi/server.go)

```
Usage: quiwi server [arguments]
  -cache string
    	certificate cache directory when using ACME (default ".")
  -cert string
    	TLS certificate path
  -domains string
    	allowed host names for ACME (separated by a comma)
  -key string
    	TLS certificate key path
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

Examples:
```
# Listen on port 4433:
./quiwi server -cert ../../testdata/cert.pem -key ../../testdata/key.pem

# Automatically get certificate from Let's Encrypt:
# (This will also listen on TCP port 443 to handle "tls-alpn-01" challenge)
./quiwi server -domains example.com
```

Add `SSLKEYLOGFILE=key.log` to have TLS keys logged to file.

### Client
See [cmd/quiwi/client.go](cmd/quiwi/client.go)

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

Examples
```
./quiwi client https://quic.tech:4433/

./quiwi client -insecure https://localhost:4433/file.txt
```

### Datagram
See [cmd/quiwi/datagram.go](cmd/quiwi/datagram.go)

```
Usage: quiwi datagram [arguments] [url]
  -cert string
    	TLS certificate path (server only) (default "cert.pem")
  -data string
    	Datagram for sending (or from stdin if empty)
  -insecure
    	skip verifying server certificate (client only)
  -key string
    	TLS certificate key path (server only) (default "key.pem")
  -listen string
    	listen on the given IP:port (default "0.0.0.0:0")
  -v int
    	log verbose: 0=off 1=error 2=info 3=debug 4=trace (default 2)
```

Examples:
```
# Server
./quiwi datagram -listen 127.0.0.1:4433

# Client
./quiwi datagram -insecure -data hello https://127.0.0.1:4433
```

## Testing

See [interop/README.md](interop/README.md)

## Fuzzing

See https://github.com/goburrow/quic-fuzz
