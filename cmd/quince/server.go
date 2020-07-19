package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/goburrow/quic"
	"github.com/goburrow/quic/transport"
)

func serverCommand(args []string) error {
	cmd := flag.NewFlagSet("server", flag.ExitOnError)
	listenAddr := cmd.String("listen", "localhost:4433", "listen on the given IP:port")
	certFile := cmd.String("cert", "cert.crt", "TLS certificate path")
	keyFile := cmd.String("key", "cert.key", "TLS certificate key path")
	logLevel := cmd.Int("v", 2, "log verbose: 0=off 1=error 2=info 3=debug 4=trace")
	enableRetry := cmd.Bool("retry", false, "enable address validation using Retry packet")
	cmd.Parse(args)

	config := newConfig()
	if *certFile != "" {
		cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			return err
		}
		config.TLS.Certificates = []tls.Certificate{cert}
	}
	server := quic.NewServer(config)
	server.SetHandler(&serverHandler{})
	server.SetLogger(*logLevel, os.Stderr)
	if *enableRetry {
		server.SetAddressValidator(quic.NewAddressValidator())
	}
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		server.Close()
	}()
	return server.ListenAndServe(*listenAddr)
}

type serverHandler struct{}

func (s *serverHandler) Serve(c quic.Conn, events []transport.Event) {
	for _, e := range events {
		fmt.Printf("%s connection event: %v\n", c.RemoteAddr(), e.Type)
		switch e.Type {
		case transport.EventStream:
			st := c.Stream(e.StreamID)
			if st != nil {
				// echo data back
				buf := make([]byte, 512)
				for {
					n, _ := st.Read(buf)
					if n > 0 {
						_, _ = st.Write(buf[:n])
					} else {
						break
					}
				}
			}
		}
	}
}
