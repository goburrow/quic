package main

import (
	"crypto/tls"
	"flag"
	"log"

	"github.com/goburrow/quic"
	"github.com/goburrow/quic/transport"
)

func serverCommand(args []string) error {
	cmd := flag.NewFlagSet("server", flag.ExitOnError)
	listenAddr := cmd.String("listen", "localhost:4433", "listen on the given IP:port")
	certFile := cmd.String("cert", "cert.crt", "TLS certificate path")
	keyFile := cmd.String("key", "cert.key", "TLS certificate key path")
	cmd.Parse(args)

	config := newConfig()
	if *certFile != "" {
		cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			return err
		}
		config.TLS.Certificates = []tls.Certificate{cert}
	}
	server := quic.NewServer(config, &serverHandler{})
	if err := server.Listen(*listenAddr); err != nil {
		return err
	}
	return server.Serve(nil)
}

type serverHandler struct{}

func (s *serverHandler) Created(c quic.Conn) error {
	log.Printf("new connection: %s", c.RemoteAddr())
	return nil
}

func (s *serverHandler) Serve(c quic.Conn) {
	for _, e := range c.Events() {
		log.Printf("%s connection event: %#v", c.RemoteAddr(), e)
		switch e := e.(type) {
		case *transport.StreamEvent:
			st := c.Stream(e.StreamID)
			st.Write([]byte("pong!"))
			st.Close()
		}
	}
}

func (s *serverHandler) Closed(c quic.Conn) {
	log.Printf("%s connection closed", c.RemoteAddr())
}
