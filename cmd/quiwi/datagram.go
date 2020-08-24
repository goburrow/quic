package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/goburrow/quic"
	"github.com/goburrow/quic/transport"
)

type datagramCommand struct{}

func (datagramCommand) Name() string {
	return "datagram"
}

func (datagramCommand) Desc() string {
	return "send or receive datagram over QUIC."
}

func (datagramCommand) Run(args []string) error {
	cmd := flag.NewFlagSet("datagram", flag.ExitOnError)
	listenAddr := cmd.String("listen", "0.0.0.0:0", "listen on the given IP:port")
	insecure := cmd.Bool("insecure", false, "skip verifying server certificate (client only)")
	certFile := cmd.String("cert", "cert.pem", "TLS certificate path (server only)")
	keyFile := cmd.String("key", "key.pem", "TLS certificate key path (server only)")
	logLevel := cmd.Int("v", 2, "log verbose: 0=off 1=error 2=info 3=debug 4=trace")
	cmd.Usage = func() {
		fmt.Fprintln(cmd.Output(), "Usage: quiwi datagram [arguments] [url]")
		cmd.PrintDefaults()
	}
	cmd.Parse(args)

	addr := cmd.Arg(0)
	config := newConfig()
	config.Params.MaxIdleTimeout = 30 * time.Second
	config.Params.MaxDatagramPayloadSize = 1024
	// Disable streams
	config.Params.InitialMaxStreamDataBidiLocal = 0
	config.Params.InitialMaxStreamDataBidiRemote = 0
	config.Params.InitialMaxStreamDataUni = 0
	config.Params.InitialMaxStreamsBidi = 0
	config.Params.InitialMaxStreamsUni = 0

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGQUIT)

	if addr == "" {
		// Server mode
		if *certFile != "" {
			cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
			if err != nil {
				return err
			}
			config.TLS.Certificates = []tls.Certificate{cert}
		}
		server := quic.NewServer(config)
		server.SetLogger(*logLevel, os.Stderr)
		server.SetHandler(&datagramServerHandler{})
		go func() {
			<-sigCh
			server.Close()
		}()
		return server.ListenAndServe(*listenAddr)
	}
	// Client mode
	addrURL, err := parseURL(addr)
	if err != nil {
		return err
	}
	config.TLS.ServerName = addrURL.Hostname()
	config.TLS.InsecureSkipVerify = *insecure
	client := quic.NewClient(config)
	client.SetLogger(*logLevel, os.Stderr)
	clientHandler := &datagramClientHandler{
		dgram: make(chan []byte),
		close: make(chan struct{}),
	}
	client.SetHandler(clientHandler)
	if err := client.ListenAndServe(*listenAddr); err != nil {
		return err
	}
	if err := client.Connect(canonicalAddr(addrURL)); err != nil {
		return err
	}
	select {
	case <-sigCh:
	case <-clientHandler.close:
	}
	return client.Close()
}

type datagramClientHandler struct {
	dgram chan []byte
	close chan struct{}
}

func (s *datagramClientHandler) Serve(c *quic.Conn, events []transport.Event) {
	for _, e := range events {
		switch e.Type {
		case quic.EventConnAccept:
			_, err := c.Datagram().Write([]byte("hello"))
			if err != nil {
				c.CloseWithError(transport.ApplicationError, err.Error())
				return
			}
		case transport.EventDatagramReadable:
			err := s.handleDatagramReadable(c)
			if err != nil {
				c.CloseWithError(transport.ApplicationError, err.Error())
				return
			}
		case quic.EventConnClose:
			close(s.close)
			return
		}
	}
}

func (s *datagramClientHandler) handleDatagramReadable(c *quic.Conn) error {
	dgram := c.Datagram()
	for {
		d := dgram.Pop()
		if len(d) > 0 {
			_, err := fmt.Fprintf(os.Stdout, "recv: %s\n", d)
			if err != nil {
				return err
			}
		} else {
			return nil
		}
	}
}

type datagramServerHandler struct{}

func (s *datagramServerHandler) Serve(c *quic.Conn, events []transport.Event) {
	for _, e := range events {
		switch e.Type {
		case transport.EventDatagramReadable:
			err := s.handleDatagramReadable(c)
			if err != nil {
				c.CloseWithError(transport.ApplicationError, err.Error())
				return
			}
		case quic.EventConnClose:
			return
		}
	}
}

func (s *datagramServerHandler) handleDatagramReadable(c *quic.Conn) error {
	// Echo back
	dgram := c.Datagram()
	for {
		d := dgram.Pop()
		if len(d) > 0 {
			err := dgram.Push(d)
			if err != nil {
				return err
			}
		} else {
			return nil
		}
	}
}
