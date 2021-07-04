package main

import (
	"bufio"
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
	data := cmd.String("data", "", "Datagram for sending (or from stdin if empty)")
	cmd.Usage = func() {
		fmt.Fprintln(cmd.Output(), "Usage: quiwi datagram [arguments] [url]")
		cmd.PrintDefaults()
	}
	cmd.Parse(args)

	addr := cmd.Arg(0)
	config := newConfig()
	config.Params.MaxIdleTimeout = 30 * time.Second
	config.Params.MaxDatagramFramePayloadSize = 1024
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
		data:  *data,
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
	data  string
	close chan struct{}
}

func (s *datagramClientHandler) Serve(c *quic.Conn, events []transport.Event) {
	for _, e := range events {
		switch e.Type {
		case transport.EventDatagramWritable:
			err := s.handleDatagramWritable(c)
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
		case transport.EventConnClosed:
			close(s.close)
			return
		}
	}
}

func (s *datagramClientHandler) handleDatagramWritable(c *quic.Conn) error {
	if len(s.data) > 0 {
		_, err := c.DatagramWrite([]byte(s.data))
		if err != nil {
			return err
		}
	}
	// Read from stdin and send each line in a datagram.
	go func(dgram *quic.Datagram) {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			b := scanner.Bytes()
			if len(b) > 0 {
				_, err := dgram.Write(b)
				if err != nil {
					return
				}
			}
		}
	}(c.Datagram())
	return nil
}

func (s *datagramClientHandler) handleDatagramReadable(c *quic.Conn) error {
	b := buffers.pop()
	defer buffers.push(b)
	for {
		n, err := c.DatagramRead(b)
		if err != nil {
			return err
		}
		if n > 0 {
			_, err := fmt.Fprintf(os.Stdout, "recv: %s\n", b[:n])
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
		case transport.EventConnClosed:
			return
		}
	}
}

func (s *datagramServerHandler) handleDatagramReadable(c *quic.Conn) error {
	// Echo back
	b := buffers.pop()
	defer buffers.push(b)
	for {
		n, err := c.DatagramRead(b)
		if err != nil {
			return err
		}
		if n > 0 {
			n, err = c.DatagramWrite(b[:n])
			if err != nil {
				return err
			}
		} else {
			return nil
		}
	}
}
