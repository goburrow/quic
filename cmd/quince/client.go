package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"sync"

	"github.com/goburrow/quic"
	"github.com/goburrow/quic/transport"
)

func clientCommand(args []string) error {
	cmd := flag.NewFlagSet("client", flag.ExitOnError)
	listenAddr := cmd.String("listen", "0.0.0.0:0", "listen on the given IP:port")
	insecure := cmd.Bool("insecure", false, "skip verifying server certificate")
	cipher := cmd.Int("cipher", 0, "TLS 1.3 cipher suite, e.g. 0x1303: TLS_CHACHA20_POLY1305_SHA256")
	logLevel := cmd.Int("v", 1, "log verbose: 0=off 1=error 2=info 3=debug 4=trace")
	cmd.Parse(args)

	addr := cmd.Arg(0)
	if addr == "" {
		fmt.Fprintln(cmd.Output(), "Usage: quince client [options] <url>")
		cmd.PrintDefaults()
		return nil
	}
	serverURL, err := url.Parse(addr)
	if err != nil {
		return err
	}
	if serverURL.Scheme != "https" {
		return fmt.Errorf("scheme %q is not supported", serverURL.Scheme)
	}
	if serverURL.Path == "" {
		serverURL.Path = "/"
	}
	config := newConfig()
	config.TLS.ServerName = serverURL.Hostname()
	config.TLS.InsecureSkipVerify = *insecure
	if *cipher > 0 {
		config.TLS.CipherSuites = []uint16{uint16(*cipher)}
	}
	handler := clientHandler{
		req: "GET " + serverURL.Path + "\r\n",
	}
	client := quic.NewClient(config)
	client.SetHandler(&handler)
	client.SetLogger(*logLevel, os.Stderr)
	if err := client.ListenAndServe(*listenAddr); err != nil {
		return err
	}
	handler.wg.Add(1)
	if err := client.Connect(canonicalAddr(serverURL)); err != nil {
		return err
	}
	handler.wg.Wait()
	return client.Close()
}

type clientHandler struct {
	wg  sync.WaitGroup
	req string
}

func (s *clientHandler) Serve(c *quic.Conn, events []transport.Event) {
	for _, e := range events {
		switch e.Type {
		case quic.EventConnAccept:
			st := c.Stream(4)
			_, _ = io.WriteString(st, s.req)
			_ = st.Close()
		case transport.EventStreamReadable:
			st := c.Stream(e.ID)
			if st == nil {
				c.Close()
				return
			}
			buf := make([]byte, 1024)
			for {
				n, err := st.Read(buf)
				if n > 0 {
					os.Stdout.Write(buf[:n])
				}
				if err != nil {
					c.Close()
					return
				}
				if n <= 0 {
					break
				}
			}
		case quic.EventConnClose:
			s.wg.Done()
		}
	}
}

func canonicalAddr(url *url.URL) string {
	addr := url.Hostname()
	port := url.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(addr, port)
}
