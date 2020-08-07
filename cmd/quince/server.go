package main

import (
	"crypto/tls"
	"flag"
	"io"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"

	"github.com/goburrow/quic"
	"github.com/goburrow/quic/transport"
)

func serverCommand(args []string) error {
	cmd := flag.NewFlagSet("server", flag.ExitOnError)
	listenAddr := cmd.String("listen", "localhost:4433", "listen on the given IP:port")
	certFile := cmd.String("cert", "cert.crt", "TLS certificate path")
	keyFile := cmd.String("key", "cert.key", "TLS certificate key path")
	root := cmd.String("root", "www", "root directory")
	logLevel := cmd.Int("v", 1, "log verbose: 0=off 1=error 2=info 3=debug 4=trace")
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
	server.SetHandler(&serverHandler{*root})
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

type serverHandler struct {
	root string
}

func (s *serverHandler) Serve(c *quic.Conn, events []transport.Event) {
	for _, e := range events {
		switch e.Type {
		case transport.EventStreamReadable:
			err := s.handleStreamReadable(c, e.ID)
			if err != nil {
				c.Close()
				return
			}
		case transport.EventStreamWritable:
			err := s.handleStreamWritable(c, e.ID)
			if err != nil {
				c.Close()
				return
			}
		case quic.EventConnClose:
			if c.UserData() != nil {
				for _, f := range getResponses(c) {
					f.Close()
				}
			}
		}
	}
}

func (s *serverHandler) handleStreamReadable(c *quic.Conn, streamID uint64) error {
	st := c.Stream(streamID)
	if st == nil {
		return nil // Stream not found?
	}
	// TODO: Here we assume the whole request is in a single read.
	buf := make([]byte, 2048)
	n, err := st.Read(buf)
	if n <= 0 {
		return err
	}
	// Parse request
	req := string(buf[:n])
	if !strings.HasPrefix(req, "GET /") {
		return st.Close()
	}
	reqURL, err := url.ParseRequestURI(strings.TrimSpace(req[4:]))
	if err != nil {
		return st.Close()
	}
	// Send file
	name := filepath.Join(s.root, path.Clean(reqURL.Path))
	f, err := os.Open(name)
	if err != nil {
		io.WriteString(st, "not found")
		return st.Close()
	}
	if info, err := f.Stat(); err != nil || info.Mode().IsDir() {
		f.Close()
		io.WriteString(st, "not found")
		return st.Close()
	}
	// Write initial data
	for i := 0; i < 4; i++ {
		n, err := f.Read(buf)
		if n > 0 {
			m, _ := st.Write(buf[:n])
			if m < n {
				_, err = f.Seek(int64(m-n), io.SeekCurrent)
				if err != nil {
					f.Close()
					return err
				}
				break
			}
		}
		if err != nil {
			f.Close()
			if err == io.EOF {
				return st.Close() // Done sending
			}
			return err // Internal error
		}
	}
	getResponses(c)[streamID] = f // Continue later
	return nil
}

func (s *serverHandler) handleStreamWritable(c *quic.Conn, streamID uint64) error {
	responses := getResponses(c)
	f := responses[streamID]
	if f == nil {
		return nil
	}
	st := c.Stream(streamID)
	if st == nil {
		delete(responses, streamID)
		f.Close()
		return nil // Stream no longer available?
	}
	buf := make([]byte, 2048)
	for i := 0; i < 4; i++ {
		n, err := f.Read(buf)
		if n > 0 {
			m, _ := st.Write(buf[:n])
			if m < n {
				_, err = f.Seek(int64(m-n), io.SeekCurrent)
				return err
			}
		}
		if err != nil {
			delete(responses, streamID)
			f.Close()
			if err == io.EOF {
				return st.Close() // Done sending
			}
			return err // Internal error
		}
	}
	return nil
}

func getResponses(c *quic.Conn) map[uint64]*os.File {
	if c.UserData() == nil {
		responses := make(map[uint64]*os.File)
		c.SetUserData(responses)
		return responses
	}
	return c.UserData().(map[uint64]*os.File)
}
