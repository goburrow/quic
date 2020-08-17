package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sync"

	"github.com/goburrow/quic"
	"github.com/goburrow/quic/transport"
)

func clientCommand(args []string) error {
	cmd := flag.NewFlagSet("client", flag.ExitOnError)
	listenAddr := cmd.String("listen", "0.0.0.0:0", "listen on the given IP:port")
	insecure := cmd.Bool("insecure", false, "skip verifying server certificate")
	root := cmd.String("root", "", "root download directory")
	cipher := cmd.String("cipher", "", "TLS 1.3 cipher suite, e.g. TLS_CHACHA20_POLY1305_SHA256")
	qlogFile := cmd.String("qlog", "", "write logs to qlog file")
	logLevel := cmd.Int("v", 1, "log verbose: 0=off 1=error 2=info 3=debug 4=trace")
	cmd.Parse(args)

	addrs := cmd.Args()
	if len(addrs) == 0 {
		fmt.Fprintln(cmd.Output(), "Usage: quince client [options] <url>")
		cmd.PrintDefaults()
		return nil
	} else if len(addrs) > 1 && *root == "" {
		// TODO: Support different host
		fmt.Fprintln(cmd.Output(), "Multiple downloads require a root directory")
		return nil
	}
	urls := make([]*url.URL, len(addrs))
	for i, addr := range addrs {
		addrURL, err := parseURL(addr)
		if err != nil {
			return err
		}
		// In reverse
		urls[len(urls)-1-i] = addrURL
	}
	config := newConfig()
	config.TLS.ServerName = urls[len(urls)-1].Hostname()
	config.TLS.InsecureSkipVerify = *insecure
	switch *cipher {
	case "":
		// Auto
	case "TLS_AES_128_GCM_SHA256":
		config.TLS.CipherSuites = []uint16{tls.TLS_AES_128_GCM_SHA256}
	case "TLS_AES_256_GCM_SHA384":
		config.TLS.CipherSuites = []uint16{tls.TLS_AES_256_GCM_SHA384}
	case "TLS_CHACHA20_POLY1305_SHA256":
		config.TLS.CipherSuites = []uint16{tls.TLS_CHACHA20_POLY1305_SHA256}
	default:
		return fmt.Errorf("unsupported cipher: %v", *cipher)
	}
	handler := clientHandler{
		buf:   newBuffers(2048, 10),
		root:  *root,
		files: urls,
	}
	client := quic.NewClient(config)
	client.SetHandler(&handler)
	if *qlogFile == "" {
		client.SetLogger(*logLevel, os.Stderr)
	} else {
		logFd, err := os.Create(*qlogFile + ".txt")
		if err != nil {
			return err
		}
		defer logFd.Close()
		defer func() {
			logFd.Seek(0, os.SEEK_SET)
			qlogTransformToFile(*qlogFile, logFd)
		}()
		client.SetLogger(*logLevel, logFd)
	}

	if err := client.ListenAndServe(*listenAddr); err != nil {
		return err
	}
	handler.wg.Add(1)
	if err := client.Connect(canonicalAddr(urls[len(urls)-1])); err != nil {
		return err
	}
	handler.wg.Wait()
	return client.Close()
}

type clientHandler struct {
	wg    sync.WaitGroup
	buf   buffers
	root  string     // Download directory. If empty, write to stdout
	files []*url.URL // List of files to download
}

func (s *clientHandler) Serve(c *quic.Conn, events []transport.Event) {
	for _, e := range events {
		switch e.Type {
		case quic.EventConnAccept, transport.EventStreamCreatable:
			err := s.downloadFiles(c)
			if err != nil {
				c.Close()
				return
			}
		case transport.EventStreamReadable:
			err := s.handleStreamReadable(c, e.ID)
			if err != nil {
				c.Close()
				return
			}
			if len(s.files) == 0 && len(s.getRequests(c)) == 0 {
				c.Close()
				return
			}
		case quic.EventConnClose:
			// Clean up
			for _, f := range s.getRequests(c) {
				s.closeFile(f)
				s.wg.Done()
			}
			s.wg.Done()
		}
	}
}

func (s *clientHandler) downloadFiles(c *quic.Conn) error {
	for len(s.files) > 0 {
		fileURL := s.files[len(s.files)-1]
		st, id, err := c.NewStream(true)
		if err != nil {
			if err, ok := err.(*transport.Error); ok && err.Code == transport.StreamLimitError {
				return nil
			}
			return err
		}
		var output *os.File
		if s.root == "" {
			output = os.Stdout
		} else {
			name := filepath.Join(s.root, path.Clean(fileURL.Path))
			output, err = os.Create(name)
			if err != nil {
				return err
			}
		}
		req := fmt.Sprintf("GET %s\r\n", fileURL.Path)
		_, err = st.WriteString(req)
		if err != nil {
			return err
		}
		st.Close()
		s.files = s.files[:len(s.files)-1]
		s.getRequests(c)[id] = output
		s.wg.Add(1)
	}
	return nil
}

func (s *clientHandler) handleStreamReadable(c *quic.Conn, streamID uint64) error {
	requests := s.getRequests(c)
	f := requests[streamID]
	if f == nil {
		return nil
	}
	st, err := c.Stream(streamID)
	if err != nil {
		return err
	}
	buf := s.buf.pop()
	defer s.buf.push(buf)
	for {
		n, err := st.Read(buf)
		if n > 0 {
			_, err := f.Write(buf[:n])
			if err != nil {
				s.closeFile(f)
				delete(requests, streamID)
				s.wg.Done()
				return st.CloseRead(1)
			}
		}
		if err != nil {
			s.closeFile(f)
			delete(requests, streamID)
			s.wg.Done()
			if err == io.EOF {
				return nil
			}
			st.CloseRead(1)
			return err
		}
		if n <= 0 {
			return nil
		}
	}
}

func (s *clientHandler) getRequests(c *quic.Conn) map[uint64]*os.File {
	if c.UserData() == nil {
		responses := make(map[uint64]*os.File)
		c.SetUserData(responses)
		return responses
	}
	return c.UserData().(map[uint64]*os.File)
}

func (s *clientHandler) closeFile(f *os.File) {
	// Do not close file when download directory is not specified as it is stdout.
	if s.root != "" {
		f.Close()
	}
}

func parseURL(addr string) (*url.URL, error) {
	addrURL, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}
	if addrURL.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme: %v", addrURL.Scheme)
	}
	if addrURL.Path == "" {
		addrURL.Path = "/"
	}
	return addrURL, nil
}

func canonicalAddr(url *url.URL) string {
	addr := url.Hostname()
	port := url.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(addr, port)
}
