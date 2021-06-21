package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sync"

	"github.com/goburrow/quic"
	"github.com/goburrow/quic/transport"
)

type clientCommand struct{}

func (clientCommand) Name() string {
	return "client"
}

func (clientCommand) Desc() string {
	return "download file using http/0.9 over QUIC."
}

func (clientCommand) Run(args []string) error {
	cmd := flag.NewFlagSet("client", flag.ExitOnError)
	listenAddr := cmd.String("listen", "0.0.0.0:0", "listen on the given IP:port")
	insecure := cmd.Bool("insecure", false, "skip verifying server certificate")
	root := cmd.String("root", "", "root download directory")
	multi := cmd.Bool("multi", false, "download files using multiple streams")
	version := cmd.Uint("version", 0, "use specific QUIC version")
	cipher := cmd.String("cipher", "", "TLS 1.3 cipher suite, e.g. TLS_CHACHA20_POLY1305_SHA256")
	qlogFile := cmd.String("qlog", "", "write logs to qlog file")
	logLevel := cmd.Int("v", 2, "log verbose: 0=off 1=error 2=info 3=debug 4=trace")
	useAsync := cmd.Bool("async", false, "use asynchronous Stream APIs")
	keyUpdate := cmd.Int("keyupdate", 0, "key update interval")
	cmd.Usage = func() {
		fmt.Fprintln(cmd.Output(), "Usage: quiwi client [arguments] <url>")
		cmd.PrintDefaults()
	}
	cmd.Parse(args)

	addrs := cmd.Args()
	if len(addrs) == 0 {
		cmd.Usage()
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
		urls[i] = addrURL
	}
	config := newConfig()
	if *version > 0 {
		config.Version = uint32(*version)
	}
	config.TLS.ServerName = urls[len(urls)-1].Hostname()
	config.TLS.InsecureSkipVerify = *insecure
	if err := setCipherSuites(config.TLS, *cipher); err != nil {
		return err
	}
	if *keyUpdate > 0 {
		config.MaxPacketsPerKey = uint64(*keyUpdate)
	}
	handler := clientHandler{
		root:  *root,
		async: *useAsync,
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
	if *multi {
		// Download all files using multiple streams. All urls must have same host.
		handler.files = urls
		handler.wg.Add(1) // For connection closed
		if err := client.Connect(canonicalAddr(handler.files[0])); err != nil {
			return err
		}
		handler.wg.Wait()
	} else {
		// Create a new connection for each download.
		for i := range urls {
			handler.files = urls[i : i+1]
			handler.wg.Add(1) // For connection closed
			if err := client.Connect(canonicalAddr(handler.files[0])); err != nil {
				return err
			}
			handler.wg.Wait()
		}
	}
	return client.Close()
}

// clientHandler implements quic.Handler.
type clientHandler struct {
	wg    sync.WaitGroup
	root  string     // Download directory. If empty, write to stdout
	files []*url.URL // List of files to download
	async bool
}

// Serve handles connection events.
func (s *clientHandler) Serve(c *quic.Conn, events []transport.Event) {
	if s.async {
		s.serveAsync(c, events)
	} else {
		s.serveSync(c, events)
	}
}

// serveSync demonstrates using synchronous Stream APIs.
func (s *clientHandler) serveSync(c *quic.Conn, events []transport.Event) {
	for _, e := range events {
		switch e.Type {
		case transport.EventConnOpen, transport.EventStreamCreatable:
			err := s.handleStreamCreatable(c)
			if err != nil {
				c.CloseWithError(transport.ApplicationError, err.Error())
				return
			}
		case transport.EventStreamReadable:
			err := s.handleStreamReadable(c, e.ID)
			if err != nil {
				c.CloseWithError(transport.ApplicationError, err.Error())
				return
			}
			if len(s.files) == 0 && len(s.getRequests(c)) == 0 {
				// Download finished
				c.Close()
				return
			}
		case transport.EventConnClosed:
			// Clean up
			for _, f := range s.getRequests(c) {
				s.closeFile(f)
			}
			s.wg.Done()
		}
	}
}

func (s *clientHandler) handleStreamCreatable(c *quic.Conn) error {
	for len(s.files) > 0 {
		fileURL := s.files[0]
		streamID, ok := c.NewStream(true)
		if !ok {
			break
		}
		var output *os.File
		var err error
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
		_, err = c.StreamWrite(streamID, []byte(req))
		if err != nil {
			return err
		}
		c.StreamClose(streamID)
		s.files = s.files[1:]
		s.getRequests(c)[streamID] = output
	}
	return nil
}

func (s *clientHandler) handleStreamReadable(c *quic.Conn, streamID uint64) error {
	requests := s.getRequests(c)
	f := requests[streamID]
	if f == nil {
		return nil
	}
	buf := buffers.pop()
	defer buffers.push(buf)
	for {
		n, err := c.StreamRead(streamID, buf)
		if n > 0 {
			_, err := f.Write(buf[:n])
			if err != nil {
				s.closeFile(f)
				delete(requests, streamID)
				return c.StreamCloseRead(streamID, 1)
			}
		}
		if err != nil {
			s.closeFile(f)
			delete(requests, streamID)
			if err == io.EOF {
				return nil
			}
			c.StreamCloseRead(streamID, 1)
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

// serveAsync demonstrates using asynchronous Stream APIs.
func (s *clientHandler) serveAsync(c *quic.Conn, events []transport.Event) {
	for _, e := range events {
		switch e.Type {
		case transport.EventConnOpen, transport.EventStreamCreatable:
			for len(s.files) > 0 {
				streamID, ok := c.NewStream(true)
				if !ok {
					// Exceeded stream limits
					break
				}
				st, err := c.Stream(streamID)
				if err != nil {
					c.CloseWithError(transport.ApplicationError, err.Error())
					return
				}
				fileURL := s.files[0]
				s.files = s.files[1:]
				if c.UserData() == nil {
					c.SetUserData(1)
				} else {
					c.SetUserData(c.UserData().(int) + 1)
				}
				go s.downloadFileAsync(st, fileURL)
			}
		case transport.EventStreamClosed:
			if c.UserData() != nil {
				streams := c.UserData().(int) - 1
				c.SetUserData(streams)
				if streams == 0 && len(s.files) == 0 {
					// Download finished
					c.Close()
				}
			}
		case transport.EventConnClosed:
			s.wg.Done()
		}
	}
}

func (s *clientHandler) downloadFileAsync(st *quic.Stream, fileURL *url.URL) {
	var output *os.File
	if s.root == "" {
		output = os.Stdout
	} else {
		name := filepath.Join(s.root, path.Clean(fileURL.Path))
		f, err := os.Create(name)
		if err != nil {
			log.Printf("download %v: %v", fileURL.Path, err)
			return
		}
		defer f.Close()
		output = f
	}
	req := fmt.Sprintf("GET %s\r\n", fileURL.Path)
	_, err := st.Write([]byte(req))
	if err != nil {
		log.Printf("download %v: %v", fileURL.Path, err)
		return
	}
	err = st.Close()
	if err != nil {
		log.Printf("download %v: %v", fileURL.Path, err)
		st.CloseRead(1)
		return
	}
	_, err = io.Copy(output, st)
	if err != nil {
		log.Printf("download %v: %v", fileURL.Path, err)
		st.CloseRead(1)
	}
}

func parseURL(addr string) (*url.URL, error) {
	addrURL, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}
	if addrURL.Scheme != "https" {
		return nil, fmt.Errorf("unsupported url scheme: %v", addrURL)
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
