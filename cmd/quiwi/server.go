package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/goburrow/quic"
	"github.com/goburrow/quic/transport"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

type serverCommand struct{}

func (serverCommand) Name() string {
	return "server"
}

func (serverCommand) Desc() string {
	return "start a QUIC server."
}

func (serverCommand) Run(args []string) error {
	cmd := flag.NewFlagSet("server", flag.ExitOnError)
	listenAddr := cmd.String("listen", ":4433", "listen on the given IP:port")
	certFile := cmd.String("cert", "", "TLS certificate path")
	keyFile := cmd.String("key", "", "TLS certificate key path")
	domains := cmd.String("domains", "", "allowed host names for ACME (separated by a comma)")
	cacheDir := cmd.String("cache", ".", "certificate cache directory when using ACME")
	root := cmd.String("root", "www", "root directory")
	qlogPath := cmd.String("qlog", "", "qlog directory or file path")
	logLevel := cmd.Int("v", 2, "log verbose: 0=off 1=error 2=info 3=debug 4=trace")
	useAsync := cmd.Bool("async", false, "use asynchronous Stream APIs")
	enableRetry := cmd.Bool("retry", false, "enable address validation using Retry packet")
	cmd.Usage = func() {
		fmt.Fprintln(cmd.Output(), "Usage: quiwi server [arguments]")
		cmd.PrintDefaults()
	}
	cmd.Parse(args)

	config := newConfig()
	if *certFile != "" {
		// Configure TLS
		cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			return err
		}
		config.TLS.Certificates = []tls.Certificate{cert}
	}
	if *domains != "" {
		// Configure ACME
		acme := acmeHandler{
			domains:  *domains,
			cacheDir: *cacheDir,
		}
		err := acme.listen(config.TLS)
		if err != nil {
			return err
		}
		defer acme.Close()
		go acme.serve()
	}
	if len(config.TLS.Certificates) == 0 && config.TLS.GetCertificate == nil && config.TLS.GetConfigForClient == nil {
		return fmt.Errorf("TLS certificate must be set")
	}
	server := quic.NewServer(config)
	server.SetHandler(&serverHandler{
		root:  *root,
		async: *useAsync,
	})
	if *enableRetry {
		// Stateless retry
		server.SetAddressValidator(quic.NewAddressValidator())
	}
	// Logging
	if *qlogPath == "" {
		server.SetLogger(*logLevel, os.Stderr)
	} else {
		qw, err := newQLogWriter(*qlogPath, "server-")
		if err != nil {
			return err
		}
		defer qw.Close()
		go qw.process()
		server.SetLogger(*logLevel, qw)
	}

	sigCh := make(chan os.Signal, 3)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		<-sigCh
		server.Close()
	}()
	return server.ListenAndServe(*listenAddr)
}

// serverHandler implements quic.Handler
type serverHandler struct {
	root  string
	async bool
}

// Serve processes connection events.
func (s *serverHandler) Serve(c *quic.Conn, events []transport.Event) {
	if s.async {
		s.serveAsync(c, events)
	} else {
		s.serveSync(c, events)
	}
}

// serveSync demonstrates using synchronous Stream APIs.
func (s *serverHandler) serveSync(c *quic.Conn, events []transport.Event) {
	for _, e := range events {
		switch e.Type {
		case transport.EventStreamReadable:
			err := s.handleStreamReadable(c, e.Data)
			if err != nil {
				c.CloseWithError(transport.ApplicationError, err.Error())
				return
			}
		case transport.EventStreamWritable:
			err := s.handleStreamWritable(c, e.Data)
			if err != nil {
				c.CloseWithError(transport.ApplicationError, err.Error())
				return
			}
		case transport.EventConnClosed:
			for _, f := range s.getResponses(c) {
				f.f.Close()
			}
		}
	}
}

func (s *serverHandler) handleStreamReadable(c *quic.Conn, streamID uint64) error {
	// TODO: Here we assume the whole request is in a single read.
	buf := buffers.pop()
	defer buffers.push(buf)
	n, err := c.StreamRead(streamID, buf)
	if n <= 0 {
		if err == io.EOF {
			return nil
		}
		return err
	}
	f := getFile(s.root, string(buf[:n]))
	if f == nil {
		c.StreamWrite(streamID, []byte("not found"))
		return c.StreamClose(streamID)
	}
	reader := newBufferFileReader(f)
	// Write initial data
	for i := 0; i < 4; i++ {
		b, err := reader.r.Peek(reader.r.Size())
		if len(b) > 0 {
			n, err := c.StreamWrite(streamID, b)
			if err != nil {
				f.Close()
				c.StreamCloseWrite(streamID, 1)
				return err
			}
			reader.r.Discard(n)
			if n < len(b) {
				break
			}
		}
		if err != nil {
			if err == bufio.ErrBufferFull && len(b) > 0 {
				continue
			}
			f.Close()
			if err == io.EOF {
				c.StreamClose(streamID) // Done sending
				return nil
			}
			c.StreamCloseWrite(streamID, 1) // Internal error
			return err
		}
	}
	s.getResponses(c)[streamID] = reader // Continue later
	return nil
}

func (s *serverHandler) handleStreamWritable(c *quic.Conn, streamID uint64) error {
	responses := s.getResponses(c)
	reader := responses[streamID]
	if reader.f == nil {
		return nil
	}
	for i := 0; i < 4; i++ {
		b, err := reader.r.Peek(reader.r.Size())
		if len(b) > 0 {
			n, err := c.StreamWrite(streamID, b)
			if err != nil {
				reader.f.Close()
				delete(responses, streamID)
				c.StreamCloseWrite(streamID, 1)
				return err
			}
			reader.r.Discard(n)
			if n < len(b) {
				return nil
			}
		}
		if err != nil {
			if err == bufio.ErrBufferFull && len(b) > 0 {
				continue
			}
			reader.f.Close()
			delete(responses, streamID)
			if err == io.EOF {
				c.StreamClose(streamID) // Done sending
				return nil
			}
			c.StreamCloseWrite(streamID, 1) // Internal error
			return err
		}
	}
	return nil
}

func (s *serverHandler) getResponses(c *quic.Conn) map[uint64]bufferFile {
	if c.UserData() == nil {
		responses := make(map[uint64]bufferFile)
		c.SetUserData(responses)
		return responses
	}
	return c.UserData().(map[uint64]bufferFile)
}

// serveAsync demonstrates using asynchronous Stream APIs.
func (s *serverHandler) serveAsync(c *quic.Conn, events []transport.Event) {
	for _, e := range events {
		switch e.Type {
		case transport.EventStreamOpen:
			st, err := c.Stream(e.Data)
			if err != nil {
				c.CloseWithError(transport.ApplicationError, err.Error())
				return
			}
			go s.handleStreamAsync(st)
		}
	}
}

// handleStream must be run in a new goroutine.
func (s *serverHandler) handleStreamAsync(st *quic.Stream) {
	defer st.Close()
	//st.SetDeadline(time.Now().Add(5 * time.Minute))

	// TODO: Here we assume the whole request is in a single read.
	buf := buffers.pop()
	defer buffers.push(buf)
	n, _ := st.Read(buf)
	if n <= 0 {
		st.CloseWrite(1)
		return
	}
	f := getFile(s.root, string(buf[:n]))
	if f == nil {
		st.Write([]byte("not found"))
		return
	}
	defer f.Close()
	_, err := io.CopyBuffer(st, f, buf)
	if err != nil {
		st.CloseWrite(1)
	}
}

func getFile(root, req string) *os.File {
	// Parse request
	if !strings.HasPrefix(req, "GET /") {
		return nil
	}
	reqURL, err := url.ParseRequestURI(strings.TrimSpace(req[4:]))
	if err != nil {
		return nil
	}
	name := filepath.Join(root, path.Clean(reqURL.Path))
	f, err := os.Open(name)
	if err != nil {
		return nil
	}
	if info, err := f.Stat(); err != nil || info.Mode().IsDir() {
		f.Close()
		return nil
	}
	return f
}

// acmeHandler listens on the standard TLS port (443) and handles "tls-alpn-01" challenge
// from Let's Encrypt.
type acmeHandler struct {
	domains  string
	cacheDir string
	ln       net.Listener
}

func (s *acmeHandler) listen(config *tls.Config) error {
	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(strings.Split(s.domains, ",")...),
		Cache:      autocert.DirCache(s.cacheDir),
	}
	config.GetCertificate = certManager.GetCertificate
	config.NextProtos = append(config.NextProtos, acme.ALPNProto)
	listener, err := tls.Listen("tcp", ":443", config)
	if err != nil {
		return fmt.Errorf("acme listen: %v", err)
	}
	s.ln = listener
	return nil
}

func (s *acmeHandler) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			log.Printf("acme accept: %v", err)
			return
		}
		// Maybe handshake in separated goroutines?
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		err = conn.(*tls.Conn).Handshake()
		if err != nil {
			log.Printf("acme handshake: %v", err)
		}
		conn.Close()
	}
}

func (s *acmeHandler) Close() error {
	return s.ln.Close()
}
