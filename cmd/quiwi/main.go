package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"

	"github.com/goburrow/quic/tls13"
	"github.com/goburrow/quic/transport"
)

type command interface {
	Name() string
	Desc() string
	Run([]string) error
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	commands := []command{clientCommand{}, datagramCommand{}, qlogCommand{}, serverCommand{}}
	flag.Usage = func() {
		output := flag.CommandLine.Output()
		fmt.Fprintln(output, "Usage: quiwi <command> [arguments]")
		fmt.Fprintln(output, "commands:")
		for _, c := range commands {
			fmt.Fprintf(output, "\t%-16s%s\n", c.Name(), c.Desc())
		}
		flag.PrintDefaults()
	}
	flag.Parse()
	cmd := flag.Arg(0)
	for _, c := range commands {
		if c.Name() == cmd {
			err := c.Run(flag.Args()[1:])
			if err != nil {
				log.Fatal(err)
			}
			return
		}
	}
	flag.Usage()
	os.Exit(2)
}

func newConfig() *transport.Config {
	c := transport.NewConfig()
	c.Params.MaxUDPPayloadSize = transport.MaxIPv6PacketSize
	c.Params.MaxIdleTimeout = 30 * time.Second
	c.Params.InitialMaxData = 1000000
	c.Params.InitialMaxStreamDataBidiLocal = 100000
	c.Params.InitialMaxStreamDataBidiRemote = 100000
	c.Params.InitialMaxStreamDataUni = 100000
	c.Params.InitialMaxStreamsBidi = 8
	c.Params.InitialMaxStreamsUni = 8
	c.TLS = &tls.Config{
		NextProtos: []string{
			"hq",
			"hq-interop",
			"http/0.9",
		},
		ClientSessionCache: tls13.NewLRUClientSessionCache(10),
		KeyLogWriter:       newKeyLogWriter(),
	}
	return c
}

func setCipherSuites(config *tls.Config, cipher string) error {
	switch cipher {
	case "":
		// Auto
	case tls.CipherSuiteName(tls.TLS_AES_128_GCM_SHA256):
		config.CipherSuites = []uint16{tls.TLS_AES_128_GCM_SHA256}
	case tls.CipherSuiteName(tls.TLS_AES_256_GCM_SHA384):
		config.CipherSuites = []uint16{tls.TLS_AES_256_GCM_SHA384}
	case tls.CipherSuiteName(tls.TLS_CHACHA20_POLY1305_SHA256):
		config.CipherSuites = []uint16{tls.TLS_CHACHA20_POLY1305_SHA256}
	default:
		return fmt.Errorf("unsupported cipher: %v", cipher)
	}
	return nil
}

func newKeyLogWriter() io.Writer {
	logFile := os.Getenv("SSLKEYLOGFILE")
	if logFile == "" {
		return nil
	}
	f, err := os.OpenFile(logFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return nil
	}
	return &keyLogWriter{w: f}
}

type keyLogWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (w *keyLogWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.w.Write(b)
}

var buffers = newBufferCache(8192, 10)

type bufferCache struct {
	list chan []byte
	size int
}

func newBufferCache(size, length int) bufferCache {
	return bufferCache{
		list: make(chan []byte, length),
		size: size,
	}
}

func (s *bufferCache) pop() []byte {
	var b []byte
	select {
	case b = <-s.list:
		// Got one
	default:
		b = make([]byte, s.size)
	}
	return b
}

func (s *bufferCache) push(b []byte) {
	if cap(b) != s.size {
		panic("invalid buffer capacity")
	}
	b = b[:s.size]
	select {
	case s.list <- b:
	default:
		// Full
	}
}
