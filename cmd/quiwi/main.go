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
			fmt.Sprintf("hq-%d", c.Version&0xff),
			"http/0.9",
		},
		ClientSessionCache: tls13.NewLRUClientSessionCache(10),
		KeyLogWriter:       newKeyLogWriter(),
	}
	return c
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

type buffers struct {
	list chan []byte
	size int
}

func newBuffers(size, length int) buffers {
	return buffers{
		list: make(chan []byte, length),
		size: size,
	}
}

func (s *buffers) pop() []byte {
	var b []byte
	select {
	case b = <-s.list:
		// Got one
	default:
		b = make([]byte, s.size)
	}
	return b
}

func (s *buffers) push(b []byte) {
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
