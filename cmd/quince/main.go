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

	"github.com/goburrow/quic/transport"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	flag.Usage = func() {
		fmt.Fprintln(flag.CommandLine.Output(), "Usage: quince <command> [options]")
		flag.PrintDefaults()
	}
	flag.Parse()
	cmd := flag.Arg(0)
	var err error
	switch cmd {
	case "server":
		err = serverCommand(flag.Args()[1:])
	case "client":
		err = clientCommand(flag.Args()[1:])
	case "qlog":
		err = qlogCommand(flag.Args()[1:])
	default:
		flag.Usage()
		os.Exit(2)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func newConfig() *transport.Config {
	c := transport.NewConfig()
	c.Params.MaxUDPPayloadSize = transport.MaxIPv6PacketSize
	c.Params.MaxIdleTimeout = 5 * time.Second
	c.Params.InitialMaxData = 800000
	c.Params.InitialMaxStreamDataBidiLocal = 100000
	c.Params.InitialMaxStreamDataBidiRemote = 100000
	c.Params.InitialMaxStreamDataUni = 100000
	c.Params.InitialMaxStreamsBidi = 8
	c.Params.InitialMaxStreamsUni = 8
	c.TLS = &tls.Config{
		NextProtos: []string{
			fmt.Sprintf("hq-%d", transport.ProtocolVersion&0xff),
			"http/0.9",
		},
		KeyLogWriter: newKeyLogWriter(),
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
