package quic

import (
	"bytes"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/goburrow/quic/transport"
)

type logLevel int

// Log levels
const (
	levelOff logLevel = iota
	levelError
	levelInfo
	levelDebug
	levelTrace
)

const logTimeFormat = "2006/01/02 15:04:05.000000" // Similar to log package

// logger logs QUIC transactions.
type logger struct {
	mu     sync.Mutex
	writer io.Writer
	level  int32 // atomic
}

func (s *logger) setWriter(w io.Writer) {
	s.mu.Lock()
	s.writer = w
	s.mu.Unlock()
}

func (s *logger) setLevel(l logLevel) {
	atomic.StoreInt32(&s.level, int32(l))
}

func (s *logger) Write(b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writer.Write(b)
}

func (s *logger) log(level logLevel, format string, values ...interface{}) {
	if s.logLevel() < level {
		return
	}
	p := newPacket()
	defer freePacket(p)
	b := bytes.NewBuffer(p.buf[:0])
	b.WriteString(time.Now().Format(logTimeFormat))
	b.WriteString(" ")
	fmt.Fprintf(b, format, values...)
	b.WriteString("\n")
	s.Write(b.Bytes())
}

func (s *logger) attachLogger(c *Conn) {
	if s.logLevel() < levelDebug {
		return
	}
	tl := transactionLogger{
		writer: s, // Write protected
		prefix: fmt.Sprintf("cid=%x", c.scid),
	}
	c.conn.SetLogger(tl.logEvent)
}

func (s *logger) detachLogger(c *Conn) {
	c.conn.SetLogger(nil)
}

func (s *logger) logLevel() logLevel {
	return logLevel(atomic.LoadInt32(&s.level))
}

type transactionLogger struct {
	writer *logger
	prefix string
}

func (s *transactionLogger) logEvent(e transport.LogEvent) {
	p := newPacket()
	defer freePacket(p)
	b := bytes.NewBuffer(p.buf[:0])
	b.WriteString(e.Time.Format(logTimeFormat))
	b.WriteString("   ") // extra indentation for transport-level events
	b.WriteString(e.Type)
	if s.prefix != "" {
		b.WriteString(" ")
		b.WriteString(s.prefix)
	}
	for _, f := range e.Fields {
		b.WriteString(" ")
		b.WriteString(f.String())
	}
	b.WriteString("\n")
	s.writer.Write(b.Bytes())
}
