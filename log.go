package quic

import (
	"bytes"
	"fmt"
	"io"
	"sync"
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
	level  logLevel
	mu     sync.Mutex
	writer io.Writer
}

func (s *logger) setWriter(w io.Writer) {
	s.mu.Lock()
	s.writer = w
	s.mu.Unlock()
}

func (s *logger) Write(b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writer.Write(b)
}

func (s *logger) log(level logLevel, format string, values ...interface{}) {
	if s.level < level || s.writer == nil {
		return
	}
	b := bytes.Buffer{}
	b.WriteString(time.Now().Format(logTimeFormat))
	b.WriteString(" ")
	fmt.Fprintf(&b, format, values...)
	b.WriteString("\n")
	s.writer.Write(b.Bytes())
}

func (s *logger) attachLogger(c *Conn) {
	if s.level < levelDebug || s.writer == nil {
		return
	}
	tl := transactionLogger{
		writer: s, // Write protected
		prefix: fmt.Sprintf("cid=%x", c.scid),
	}
	c.conn.OnLogEvent(tl.logEvent)
}

func (s *logger) detachLogger(c *Conn) {
	c.conn.OnLogEvent(nil)
}

type transactionLogger struct {
	writer io.Writer
	prefix string
}

func (s *transactionLogger) logEvent(e transport.LogEvent) {
	s.writer.Write(formatLogEvent(e, s.prefix))
}

func formatLogEvent(e transport.LogEvent, prefix string) []byte {
	b := bytes.Buffer{}
	b.WriteString(e.Time.Format(logTimeFormat))
	b.WriteString("   ") // extra indentation for transport-level events
	b.WriteString(e.Type)
	if prefix != "" {
		b.WriteString(" ")
		b.WriteString(prefix)
	}
	for _, f := range e.Fields {
		b.WriteString(" ")
		b.WriteString(f.String())
	}
	b.WriteString("\n")
	return b.Bytes()
}
