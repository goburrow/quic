package quic

import (
	"fmt"
	"io"
	"strconv"
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
const hexTable = "0123456789abcdef"

type fieldType int8

const (
	fieldTypeString fieldType = iota
	fieldTypeInt
	fieldTypeHex
	fieldTypeError
	fieldTypeStringer
)

type logField struct {
	key string
	str string
	num int
	byt []byte
	any interface{}
	typ fieldType
}

func (s *logField) log(b []byte) []byte {
	// Always add whitespace
	b = append(b, ' ')
	if s.key != "" {
		b = append(b, s.key...)
		b = append(b, '=')
	}
	switch s.typ {
	case fieldTypeString:
		b = append(b, s.str...)
	case fieldTypeInt:
		b = strconv.AppendInt(b, int64(s.num), 10)
	case fieldTypeHex:
		for _, v := range s.byt {
			b = append(b, hexTable[v>>4])
			b = append(b, hexTable[v&0x0f])
		}
	case fieldTypeError:
		b = append(b, s.any.(error).Error()...)
	case fieldTypeStringer:
		b = append(b, s.any.(fmt.Stringer).String()...)
	}
	return b
}

func zs(key string, val string) logField {
	return logField{
		key: key,
		typ: fieldTypeString,
		str: val,
	}
}

func zi(key string, val int) logField {
	return logField{
		key: key,
		typ: fieldTypeInt,
		num: val,
	}
}

func zx(key string, val []byte) logField {
	return logField{
		key: key,
		typ: fieldTypeHex,
		byt: val,
	}
}

func ze(key string, val error) logField {
	return logField{
		key: key,
		typ: fieldTypeError,
		any: val,
	}
}

func zv(key string, val fmt.Stringer) logField {
	return logField{
		key: key,
		typ: fieldTypeStringer,
		any: val,
	}
}

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

func (s *logger) log(level logLevel, fields ...logField) {
	if s.logLevel() < level {
		return
	}
	p := newPacket()
	defer freePacket(p)
	b := p.buf[:0]
	b = time.Now().AppendFormat(b, logTimeFormat)
	for _, f := range fields {
		b = f.log(b)
	}
	b = append(b, '\n')
	s.Write(b)
}

func (s *logger) attachLogger(c *Conn) {
	if s.logLevel() < levelDebug {
		return
	}
	fd := zx("cid", c.scid)
	tl := transactionLogger{
		writer: s, // Write protected
		prefix: string(fd.log(nil)),
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
	b := p.buf[:0]
	b = e.Time.AppendFormat(b, logTimeFormat)
	b = append(b, "   "...) // extra indentation for transport-level events
	b = append(b, e.Name...)
	if len(s.prefix) > 0 {
		// Prefix already included a whitespace
		b = append(b, s.prefix...)
	}
	b = append(b, ' ')
	b = append(b, e.Data...)
	b = append(b, '\n')
	s.writer.Write(b)
}
