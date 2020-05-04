// Package quic provides a basic QUIC client and server connection.
package quic

import (
	"crypto/rand"
	"io"
	"net"
	"sync"
	"time"

	"github.com/goburrow/quic/transport"
)

const (
	maxDatagramSize = transport.MaxIPv6PacketSize
	bufferSize      = 1536
	maxTokenLen     = 64 + transport.MaxCIDLength
)

// Conn is a QUIC connection.
type Conn interface {
	RemoteAddr() net.Addr
	Events() []interface{}
	Stream(uint64) io.ReadWriteCloser
	Close() error
}

// Handler defines interface to handle QUIC connection states.
type Handler interface {
	Created(Conn) error
	Serve(Conn)
	Closed(Conn)
}

type noopHandler struct{}

func (s noopHandler) Created(Conn) error {
	return nil
}

func (s noopHandler) Serve(Conn) {}

func (s noopHandler) Closed(Conn) {}

// remoteConn implements Conn.
type remoteConn struct {
	scid [transport.MaxCIDLength]byte
	addr net.Addr
	conn *transport.Conn
	recv chan *packet
}

func (s *remoteConn) RemoteAddr() net.Addr {
	return s.addr
}

func (s *remoteConn) Events() []interface{} {
	return s.conn.Events()
}

func (s *remoteConn) Stream(id uint64) io.ReadWriteCloser {
	return s.conn.Stream(id)
}

func (s *remoteConn) Close() error {
	s.conn.Close(true, transport.NoError, "")
	return nil
}

type localConn struct {
	config *transport.Config
	socket net.PacketConn

	peersMu sync.RWMutex
	peers   map[string]*remoteConn

	handler Handler
	logger  Logger
}

func (s *localConn) listen(addr string) error {
	localAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	socket, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		return err
	}
	s.logger.Log(LevelInfo, "listening %s", socket.LocalAddr())
	s.socket = socket
	return nil
}

func (s *localConn) handleConn(c *remoteConn) {
	defer func() {
		s.handler.Closed(c)
		s.peersMu.Lock()
		delete(s.peers, string(c.scid[:]))
		s.peersMu.Unlock()
	}()
	for !c.conn.IsClosed() {
		timeout := c.conn.Timeout()
		if timeout < 0 {
			// TODO
			timeout = 10 * time.Second
		}
		var p *packet
		var ok bool
		select {
		case p, ok = <-c.recv:
			if ok {
				s.connRecv(c, p.data)
			} else {
				// Server closed
				c.conn.Close(true, transport.NoError, "bye")
			}
		case <-time.After(timeout):
			s.logger.Log(LevelDebug, "%s %x timed out after %s", c.addr, c.scid, timeout)
			c.conn.Write(nil)
		}
		if c.conn.IsEstablished() {
			s.handler.Serve(c)
		}
		if p == nil {
			p = newPacket()
		}
		s.connSend(c, p.buf[:maxDatagramSize])
		freePacket(p)
	}
	s.logger.Log(LevelDebug, "%s %x closed", c.addr, c.scid)
}

func (s *localConn) connRecv(c *remoteConn, data []byte) {
	n, err := c.conn.Write(data)
	if err != nil {
		s.logger.Log(LevelError, "%s receive failed: %v", c.addr, err)
		return
	}
	s.logger.Log(LevelDebug, "%s received %d bytes", c.addr, n)
}

func (s *localConn) connSend(c *remoteConn, buf []byte) error {
	for {
		n, err := c.conn.Read(buf)
		if err != nil {
			s.logger.Log(LevelError, "%s send failed: %v", c.addr, err)
			return err
		}
		if n == 0 {
			s.logger.Log(LevelDebug, "%s done sending", c.addr)
			return nil
		}
		n, err = s.socket.WriteTo(buf[:n], c.addr)
		if err != nil {
			s.logger.Log(LevelError, "%s send failed: %v", c.addr, err)
			return err
		}
		s.logger.Log(LevelDebug, "%s sent %d bytes", c.addr, n)
	}
}

// rand uses tls.Config.Rand if available.
func (s *localConn) rand(b []byte) error {
	var err error
	if s.config.TLS != nil && s.config.TLS.Rand != nil {
		_, err = io.ReadFull(s.config.TLS.Rand, b)
	} else {
		_, err = rand.Read(b)
	}
	return err
}

type packet struct {
	buf  [bufferSize]byte
	data []byte // Always points to buf
	addr net.Addr
}

var packetPool = sync.Pool{}

func newPacket() *packet {
	p := packetPool.Get()
	if p != nil {
		return p.(*packet)
	}
	return &packet{}
}

func freePacket(p *packet) {
	p.data = nil
	p.addr = nil
	packetPool.Put(p)
}
