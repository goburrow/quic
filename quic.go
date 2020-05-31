// Package quic provides a basic QUIC client and server connection.
package quic

import (
	"crypto/rand"
	"errors"
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

// Conn is an asynchronous QUIC connection.
type Conn interface {
	net.Conn
	// Stream returns QUIC stream by ID.
	Stream(id uint64) io.ReadWriteCloser
	// SetStream sets or creates stream for Read and Write.
	SetStream(id uint64)
}

// Handler defines interface to handle QUIC connection states.
type Handler interface {
	Serve(conn Conn, events []interface{})
}

type noopHandler struct{}

func (s noopHandler) Serve(Conn, []interface{}) {}

// ConnAcceptEvent is an event where a new connection is established.
type ConnAcceptEvent struct{}

// ConnCloseEvent is an event where a connection is closed.
type ConnCloseEvent struct{}

// remoteConn implements Conn.
type remoteConn struct {
	scid [transport.MaxCIDLength]byte
	addr net.Addr
	conn *transport.Conn

	events []interface{}
	recvCh chan *packet

	// Current stream for Read and Write
	stream *transport.Stream
}

func newRemoteConn(addr net.Addr) *remoteConn {
	return &remoteConn{
		addr:   addr,
		recvCh: make(chan *packet, 1),
	}
}

func (s *remoteConn) Read(b []byte) (int, error) {
	if s.stream == nil {
		return 0, errors.New("invalid stream")
	}
	return s.stream.Read(b)
}

func (s *remoteConn) Write(b []byte) (int, error) {
	if s.stream == nil {
		return 0, errors.New("invalid stream")
	}
	return s.stream.Write(b)
}

func (s *remoteConn) Close() error {
	s.conn.Close(true, transport.NoError, "close")
	return nil
}

func (s *remoteConn) Stream(id uint64) io.ReadWriteCloser {
	st, err := s.conn.Stream(id)
	if err != nil {
		// TODO: log error
		return nil
	}
	return st
}

func (s *remoteConn) SetStream(id uint64) {
	s.stream, _ = s.conn.Stream(id)
}

func (s *remoteConn) LocalAddr() net.Addr {
	return nil // TODO: get from socket
}

func (s *remoteConn) RemoteAddr() net.Addr {
	return s.addr
}

func (s *remoteConn) SetDeadline(t time.Time) error {
	return errors.New("not implemented")
}

func (s *remoteConn) SetReadDeadline(t time.Time) error {
	return errors.New("not implemented")
}

func (s *remoteConn) SetWriteDeadline(t time.Time) error {
	return errors.New("not implemented")
}

type localConn struct {
	config *transport.Config
	socket net.PacketConn

	peersMu sync.RWMutex
	peers   map[string]*remoteConn

	closing   bool      // locked by peersMu.
	closeCond sync.Cond // locked by peersMu. Closing a connection will broadcast when connections is empty
	closeCh   chan struct{}

	handler Handler
	logger  Logger
}

func (s *localConn) init(config *transport.Config) {
	s.config = config
	s.peers = make(map[string]*remoteConn)
	s.closeCh = make(chan struct{})
	s.closeCond.L = &s.peersMu
	s.handler = noopHandler{}
	s.logger = leveledLogger(LevelInfo)
}

// SetHandler sets QUIC connection callbacks.
func (s *localConn) SetHandler(v Handler) {
	s.handler = v
}

// SetLogger sets transaction logger.
func (s *localConn) SetLogger(v Logger) {
	s.logger = v
}

// SetListen sets listening socket connection.
func (s *localConn) SetListen(conn net.PacketConn) {
	s.socket = conn
}

func (s *localConn) handleConn(c *remoteConn) {
	defer s.connClosed(c)
	established := false
	for !c.conn.IsClosed() {
		timeout := c.conn.Timeout()
		if timeout < 0 {
			// TODO
			timeout = 10 * time.Second
		}
		timer := time.NewTimer(timeout)
		var p *packet
		select {
		case p = <-c.recvCh:
			// Got packet
			s.recvConn(c, p.data)
		case <-timer.C:
			// Read timeout
			s.logger.Log(LevelDebug, "%s %x timed out after %s", c.addr, c.scid, timeout)
			c.conn.Write(nil)
		case <-s.closeCh:
			// Server is closing (see s.close)
			c.conn.Close(true, transport.NoError, "bye")
		}
		timer.Stop()
		if established {
			s.serveConn(c)
		} else {
			if c.conn.IsEstablished() {
				// Maybe also attach packet header in the event?
				c.events = append(c.events, ConnAcceptEvent{})
				established = true
				s.serveConn(c)
			}
		}
		if p == nil {
			// For sending data
			p = newPacket()
		}
		s.sendConn(c, p.buf[:maxDatagramSize])
		freePacket(p)
	}
}

func (s *localConn) recvConn(c *remoteConn, data []byte) {
	n, err := c.conn.Write(data)
	if err != nil {
		s.logger.Log(LevelError, "%s receive failed: %v", c.addr, err)
		return
	}
	s.logger.Log(LevelTrace, "%s processed %d bytes", c.addr, n)
}

func (s *localConn) sendConn(c *remoteConn, buf []byte) error {
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
		s.logger.Log(LevelTrace, "%s sent %d bytes\n%x", c.addr, n, buf[:n])
	}
}

func (s *localConn) serveConn(c *remoteConn) {
	c.events = c.conn.Events(c.events)
	s.handler.Serve(c, c.events)
	// Clear events
	for i := range c.events {
		c.events[i] = nil
	}
	c.events = c.events[:0]
}

func (s *localConn) connClosed(c *remoteConn) {
	s.logger.Log(LevelDebug, "%s %x closed", c.addr, c.scid)
	c.events = append(c.events, ConnCloseEvent{})
	s.serveConn(c)
	s.peersMu.Lock()
	delete(s.peers, string(c.scid[:]))
	// If server is closing and this is the last one, tell others
	if s.closing && len(s.peers) == 0 {
		s.closeCond.Broadcast()
	}
	s.peersMu.Unlock()
}

// close closes receving packet channel of all connections to signal terminating handleConn gorotines.
func (s *localConn) close(timeout time.Duration) {
	s.peersMu.Lock()
	if s.closing {
		// Already closing
		s.peersMu.Unlock()
		return
	}
	s.closing = true
	close(s.closeCh) // This should ask all connections to close
	s.peersMu.Unlock()
	if timeout > 0 {
		// Can not use WaitGroup since we want to use closing timeout (and possible context.Context)
		timer := time.AfterFunc(timeout, func() {
			s.peersMu.Lock()
			s.closeCond.Broadcast()
			s.peersMu.Unlock()
		})
		defer timer.Stop()
		s.peersMu.Lock()
		if len(s.peers) > 0 {
			s.closeCond.Wait()
		}
		s.peersMu.Unlock()
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

	header transport.Header
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
	p.header = transport.Header{}
	packetPool.Put(p)
}
