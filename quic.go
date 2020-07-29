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
	bufferSize      = 1500
)

// Extend transport events
const (
	EventConnAccept = "conn_accept"
	EventConnClose  = "conn_close"
)

// Conn is an asynchronous QUIC connection.
type Conn interface {
	// Stream creates or returns an existing QUIC stream given the ID.
	Stream(id uint64) io.ReadWriteCloser
	// LocalAddr returns the local network address.
	LocalAddr() net.Addr
	// RemoteAddr returns the remote network address.
	RemoteAddr() net.Addr
	// Close sets state of the connection to closing.
	Close() error
}

// Handler defines interface to handle QUIC connection states.
type Handler interface {
	Serve(conn Conn, events []transport.Event)
}

type noopHandler struct{}

func (s noopHandler) Serve(Conn, []transport.Event) {}

// remoteConn implements Conn.
type remoteConn struct {
	scid []byte
	addr net.Addr
	conn *transport.Conn

	events []transport.Event
	recvCh chan *packet
}

func newRemoteConn(addr net.Addr, scid []byte, conn *transport.Conn) *remoteConn {
	return &remoteConn{
		addr:   addr,
		scid:   scid,
		conn:   conn,
		recvCh: make(chan *packet, 1),
	}
}

// Close sets the connection status to close state.
func (s *remoteConn) Close() error {
	s.conn.Close(true, transport.NoError, "bye")
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

func (s *remoteConn) LocalAddr() net.Addr {
	return nil // TODO: get from socket
}

func (s *remoteConn) RemoteAddr() net.Addr {
	return s.addr
}

// localConn is a local quic connection.
type localConn struct {
	config *transport.Config
	socket net.PacketConn

	peersMu sync.RWMutex
	peers   map[string]*remoteConn

	closing   bool      // locked by peersMu.
	closeCond sync.Cond // locked by peersMu. Closing a connection will broadcast when connections is empty
	closeCh   chan struct{}

	handler Handler
	logger  logger
}

func (s *localConn) init(config *transport.Config) {
	s.config = config
	s.peers = make(map[string]*remoteConn)
	s.closeCh = make(chan struct{})
	s.closeCond.L = &s.peersMu
	s.handler = noopHandler{}
}

// SetHandler sets QUIC connection callbacks.
func (s *localConn) SetHandler(v Handler) {
	s.handler = v
}

// SetLogger sets transaction logger.
func (s *localConn) SetLogger(level int, w io.Writer) {
	s.logger.setWriter(w)
	s.logger.level = logLevel(level)
}

// SetListen sets listening socket connection.
func (s *localConn) SetListen(conn net.PacketConn) {
	s.socket = conn
}

// handleConn handles data sending to the connection c.
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
			s.logger.log(levelDebug, "read_timed_out addr=%s scid=%x timeout=%s", c.addr, c.scid, timeout)
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
				c.events = append(c.events, transport.Event{Type: EventConnAccept})
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
		s.logger.log(levelError, "receive_failed addr=%s scid=%x %v", c.addr, c.scid, err)
		// Close connection when receive failed
		if err, ok := err.(*transport.Error); ok {
			c.conn.Close(false, err.Code, err.Message)
		} else {
			c.conn.Close(false, transport.InternalError, "")
		}
		return
	}
	s.logger.log(levelTrace, "datagrams_processed addr=%s scid=%x byte_length=%d", c.addr, c.scid, n)
}

func (s *localConn) sendConn(c *remoteConn, buf []byte) error {
	for {
		n, err := c.conn.Read(buf)
		if err != nil {
			s.logger.log(levelError, "send_failed addr=%s scid=%x %v", c.addr, c.scid, err)
			return err
		}
		if n == 0 {
			s.logger.log(levelTrace, "send_done addr=%s scid=%x", c.addr, c.scid)
			return nil
		}
		n, err = s.socket.WriteTo(buf[:n], c.addr)
		if err != nil {
			s.logger.log(levelError, "send_failed addr=%s scid=%x %v", c.addr, c.scid, err)
			return err
		}
		s.logger.log(levelTrace, "datagrams_sent addr=%s scid=%x byte_length=%d raw=%x", c.addr, c.scid, n, buf[:n])
	}
}

func (s *localConn) serveConn(c *remoteConn) {
	c.events = c.conn.Events(c.events)
	s.handler.Serve(c, c.events)
	for i := range c.events {
		c.events[i] = transport.Event{}
	}
	c.events = c.events[:0]
}

func (s *localConn) connClosed(c *remoteConn) {
	s.logger.log(levelDebug, "connection_closed addr=%s scid=%x", c.addr, c.scid)
	c.events = append(c.events, transport.Event{Type: EventConnClose})
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
	data   []byte // Always points to buf
	addr   net.Addr
	header transport.Header

	buf [bufferSize]byte
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
