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

// Handler defines interface to handle QUIC connection states.
type Handler interface {
	Serve(conn *Conn, events []transport.Event)
}

type noopHandler struct{}

func (s noopHandler) Serve(*Conn, []transport.Event) {}

// Conn is an asynchronous QUIC connection.
type Conn struct {
	scid []byte
	addr net.Addr
	conn *transport.Conn

	events []transport.Event
	recvCh chan *packet

	nextStreamIDBidi uint64
	nextStreamIDUni  uint64

	userData interface{}
}

func newRemoteConn(addr net.Addr, scid []byte, conn *transport.Conn) *Conn {
	return &Conn{
		addr:   addr,
		scid:   scid,
		conn:   conn,
		recvCh: make(chan *packet, 8),

		nextStreamIDBidi: 0, // client by default
		nextStreamIDUni:  2, // client by default
	}
}

// ID returns connection id. The returned data must not be modified.
func (s *Conn) ID() []byte {
	return s.scid
}

// Stream creates or returns an existing QUIC stream given the ID.
func (s *Conn) Stream(id uint64) (*transport.Stream, error) {
	return s.conn.Stream(id)
}

// NewStream creates and returns a new local stream and id.
func (s *Conn) NewStream(bidi bool) (*transport.Stream, uint64, error) {
	var id uint64
	if bidi {
		id = s.nextStreamIDBidi
	} else {
		id = s.nextStreamIDUni
	}
	st, err := s.conn.Stream(id)
	if err != nil {
		return nil, 0, err
	}
	if bidi {
		s.nextStreamIDBidi += 4
	} else {
		s.nextStreamIDUni += 4
	}
	return st, id, nil
}

// LocalAddr returns the local network address.
func (s *Conn) LocalAddr() net.Addr {
	return nil // TODO: get from socket
}

// RemoteAddr returns the remote network address.
func (s *Conn) RemoteAddr() net.Addr {
	return s.addr
}

// SetUserData attaches (or removes) user data to the connection.
func (s *Conn) SetUserData(data interface{}) {
	s.userData = data
}

// UserData returns attached data.
func (s *Conn) UserData() interface{} {
	return s.userData
}

// Close sets the connection status to close state.
func (s *Conn) Close() error {
	s.conn.Close(true, transport.NoError, "bye")
	return nil
}

// CloseWithError sets the connection to close state with provided code and reason sending to peer.
func (s *Conn) CloseWithError(code uint64, reason string) {
	s.conn.Close(true, code, reason)
}

// localConn is a local quic connection.
type localConn struct {
	config *transport.Config
	socket net.PacketConn

	peersMu   sync.RWMutex
	peers     map[string]*Conn // by cid
	peersAddr map[string]*Conn // by address

	closing   bool      // locked by peersMu.
	closeCond sync.Cond // locked by peersMu. Closing a connection will broadcast when connections is empty
	closeCh   chan struct{}

	handler Handler
	logger  logger
}

func (s *localConn) init(config *transport.Config) {
	s.config = config
	s.peers = make(map[string]*Conn)
	s.peersAddr = make(map[string]*Conn)
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

// SetListener sets listening socket connection.
func (s *localConn) SetListener(conn net.PacketConn) {
	s.socket = conn
}

// handleConn handles data sending to the connection c.
func (s *localConn) handleConn(c *Conn) {
	defer s.connClosed(c)
	established := false
	for !c.conn.IsClosed() {
		p := s.pollConn(c)
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

func (s *localConn) pollConn(c *Conn) *packet {
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
		err := s.recvConn(c, p.data)
		if err == nil {
			// Maybe another packets arrived too while we processed the first one.
			s.pollConnDelayed(c)
		}
	case <-timer.C:
		// Read timeout
		s.logger.log(levelTrace, "verbose cid=%x addr=%s message=read_timed_out: %s", c.scid, c.addr, timeout)
		c.conn.Write(nil)
	case <-s.closeCh:
		// Server is closing (see s.close)
		c.conn.Close(true, transport.NoError, "bye")
	}
	timer.Stop()
	return p
}

func (s *localConn) pollConnDelayed(c *Conn) {
	if !c.conn.IsEstablished() {
		return
	}
	// TODO: check whether we only need to send back ACK, then we can delay it.
	timer := time.NewTimer(2 * time.Millisecond) // FIXME: timer granularity
	for {
		select {
		case <-timer.C:
			return
		case p := <-c.recvCh:
			err := s.recvConn(c, p.data)
			freePacket(p)
			if err != nil {
				return
			}
		}
	}
}

func (s *localConn) recvConn(c *Conn, data []byte) error {
	n, err := c.conn.Write(data)
	if err != nil {
		s.logger.log(levelError, "internal_error cid=%x addr=%s description=receive_failed: %v", c.scid, c.addr, err)
		// Close connection when receive failed
		if err, ok := err.(*transport.Error); ok {
			c.conn.Close(false, err.Code, err.Message)
		} else {
			c.conn.Close(false, transport.InternalError, "")
		}
		return err
	}
	s.logger.log(levelTrace, "datagrams_processed cid=%x addr=%s byte_length=%d", c.scid, c.addr, n)
	return nil
}

func (s *localConn) sendConn(c *Conn, buf []byte) error {
	for {
		n, err := c.conn.Read(buf)
		if err != nil {
			s.logger.log(levelError, "internal_error cid=%x addr=%s description=receive_failed: %v", c.scid, c.addr, err)
			return err
		}
		if n == 0 {
			s.logger.log(levelTrace, "verbose cid=%x addr=%s message=send_done", c.scid, c.addr)
			return nil
		}
		n, err = s.socket.WriteTo(buf[:n], c.addr)
		if err != nil {
			s.logger.log(levelError, "internal_error cid=%x addr=%s description=send_failed: %v", c.scid, c.addr, err)
			return err
		}
		s.logger.log(levelTrace, "datagrams_sent cid=%x addr=%s byte_length=%d raw=%x", c.scid, c.addr, n, buf[:n])
	}
}

func (s *localConn) serveConn(c *Conn) {
	c.events = c.conn.Events(c.events)
	if len(c.events) > 0 {
		s.logger.log(levelDebug, "debug cid=%x message=events: %v", c.scid, c.events)
		s.handler.Serve(c, c.events)
		for i := range c.events {
			c.events[i] = transport.Event{}
		}
		c.events = c.events[:0]
	}
}

func (s *localConn) connClosed(c *Conn) {
	s.logger.log(levelInfo, "connection_closed cid=%x addr=%s", c.scid, c.addr)
	c.events = append(c.events, transport.Event{Type: EventConnClose})
	s.serveConn(c)
	s.peersMu.Lock()
	delete(s.peers, string(c.scid[:]))
	delete(s.peersAddr, c.addr.String())
	// If server is closing and this is the last one, tell others
	if s.closing && len(s.peers) == 0 {
		s.closeCond.Broadcast()
	}
	s.peersMu.Unlock()
}

// close closes receiving packet channel of all connections to signal terminating handleConn gorotines.
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
