// Package quic provides client and server functions for QUIC connections.
//
// The process of creating a basic client and server looks like this:
//
//	config := transport.NewConfig()
//
// 	client := quic.NewClient(config)
// 	client.SetHandler(handler)
// 	err := client.ListenAndServe(address)
// 	err = client.Connect(serverAddress)
// 	// wait
// 	client.Close()
//
// 	server := quic.NewServer(config)
// 	server.SetHandler(handler)
// 	err := server.ListenAndServe(address)
//
// The handler is where applications interact with QUIC connections:
//
// 	func (handler) Serve(conn *quic.Conn, events []transport.Event) {
// 		for _, e := range events {
// 			switch e.Type {
// 			case transport.EventConnOpen:
// 			case transport.EventConnClosed:
// 			}
// 		}
// 	}
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
	cidLength       = transport.MaxCIDLength
	bufferSize      = 1500
)

var errClosed = errors.New("use of closed connection") // XXX: use net.ErrClosed in Go 1.6?
var errDeadlineExceeded = deadlineExceededError{}      // XXX: use os.ErrDeadlineExceeded?
var errWait = errors.New("waiting")

type deadlineExceededError struct{}

func (deadlineExceededError) Error() string {
	return "deadline exceeded"
}

func (deadlineExceededError) Timeout() bool {
	return true
}

func (deadlineExceededError) Temporary() bool {
	return true
}

// Handler defines interface to handle QUIC connection states.
// Multiple goroutines may invoke methods on a Handler simultaneously.
type Handler interface {
	// Serve handles connection events.
	// Applications should keep execution time in the callback to a minimum.
	// If extra works needed, applications should consider using asynchronous APIs,
	// i.e Stream functions instead of Conn.Stream* functions.
	// Currently, each connection has its own goroutine for this callback.
	Serve(conn *Conn, events []transport.Event)
}

type noopHandler struct{}

func (s noopHandler) Serve(*Conn, []transport.Event) {}

// Conn is a QUIC connection presenting a peer connected to this client or server.
// Conn is not safe for concurrent use.
// Its methods would only be called inside the Handler callback.
type Conn struct {
	scid []byte
	addr net.Addr
	conn *transport.Conn

	streams  map[uint64]*Stream
	datagram *Datagram

	events []transport.Event
	// Channels for communicating with the connection.
	recvCh chan *packet
	cmdCh  chan connCommand
	// Initial attempt key genereted for server connection.
	attemptKey []byte
	// Stream IDs
	nextStreamIDBidi uint64
	nextStreamIDUni  uint64

	userData interface{}
}

func newRemoteConn(addr net.Addr, scid []byte, conn *transport.Conn, isClient bool) *Conn {
	c := &Conn{
		addr: addr,
		scid: scid,
		conn: conn,

		streams: make(map[uint64]*Stream),
		recvCh:  make(chan *packet, 8),
		cmdCh:   make(chan connCommand, 4),

		nextStreamIDBidi: 0, // client by default
		nextStreamIDUni:  2, // client by default
	}
	if !isClient {
		c.nextStreamIDBidi++
		c.nextStreamIDUni++
	}
	return c
}

// ConnectionState returns details about the connection.
func (s *Conn) ConnectionState() transport.ConnectionState {
	return s.conn.ConnectionState()
}

// StreamWrite adds data to the stream buffer for sending.
func (s *Conn) StreamWrite(streamID uint64, b []byte) (int, error) {
	st, err := s.conn.Stream(streamID)
	if err != nil {
		return 0, err
	}
	return st.Write(b)
}

// StreamRead gets data received from the stream buffer.
func (s *Conn) StreamRead(streamID uint64, b []byte) (int, error) {
	st, err := s.conn.Stream(streamID)
	if err != nil {
		return 0, err
	}
	return st.Read(b)
}

// StreamCloseWrite terminates sending part of the stream.
func (s *Conn) StreamCloseWrite(streamID uint64, errorCode uint64) error {
	st, err := s.conn.Stream(streamID)
	if err != nil {
		return err
	}
	return st.CloseWrite(errorCode)
}

// StreamCloseRead terminates reading part of the stream.
func (s *Conn) StreamCloseRead(streamID uint64, errorCode uint64) error {
	st, err := s.conn.Stream(streamID)
	if err != nil {
		return err
	}
	return st.CloseRead(errorCode)
}

// StreamClose gracefully closes sending part of the stream.
func (s *Conn) StreamClose(streamID uint64) error {
	st, err := s.conn.Stream(streamID)
	if err != nil {
		return err
	}
	return st.Close()
}

// Stream creates or returns an existing QUIC stream given the ID.
// NOTE: The returned stream would only be used in a different goroutine.
// See Stream struct for details.
func (s *Conn) Stream(streamID uint64) (*Stream, error) {
	if st := s.streams[streamID]; st != nil {
		return st, nil
	}
	_, err := s.conn.Stream(streamID)
	if err != nil {
		return nil, err
	}
	st := newStream(s, streamID)
	s.streams[streamID] = st
	return st, nil
}

// NewStream creates and returns a new local stream id.
// If number of streams exceeds peer limits, the function will return false.
func (s *Conn) NewStream(bidi bool) (uint64, bool) {
	var id uint64
	if bidi {
		id = s.nextStreamIDBidi
	} else {
		id = s.nextStreamIDUni
	}
	_, err := s.conn.Stream(id)
	if err != nil {
		return 0, false
	}
	if bidi {
		s.nextStreamIDBidi += 4
	} else {
		s.nextStreamIDUni += 4
	}
	return id, true
}

// DatagramWrite queues data to the connection buffer for sending via datagram.
func (s *Conn) DatagramWrite(b []byte) error {
	_, err := s.conn.Datagram().Write(b)
	return err
}

// DatagramRead pulls received datagram directly from the connection buffer.
// It returns nil when there is no data to read.
func (s *Conn) DatagramRead() []byte {
	return s.conn.Datagram().Pop()
}

// Datagram returns a Datagram associated with the connection.
// NOTE: Unlike other Conn.Datagram* functions, the returned Datagram must only be used
// in a different goroutine (i.e. not in the connection handler).
// See Datagram struct for details.
func (s *Conn) Datagram() *Datagram {
	if s.datagram == nil {
		s.datagram = newDatagram(s)
	}
	return s.datagram
}

// LocalAddr returns the local network address.
func (s *Conn) LocalAddr() net.Addr {
	return s.addr // TODO: get from socket
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
	s.setClosing(transport.NoError, "bye")
	return nil
}

// CloseWithError sets the connection to close state with provided code and reason sending to peer.
func (s *Conn) CloseWithError(code uint64, reason string) {
	s.conn.Close(true, code, reason)
}

func (s *Conn) readEvents() {
	s.events = s.conn.Events(s.events)
}

func (s *Conn) clearEvents() {
	for i := range s.events {
		// Not necessary, but just in case more fields are added to Event in future.
		s.events[i] = transport.Event{}
	}
	s.events = s.events[:0]
}

func (s *Conn) setClosing(errCode uint64, reason string) {
	s.conn.Close(false, errCode, reason)
}

func (s *Conn) onClosed() {
	if s.datagram != nil {
		s.datagram.setClosed()
	}
	for _, st := range s.streams {
		st.setClosed()
	}
}

// handleEvents handles transport connection events.
func (s *Conn) handleEvents() {
	for _, e := range s.events {
		switch e.Type {
		case transport.EventStreamWritable:
			s.eventStreamWritable(e.ID)
		case transport.EventStreamReadable:
			s.eventStreamReadable(e.ID)
		case transport.EventStreamClosed:
			s.eventStreamClosed(e.ID)
		case transport.EventDatagramReadable:
			s.eventDatagramReadable()
		}
	}
}

// handleCommand handles commands sent by Stream or Datagram.
func (s *Conn) handleCommand(p *connCommand) {
	switch p.cmd {
	case cmdStreamWrite:
		s.cmdStreamWrite(p.id)
	case cmdStreamRead:
		s.cmdStreamRead(p.id)
	case cmdStreamClose:
		s.cmdStreamClose(p.id)
	case cmdStreamCloseWrite:
		s.cmdStreamCloseWrite(p.id, p.n)
	case cmdStreamCloseRead:
		s.cmdStreamCloseRead(p.id, p.n)
	case cmdDatagramWrite:
		s.cmdDatagramWrite()
	case cmdDatagramRead:
		s.cmdDatagramRead()
	}
}

// cmdStreamWrite handles command to write data to a stream for sending.
func (s *Conn) cmdStreamWrite(streamID uint64) {
	ss := s.streams[streamID]
	if ss == nil {
		return
	}
	st, err := s.conn.Stream(streamID)
	if err != nil {
		ss.sendWriteResult(err)
		return
	}
	done, err := ss.recvWriteData(st)
	if done || err != nil {
		ss.sendWriteResult(err)
		return
	}
	// Writing is blocked. Waiting on event EventStreamWritable.
	ss.sendWriteResult(errWait)
}

// cmdStreamRead handles command to read data from a stream and send back to the Stream caller.
func (s *Conn) cmdStreamRead(streamID uint64) {
	ss := s.streams[streamID]
	if ss == nil {
		return
	}
	st, err := s.conn.Stream(streamID)
	if err != nil {
		ss.sendReadResult(err)
		return
	}
	done, err := ss.recvReadData(st)
	if done || err != nil {
		ss.sendReadResult(err)
		return
	}
	// No data to read. Waiting on event EventStreamReadable.
	ss.sendReadResult(errWait)
}

// cmdStreamClose handles command to gracefully close a connection stream.
// It sends closing result to the Stream closing goroutine.
func (s *Conn) cmdStreamClose(streamID uint64) {
	ss := s.streams[streamID]
	if ss == nil {
		return
	}
	st, err := s.conn.Stream(streamID)
	if err != nil {
		ss.sendCloseResult(err)
		return
	}
	err = st.Close()
	ss.sendCloseResult(err)
}

// cmdStreamCloseWrite handles command to close sending part of the stream.
func (s *Conn) cmdStreamCloseWrite(streamID uint64, errorCode uint64) {
	ss := s.streams[streamID]
	if ss == nil {
		return
	}
	st, err := s.conn.Stream(streamID)
	if err != nil {
		ss.sendCloseResult(err)
		return
	}
	err = st.CloseWrite(errorCode)
	ss.sendCloseResult(err)
}

// cmdStreamCloseRead handles command to close receiving part of the stream.
func (s *Conn) cmdStreamCloseRead(streamID uint64, errorCode uint64) {
	ss := s.streams[streamID]
	if ss == nil {
		return
	}
	st, err := s.conn.Stream(streamID)
	if err != nil {
		ss.sendCloseResult(err)
		return
	}
	err = st.CloseRead(errorCode)
	ss.sendCloseResult(err)
}

// cmdDatagramWrite handles command to send a datagram.
func (s *Conn) cmdDatagramWrite() {
	if s.datagram == nil {
		return
	}
	_, err := s.datagram.recvWriteData(s.conn.Datagram())
	s.datagram.sendWriteResult(err)
	// Writing on datagram is never blocked so no need to subscribe to any event.
}

// cmdDatagramRead handles command to receive a datagram if available.
func (s *Conn) cmdDatagramRead() {
	if s.datagram == nil {
		return
	}
	done, err := s.datagram.recvReadData(s.conn.Datagram())
	if done || err != nil {
		s.datagram.sendReadResult(err)
		return
	}
	// Waiting on event EventDatagramReadable
	s.datagram.sendReadResult(errWait)
}

// eventStreamWritable handles connection event EventStreamWritable.
// It reads the buffer provided by Stream caller that is writing and put data into
// the connection stream for sending.
// If any error occurs or all data consumed, it sends result to the Stream caller.
func (s *Conn) eventStreamWritable(streamID uint64) {
	ss := s.streams[streamID]
	if ss == nil {
		return
	}
	if ss.isWriting() {
		st, err := s.conn.Stream(streamID)
		if err != nil {
			ss.sendWriteResult(err)
			return
		}
		done, err := ss.recvWriteData(st)
		if done || err != nil {
			ss.sendWriteResult(err)
			return
		}
		ss.sendWriteResult(errWait)
	}
}

// eventStreamReadable handles connection event EventStreamReadable.
// It reads stream data and sends result to the Stream caller that is waiting for read result.
func (s *Conn) eventStreamReadable(streamID uint64) {
	ss := s.streams[streamID]
	if ss == nil {
		return
	}
	if ss.isReading() {
		st, err := s.conn.Stream(streamID)
		if err != nil {
			ss.sendReadResult(err)
			return
		}
		done, err := ss.recvReadData(st)
		if done || err != nil {
			ss.sendReadResult(err)
			return
		}
		ss.sendReadResult(errWait)
	}
}

func (s *Conn) eventStreamClosed(streamID uint64) {
	ss := s.streams[streamID]
	if ss != nil {
		ss.setClosed()
		delete(s.streams, streamID)
	}
}

// eventDatagramReadable handles connection event EventDatagramReadable.
// It reads data and sends result to the Datagram caller that is waiting for read result.
func (s *Conn) eventDatagramReadable() {
	if s.datagram == nil {
		return
	}
	if s.datagram.isReading() {
		done, err := s.datagram.recvReadData(s.conn.Datagram())
		if done || err != nil {
			s.datagram.sendReadResult(err)
			return
		}
		s.datagram.sendReadResult(errWait)
	}
}

// localConn is a local QUIC connection, either Client or Server.
type localConn struct {
	config *transport.Config
	socket net.PacketConn

	// peers include all active connections.
	peersMu sync.RWMutex
	peers   map[string]*Conn // by cid and attempt key

	closing   bool      // locked by peersMu.
	closeCond sync.Cond // locked by peersMu. Closing a connection will broadcast when connections is empty
	closeCh   chan struct{}

	handler Handler
	logger  logger
}

func (s *localConn) init(config *transport.Config) {
	s.config = config
	s.peers = make(map[string]*Conn)
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
	s.logger.setLevel(logLevel(level))
	s.logger.setWriter(w)
}

// SetListener sets listening socket connection.
func (s *localConn) SetListener(conn net.PacketConn) {
	s.socket = conn
}

// LocalAddr returns the local network address.
func (s *localConn) LocalAddr() net.Addr {
	if s.socket == nil {
		return nil
	}
	return s.socket.LocalAddr()
}

// handleConn handles data sending to the connection c.
// Each connection is run in its own goroutine.
func (s *localConn) handleConn(c *Conn) {
	defer s.connClosed(c)
	established := false
	for !c.conn.IsClosed() {
		s.pollConn(c)
		if established {
			s.serveConn(c)
		} else {
			// First time state switched to active
			if c.conn.HandshakeComplete() {
				// Handshake done, remove the attempt key
				if c.attemptKey != nil {
					s.peersMu.Lock()
					delete(s.peers, string(c.attemptKey))
					c.attemptKey = nil
					s.peersMu.Unlock()
				}
				established = true
				s.serveConn(c)
			}
		}
		p := newPacket()
		s.sendConn(c, p.buf[:maxDatagramSize])
		freePacket(p)
	}
}

func (s *localConn) pollConn(c *Conn) {
	timeout := c.conn.Timeout()
	if timeout < 0 {
		// TODO
		timeout = 10 * time.Second
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case p := <-c.recvCh:
		// Got packet
		err := s.recvConn(c, p.data)
		freePacket(p)
		if err != nil {
			return
		}
	case p := <-c.cmdCh:
		c.handleCommand(&p)
	case <-timer.C:
		// Read timeout
		s.logger.log(levelTrace, "verbose cid=%x addr=%s message=read_timed_out: %s", c.scid, c.addr, timeout)
		c.conn.Write(nil)
		return
	case <-s.closeCh:
		// Server is closing (see s.close)
		c.Close()
		return
	}
	// Maybe another packets arrived too while we processed the first one.
	if c.conn.HandshakeComplete() {
		// Only for application space
		s.pollConnDelay(c)
	}
}

func (s *localConn) pollConnDelay(c *Conn) {
	// TODO: check whether we only need to send back ACK, then we can delay it.
	timer := time.NewTimer(2 * time.Millisecond) // FIXME: timer granularity
	defer timer.Stop()
	for i := 8; i > 0; i-- {
		select {
		case <-timer.C:
			return
		case p := <-c.recvCh:
			err := s.recvConn(c, p.data)
			freePacket(p)
			if err != nil {
				return
			}
		case p := <-c.cmdCh:
			c.handleCommand(&p)
		case <-s.closeCh:
			c.Close()
			return
		}
	}
}

func (s *localConn) recvConn(c *Conn, data []byte) error {
	n, err := c.conn.Write(data)
	if err != nil {
		if _, ok := transport.IsPacketDropped(err); ok {
			// TODO: queue packet for later processing.
			return nil
		}
		// Close connection when receive failed
		if err, ok := err.(*transport.Error); ok {
			c.setClosing(err.Code, err.Message)
		} else {
			s.logger.log(levelError, "internal_error cid=%x addr=%s description=receive_failed: %v", c.scid, c.addr, err)
			c.setClosing(transport.InternalError, "")
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
			// Close connection when send failed
			if err, ok := err.(*transport.Error); ok {
				c.setClosing(err.Code, err.Message)
			} else {
				s.logger.log(levelError, "internal_error cid=%x addr=%s description=send_failed: %v", c.scid, c.addr, err)
				c.setClosing(transport.InternalError, "")
			}
			return err
		}
		if n == 0 {
			s.logger.log(levelTrace, "verbose cid=%x addr=%s message=send_done", c.scid, c.addr)
			return nil
		}
		n, err = s.socket.WriteTo(buf[:n], c.addr)
		if err != nil {
			s.logger.log(levelError, "internal_error cid=%x addr=%s description=send_failed: %v", c.scid, c.addr, err)
			c.setClosing(transport.InternalError, "")
			return err
		}
		s.logger.log(levelTrace, "datagrams_sent cid=%x addr=%s byte_length=%d raw=%x", c.scid, c.addr, n, buf[:n])
	}
}

func (s *localConn) serveConn(c *Conn) {
	c.readEvents()
	if len(c.events) > 0 {
		s.logger.log(levelDebug, "debug cid=%x message=events: %v", c.scid, c.events)
		s.handler.Serve(c, c.events)
		c.handleEvents()
		c.clearEvents()
	}
}

func (s *localConn) connClosed(c *Conn) {
	s.logger.log(levelInfo, "connection_closed cid=%x addr=%s", c.scid, c.addr)
	s.serveConn(c)
	c.onClosed() // This is called after callback to ensure resources are created after cleanup

	s.peersMu.Lock()
	delete(s.peers, string(c.scid[:]))
	if c.attemptKey != nil {
		delete(s.peers, string(c.attemptKey))
		c.attemptKey = nil
	}
	// If server is closing and this is the last one, tell others
	if s.closing && len(s.peers) == 0 {
		s.closeCond.Broadcast()
	}
	s.peersMu.Unlock()
}

// close closes receiving packet channel of all connections to signal terminating handleConn goroutines.
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

type command uint8

const (
	cmdStreamWrite command = iota
	cmdStreamRead
	cmdStreamClose
	cmdStreamCloseWrite
	cmdStreamCloseRead

	cmdDatagramWrite
	cmdDatagramRead
)

type connCommand struct {
	id  uint64 // stream id
	n   uint64
	cmd command
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
