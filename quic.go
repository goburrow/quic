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
	"io"
	"net"
	"sync"
	"time"

	"github.com/goburrow/quic/transport"
)

const (
	cidLength = 16 // must be less than transport.MaxCIDLength
	// bufferSize is the size of the global buffers for sending and receiving UDP datagrams.
	bufferSize = 1500

	keyUnavailableTrigger = "key_unavailable"
)

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
	conn    *transport.Conn
	addr    net.Addr
	udpAddr net.UDPAddr
	scid    []byte

	streams  map[uint64]*Stream // async streams
	datagram *Datagram          // async datagram

	events []transport.Event
	// Channels for communicating with the connection.
	recvCh chan *packet
	cmdCh  chan connCommand
	// Timers
	timeoutTimer *time.Timer // Read timeout timer, set when polling.
	// Initial attempt key genereted for server connection.
	attemptKey []byte
	// Stream IDs
	nextStreamIDBidi uint64
	nextStreamIDUni  uint64

	// queuedPackets is for undecryptable packets which are queued for later processing.
	// Currently, only last one is needed.
	queuedPackets *packet

	userData interface{}
}

func newRemoteConn(addr net.Addr, scid []byte, conn *transport.Conn, isClient bool) *Conn {
	c := &Conn{
		scid: scid,
		conn: conn,

		streams: make(map[uint64]*Stream),
		recvCh:  make(chan *packet, 16),
		cmdCh:   make(chan connCommand, 8),

		nextStreamIDBidi: 0, // client by default
		nextStreamIDUni:  2, // client by default
	}
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		c.udpAddr = *udpAddr
		c.addr = &c.udpAddr
	} else {
		c.addr = addr
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

// StreamWriteTo writes stream data to w until there is no more data or when an error occurs.
func (s *Conn) StreamWriteTo(streamID uint64, w io.Writer) (int64, error) {
	st, err := s.conn.Stream(streamID)
	if err != nil {
		return 0, err
	}
	return st.WriteTo(w)
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
func (s *Conn) DatagramWrite(b []byte) (int, error) {
	return s.conn.Datagram().Write(b)
}

// DatagramRead pulls received datagram directly from the connection buffer.
// It returns nil when there is no data to read.
func (s *Conn) DatagramRead(b []byte) (int, error) {
	return s.conn.Datagram().Read(b)
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

// Close sets the connection status to closing state.
// If peer has already initiated closing with an error, this function will return
// that error, which is either transport.Error or transport.AppError
func (s *Conn) Close() error {
	return s.conn.Close(transport.NoError, "bye", false)
}

// CloseWithError sets the connection to closing state with an
// application code code and reason sending to peer.
// The function returns error if peer has already initiated closing.
func (s *Conn) CloseWithError(code uint64, reason string) error {
	return s.conn.Close(code, reason, true)
}

func (s *Conn) setClosing(errCode uint64, reason string) {
	s.conn.Close(errCode, reason, false)
}

func (s *Conn) onClosed(err error) {
	// When connection closed and there are still data not read by Datagram or Stream
	// because of async
	if s.datagram != nil {
		s.datagram.setClosed(err, s.conn.Datagram())
	}
	for id, st := range s.streams {
		t, _ := s.conn.Stream(id)
		st.setClosed(err, t)
	}
}

func (s *Conn) readEvents() {
	s.events = s.conn.Events(s.events)
}

// handleEvents handles transport connection events.
func (s *Conn) handleEvents() {
	for _, e := range s.events {
		switch e.Type {
		case transport.EventStreamWritable:
			s.cmdStreamWrite(e.Data)
		case transport.EventStreamReadable:
			s.cmdStreamRead(e.Data)
		case transport.EventStreamClosed:
			s.eventStreamClosed(e.Data)
		case transport.EventDatagramWritable:
			s.cmdDatagramWrite()
		case transport.EventDatagramReadable:
			s.cmdDatagramRead()
		}
	}
	s.events = s.events[:0]
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
	st, _ := s.conn.Stream(streamID)
	if st != nil {
		ss.sendWriter(st)
	}
}

// cmdStreamRead handles command to read data from a stream and send back to the Stream caller.
func (s *Conn) cmdStreamRead(streamID uint64) {
	ss := s.streams[streamID]
	if ss == nil {
		return
	}
	st, _ := s.conn.Stream(streamID)
	if st != nil {
		ss.sendReader(st)
	}
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
	s.datagram.sendWriter(s.conn.Datagram())
}

// cmdDatagramRead handles command to receive a datagram if available.
func (s *Conn) cmdDatagramRead() {
	if s.datagram == nil {
		return
	}
	s.datagram.sendReader(s.conn.Datagram())
}

func (s *Conn) eventStreamClosed(streamID uint64) {
	// Stream has been closed gracefully.
	ss := s.streams[streamID]
	if ss != nil {
		// We do not expect application to read this error as stream is only closed
		// when data is fully read by the application.
		ss.setClosed(io.ErrClosedPipe, nil)
		delete(s.streams, streamID)
	}
}

// setTimeoutTimer set timer with the duration from connection receive timeout.
func (s *Conn) setTimeoutTimer() {
	timeout := s.conn.Timeout()
	if timeout < 0 {
		// TODO
		timeout = 10 * time.Second
	}
	if s.timeoutTimer == nil {
		s.timeoutTimer = time.NewTimer(timeout)
	} else {
		s.timeoutTimer.Reset(timeout)
	}
}

func (s *Conn) stopTimeoutTimer() {
	s.timeoutTimer.Stop()
}

func (s *Conn) queuePacket(p *packet) {
	if s.queuedPackets != nil {
		freePacket(s.queuedPackets)
	}
	s.queuedPackets = p
}

func (s *Conn) dequeuePacket() *packet {
	if s.queuedPackets == nil {
		return nil
	}
	p := s.queuedPackets
	s.queuedPackets = nil
	return p
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
	cidIss  CIDIssuer
	logger  logger
}

func (s *localConn) init(config *transport.Config) {
	s.config = config
	s.peers = make(map[string]*Conn)
	s.closeCh = make(chan struct{})
	s.closeCond.L = &s.peersMu
	s.handler = noopHandler{}
	s.cidIss = newCIDIssuer(config)
}

// SetHandler sets QUIC connection callbacks.
func (s *localConn) SetHandler(v Handler) {
	s.handler = v
}

// SetLogger sets transaction logger.
// It is safe to change connection logger at any time.
func (s *localConn) SetLogger(level int, w io.Writer) {
	s.logger.setLevel(logLevel(level))
	s.logger.setWriter(w)
}

// SetListener sets listening socket connection.
func (s *localConn) SetListener(conn net.PacketConn) {
	s.socket = conn
}

// SetCIDIssuer sets generator for connection ids.
// By default, it generates random IDs from Reader in crypto/rand.
// If transport.Config.TLS.Rand is available, it will use that source instead.
func (s *localConn) SetCIDIssuer(cidIss CIDIssuer) {
	s.cidIss = cidIss
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
		s.connPoll(c)
		if established {
			s.connServe(c)
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
				s.connServe(c)
			}
		}
		err := s.connSend(c)
		if err != nil && established {
			s.connServe(c)
		}
	}
}

func (s *localConn) connPoll(c *Conn) {
	c.setTimeoutTimer()
	defer c.stopTimeoutTimer()
	select {
	case p := <-c.recvCh:
		// Got packet
		err := s.connRecv(c, p)
		if err != nil {
			return
		}
	case p := <-c.cmdCh:
		c.handleCommand(&p)
	case <-c.timeoutTimer.C:
		// Read timeout
		s.logger.log(levelTrace, zs("", "generic:verbose"),
			zx("cid", c.scid), zs("message", "read_timed_out"))
		c.conn.Write(nil)
		return
	case <-s.closeCh:
		// Server is closing (see s.close)
		c.Close()
		return
	}
	// Maybe another packets arrived too while we processed the first one.
	s.connPollNoDelay(c, 3)
}

func (s *localConn) connPollNoDelay(c *Conn, count int) int {
	packets := 0
	for ; count > 0; count-- {
		select {
		case p := <-c.recvCh:
			err := s.connRecv(c, p)
			if err != nil {
				return -1
			}
			packets++
		case p := <-c.cmdCh:
			c.handleCommand(&p)
		case <-s.closeCh:
			c.Close()
			return -1
		default:
		}
	}
	return packets
}

func (s *localConn) connRecv(c *Conn, p *packet) error {
	_, err := c.conn.Write(p.data)
	if err != nil {
		if trigger := transport.IsPacketDropped(err); trigger != "" {
			// Queue packet for later processing.
			if trigger == keyUnavailableTrigger {
				c.queuePacket(p)
				s.logger.log(levelDebug, zs("", "transport:packet_buffered"),
					zx("cid", c.scid), zv("", &p.header))
			} else {
				freePacket(p)
			}
			return nil
		}
		// Close connection when receive failed
		s.logger.log(levelError, zs("", "generic:error"),
			zx("cid", c.scid), zs("message", "receive_failed"), ze("", err))
		if err, ok := err.(*transport.Error); ok {
			c.setClosing(err.Code, err.Reason)
		} else {
			c.setClosing(transport.InternalError, "")
		}
		freePacket(p)
		return err
	}
	freePacket(p)
	// Re process previous undecryptable packets.
	s.connDeq(c)
	return nil
}

func (s *localConn) connDeq(c *Conn) {
	p := c.dequeuePacket()
	if p == nil {
		return
	}
	s.logger.log(levelDebug, zs("", "transport:packet_restored"),
		zx("cid", c.scid), zv("", &p.header))
	_, err := c.conn.Write(p.data)
	if err != nil {
		if trigger := transport.IsPacketDropped(err); trigger != "" {
			if trigger == keyUnavailableTrigger {
				c.queuePacket(p)
				s.logger.log(levelDebug, zs("", "transport:packet_buffered"),
					zx("cid", c.scid), zv("", &p.header))
			} else {
				freePacket(p)
			}
			return
		}
		// Close connection when receive failed
		s.logger.log(levelError, zs("", "generic:error"),
			zx("cid", c.scid), zs("message", "receive_failed"), ze("", err))
		if err, ok := err.(*transport.Error); ok {
			c.setClosing(err.Code, err.Reason)
		} else {
			c.setClosing(transport.InternalError, "")
		}
	}
	freePacket(p)
}

// connSend returns additional received packets when waiting.
func (s *localConn) connSend(c *Conn) error {
	p := newPacket()
	defer freePacket(p)
	for {
		n, err := c.conn.Read(p.buf[:])
		if err != nil {
			// Close connection when send failed
			s.logger.log(levelError, zs("", "generic:error"),
				zx("cid", c.scid), zs("message", "send_failed"), ze("", err))
			if err, ok := err.(*transport.Error); ok {
				c.setClosing(err.Code, err.Reason)
			} else {
				c.setClosing(transport.InternalError, "")
			}
			return err
		}
		if n == 0 {
			s.logger.log(levelTrace, zs("", "generic:verbose"),
				zx("cid", c.scid), zs("message", "send_done"))
			return nil
		}
		delay := c.conn.Delay()
		if delay > 0 {
			// Process incoming packets or commands while waiting until the time for sending this packet.
			s.connPollNoDelay(c, 1+int(delay/time.Millisecond))
		}
		p.data = p.buf[:n]
		n, err = s.socket.WriteTo(p.data, c.addr)
		if err != nil {
			s.logger.log(levelError, zs("", "generic:error"),
				zx("cid", c.scid), zv("addr", c.addr), zs("message", "send_failed"), ze("", err))
			c.setClosing(transport.InternalError, "")
			return err
		}
		s.logger.log(levelTrace, zs("", "transport:datagrams_sent"),
			zx("cid", c.scid), zv("addr", c.addr), zx("raw", p.data))
	}
}

func (s *localConn) connServe(c *Conn) {
	c.readEvents()
	if len(c.events) > 0 {
		s.logger.log(levelDebug, zs("", "generic:debug"),
			zx("cid", c.scid), zs("message", "events"), zi("", len(c.events)))
		s.handler.Serve(c, c.events)
		c.handleEvents()
	}
}

func (s *localConn) connClosed(c *Conn) {
	// Use peer error if presents
	state := c.ConnectionState()
	err := state.PeerError
	if err == nil {
		err = state.LocalError
	}
	s.connServe(c)
	if err == nil {
		s.logger.log(levelInfo, zs("", "connectivity:connection_closed"),
			zx("cid", c.scid), zv("addr", c.addr))
		err = net.ErrClosed // Async streams will get this error.
	} else {
		s.logger.log(levelError, zs("", "connectivity:connection_closed"),
			zx("cid", c.scid), zv("addr", c.addr), ze("message", err))
	}
	c.onClosed(err) // This is called after callback to cleanup any resources the application created.

	s.peersMu.Lock()
	delete(s.peers, string(c.scid))
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
	data    []byte // Always points to buf
	addr    net.Addr
	udpAddr net.UDPAddr
	header  transport.Header

	buf [bufferSize]byte
}

var packetPool = sync.Pool{
	New: func() interface{} {
		return &packet{}
	},
}

func newPacket() *packet {
	return packetPool.Get().(*packet)
}

func freePacket(p *packet) {
	p.data = nil
	p.addr = nil
	p.udpAddr = net.UDPAddr{}
	p.header = transport.Header{}
	packetPool.Put(p)
}

func readPacket(p *packet, conn net.PacketConn) error {
	if udpConn, ok := conn.(*net.UDPConn); ok {
		// Use UDP directly to reduce memory allocations
		n, addr, err := udpConn.ReadFromUDP(p.buf[:])
		if err != nil {
			return err
		}
		p.data = p.buf[:n]
		p.udpAddr = *addr
		p.addr = &p.udpAddr
	} else {
		n, addr, err := conn.ReadFrom(p.buf[:])
		if err != nil {
			return err
		}
		p.data = p.buf[:n]
		p.addr = addr
	}
	return nil
}

// CIDIssuer generates connection ID.
type CIDIssuer interface {
	// NewCID generates a new connection ID.
	NewCID() ([]byte, error)
	// CIDLength returns the length of generated connection id which is needed
	// to decode short-header packets.
	// Currently, only constant length is supported.
	CIDLength() int
}

type cidIssuer struct {
	reader io.Reader
}

func newCIDIssuer(config *transport.Config) *cidIssuer {
	reader := rand.Reader
	if config.TLS != nil && config.TLS.Rand != nil {
		reader = config.TLS.Rand
	}
	return &cidIssuer{
		reader: reader,
	}
}

func (s *cidIssuer) NewCID() ([]byte, error) {
	cid := make([]byte, cidLength)
	_, err := io.ReadFull(s.reader, cid)
	return cid, err
}

func (s *cidIssuer) CIDLength() int {
	return cidLength
}
