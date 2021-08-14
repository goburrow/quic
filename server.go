package quic

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"time"

	"github.com/goburrow/quic/transport"
)

// Server is a server-side QUIC connection.
// All setters must only be invoked before calling Serve.
type Server struct {
	localConn

	addrValid AddressValidator
}

// NewServer creates a new QUIC server.
func NewServer(config *transport.Config) *Server {
	s := &Server{}
	s.localConn.init(config)
	return s
}

// SetAddressValidator sets validation for QUIC connections address.
func (s *Server) SetAddressValidator(v AddressValidator) {
	s.addrValid = v
}

// ListenAndServe starts listening on UDP network address addr and
// serves incoming packets.
func (s *Server) ListenAndServe(addr string) error {
	socket, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	s.socket = socket
	return s.Serve()
}

// Serve handles incoming requests from a socket connection.
// XXX: Since net.PacketConn methods can be called simultaneously, users should be able to
// run Serve in multiple goroutines. For example:
//
// 	s.SetListen(socket)
// 	for i := 1; i < num; i++ {
// 		go s.Serve()
// 	}
// 	s.Serve() // main one blocking
func (s *Server) Serve() error {
	if s.socket == nil {
		return errors.New("no listening connection")
	}
	s.logger.log(levelInfo, zs("", "connectivity:server_listening"),
		zv("addr", s.socket.LocalAddr()))
	for {
		p := newPacket()
		n, addr, err := s.socket.ReadFrom(p.buf[:])
		if n > 0 {
			// Process returned data first before considering error
			p.data = p.buf[:n]
			p.addr = addr
			s.recv(p)
		} else {
			freePacket(p)
		}
		if err != nil {
			// Stop on socket error.
			// FIXME: Should we stop on timeout when read deadline is set
			if err, ok := err.(net.Error); ok && err.Timeout() {
				s.logger.log(levelTrace, zs("", "generic:verbose"),
					zs("message", "read_timed_out"), ze("", err))
			} else {
				return err
			}
		}
	}
}

func (s *Server) recv(p *packet) {
	_, err := p.header.Decode(p.data, cidLength)
	if err != nil {
		s.logger.log(levelTrace, zs("", "transport:datagrams_received"),
			zv("addr", p.addr), zx("raw", p.data))
		s.logger.log(levelDebug, zs("", "transport:packet_dropped"),
			zv("addr", p.addr), zi("packet_size", len(p.data)), zs("trigger", "header_parse_error"), ze("message", err))
		freePacket(p)
		return
	}
	s.logger.log(levelTrace, zs("", "transport:datagrams_received"),
		zx("cid", p.header.DCID), zv("addr", p.addr), zx("raw", p.data))
	s.peersMu.RLock()
	if s.closing {
		// Do not process packet when closing
		s.peersMu.RUnlock()
		freePacket(p)
		return
	}
	c := s.peers[string(p.header.DCID)]
	if c == nil {
		c = s.peers[string(s.attemptKey(p.addr, p.header.DCID))]
	}
	s.peersMu.RUnlock()
	if c == nil {
		// Server must ensure the any datagram packet containing Initial packet being at least 1200 bytes
		if p.header.Type != "initial" || len(p.data) < transport.MinInitialPacketSize {
			s.logger.log(levelDebug, zs("", "transport:packet_dropped"),
				zx("cid", p.header.DCID), zv("addr", p.addr), zs("trigger", "unexpected_packet"), zv("", &p.header))
			freePacket(p)
			return
		}
		if !transport.IsVersionSupported(p.header.Version) {
			// Negotiate version
			s.logger.log(levelDebug, zs("", "transport:packet_dropped"),
				zx("cid", p.header.DCID), zv("addr", p.addr), zs("trigger", "unsupported_version"), zv("", &p.header))
			s.negotiate(p.addr, &p.header)
			freePacket(p)
			return
		}
		go s.handleNewConn(p)
	} else {
		c.recvCh <- p
	}
}

func (s *Server) negotiate(addr net.Addr, h *transport.Header) {
	p := newPacket()
	defer freePacket(p)
	n, err := transport.NegotiateVersion(p.buf[:], h.SCID, h.DCID)
	if err != nil {
		s.logger.log(levelError, zs("", "generic:error"),
			zx("cid", h.DCID), zv("addr", addr), zv("", h), zs("message", "version_negotiation_failed"), ze("", err))
		return
	}
	p.data = p.buf[:n]
	n, err = s.socket.WriteTo(p.data, addr)
	if err != nil {
		s.logger.log(levelError, zs("", "generic:error"),
			zx("cid", h.DCID), zv("addr", addr), zv("", h), zs("message", "version_negotiation_failed"), ze("", err))
		return
	}
	s.logger.log(levelDebug, zs("", "transport:packet_sent"),
		zx("cid", h.DCID), zv("addr", addr), zx("dcid", h.SCID), zx("scid", h.DCID))
	s.logger.log(levelTrace, zs("", "transport:datagrams_sent"),
		zx("cid", h.DCID), zv("addr", addr), zx("raw", p.data))
}

func (s *Server) retry(addr net.Addr, h *transport.Header) {
	p := newPacket()
	defer freePacket(p)
	// newCID is a new DCID client should send in next Initial packet
	var newCID [cidLength]byte
	if err := s.rand(newCID[:]); err != nil {
		s.logger.log(levelError, zs("", "generic:error"),
			zx("cid", h.DCID), zv("addr", addr), zv("", h), zs("message", "retry_failed"), ze("", err))
		return
	}
	token := s.addrValid.GenerateToken(addr, h.DCID)
	// Header => Retry: DCID => ODCID, SCID => DCID, newCID => SCID
	n, err := transport.Retry(p.buf[:], h.SCID, newCID[:], h.DCID, token)
	if err != nil {
		s.logger.log(levelError, zs("", "generic:error"),
			zx("cid", h.DCID), zv("addr", addr), zv("", h), zs("message", "retry_failed"), ze("", err))
		return
	}
	p.data = p.buf[:n]
	n, err = s.socket.WriteTo(p.data, addr)
	if err != nil {
		s.logger.log(levelError, zs("", "generic:error"),
			zx("cid", h.DCID), zv("addr", addr), zv("", h), zs("message", "retry_failed"), ze("", err))
		return
	}
	s.logger.log(levelDebug, zs("", "transport:packet_sent"),
		zx("cid", h.DCID), zv("addr", addr), zs("packet_type", "retry"), zx("dcid", h.SCID), zx("scid", newCID[:]), zx("odcid", h.DCID), zx("token", token))
	s.logger.log(levelTrace, zs("", "transport:datagrams_sent"),
		zx("cid", h.DCID), zv("addr", addr), zx("raw", p.data))
}

func (s *Server) verifyToken(addr net.Addr, token []byte) []byte {
	return s.addrValid.ValidateToken(addr, token)
}

// handleNewConn creates a new connection and handles packets sent to this connection.
// Since verifying token and initializing a new connection can take a bit time,
// this method (instead of s.handleConn) is invoked in a new goroutine so that
// server can continue process other packets.
func (s *Server) handleNewConn(p *packet) {
	var scid, odcid []byte
	if s.addrValid != nil {
		// Retry token
		if len(p.header.Token) == 0 {
			s.logger.log(levelDebug, zs("", "transport:packet_dropped"),
				zv("addr", p.addr), zv("", &p.header), zs("trigger", "retry_required"))
			s.retry(p.addr, &p.header)
			freePacket(p)
			return
		}
		odcid = s.verifyToken(p.addr, p.header.Token)
		if len(odcid) == 0 {
			s.logger.log(levelInfo, zs("", "transport:packet_dropped"),
				zv("addr", p.addr), zv("", &p.header), zs("trigger", "invalid_token"))
			freePacket(p)
			return
		}
		// Reuse the SCID sent in Retry
		scid = p.header.DCID
	}
	c, err := s.newConn(p.addr, scid, odcid)
	if err != nil {
		s.logger.log(levelError, zs("", "transport:packet_dropped"),
			zv("addr", p.addr), zv("", &p.header), zs("trigger", "create_connection_failed"), ze("message", err))
		freePacket(p)
		return
	}
	if len(odcid) == 0 {
		odcid = p.header.DCID
	}
	c.attemptKey = s.attemptKey(p.addr, odcid)
	s.peersMu.Lock()
	if s.closing {
		// Do not create a new handler when server is closing
		s.peersMu.Unlock()
		freePacket(p)
		return
	}
	if ec := s.peers[string(c.scid)]; ec != nil {
		// scid is randomly generated, but possible clash. Drop packet for now.
		s.peersMu.Unlock()
		s.logger.log(levelError, zs("", "transport:packet_dropped"),
			zv("addr", p.addr), zv("", &p.header), zs("trigger", "create_connection_failed"), zs("message", "generated cid conflict"))
		freePacket(p)
		return
	}
	if ec := s.peers[string(c.attemptKey)]; ec != nil {
		// Client may send multiple initial packets, discard the new connection and reuse the one already created.
		s.peersMu.Unlock()
		s.logger.log(levelInfo, zs("", "generic:info"),
			zx("cid", c.scid), zv("addr", p.addr), zx("odcid", odcid), zs("message", "found connection from initial attempt key, discard new connection"))
		ec.recvCh <- p
		return
	}
	s.peers[string(c.scid)] = c
	s.peers[string(c.attemptKey)] = c
	s.peersMu.Unlock()
	s.logger.log(levelInfo, zs("", "connectivity:connection_started"),
		zx("cid", c.scid), zv("addr", p.addr), zs("vantage_point", "server"), zx("odcid", odcid))
	c.recvCh <- p // Buffered channel
	s.handleConn(c)
}

func (s *Server) newConn(addr net.Addr, oscid, odcid []byte) (*Conn, error) {
	// Generate id for new connection since short packets don't include CID length so
	// we use a fixed length for all connections
	scid := make([]byte, cidLength)
	if len(oscid) == cidLength {
		copy(scid, oscid)
	} else {
		if err := s.rand(scid); err != nil {
			return nil, err
		}
	}
	conn, err := transport.Accept(scid, odcid, s.config)
	if err != nil {
		return nil, err
	}
	c := newRemoteConn(addr, scid, conn, false)
	s.logger.attachLogger(c)
	return c, nil
}

// attemptKey generates an initial attempt key from a request.
// This is to find right connection for multiple initial packets.
func (s *Server) attemptKey(addr net.Addr, cid []byte) []byte {
	h := sha256.New()
	h.Write([]byte(addr.String()))
	h.Write(cid)
	return h.Sum(nil)
}

// Close sends Close frame to all connected clients and closes the socket given in Serve.
// Note: if Close is called before Serve, the socket may not be set so it will not be close.
// In that case Serve will hang until it gets socket read error.
func (s *Server) Close() error {
	s.close(30 * time.Second)
	if s.socket != nil {
		// Closing socket should unblock Serve
		return s.socket.Close()
	}
	return nil
}

// AddressValidator generates and validates server retry token.
// https://www.rfc-editor.org/rfc/rfc9000.html#token-integrity
type AddressValidator interface {
	// GenerateToken creates a new token from given addr and odcid.
	GenerateToken(addr net.Addr, odcid []byte) []byte
	// ValidateToken returns odcid when the address and token pair is valid,
	// empty slice otherwise.
	ValidateToken(addr net.Addr, token []byte) []byte
}

// NewAddressValidator returns a simple implementation of AddressValidator.
// It encrypts client original CID into token which is valid for 10 seconds.
func NewAddressValidator() AddressValidator {
	s, err := newAddressValidator()
	if err != nil {
		panic(err)
	}
	return s
}

// addressValidator implements AddressValidator.
// The token include ODCID encrypted using AES-GSM AEAD with a randomly-generated key.
type addressValidator struct {
	aead   cipher.AEAD
	nonce  []byte // First 4 bytes is current time
	timeFn func() time.Time
}

// NewAddressValidator creates a new AddressValidator or returns error when failed to
// generate secret or AEAD.
func newAddressValidator() (*addressValidator, error) {
	var key [16]byte
	_, err := rand.Read(key[:])
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}
	return &addressValidator{
		aead:   aead,
		nonce:  nonce,
		timeFn: time.Now,
	}, nil
}

// Generate encrypts odcid using current time as nonce and addr as additional data.
func (s *addressValidator) GenerateToken(addr net.Addr, odcid []byte) []byte {
	now := s.timeFn().Unix()
	nonce := make([]byte, len(s.nonce))
	binary.BigEndian.PutUint32(nonce, uint32(now))
	copy(nonce[4:], s.nonce[4:])

	token := make([]byte, 4+len(odcid)+s.aead.Overhead())
	binary.BigEndian.PutUint32(token, uint32(now))
	s.aead.Seal(token[4:4], nonce, odcid, []byte(addr.String()))
	return token
}

// Validate decrypts token and returns odcid.
func (s *addressValidator) ValidateToken(addr net.Addr, token []byte) []byte {
	if len(token) < 4 {
		return nil
	}
	const validity = 10 // Second
	now := s.timeFn().Unix()
	issued := int64(binary.BigEndian.Uint32(token))
	if issued < now-validity || issued > now {
		// TODO: Fix overflow when time > MAX_U32
		return nil
	}
	nonce := make([]byte, len(s.nonce))
	copy(nonce, token[:4])
	copy(nonce[4:], s.nonce[4:])
	odcid, err := s.aead.Open(nil, nonce, token[4:], []byte(addr.String()))
	if err != nil {
		return nil
	}
	return odcid
}
