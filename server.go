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

	addrVer AddressVerifier
}

// NewServer creates a new QUIC server.
func NewServer(config *transport.Config) *Server {
	s := &Server{}
	s.localConn.init(config)
	return s
}

// SetAddressVerifier sets validation for QUIC connections address.
func (s *Server) SetAddressVerifier(v AddressVerifier) {
	s.addrVer = v
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
		err := readPacket(p, s.socket)
		if len(p.data) > 0 {
			// Process returned data first before considering error
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
	_, err := p.header.Decode(p.data, s.cidIss.CIDLength())
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
	newCID, err := s.cidIss.NewCID()
	if err != nil {
		s.logger.log(levelError, zs("", "generic:error"),
			zx("cid", h.DCID), zv("addr", addr), zv("", h), zs("message", "retry_failed"), ze("", err))
		return
	}
	token := s.addrVer.NewToken(addr, newCID, h.DCID)
	if len(token) == 0 {
		// Ignore.
		return
	}
	// Header => Retry: DCID => ODCID, SCID => DCID, newCID => SCID
	n, err := transport.Retry(p.buf[:], h.SCID, newCID, h.DCID, token)
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
		zx("cid", h.DCID), zv("addr", addr), zs("packet_type", "retry"), zx("dcid", h.SCID), zx("scid", newCID), zx("odcid", h.DCID), zx("token", token))
	s.logger.log(levelTrace, zs("", "transport:datagrams_sent"),
		zx("cid", h.DCID), zv("addr", addr), zx("raw", p.data))
}

// handleNewConn creates a new connection and handles packets sent to this connection.
// Since verifying token and initializing a new connection can take a bit time,
// this method (instead of s.handleConn) is invoked in a new goroutine so that
// server can continue process other packets.
func (s *Server) handleNewConn(p *packet) {
	var scid, odcid []byte
	if s.addrVer != nil && s.addrVer.IsActive(p.addr) {
		// Retry token
		odcid = s.addrVer.VerifyToken(p.addr, p.header.DCID, p.header.Token)
		if len(odcid) == 0 {
			s.logger.log(levelDebug, zs("", "transport:packet_dropped"),
				zv("addr", p.addr), zv("", &p.header), zs("trigger", "retry_required"))
			s.retry(p.addr, &p.header)
			freePacket(p)
			return
		}
		// Use SCID originally from retry packet as it is verified.
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
	var scid []byte
	var err error
	if len(oscid) > 0 {
		// scid is verified, just make a copy.
		scid = make([]byte, len(oscid))
		copy(scid, oscid)
	} else {
		scid, err = s.cidIss.NewCID()
		if err != nil {
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

// AddressVerifier generates and validates server retry token.
// https://www.rfc-editor.org/rfc/rfc9000.html#token-integrity
type AddressVerifier interface {
	IsActive(addr net.Addr) bool
	// NewToken creates a new token from given address, retry source connection ID
	// and original destination connection ID.
	NewToken(addr net.Addr, rscid, odcid []byte) []byte
	// VerifyToken returns odcid when the address and token pair is valid,
	// empty slice otherwise.
	VerifyToken(addr net.Addr, dcid, token []byte) []byte
}

// NewAddressVerifier returns a simple implementation of AddressValidator.
// It encrypts client original CID into token which is valid for 10 seconds.
func NewAddressVerifier() AddressVerifier {
	s, err := newAddressVerifier()
	if err != nil {
		panic(err)
	}
	return s
}

// addressVerifier implements AddressValidator.
// The token include ODCID encrypted using AES-GSM AEAD with a randomly-generated key.
type addressVerifier struct {
	aead   cipher.AEAD
	nonce  []byte
	timeFn func() time.Time
}

// NewAddressValidator creates a new AddressValidator or returns error when failed to
// generate secret or AEAD.
func newAddressVerifier() (*addressVerifier, error) {
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
	return &addressVerifier{
		aead:   aead,
		nonce:  nonce,
		timeFn: time.Now,
	}, nil
}

func (s *addressVerifier) IsActive(addr net.Addr) bool {
	return true
}

// NewToken encrypts expiry time which odcid as nonce and rscid and addr as associated data.
//
// 	Non-Shared-State Retry Service Token {
// 	  Token Type (1) = 0,
// 	  ODCIL (7) = 8..20,
// 	  Original Destination Connection ID (64..160),
// 	  Opaque Data (..),
// 	}
//
// https://quicwg.org/load-balancers/draft-ietf-quic-load-balancers.html#section-7.2.2
func (s *addressVerifier) NewToken(addr net.Addr, rscid, odcid []byte) []byte {
	bodyLen := 1 + len(odcid)
	// Expiry time is encrypted in opaque data
	tokenLen := bodyLen + 8 + s.aead.Overhead()
	// Allocate extra bytes for nonce and associated data
	ipAddr := []byte(addr.String())
	b := make([]byte, tokenLen+len(s.nonce)+len(rscid)+len(ipAddr))

	token := b[:tokenLen]
	token[0] = uint8(len(odcid))
	token[0] &= 0x7f // Ensure token type is '0'
	copy(token[1:], odcid)
	expiry := s.timeFn().Add(10 * time.Second).Unix()
	binary.BigEndian.PutUint64(token[bodyLen:], uint64(expiry))

	nonce := b[tokenLen : tokenLen+len(s.nonce)]
	copy(nonce, s.nonce)
	for i := range odcid {
		nonce[i%len(nonce)] ^= odcid[i]
	}

	data := b[tokenLen+len(nonce):]
	copy(data, rscid)
	copy(data[len(rscid):], ipAddr)

	s.aead.Seal(token[bodyLen:bodyLen], nonce, token[bodyLen:bodyLen+8], data)
	return token
}

// VerifyToken decrypts token and returns odcid.
func (s *addressVerifier) VerifyToken(addr net.Addr, dcid, token []byte) []byte {
	if len(token) < 1 {
		return nil
	}
	odcil := int(token[0] & 0x7f)
	if len(token) != 1+odcil+8+s.aead.Overhead() {
		return nil
	}
	odcid := token[1 : 1+odcil]
	ipAddr := []byte(addr.String())
	b := make([]byte, 8+len(s.nonce)+len(dcid)+len(ipAddr))

	nonce := b[8 : 8+len(s.nonce)]
	copy(nonce, s.nonce)
	for i := range odcid {
		nonce[i%len(nonce)] ^= odcid[i]
	}

	data := b[8+len(nonce):]
	copy(data, dcid)
	copy(data[len(dcid):], ipAddr)

	expiry, err := s.aead.Open(b[:0], nonce, token[1+odcil:], data)
	if err != nil || len(expiry) != 8 {
		return nil
	}
	expiryTime := int64(binary.BigEndian.Uint64(expiry))
	now := s.timeFn().Unix()
	if expiryTime < now {
		return nil
	}
	// Return a copy of odcid from token
	b = make([]byte, len(odcid))
	copy(b, odcid)
	return b
}

type serverCIDIssuer struct {
	serverID []byte
}

// NewServerCIDIssuer returns a new CIDIssuer that creates CID using Plaintext Algorithm.
// Server ID is encoded in CID using QUIC varint encoding.
// https://quicwg.org/load-balancers/draft-ietf-quic-load-balancers.html#section-5.1
func NewServerCIDIssuer(id uint64) CIDIssuer {
	return &serverCIDIssuer{
		serverID: encodeServerID(id),
	}
}

func (s *serverCIDIssuer) NewCID() ([]byte, error) {
	cid := make([]byte, cidLength)
	cid[0] = 0x3f & cidLength
	n := copy(cid[1:], s.serverID)
	_, err := rand.Read(cid[1+n:])
	return cid, err
}

func (s *serverCIDIssuer) CIDLength() int {
	return cidLength
}

func encodeServerID(id uint64) []byte {
	var b []byte
	if id < 1<<6 {
		b = make([]byte, 1)
		b[0] = uint8(id)
	} else if id < 1<<14 {
		b = make([]byte, 2)
		b[1] = uint8(id)
		b[0] = uint8(id>>8) | 0x40
	} else if id < 1<<30 {
		b = make([]byte, 4)
		b[3] = uint8(id)
		b[2] = uint8(id >> 8)
		b[1] = uint8(id >> 16)
		b[0] = uint8(id>>24) | 0x80
	} else {
		b = make([]byte, 8)
		b[7] = uint8(id)
		b[6] = uint8(id >> 8)
		b[5] = uint8(id >> 16)
		b[4] = uint8(id >> 24)
		b[3] = uint8(id >> 32)
		b[2] = uint8(id >> 40)
		b[1] = uint8(id >> 48)
		b[0] = uint8(id>>56) | 0xc0
	}
	return b
}

func decodeServerID(b []byte) (uint64, int) {
	switch b[0] >> 6 {
	case 0:
		id := uint64(b[0] & 0x3f)
		return id, 1
	case 1:
		if len(b) < 2 {
			return 0, 0
		}
		id := uint64(b[1]) | uint64(b[0]&0x3f)<<8
		return id, 2
	case 2:
		if len(b) < 4 {
			return 0, 0
		}
		id := uint64(b[3]) | uint64(b[2])<<8 | uint64(b[1])<<16 | uint64(b[0]&0x3f)<<24
		return id, 4
	case 3:
		if len(b) < 8 {
			return 0, 0
		}
		id := uint64(b[7]) | uint64(b[6])<<8 | uint64(b[5])<<16 | uint64(b[4])<<24 |
			uint64(b[3])<<32 | uint64(b[2])<<40 | uint64(b[1])<<48 | uint64(b[0]&0x3f)<<56
		return id, 8
	default:
		panic("unreachable")
	}
}
