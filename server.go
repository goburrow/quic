package quic

import (
	"errors"
	"net"

	"github.com/goburrow/quic/transport"
)

// Server is a server-side QUIC connection.
type Server struct {
	localConn

	addrValid AddressValidator
}

// NewServer creates a new QUIC server.
func NewServer(config *transport.Config) *Server {
	return &Server{
		localConn: localConn{
			config:  config,
			logger:  leveledLogger(LevelInfo),
			peers:   make(map[string]*remoteConn),
			handler: noopHandler{},
		},
	}
}

// SetHandler sets QUIC connection callbacks.
func (s *Server) SetHandler(v Handler) {
	s.handler = v
}

// SetAddressValidator sets validation for QUIC connections address.
func (s *Server) SetAddressValidator(v AddressValidator) {
	s.addrValid = v
}

// SetLogger sets transaction logger.
func (s *Server) SetLogger(v Logger) {
	s.logger = v
}

// Listen starts listening on UDP network address addr.
func (s *Server) Listen(addr string) error {
	return s.listen(addr)
}

// Serve handles incoming requests from a socket connection.
// Listen must be successfully called prior to Serve when given socket is nil.
func (s *Server) Serve(socket net.PacketConn) error {
	if socket != nil {
		s.socket = socket
	}
	if s.socket == nil {
		return errors.New("socket not listening")
	}
	for {
		p := newPacket()
		n, addr, err := s.socket.ReadFrom(p.buf[:])
		if n > 0 {
			// Process returned data first before considering error
			p.data = p.buf[:n]
			p.addr = addr
			s.logger.Log(LevelDebug, "%s got %d bytes\n%x", addr, n, p.data)
			s.recv(p)
		}
		if err != nil {
			// Stop on socket error.
			// FIXME: Check if the error is timeout when read deadline is set
			return err
		}
	}
}

func (s *Server) recv(p *packet) {
	h := &transport.Header{}
	_, err := h.Decode(p.data, transport.MaxCIDLength)
	if err != nil {
		s.logger.Log(LevelDebug, "%s could not decode packet: %v", p.addr, err)
		freePacket(p)
		return
	}
	s.logger.Log(LevelDebug, "%s got %s", p.addr, h)
	s.peersMu.RLock()
	c, ok := s.peers[string(h.DCID)]
	s.peersMu.RUnlock()
	if !ok {
		// Server must ensure the any datagram packet containing Initial packet being at least 1200 bytes
		if h.Type != 0 || len(p.data) < transport.MinInitialPacketSize {
			s.logger.Log(LevelDebug, "%s dropped invalid initial packet: %s", p.addr, h)
			freePacket(p)
			return
		}
		if h.Version != transport.ProtocolVersion {
			// Negotiate version
			s.negotiate(p.addr, h)
			freePacket(p)
			return
		}
		var odcid []byte
		if s.addrValid != nil {
			if len(h.Token) == 0 {
				s.retry(p.addr, h)
				freePacket(p)
				return
			}
			odcid = s.verifyToken(p.addr, h.Token)
			if len(odcid) == 0 {
				s.logger.Log(LevelInfo, "%s invalid retry token: %v", p.addr, h)
				freePacket(p)
				return
			}
		}
		c, err = s.newConn(p.addr, h.DCID, odcid)
		if err != nil {
			s.logger.Log(LevelError, "%s create connection: %v", err)
			freePacket(p)
			return
		}
		s.peersMu.Lock()
		if _, ok = s.peers[string(c.scid[:])]; ok {
			s.peersMu.Unlock()
			s.logger.Log(LevelError, "%s connection id conflict scid=%x", p.addr, c.scid)
			freePacket(p)
			return
		}
		s.peers[string(c.scid[:])] = c
		s.peersMu.Unlock()
		s.logger.Log(LevelDebug, "%s new connection scid=%x odcid=%x", p.addr, c.scid, odcid)
		if err = s.handler.Created(c); err != nil {
			s.peersMu.Lock()
			delete(s.peers, string(c.scid[:]))
			s.peersMu.Unlock()
			s.logger.Log(LevelError, "%s create connection: %v", err)
			freePacket(p)
			return
		}
		go s.handleConn(c)
	}
	c.recv <- p
}

func (s *Server) negotiate(addr net.Addr, h *transport.Header) {
	p := newPacket()
	defer freePacket(p)
	n, err := transport.NegotiateVersion(p.buf[:], h.SCID, h.DCID)
	if err != nil {
		s.logger.Log(LevelError, "%s negotiate: %s %v", addr, h, err)
		return
	}
	_, err = s.socket.WriteTo(p.buf[:n], addr)
	if err != nil {
		s.logger.Log(LevelError, "%s negotiate: %s %v", addr, h, err)
		return
	}
	s.logger.Log(LevelDebug, "%s negotiate: newversion=%d %s", addr, transport.ProtocolVersion, h)
}

func (s *Server) retry(addr net.Addr, h *transport.Header) {
	p := newPacket()
	defer freePacket(p)
	// newCID is a new DCID client shoud send in next Initial packet
	var newCID [transport.MaxCIDLength]byte
	if err := s.rand(newCID[:]); err != nil {
		s.logger.Log(LevelError, "%s retry: %s %v", addr, h, err)
		return
	}
	// Set token to current header so it will be logged
	h.Token = s.addrValid.Generate([]byte(addr.String()), h.DCID)
	n, err := transport.Retry(p.buf[:], h.SCID, newCID[:], h.DCID, h.Token)
	if err != nil {
		s.logger.Log(LevelError, "%s retry: %s %v", addr, h, err)
		return
	}
	_, err = s.socket.WriteTo(p.buf[:n], addr)
	if err != nil {
		s.logger.Log(LevelError, "%s retry: %s %v", addr, h, err)
		return
	}
	s.logger.Log(LevelDebug, "%s retry: %v newcid=%x", addr, h, newCID)
}

func (s *Server) verifyToken(addr net.Addr, token []byte) []byte {
	return s.addrValid.Validate([]byte(addr.String()), token)
}

func (s *Server) newConn(addr net.Addr, scid, odcid []byte) (*remoteConn, error) {
	c := &remoteConn{
		addr: addr,
		recv: make(chan *packet, 1),
	}
	var err error
	if len(scid) == len(c.scid) {
		copy(c.scid[:], scid)
	} else {
		// Generate id for new connection since short packets don't include CID length so
		// we use MaxCIDLength for all connections
		if err = s.rand(c.scid[:]); err != nil {
			return nil, err
		}
	}
	if c.conn, err = transport.Accept(c.scid[:], odcid, s.config); err != nil {
		return nil, err
	}
	return c, nil
}

// Close tries to send Close frame to all connected clients and closes its socket.
func (s *Server) Close() error {
	s.peersMu.RLock()
	for _, c := range s.peers {
		close(c.recv)
	}
	s.peersMu.RUnlock()
	// TODO: wait and close socket
	return nil
}

// AddressValidator generates and validates server retry token.
// https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#token-integrity
type AddressValidator interface {
	Generate(addr, odcid []byte) []byte
	Validate(addr, token []byte) []byte
}
