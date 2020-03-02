package quic

import (
	"errors"
	"net"

	"github.com/goburrow/quic/transport"
)

// Server is a server-side QUIC connection.
type Server struct {
	localConn
}

// NewServer creates a new QUIC server.
func NewServer(config *transport.Config, handler Handler) *Server {
	return &Server{
		localConn: localConn{
			config:  config,
			logger:  leveledLogger(LevelInfo),
			peers:   make(map[string]*remoteConn),
			handler: handler,
		},
	}
}

func (s *Server) Listen(addr string) error {
	return s.listen(addr)
}

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
		if err != nil {
			return err
		}
		p.data = p.buf[:n]
		p.addr = addr
		s.logger.Log(LevelDebug, "%s got %d bytes\n%x", addr, n, p.data)
		h, err := transport.DecodeHeader(p.data, transport.MaxCIDLength)
		if err != nil {
			// Ignore invalid packet
			s.logger.Log(LevelDebug, "%s parse header: %v", addr, err)
			freePacket(p)
			continue
		}
		s.logger.Log(LevelDebug, "%s receiving packet %s", addr, h)
		s.recv(p, h)
	}
}

func (s *Server) recv(p *packet, h *transport.Header) {
	s.peersMu.RLock()
	c, ok := s.peers[string(h.DCID)]
	s.peersMu.RUnlock()
	if !ok {
		// TODO: Check first packet must be Initial
		if h.Version != transport.ProtocolVersion {
			// Negotiate version
			s.logger.Log(LevelDebug, "%s negotiate version %d: %s", p.addr, transport.ProtocolVersion, h)
			s.negotiate(p.addr, h.SCID, h.DCID)
			freePacket(p)
			return
		}
		// Server must ensure the any datagram packet containing Initial packet being at least 1200 bytes
		if len(p.data) < transport.MinInitialPacketSize {
			// TODO: Put this check back to transport package
			s.logger.Log(LevelDebug, "%s dropped initial packet: %s", p.addr, h)
			freePacket(p)
			return
		}
		var err error
		c, err = s.newConn(p.addr, h.DCID, nil)
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
		s.logger.Log(LevelDebug, "%s new connection scid=%x", p.addr, c.scid)
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

func (s *Server) negotiate(addr net.Addr, dcid, scid []byte) {
	p := newPacket()
	defer freePacket(p)
	n, err := transport.NegotiateVersion(p.buf[:], dcid, scid)
	if err != nil {
		s.logger.Log(LevelError, "%s negotiate version: %v", addr, err)
		return
	}
	_, err = s.socket.WriteTo(p.buf[:n], addr)
	if err != nil {
		s.logger.Log(LevelError, "%s negotiate version: %v", addr, err)
	}
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
		// Generate id for new connection
		if err = s.rand(c.scid[:]); err != nil {
			return nil, err
		}
	}
	if c.conn, err = transport.Accept(c.scid[:], odcid, s.config); err != nil {
		return nil, err
	}
	return c, nil
}

func (s *Server) Close() error {
	s.peersMu.RLock()
	for _, c := range s.peers {
		close(c.recv)
	}
	s.peersMu.RUnlock()
	// TODO: wait and close socket
	return nil
}
