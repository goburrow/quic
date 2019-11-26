package quic

import (
	"errors"
	"fmt"
	"net"

	"github.com/goburrow/quic/transport"
)

// Client is a client-side QUIC connection.
type Client struct {
	localConn
}

// NewClient creates a new QUIC client.
func NewClient(config *transport.Config, handler Handler) *Client {
	return &Client{
		localConn: localConn{
			config:  config,
			logger:  leveledLogger(LevelInfo),
			peers:   make(map[string]*remoteConn),
			handler: handler,
		},
	}
}

func (s *Client) Listen(addr string) error {
	if s.socket != nil {
		return errors.New("socket already listening")
	}
	if err := s.listen(addr); err != nil {
		return err
	}
	go s.serve()
	return nil
}

func (s *Client) serve() error {
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

func (s *Client) recv(p *packet, h *transport.Header) {
	s.peersMu.RLock()
	c, ok := s.peers[string(h.DCID)]
	s.peersMu.RUnlock()
	if ok {
		c.recv <- p
	} else {
		s.logger.Log(LevelDebug, "%s ignore unknown destination: %s", p.addr, h)
		freePacket(p)
	}
}

func (s *Client) Connect(addr string) error {
	c, err := s.newConn(addr)
	if err != nil {
		return err
	}
	s.peersMu.Lock()
	if _, ok := s.peers[string(c.scid[:])]; ok {
		s.peersMu.Unlock()
		return fmt.Errorf("connection id conflict scid=%x", c.scid)
	}
	s.peers[string(c.scid[:])] = c
	s.peersMu.Unlock()
	// Send initial packet
	p := newPacket()
	defer freePacket(p)
	if err = s.connSend(c, p.buf[:maxDatagramSize]); err != nil {
		s.peersMu.Lock()
		delete(s.peers, string(c.scid[:]))
		s.peersMu.Unlock()
		return fmt.Errorf("send %s: %v", c.addr, err)
	}
	if err = s.handler.Created(c); err != nil {
		s.peersMu.Lock()
		delete(s.peers, string(c.scid[:]))
		s.peersMu.Unlock()
		return err
	}
	go s.handleConn(c)
	return nil
}

func (s *Client) newConn(addr string) (*remoteConn, error) {
	var err error
	c := &remoteConn{
		recv: make(chan *packet, 1),
	}
	if c.addr, err = net.ResolveUDPAddr("udp", addr); err != nil {
		return nil, err
	}
	if err = s.rand(c.scid[:]); err != nil {
		return nil, fmt.Errorf("generate connection id: %v", err)
	}
	c.conn, err = transport.Connect(c.scid[:], s.config)
	if err != nil {
		return nil, err
	}
	return c, nil
}
