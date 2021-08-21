package quic

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/goburrow/quic/transport"
)

// Client is a client-side QUIC connection.
// All setters must only be invoked before calling Serve.
type Client struct {
	localConn
}

// NewClient creates a new QUIC client.
func NewClient(config *transport.Config) *Client {
	c := &Client{}
	c.localConn.init(config)
	return c
}

// ListenAndServe starts listening on UDP network address addr and
// serves incoming packets. Unlike Server.ListenAndServe, this function
// does not block as Serve is invoked in a goroutine.
func (s *Client) ListenAndServe(addr string) error {
	socket, err := net.ListenPacket("udp", addr)
	s.socket = socket
	if err == nil {
		go s.Serve()
	}
	return err
}

// Serve handles requests from given socket.
func (s *Client) Serve() error {
	if s.socket == nil {
		return errors.New("no listening connection")
	}
	for {
		p := newPacket()
		err := s.readFrom(p)
		if len(p.data) > 0 {
			s.recv(p)
		} else {
			freePacket(p)
		}
		if err != nil {
			return err
		}
	}
}

func (s *Client) recv(p *packet) {
	_, err := p.header.Decode(p.data, s.cidGen.CIDLength())
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
		// Server is closing
		s.peersMu.RUnlock()
		return
	}
	c := s.peers[string(p.header.DCID)]
	s.peersMu.RUnlock()
	if c == nil {
		s.logger.log(levelDebug, zs("", "transport:packet_dropped"),
			zx("cid", p.header.DCID), zv("addr", p.addr), zs("trigger", "unknown_connection_id"), zv("", &p.header))
		freePacket(p)
	} else {
		c.recvCh <- p
	}
}

// Connect establishes a new connection to UDP network address addr.
func (s *Client) Connect(addr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	c, err := s.newConn(udpAddr)
	if err != nil {
		return err
	}
	s.peersMu.Lock()
	if s.closing {
		s.peersMu.Unlock()
		return fmt.Errorf("client is already closed")
	}
	if _, ok := s.peers[string(c.scid)]; ok {
		s.peersMu.Unlock()
		return fmt.Errorf("connection id conflict cid=%x", c.scid)
	}
	s.peers[string(c.scid)] = c
	s.peersMu.Unlock()
	// Send initial packet
	s.logger.log(levelInfo, zs("", "connectivity:connection_started"),
		zx("cid", c.scid), zv("addr", c.addr), zs("vantage_point", "client"))
	if err = s.connSend(c); err != nil {
		s.peersMu.Lock()
		delete(s.peers, string(c.scid))
		s.peersMu.Unlock()
		return fmt.Errorf("send %s: %v", c.addr, err)
	}
	go s.handleConn(c)
	return nil
}

// Close closes all current established connections and listening socket.
func (s *Client) Close() error {
	s.close(10 * time.Second)
	if s.socket != nil {
		return s.socket.Close()
	}
	return nil
}

func (s *Client) newConn(addr net.Addr) (*Conn, error) {
	scid, err := s.cidGen.NewCID()
	if err != nil {
		return nil, fmt.Errorf("generate connection id: %v", err)
	}
	dcid, err := s.cidGen.NewCID()
	if err != nil {
		return nil, fmt.Errorf("generate connection id: %v", err)
	}
	conn, err := transport.Connect(scid, dcid, s.config)
	if err != nil {
		return nil, err
	}
	c := newRemoteConn(addr, scid, conn, true)
	s.logger.attachLogger(c)
	return c, nil
}
