package quic

import (
	"errors"
	"net"
	"sync"
)

type LoadBalancer struct {
	socket net.PacketConn

	peersMu sync.RWMutex
	// servers: id -> addr
	servers map[uint]net.Addr
	// clients: connection id -> addr
	clientCIDs map[string]net.Addr

	logger  logger
	cidIss  CIDIssuer
	addrVer AddressVerifier
}

func (s *LoadBalancer) init() {
}

// SetAddressVerifier sets validation for QUIC connections address.
func (s *LoadBalancer) SetAddressVerifier(v AddressVerifier) {
	s.addrVer = v
}

func (s *LoadBalancer) AddServer(id uint, addr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	s.peersMu.Lock()
	s.servers[id] = udpAddr
	s.peersMu.Unlock()
	return nil
}

// ListenAndServe starts listening on UDP network address addr and
// serves incoming packets.
func (s *LoadBalancer) ListenAndServe(addr string) error {
	socket, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	s.socket = socket
	return s.Serve()
}

// Serve handles incoming requests from a socket connection.
func (s *LoadBalancer) Serve() error {
	if s.socket == nil {
		return errors.New("no listening connection")
	}
	s.logger.log(levelInfo, zs("", "connectivity:server_listening"),
		zv("addr", s.socket.LocalAddr()))
	p := newPacket()
	defer freePacket(p)
	for {
		err := readPacket(p, s.socket)
		if len(p.data) > 0 {
			// Process returned data first before considering error
			s.recv(p)
		}
		if err != nil {
			// Stop on socket error.
			if err, ok := err.(net.Error); ok && err.Timeout() {
				s.logger.log(levelTrace, zs("", "generic:verbose"),
					zs("message", "read_timed_out"), ze("", err))
			} else {
				return err
			}
		}
	}
}

func (s *LoadBalancer) recv(p *packet) {
	_, err := p.header.Decode(p.data, s.cidIss.CIDLength())
	if err != nil {
		s.logger.log(levelTrace, zs("", "transport:datagrams_received"),
			zv("addr", p.addr), zx("raw", p.data))
		s.logger.log(levelDebug, zs("", "transport:packet_dropped"),
			zv("addr", p.addr), zi("packet_size", len(p.data)), zs("trigger", "header_parse_error"), ze("message", err))
		return
	}
	s.logger.log(levelTrace, zs("", "transport:datagrams_received"),
		zx("cid", p.header.DCID), zv("addr", p.addr), zx("raw", p.data))
}
