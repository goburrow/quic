package transport

// https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#flow-control
type flowControl struct {
	received uint64
	sent     uint64

	maxRecv     uint64
	maxRecvNext uint64

	maxSend uint64
}

func (s *flowControl) init(maxRecv uint64) {
	s.maxRecv = maxRecv
	s.maxRecvNext = maxRecv
}

func (s *flowControl) canRecv(n int) bool {
	return s.received+uint64(n) <= s.maxRecv
}

func (s *flowControl) addRecv(n int) {
	s.received += uint64(n)
}

func (s *flowControl) setMaxSend(n uint64) {
	if n > s.maxSend {
		s.maxSend = n
	}
}

func (s *flowControl) addSend(n int) {
	s.sent += uint64(n)
}

func (s *flowControl) canSend() int {
	if s.maxSend > s.sent {
		return int(s.maxSend - s.sent)
	}
	return 0
}

func (s *flowControl) setMaxRecv(n uint64) {
	s.maxRecv = n
}

// Returns true if the connection-level flow control needs to be updated.
//
// This happens when the new max data limit is at least double the amount
// of data that can be received before blocking.
func (s *flowControl) shouldUpdateMaxRecv() uint64 {
	if s.maxRecvNext != s.maxRecv &&
		s.maxRecvNext/2 > s.maxRecv-s.received {
		return s.maxRecvNext
	}
	return 0
}
