package transport

import "fmt"

// https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#flow-control
type flowControl struct {
	totalRecv   uint64 // Total bytes received from peer - updated when data is received.
	maxRecv     uint64 // Receiving limits - updated when MAX_DATA is sent.
	maxRecvNext uint64 // Receiving limits for sending MAX_DATA updated when data is consumed.

	totalSend uint64 // Total bytes sent to peer - updated when data is sent successfully.
	maxSend   uint64 // Sending limits - updated when got MAX_DATA.
}

func (s *flowControl) init(maxRecv, maxSend uint64) {
	s.maxRecv = maxRecv
	s.maxRecvNext = maxRecv
	s.maxSend = maxSend
}

// canRecv returns true if number of bytes received does not exceed limits.
func (s *flowControl) canRecv() uint64 {
	if s.maxRecv > s.totalRecv {
		return s.maxRecv - s.totalRecv
	}
	return 0
}

// addRecv adds to number of bytes received.
// This function is called when data is successfully received.
func (s *flowControl) addRecv(n int) {
	s.totalRecv += uint64(n)
}

func (s *flowControl) setRecv(n uint64) {
	s.totalRecv = n
}

// addMaxRecvNext adds to maximum data will be received in next commit.
func (s *flowControl) addMaxRecvNext(n uint64) {
	s.maxRecvNext += n
}

// commitMaxRecv sets maxRecv to current maxRecvNext.
func (s *flowControl) commitMaxRecv() {
	s.maxRecv = s.maxRecvNext
}

// shouldUpdateMaxData returns true if the connection-level flow control
// needs to be updated.
// This happens when the new max data limit is at least double the amount
// of data that can be received before blocking.
func (s *flowControl) shouldUpdateMaxRecv() bool {
	return s.maxRecvNext != s.maxRecv && s.maxRecv >= s.totalRecv &&
		s.maxRecvNext/2 > s.maxRecv-s.totalRecv
}

func (s *flowControl) canSend() uint64 {
	if s.maxSend > s.totalSend {
		return s.maxSend - s.totalSend
	}
	return 0
}

func (s *flowControl) addSend(n int) {
	s.totalSend += uint64(n)
}

func (s *flowControl) setSend(n uint64) {
	s.totalSend = n
}

func (s *flowControl) setMaxSend(n uint64) {
	if n > s.maxSend {
		s.maxSend = n
	}
}

func (s *flowControl) String() string {
	return fmt.Sprintf("recv=%d maxRecv=%d maxRecvNext=%d send=%d maxSend=%d",
		s.totalRecv, s.maxRecv, s.maxRecvNext, s.totalSend, s.maxSend)
}
