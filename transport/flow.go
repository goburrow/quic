package transport

import "fmt"

// https://www.rfc-editor.org/rfc/rfc9000.html#section-4
type flowControl struct {
	recvTotal   uint64 // Total bytes received from peer - updated when data is received.
	recvMax     uint64 // Receiving limits - updated when MAX_DATA is sent.
	recvMaxNext uint64 // Receiving limits for sending MAX_DATA updated when data is consumed.

	sendTotal   uint64 // Total bytes sent to peer - updated when data is sent successfully.
	sendMax     uint64 // Sending limits - updated when got MAX_DATA.
	sendBlocked bool   // Whether the connection needs to send DATA_BLOCKED or STREAM_DATA_BLOCKED
}

func (s *flowControl) init(maxRecv, maxSend uint64) {
	s.recvMax = maxRecv
	s.recvMaxNext = maxRecv
	s.sendMax = maxSend
}

// availRecv returns number of bytes can be received.
func (s *flowControl) availRecv() uint64 {
	if s.recvMax > s.recvTotal {
		return s.recvMax - s.recvTotal
	}
	return 0
}

// addRecv adds to number of bytes received.
// This function is called when data is successfully received.
func (s *flowControl) addRecv(n uint64) {
	s.recvTotal += n
}

func (s *flowControl) setRecv(n uint64) {
	s.recvTotal = n
}

// addRecvMaxNext adds to maximum data will be received in next commit.
func (s *flowControl) addRecvMaxNext(n uint64) {
	s.recvMaxNext += n
}

// commitRecvMax sets recvMax to current recvMaxNext.
func (s *flowControl) commitRecvMax() {
	s.recvMax = s.recvMaxNext
}

// shouldUpdateRecvMax returns true if the connection-level flow control
// needs to be updated.
// This happens when the new max data limit is at least double the amount
// of data that can be received before blocking.
func (s *flowControl) shouldUpdateRecvMax() bool {
	return s.recvMaxNext > s.recvMax && s.recvMax >= s.recvTotal &&
		(s.recvMax-s.recvTotal) < s.recvMaxNext/2
}

// availSend returns number of bytes can be sent.
func (s *flowControl) availSend() uint64 {
	if s.sendMax > s.sendTotal {
		return s.sendMax - s.sendTotal
	}
	return 0
}

// addSend adds n to total bytes sent.
func (s *flowControl) addSend(n int) {
	s.sendTotal += uint64(n)
}

// setSend sets total bytes sent.
func (s *flowControl) setSend(n uint64) {
	s.sendTotal = n
}

// setSendMax updates maximum number of bytes can send.
func (s *flowControl) setSendMax(n uint64) {
	if n > s.sendMax {
		s.sendMax = n
	}
}

// setSendBlocked sets sending blocked.
func (s *flowControl) setSendBlocked(blocked bool) {
	s.sendBlocked = blocked
}

func (s *flowControl) String() string {
	return fmt.Sprintf("recv=%d recvMax=%d recvMaxNext=%d send=%d sendMax=%d sendBlocked=%v",
		s.recvTotal, s.recvMax, s.recvMaxNext, s.sendTotal, s.sendMax, s.sendBlocked)
}
