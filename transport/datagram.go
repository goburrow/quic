package transport

import (
	"fmt"
	"io"
)

const (
	// Maximum size of buffer is 32 * max_datagram_payload_size
	maxDatagramBufferLen = 32
)

// Datagram provides unreliable datagrams over QUIC transport.
// https://quicwg.org/datagram/draft-ietf-quic-datagram.html
type Datagram struct {
	// Buffers
	send, recv datagramBuffer
	// Max datagram payload size
	maxSend, maxRecv int
}

func (s *Datagram) Write(b []byte) (int, error) {
	if len(b) > s.maxSend {
		return 0, newError(ApplicationError, sprint("max_datagram_payload_size ", s.maxSend))
	}
	data := make([]byte, len(b))
	copy(data, b)
	s.send.push(data)
	return len(b), nil
}

// Push adds data for sending.
// Unlike Write, Push does not create a copy of the data provided so b must be immutable until it is sent.
func (s *Datagram) Push(b []byte) error {
	if len(b) > s.maxSend {
		return newError(ApplicationError, sprint("max_datagram_payload_size ", s.maxSend))
	}
	s.send.push(b)
	return nil
}

func (s *Datagram) Read(b []byte) (int, error) {
	if s.recv.avail() > len(b) {
		return 0, io.ErrShortBuffer
	}
	data := s.recv.pop()
	n := copy(b, data)
	return n, nil
}

// Pop returns received data or nil if it is empty.
func (s *Datagram) Pop() []byte {
	return s.recv.pop()
}

func (s *Datagram) pushRecv(b []byte) error {
	if len(b) > s.maxRecv {
		return newError(ProtocolViolation, sprint("max_datagram_payload_size ", s.maxRecv))
	}
	s.recv.push(b)
	return nil
}

func (s *Datagram) popSend(max int) []byte {
	if s.send.avail() > max {
		return nil
	}
	return s.send.pop()
}

// isReadable returns true if the datagram has any data to read.
func (s *Datagram) isReadable() bool {
	return s.recv.avail() > 0
}

// isFlushable returns true if it has any datagram to send.
func (s *Datagram) isFlushable() bool {
	return s.send.avail() > 0
}

func (s *Datagram) setMaxSend(max uint64) {
	s.maxSend = int(max)
}

func (s *Datagram) setMaxRecv(max uint64) {
	s.maxRecv = int(max)
}

type datagramBuffer struct {
	data [][]byte
	// Write/Read index.
	// Data at w is always nil. Nothing to read if data at r is nil.
	w, r int
}

func (s *datagramBuffer) push(b []byte) {
	// Can either extend the buffer or start over
	if s.w >= len(s.data) {
		s.data = append(s.data, nil)
	}
	s.data[s.w] = b
	s.w++
	if s.w >= maxDatagramBufferLen {
		s.w = 0
	}
	if s.w == s.r {
		// Slow read
		s.data[s.r] = nil
		s.r++
		if s.r >= maxDatagramBufferLen {
			s.r = 0
		}
	}
}

func (s *datagramBuffer) pop() []byte {
	if s.r >= len(s.data) || s.data[s.r] == nil {
		return nil
	}
	b := s.data[s.r]
	s.data[s.r] = nil
	s.r++
	if s.r >= maxDatagramBufferLen {
		s.r = 0
	}
	return b
}

func (s *datagramBuffer) avail() int {
	if s.r < len(s.data) {
		return len(s.data[s.r])
	}
	return 0
}

func (s *datagramBuffer) String() string {
	return fmt.Sprintf("length=%d read=%d write=%d", len(s.data), s.r, s.w)
}
