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

// Write makes a copy of the data and push to this datagram buffer for sending.
// The length of b must not exceed the maximum datagram size that peer can receive.
// This value is specified in the connection event EventDatagramWritable.
func (s *Datagram) Write(b []byte) (int, error) {
	if len(b) > s.maxSend {
		return 0, newError(ApplicationError, sprint("datagram: payload size exceeded limit ", s.maxSend))
	}
	s.send.write(b)
	return len(b), nil
}

// Read reads received datagrams.
// If the size of provided buffer is less than the datagram size, io.ErrShortBuffer will be returned.
// See MaxDatagramPayloadSize in Parameters for maximum datagram size this connect can receive.
func (s *Datagram) Read(b []byte) (int, error) {
	if s.recv.avail() > len(b) {
		return 0, io.ErrShortBuffer
	}
	n := s.recv.read(b)
	return n, nil
}

func (s *Datagram) pushRecv(b []byte) error {
	if len(b) > s.maxRecv {
		return newError(ProtocolViolation, sprint("datagram: payload size exceeded limit ", s.maxRecv))
	}
	s.recv.write(b)
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

	w int // Writing index, data at w is always nil.
	r int // Reading index, data at r is nil if there is nothing to read.
}

func (s *datagramBuffer) write(b []byte) {
	if len(s.data) == 0 {
		s.data = make([][]byte, maxDatagramBufferLen)
	}
	data := newDataBuffer(len(b))
	copy(data, b)
	s.data[s.w] = data
	s.w++
	if s.w >= len(s.data) {
		s.w = 0
	}
	if s.w == s.r {
		// Slow read
		if s.data[s.r] != nil {
			freeDataBuffer(s.data[s.r])
			s.data[s.r] = nil
		}
		s.r++
		if s.r >= len(s.data) {
			s.r = 0
		}
	}
}

func (s *datagramBuffer) read(b []byte) int {
	data := s.pop()
	if data == nil {
		return 0
	}
	n := copy(b, data)
	freeDataBuffer(data)
	return n
}

func (s *datagramBuffer) pop() []byte {
	if s.r >= len(s.data) || s.data[s.r] == nil {
		return nil
	}
	b := s.data[s.r]
	s.data[s.r] = nil
	s.r++
	if s.r >= len(s.data) {
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
	n := s.w - s.r
	if n < 0 {
		n += len(s.data)
	}
	return fmt.Sprintf("length=%d write=%d read=%d", n, s.w, s.r)
}
