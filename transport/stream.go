package transport

import (
	"fmt"
	"io"
)

type Stream struct {
	recv recvStream
	send sendStream
}

func (s *Stream) init(maxRecv, maxSend uint64) {
	s.recv.setMaxData(maxRecv)
	s.send.setMaxData(maxSend)
}

func (s *Stream) reset() {
	maxRecv := s.recv.maxData
	maxSend := s.send.maxData
	s.recv = recvStream{
		maxData: maxRecv,
	}
	s.send = sendStream{
		maxData: maxSend,
	}
}

func (s *Stream) Read(b []byte) (int, error) {
	return s.recv.Read(b)
}

func (s *Stream) Write(b []byte) (int, error) {
	return s.send.Write(b)
}

func (s *Stream) Close() error {
	s.send.fin = true
	return nil
}

func (s *Stream) String() string {
	return fmt.Sprintf("recv{%s} send{%s}", &s.recv, &s.send)
}

type recvStream struct {
	buf rangeBufferList // Chunks of received data, ordered by offset

	maxData uint64 // maximum data can receive
	offset  uint64 // read offset
	length  uint64 // total length

	fin bool
}

// setMaxData updates maximum data can send. It's done by flow control.
func (s *recvStream) setMaxData(maxData uint64) {
	if maxData > s.maxData {
		s.maxData = maxData
	}
}

func (s *recvStream) push(data []byte, offset uint64, fin bool) error {
	end := offset + uint64(len(data))
	if end > s.maxData {
		return errFlowControl
	}
	if s.fin {
		// Stream's size is known, forbid new data or changing it.
		if end > s.length {
			return errFinalSize
		}
	}
	if fin {
		if end < s.length {
			// Stream's known size is lower than data already received.
			return errFinalSize
		}
		s.fin = true
	}
	if s.offset >= end {
		// Data has been read
		return nil
	}
	s.buf.write(data, offset)
	if end > s.length {
		s.length = end
	}
	return nil
}

// reset returns how many bytes need to be removed from the flow control.
func (s *recvStream) reset(finalSize uint64) (int, error) {
	if s.fin {
		if finalSize != s.length {
			return 0, errFinalSize
		}
	}
	if finalSize < s.length {
		return 0, errFinalSize
	}
	n := int(s.length - finalSize)
	s.fin = true
	s.length = finalSize
	return n, nil
}

// Read makes recvStream an io.Reader.
func (s *recvStream) Read(b []byte) (int, error) {
	if s.isFin() {
		return 0, io.EOF
	}
	n := s.buf.read(b, s.offset)
	s.offset += uint64(n)
	return n, nil
}

func (s *recvStream) isFin() bool {
	return s.fin && s.offset >= s.length
}

func (s *recvStream) String() string {
	return fmt.Sprintf("offset=%d length=%d max=%d", s.offset, s.length, s.maxData)
}

type sendStream struct {
	buf rangeBufferList // Chunks of data to be sent, ordered by offset

	maxData uint64 // maximum data allowed to send
	offset  uint64 // read offset
	length  uint64 // total length

	fin bool
}

// setMaxData updates maximum data can send. It's done by flow control.
func (s *sendStream) setMaxData(maxData uint64) {
	if maxData > s.maxData {
		s.maxData = maxData
	}
}

func (s *sendStream) push(data []byte, offset uint64, fin bool) error {
	end := offset + uint64(len(data))
	if end > s.maxData {
		return errFlowControl
	}
	if s.fin {
		// Stream's size is known, forbid new data or changing it.
		if end > s.length {
			return errFinalSize
		}
	}
	if fin {
		if end < s.length {
			// Stream's known size is lower than data already received.
			return errFinalSize
		}
		s.fin = true
	}
	s.buf.write(data, offset)
	if end > s.length {
		s.length = end
	}
	return nil
}

// pop would be called after checking ready().
func (s *sendStream) pop(max int) (data []byte, offset uint64, fin bool) {
	data, offset = s.buf.pop(max)
	end := offset + uint64(len(data))
	fin = s.fin && end >= s.length
	if end > s.offset {
		s.offset = end
	}
	return
}

// ready returns true is the stream has data to send and is allowed to send.
func (s *sendStream) ready() bool {
	return len(s.buf) > 0 && s.buf[0].offset < s.maxData
}

// Write append data to the stream.
func (s *sendStream) Write(b []byte) (int, error) {
	err := s.push(b, s.length, false)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (s *sendStream) String() string {
	return fmt.Sprintf("offset=%d length=%d max=%d", s.offset, s.length, s.maxData)
}

/// streamMap keeps track of QUIC streams and enforces stream limits.
type streamMap struct {
	// Streams indexed by stream ID
	streams map[uint64]*Stream

	openedStreams struct {
		peerBidi  uint64
		peerUni   uint64
		localBidi uint64
		localUni  uint64
	}

	// Maximum stream count limit
	maxStreams struct {
		peerBidi  uint64
		peerUni   uint64
		localBidi uint64
		localUni  uint64
	}
}

func (s *streamMap) init(maxBidi, maxUni uint64) {
	s.streams = make(map[uint64]*Stream)
	s.maxStreams.localBidi = maxBidi
	s.maxStreams.localUni = maxUni
}

func (s *streamMap) get(id uint64) *Stream {
	return s.streams[id]
}

// create adds and returns new stream or nil if it exceeds limits.
func (s *streamMap) create(id uint64, local, bidi bool) *Stream {
	if local {
		if bidi {
			if s.openedStreams.localBidi >= s.maxStreams.peerBidi {
				return nil
			}
			s.openedStreams.localBidi++
		} else {
			if s.openedStreams.localUni >= s.maxStreams.peerUni {
				return nil
			}
			s.openedStreams.localUni++
		}
	} else {
		if bidi {
			if s.openedStreams.peerBidi >= s.maxStreams.localBidi {
				return nil
			}
			s.openedStreams.peerBidi++
		} else {
			if s.openedStreams.peerUni >= s.maxStreams.localUni {
				return nil
			}
			s.openedStreams.peerUni++
		}
	}
	st := &Stream{}
	s.streams[id] = st
	return st
}

func (s *streamMap) setPeerMaxStreamsBidi(v uint64) {
	if v > s.maxStreams.peerBidi {
		s.maxStreams.peerBidi = v
	}
}

func (s *streamMap) setPeerMaxStreamsUni(v uint64) {
	if v > s.maxStreams.peerUni {
		s.maxStreams.peerUni = v
	}
}

func (s *streamMap) setLocalMaxStreamsBidi(v uint64) {
	if v > s.maxStreams.localBidi {
		s.maxStreams.localBidi = v
	}
}

func (s *streamMap) setLocalMaxStreamsUni(v uint64) {
	if v > s.maxStreams.localUni {
		s.maxStreams.localUni = v
	}
}

func (s *streamMap) hasFlusable() bool {
	for _, st := range s.streams {
		if st.send.ready() {
			return true
		}
	}
	return false
}

// https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#stream-id
// Client-initiated streams have even-numbered stream IDs (with the bit set to 0),
// and server-initiated streams have odd-numbered stream IDs (with the bit set to 1).
func isStreamLocal(id uint64, isClient bool) bool {
	return (id&0x1 == 0) == isClient
}

// The second least significant bit (0x2) of the stream ID distinguishes between
// bidirectional streams (with the bit set to 0) and unidirectional streams (with the bit set to 1).
func isStreamBidi(id uint64) bool {
	return id&0x2 == 0
}
