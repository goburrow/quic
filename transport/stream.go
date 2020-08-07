package transport

import (
	"fmt"
	"io"
)

// Stream is a data stream.
// https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#name-streams
type Stream struct {
	recv recvStream
	send sendStream

	// Stream flow control is based on absolute data offset.
	// In comparision, connection-level flow control manages volume of data instead.
	flow flowControl
	// Linked to connection-level flow control. Does not apply for crypto stream.
	connFlow *flowControl
	// Whether this stream needs to send MAX_STREAM_DATA
	updateMaxData bool

	local bool
	bidi  bool
}

func (s *Stream) init(local, bidi bool) {
	s.local = local
	s.bidi = bidi
}

// pushRecv checks for maximum data can be received and pushes data to recv stream.
func (s *Stream) pushRecv(data []byte, offset uint64, fin bool) error {
	if offset+uint64(len(data)) > s.flow.maxRecv {
		return errFlowControl
	}
	err := s.recv.push(data, offset, fin)
	if err == nil {
		// Keep flow received bytes in sync with maximum absolute offset of the stream.
		s.flow.setRecv(s.recv.length)
	}
	return err
}

// Read reads data from recv stream.
func (s *Stream) Read(b []byte) (int, error) {
	n, err := s.recv.Read(b)
	if n > 0 {
		// A receiver could use the current offset of data consumed to determine the
		// flow control offset to be advertised.
		s.flow.addMaxRecvNext(uint64(n))
		if s.connFlow != nil {
			s.connFlow.addMaxRecvNext(uint64(n))
		}
		// Only tell peer to update max data when the stream is consumed.
		if !s.recv.fin && s.flow.shouldUpdateMaxRecv() {
			s.updateMaxData = true
		}
	}
	return n, err
}

// Write writes data to send stream.
func (s *Stream) Write(b []byte) (int, error) {
	if !s.bidi && !s.local {
		return 0, newError(StreamStateError, "cannot write to uni stream")
	}
	n := int(s.flow.canSend())
	if n == 0 {
		return 0, nil
	}
	if n < len(b) {
		b = b[:n]
	}
	n, err := s.send.Write(b)
	if err == nil {
		// Keep flow sent bytes in sync with read offset of the stream
		s.flow.setSend(s.send.length)
	}
	return n, err
}

// WriteString writes the contents of string b to the stream.
func (s *Stream) WriteString(b string) (int, error) {
	// b will be copied so hopefully complier does not allocate memory for byte conversion
	return s.Write([]byte(b))
}

// isReadable returns true if the stream has any data to read.
func (s *Stream) isReadable() bool {
	return s.recv.ready() || (s.recv.fin && !s.recv.finRead)
}

// isWriteable returns true if the stream has enough flow control capacity to be written to,
// and is not finished.
func (s *Stream) isWriteable() bool {
	return !s.send.fin && s.flow.canSend() > 0
}

// isFlushable returns true if the stream has data to send
func (s *Stream) isFlushable() bool {
	// flow maxSend is controlled by peer via MAX_STREAM_DATA
	return s.send.ready(s.flow.maxSend) || (s.send.fin && !s.send.finSent)
}

// popSend returns continuous data from send buffer that size less than max bytes.
// max is calculated by availability of packet buffer and flow control at connection level.
func (s *Stream) popSend(max int) (data []byte, offset uint64, fin bool) {
	if !s.isFlushable() {
		return nil, 0, false
	}
	return s.send.pop(max)
}

// pushSend pushes data back to send stream to resend.
func (s *Stream) pushSend(data []byte, offset uint64, fin bool) error {
	return s.send.push(data, offset, fin)
}

// ackSend acknowleges data is received.
// It returns true if all data has been sent and confirmed.
func (s *Stream) ackSend(offset, length uint64) bool {
	s.send.ack(offset, length)
	return s.send.complete()
}

func (s *Stream) resetRecv(finalSize uint64) (int, error) {
	return s.recv.reset(finalSize)
}

// ackMaxData acknowledges that the MAX_STREAM_DATA frame delivery is confirmed.
func (s *Stream) ackMaxData() {
	s.updateMaxData = false
}

// Close sets end of the sending stream.
func (s *Stream) Close() error {
	if !s.bidi && !s.local {
		return newError(StreamStateError, "cannot close uni stream")
	}
	s.send.fin = true
	return nil
}

func (s *Stream) String() string {
	return fmt.Sprintf("recv{%s} send{%s}", &s.recv, &s.send)
}

// recvStream is buffer for receiving data.
type recvStream struct {
	buf rangeBufferList // Chunks of received data, ordered by offset

	offset uint64 // read offset
	length uint64 // total length

	fin     bool
	finRead bool // Whether reader is notified about closing
}

func (s *recvStream) push(data []byte, offset uint64, fin bool) error {
	end := offset + uint64(len(data))
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
	n := int(finalSize - s.length)
	s.fin = true
	s.length = finalSize
	return n, nil
}

// Read makes recvStream an io.Reader.
func (s *recvStream) Read(b []byte) (int, error) {
	if s.isFin() {
		s.finRead = true
		return 0, io.EOF
	}
	n := s.buf.read(b, s.offset)
	s.offset += uint64(n)
	return n, nil
}

// ready returns true if data is available at the current read offset.
func (s *recvStream) ready() bool {
	return s.offset < s.length && len(s.buf) > 0 && s.buf[0].offset == s.offset
}

func (s *recvStream) isFin() bool {
	return s.fin && s.offset >= s.length
}

func (s *recvStream) String() string {
	return fmt.Sprintf("offset=%v length=%v fin=%v", s.offset, s.length, s.fin)
}

// sendStream is buffer for sending data.
type sendStream struct {
	buf   rangeBufferList // Chunks of data to be sent, ordered by offset
	acked rangeSet        // receive confirmed

	offset uint64 // read offset
	length uint64 // total length

	fin     bool
	finSent bool // finSent is needed when sender closes the stream after data has already been read.
}

// push would only be called directly when it needs to bypass flow control.
// e.g. pushing data back to the stream to resend.
func (s *sendStream) push(data []byte, offset uint64, fin bool) error {
	end := offset + uint64(len(data))
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

// pop returns continuous data in buffer with smallest offset up to max bytes in length.
// pop would be called after checking ready().
func (s *sendStream) pop(max int) (data []byte, offset uint64, fin bool) {
	data, offset = s.buf.pop(max)
	if len(data) == 0 {
		// Use current read offset when there is no data available.
		offset = s.offset
	}
	end := offset + uint64(len(data))
	fin = s.fin && end >= s.length
	if fin {
		s.finSent = true
	}
	if end > s.offset {
		s.offset = end
	}
	return
}

// ready returns true is the stream has any data with offset less than maxOffset.
func (s *sendStream) ready(maxOffset uint64) bool {
	return len(s.buf) > 0 && s.buf[0].offset < maxOffset
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
	return fmt.Sprintf("offset=%v length=%v fin=%v", s.offset, s.length, s.fin)
}

// ack acknowledges stream data received.
func (s *sendStream) ack(offset, length uint64) {
	s.acked.push(offset, offset+length)
}

// complete returns true if all data in the stream has been sent.
func (s *sendStream) complete() bool {
	return s.fin && s.offset >= s.length && s.acked.equals(0, s.length)
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

// create adds and returns new stream or error if it exceeds limits.
func (s *streamMap) create(id uint64, local, bidi bool) (*Stream, error) {
	if local {
		if bidi {
			if s.openedStreams.localBidi >= s.maxStreams.peerBidi {
				return nil, newError(StreamLimitError, sprint("local bidi streams exceeded ", s.maxStreams.peerBidi))
			}
			s.openedStreams.localBidi++
		} else {
			if s.openedStreams.localUni >= s.maxStreams.peerUni {
				return nil, newError(StreamLimitError, sprint("local uni streams exceeded ", s.maxStreams.peerUni))
			}
			s.openedStreams.localUni++
		}
	} else {
		if bidi {
			if s.openedStreams.peerBidi >= s.maxStreams.localBidi {
				return nil, newError(StreamLimitError, sprint("remote bidi streams exceeded ", s.maxStreams.localBidi))
			}
			s.openedStreams.peerBidi++
		} else {
			if s.openedStreams.peerUni >= s.maxStreams.localUni {
				return nil, newError(StreamLimitError, sprint("remote uni streams exceeded ", s.maxStreams.localUni))
			}
			s.openedStreams.peerUni++
		}
	}
	st := &Stream{}
	st.init(local, bidi)
	s.streams[id] = st
	return st, nil
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

func (s *streamMap) hasFlushable() bool {
	for _, st := range s.streams {
		if st.isFlushable() {
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
