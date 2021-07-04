package transport

import (
	"fmt"
	"io"
)

const (
	maxStreams = 1 << 60
	// Minimum remaining data in sending buffer that application is notified writable stream.
	minStreamBufferWritable = 8 << 10
	maxStreamBuffer         = 128 << 10
)

type deliveryState uint8

const (
	deliveryNone deliveryState = iota
	deliveryReady
	deliverySending
	deliveryConfirmed
)

// Stream is a data stream.
// https://www.rfc-editor.org/rfc/rfc9000#section-2
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
	if !bidi {
		if local {
			s.recv.setClosed() // Send only
		} else {
			s.send.setClosed() // Receive only
		}
	}
}

// pushRecv checks for maximum data can be received and pushes data to recv stream.
func (s *Stream) pushRecv(data []byte, offset uint64, fin bool) error {
	if offset+uint64(len(data)) > s.flow.recvMax {
		return newError(FlowControlError, sprint("stream: data exceeded limit ", s.flow.recvMax))
	}
	err := s.recv.push(data, offset, fin)
	if err == nil {
		// Keep flow received bytes in sync with maximum absolute offset of the stream.
		s.flow.setRecv(s.recv.length)
	}
	return err
}

// Read reads data from recv stream.
// Reading from a send-only or closed stream will result in error io.EOF.
func (s *Stream) Read(b []byte) (int, error) {
	if s.recv.closed {
		return 0, io.EOF
	}
	n, err := s.recv.Read(b)
	if n > 0 {
		// A receiver could use the current offset of data consumed to determine the
		// flow control offset to be advertised.
		s.flow.addRecvMaxNext(uint64(n))
		if s.connFlow != nil {
			s.connFlow.addRecvMaxNext(uint64(n))
		}
		// Only tell peer to update max data when the stream is consumed.
		if !s.recv.fin && s.flow.shouldUpdateRecvMax() {
			s.updateMaxData = true
		}
	}
	// Override error from buffer read (only io.EOF) when receiving part is terminated.
	if s.recv.resetReceived {
		s.recv.setClosed() // Reset error has been read by application
		return n, newAppError(s.recv.stopError, "reset_stream")
	}
	return n, err
}

// Write writes data to send stream.
// Writing to a read-only or closed stream will result in error io.EOF.
func (s *Stream) Write(b []byte) (int, error) {
	if s.send.closed {
		return 0, io.EOF
	}
	if s.send.stopReceived {
		s.send.setClosed() // Stop error has been read by application
		return 0, newAppError(s.send.resetError, "stop_sending")
	}
	if s.send.buf.size() > maxStreamBuffer {
		return 0, nil
	}
	n := int(s.flow.availSend())
	if n <= 0 {
		return 0, nil
	}
	if n < len(b) {
		b = b[:n]
	}
	n, err := s.send.Write(b)
	if n > 0 {
		// Keep flow sent bytes in sync with read offset of the stream
		s.flow.setSend(s.send.length)
		if s.isSendBlocked() {
			s.flow.setSendBlocked(true)
		}
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
	if s.recv.closed {
		return false
	}
	if s.recv.resetReceived {
		return true
	}
	return (s.recv.ready() || s.recv.fin) && s.recv.stopSending == deliveryNone
}

// updateStopSending returns application error code for terminating receiving part of the stream,
// if it is available and has not been sent. This error code is used in STOP_SENDING frame.
func (s *Stream) updateStopSending() (uint64, bool) {
	if s.recv.stopSending == deliveryReady {
		return s.recv.stopError, true
	}
	return 0, false
}

// setStopSending sets or resets whether the receiving stop error has been sent.
func (s *Stream) setStopSending(state deliveryState) {
	s.recv.stopSending = state
	if state == deliveryConfirmed && !s.recv.resetReceived {
		// Peer has acknowledged STOP_SENDING, we can now close the stream.
		s.recv.setClosed()
	}
}

// resetRecv handles RESET_STREAM frame.
func (s *Stream) resetRecv(finalSize, errorCode uint64) error {
	return s.recv.reset(finalSize, errorCode)
}

// isWritable returns true if the stream has enough flow control capacity to be written to,
// and is not finished.
func (s *Stream) isWritable() bool {
	if s.send.closed {
		return false
	}
	if s.send.stopReceived {
		return true
	}
	// XXX: To avoid over buffer, we only tell application to fill the send buffer
	// when there is only some data left (8KB) to send.
	return s.flow.availSend() > 0 && s.send.buf.size() < minStreamBufferWritable &&
		!s.send.fin && s.send.resetStream == deliveryNone
}

// isFlushable returns true if the stream has data and is allowed to send.
func (s *Stream) isFlushable() bool {
	if s.send.closed || s.send.stopReceived {
		return false
	}
	// flow maxSend is controlled by peer via MAX_STREAM_DATA.
	return s.send.ready(s.flow.sendMax) || (s.send.fin && !s.send.finSent)
}

func (s *Stream) isSendBlocked() bool {
	if s.send.closed || s.send.stopReceived || s.send.fin || s.send.resetStream != deliveryNone {
		return false
	}
	return s.flow.availSend() == 0
}

// popSend returns continuous data from send buffer that size less than max bytes.
// max is calculated by availability of packet buffer and flow control at connection level.
func (s *Stream) popSend(max int) (data []byte, offset uint64, fin bool) {
	if s.isFlushable() {
		return s.send.pop(max)
	}
	return nil, 0, false
}

// pushSend pushes data back to send stream to resend.
func (s *Stream) pushSend(data []byte, offset uint64, fin bool) error {
	if s.send.stopReceived || s.send.resetStream != deliveryNone {
		// Do not resend stream data when received STOP_SENDING or sending RESET_STREAM
		return nil
	}
	return s.send.push(data, offset, fin)
}

// ackSend acknowledges that the data sent by stream has been received.
// It returns true if all data has been sent and confirmed.
func (s *Stream) ackSend(offset, length uint64) bool {
	return s.send.ack(offset, length)
}

// setUpdateMaxData sets whether the MAX_STREAM_DATA should be sent.
func (s *Stream) setUpdateMaxData(update bool) {
	s.updateMaxData = update
}

// updateResetStream returns application error code for terminating sending part of the stream,
// if it is available and has not been sent. This error code is used in RESET_STREAM frame.
func (s *Stream) updateResetStream() (uint64, bool) {
	// Try to send all pending data first if RESET_STREAM is initiated by local.
	if s.send.resetStream == deliveryReady && (s.send.stopReceived || s.send.buf.isEmpty()) {
		return s.send.resetError, true
	}
	return 0, false
}

// setSendErrorSent sets or resets whether the sending reset error has been sent.
func (s *Stream) setResetStream(state deliveryState) {
	s.send.resetStream = state
	if state == deliveryConfirmed && !s.send.stopReceived {
		// Peer has acknowledged RESET_STREAM, we can now close the stream.
		s.send.setClosed()
	}
}

// stopSend handles peer's STOP_SENDING frame sending to this stream.
func (s *Stream) stopSend(errorCode uint64) {
	s.send.stop(errorCode)
	if s.flow.sendBlocked {
		s.flow.setSendBlocked(false)
	}
}

// isClosed returns true if both receiving and sending are closed and the stream is no longer needed.
func (s *Stream) isClosed() bool {
	return s.recv.closed && s.send.closed
}

// CloseWrite abruptly terminates the sending part of a stream.
// Closing a receive-only stream will result in error stream_state_error.
func (s *Stream) CloseWrite(errorCode uint64) error {
	if !s.bidi && !s.local {
		return newError(StreamStateError, "cannot close writing of receive-only stream")
	}
	// Results in sending RESET_STREAM frame.
	s.send.terminate(errorCode)
	return nil
}

// CloseRead aborts the reading part of the stream and requests closure.
// Closing a send-only stream will result in error stream_state_error.
func (s *Stream) CloseRead(errorCode uint64) error {
	if !s.bidi && s.local {
		return newError(StreamStateError, "cannot close reading of send-only stream")
	}
	// Results in sending STOP_SENDING frame.
	s.recv.terminate(errorCode)
	return nil
}

// Close ends the sending part of the stream (clean termination) if it is a bidirectional stream
// or locally created.
// Closing a receive-only stream is no-op.
func (s *Stream) Close() error {
	// The stream will no longer send data.
	if s.bidi || s.local {
		s.send.fin = true
		if s.flow.sendBlocked {
			s.flow.setSendBlocked(false)
		}
	}
	return nil
}

// String returns state of the stream.
func (s *Stream) String() string {
	return fmt.Sprintf("recv(%s) send(%s)", &s.recv, &s.send)
}

// recvStream is buffer for receiving data.
type recvStream struct {
	buf rangeBufferList // Chunks of received data, ordered by offset

	offset uint64 // read offset
	length uint64 // total length

	stopError     uint64        // Error code for sending STOP_SENDING.
	stopSending   deliveryState // Whether the stream needs to send STOP_SENDING.
	resetReceived bool          // Received peer's RESET_STREAM.

	// fin is true when received a fin flag
	fin bool
	// closed is true when receiving part of the stream either:
	// 1. Fully read by application (got io.EOF).
	// 2. Terminated by application (STOP_SENDING sent and confirmed by peer).
	// It is not when terminated by peer (RESET_STREAM received) because application might want
	// to read application error code and explicitly allow creating new stream.
	closed bool
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
	if end <= s.offset {
		// Data has been read
		return nil
	}
	if offset < s.offset {
		// Overlap old and new data
		data = data[s.offset-offset:]
		offset = s.offset
	}
	// buf will create a copy of data.
	s.buf.write(data, offset)
	if end > s.length {
		s.length = end
	}
	return nil
}

// Read makes recvStream an io.Reader.
func (s *recvStream) Read(b []byte) (int, error) {
	n := s.buf.read(b, s.offset)
	s.offset += uint64(n)
	if s.fin && s.offset >= s.length {
		s.setClosed() // Data is fully read by application
		return n, io.EOF
	}
	return n, nil
}

// ready returns true if data is available at the current read offset.
func (s *recvStream) ready() bool {
	if s.offset < s.length {
		r := s.buf.first()
		return r != nil && r.offset == s.offset
	}
	return false
}

// reset handles receiving RESET_STREAM frame.
func (s *recvStream) reset(finalSize, errorCode uint64) error {
	if !s.resetReceived {
		if (s.fin && finalSize != s.length) || finalSize < s.length {
			return errFinalSize
		}
		s.resetReceived = true
		s.fin = true
		s.length = finalSize
		if s.stopSending == deliveryNone {
			// Set error code and delivery status to no longer send STOP_SENDING frame.
			s.stopError = errorCode
			s.stopSending = deliveryConfirmed
		}
	}
	return nil
}

// terminate is called by application to terminate receiving.
// A STOP_SENDING frame will be sent if the stream has not been reset by peer.
func (s *recvStream) terminate(errorCode uint64) {
	if s.stopSending == deliveryNone && !s.resetReceived {
		s.stopError = errorCode
		s.stopSending = deliveryReady
	}
}

func (s *recvStream) setClosed() {
	s.closed = true
}

func (s *recvStream) String() string {
	return fmt.Sprintf("offset=%v length=%v fin=%v size=%v %v", s.offset, s.length, s.fin, s.buf.size(), &s.buf)
}

// sendStream is buffer for sending data.
type sendStream struct {
	buf   rangeBufferList // Chunks of data to be sent, ordered by offset
	acked rangeSet        // receive confirmed

	offset uint64 // read offset
	length uint64 // total length

	resetError   uint64        // Error code for sending RESET_STREAM.
	resetStream  deliveryState // Whether the stream needs to sent RESET_STREAM.
	stopReceived bool          // Received peer's STOP_SENDING.

	fin     bool
	finSent bool // finSent is needed when sender closes the stream after data has already been read.
	// closed is true when sending part of the stream is either:
	// 1. Fully sent and confirmed by peer (ack received),
	// 2. Terminated by peer (STOP_SENDING received and the error is read by application),
	// 3. Terminated by application (RESET_STREAM is sent and confirmed).
	closed bool
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
		s.finSent = false // For resending fin flag when lost
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
	r := s.buf.first()
	return r != nil && r.offset < maxOffset
}

// Write append data to the stream.
func (s *sendStream) Write(b []byte) (int, error) {
	// Split data when putting it to buffers to reduce overhead when sending data segments.
	maxSize := dataBufferSizes[2] // 4KB
	n := len(b)
	for len(b) > maxSize {
		err := s.push(b[:maxSize], s.length, false)
		if err != nil {
			return 0, err
		}
		b = b[maxSize:]
	}
	err := s.push(b, s.length, false)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// ack acknowledges stream data received.
// It returns true when all data are acknowledged.
func (s *sendStream) ack(offset, length uint64) bool {
	s.acked.push(offset, offset+length)
	complete := s.complete()
	if complete && s.resetStream == deliveryNone && !s.stopReceived {
		// Stream is complete and can be closed
		s.setClosed()
	}
	return complete
}

// complete returns true if all data in the stream has been sent and acknowledged.
func (s *sendStream) complete() bool {
	return s.fin && s.finSent && s.offset >= s.length && s.acked.equals(0, s.length)
}

// stop handles STOP_SENDING frame sent by peer.
// It indicates that the peer no longer reads the data sent by this stream.
func (s *sendStream) stop(errorCode uint64) {
	if !s.stopReceived {
		s.stopReceived = true
		// An endpoint that receives a STOP_SENDING frame MUST send a RESET_STREAM frame
		// if the stream is in the Ready or Send state.
		// An endpoint should copy the error code from the STOP_SENDING frame to the
		// RESET_STREAM frame it sends.
		if s.resetStream == deliveryNone {
			s.resetError = errorCode
			if s.fin {
				s.resetStream = deliveryConfirmed
			} else {
				s.resetStream = deliveryReady
			}
		}
	}
}

// terminate is called by application to terminate sending.
// A RESET_STREAM will be sent if the stream has not been stopped by peer.
func (s *sendStream) terminate(errorCode uint64) {
	if s.resetStream == deliveryNone {
		s.fin = true
		if !s.stopReceived {
			s.resetError = errorCode
			s.resetStream = deliveryReady
		}
	}
}

func (s *sendStream) setClosed() {
	s.closed = true
}

func (s *sendStream) String() string {
	return fmt.Sprintf("offset=%v length=%v fin=%v size=%v %v", s.offset, s.length, s.fin, s.buf.size(), &s.buf)
}

/// streamMap keeps track of QUIC streams and enforces stream limits.
type streamMap struct {
	// Streams indexed by stream ID
	streams map[uint64]*Stream
	// closedStreams is a set of stream IDs that are fully closed.
	closedStreams map[uint64]struct{}
	// closedStream is the shared stream object returned for all closed streams.
	closedStream Stream

	// Total streams opened by peer and local.
	openedStreams struct {
		peerBidi  uint64
		peerUni   uint64
		localBidi uint64
		localUni  uint64
	}
	// Maximum stream count allowed by peer and local.
	maxStreams struct {
		peerBidi  uint64
		peerUni   uint64
		localBidi uint64
		localUni  uint64
	}
	// Maximum streams to send MAX_STREAMS update.
	maxStreamsNext struct {
		localBidi uint64
		localUni  uint64
	}

	updateMaxStreamsBidi bool
	updateMaxStreamsUni  bool
}

func (s *streamMap) init(maxBidi, maxUni uint64) {
	s.streams = make(map[uint64]*Stream)
	s.closedStreams = make(map[uint64]struct{})
	s.maxStreams.localBidi = maxBidi
	s.maxStreams.localUni = maxUni
	s.maxStreamsNext.localBidi = maxBidi
	s.maxStreamsNext.localUni = maxUni
	s.closedStream = Stream{
		recv: recvStream{
			fin:           true,
			stopSending:   deliveryConfirmed,
			resetReceived: true,
			closed:        true,
		},
		send: sendStream{
			fin:          true,
			finSent:      true,
			resetStream:  deliveryConfirmed,
			stopReceived: true,
			closed:       true,
		},
		bidi: true,
	}
}

func (s *streamMap) get(id uint64) *Stream {
	if _, ok := s.closedStreams[id]; ok {
		return &s.closedStream
	}
	return s.streams[id]
}

// create adds and returns new stream or error if it exceeds limits.
// Only streams with a stream ID less than (max_stream * 4 + initial_stream_id_for_type)
// can be opened.
// https://www.rfc-editor.org/rfc/rfc9000#section-4.6
func (s *streamMap) create(id uint64, isClient bool) (*Stream, error) {
	local := isStreamLocal(id, isClient)
	bidi := isStreamBidi(id)
	if local {
		if bidi {
			if s.openedStreams.localBidi >= s.maxStreams.peerBidi || id > s.maxStreams.peerBidi*4 {
				return nil, newError(StreamLimitError, sprint("local bidirectional streams exceeded ", s.maxStreams.peerBidi))
			}
			s.openedStreams.localBidi++
		} else {
			if s.openedStreams.localUni >= s.maxStreams.peerUni || id > s.maxStreams.peerUni*4 {
				return nil, newError(StreamLimitError, sprint("local unidirectional streams exceeded ", s.maxStreams.peerUni))
			}
			s.openedStreams.localUni++
		}
	} else {
		if bidi {
			if s.openedStreams.peerBidi >= s.maxStreams.localBidi || id > s.maxStreams.localBidi*4 {
				return nil, newError(StreamLimitError, sprint("peer bidirectional streams exceeded ", s.maxStreams.localBidi))
			}
			s.openedStreams.peerBidi++
		} else {
			if s.openedStreams.peerUni >= s.maxStreams.localUni || id > s.maxStreams.localUni*4 {
				return nil, newError(StreamLimitError, sprint("peer unidirectional streams exceeded ", s.maxStreams.localUni))
			}
			s.openedStreams.peerUni++
		}
	}
	st := &Stream{}
	st.init(local, bidi)
	s.streams[id] = st
	return st, nil
}

// creatablePeerStreamBidi returns true if it can create a new local bidi stream.
func (s *streamMap) creatableLocalStreamBidi() bool {
	return s.openedStreams.localBidi < s.maxStreams.peerBidi
}

// creatablePeerStreamBidi returns true if it can create a new local uni stream.
func (s *streamMap) creatableLocalStreamUni() bool {
	return s.openedStreams.localUni < s.maxStreams.peerUni
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

func (s *streamMap) setUpdateMaxStreamsBidi(update bool) {
	s.updateMaxStreamsBidi = update
}

func (s *streamMap) setUpdateMaxStreamsUni(update bool) {
	s.updateMaxStreamsUni = update
}

func (s *streamMap) shouldUpdateMaxStreamsBidi() bool {
	return s.maxStreamsNext.localBidi != s.maxStreams.localBidi && s.maxStreams.localBidi >= s.openedStreams.peerBidi &&
		s.maxStreamsNext.localBidi/2 > s.maxStreams.localBidi-s.openedStreams.peerBidi
}

func (s *streamMap) shouldUpdateMaxStreamsUni() bool {
	return s.maxStreamsNext.localUni != s.maxStreams.localUni && s.maxStreams.localUni >= s.openedStreams.peerUni &&
		s.maxStreamsNext.localUni/2 > s.maxStreams.localUni-s.openedStreams.peerUni
}

func (s *streamMap) commitMaxStreamsBidi() {
	s.maxStreams.localBidi = s.maxStreamsNext.localBidi
}

func (s *streamMap) commitMaxStreamsUni() {
	s.maxStreams.localUni = s.maxStreamsNext.localUni
}

func (s *streamMap) hasUpdate() bool {
	if s.updateMaxStreamsBidi || s.updateMaxStreamsUni {
		return true
	}
	for _, st := range s.streams {
		if st.isFlushable() || st.updateMaxData ||
			st.flow.shouldUpdateRecvMax() || st.flow.sendBlocked {
			return true
		}
	}
	return false
}

func (s *streamMap) checkClosed(fn func(streamId uint64)) {
	for id, st := range s.streams {
		if st.isClosed() {
			// Give back max streams credit if the stream is created by peer.
			if !st.local {
				if st.bidi {
					s.maxStreamsNext.localBidi++
					if s.shouldUpdateMaxStreamsBidi() {
						s.updateMaxStreamsBidi = true
					}
				} else {
					s.maxStreamsNext.localUni++
					if s.shouldUpdateMaxStreamsUni() {
						s.updateMaxStreamsUni = true
					}
				}
			}
			delete(s.streams, id)
			s.closedStreams[id] = struct{}{}
			debug("stream closed %d", id)
			fn(id)
		}
	}
}

// https://www.rfc-editor.org/rfc/rfc9000#section-2.1
// Bits | Stream           | Type
// 0b00 | Client-Initiated | Bidirectional
// 0b01 | Server-Initiated | Bidirectional
// 0b10 | Client-Initiated | Unidirectional
// 0b11 | Server-Initiated | Unidirectional

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
