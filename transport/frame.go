package transport

import "fmt"

const (
	frameTypePadding     = 0x00
	frameTypePing        = 0x01
	frameTypeAck         = 0x02
	frameTypeAckECN      = 0x03
	frameTypeResetStream = 0x04
	frameTypeStopSending = 0x05
	frameTypeCrypto      = 0x06
	frameTypeNewToken    = 0x07
	frameTypeStream      = 0x08
	frameTypeStreamEnd   = 0x0f

	frameTypeMaxData            = 0x10
	frameTypeMaxStreamData      = 0x11
	frameTypeMaxStreamsBidi     = 0x12
	frameTypeMaxStreamsUni      = 0x13
	frameTypeDataBlocked        = 0x14
	frameTypeStreamDataBlocked  = 0x15
	frameTypeStreamsBlockedBidi = 0x16
	frameTypeStreamsBlockedUni  = 0x17

	frameTypeNewConnectionID    = 0x18
	frameTypeRetireConnectionID = 0x19
	frameTypePathChallenge      = 0x1a
	frameTypePathResponse       = 0x1b

	frameTypeConnectionClose  = 0x1c
	frameTypeApplicationClose = 0x1d
	frameTypeHanshakeDone     = 0x1e

	frameTypeDatagram           = 0x30
	frameTypeDatagramWithLength = 0x31
)

const (
	maxCryptoFrameOverhead   = 9  // type + offset + length
	maxStreamFrameOverhead   = 13 // type + id + offset + length
	maxDatagramFrameOverhead = 5  // type + length
	maxAckRanges             = 1024
)

// https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4
type frame interface {
	encodedLen() int
	encoder
	decoder
}

// The PADDING frame (type=0x00) has no semantic value.
type paddingFrame int

func newPaddingFrame(n int) *paddingFrame {
	f := paddingFrame(n)
	return &f
}

func (s *paddingFrame) encodedLen() int {
	return int(*s)
}

func (s *paddingFrame) encode(b []byte) (int, error) {
	n := int(*s)
	if len(b) < n {
		return 0, errShortBuffer
	}
	for i := 0; i < n; i++ {
		b[i] = 0
	}
	return n, nil
}

func (s *paddingFrame) decode(b []byte) (int, error) {
	n := 1
	if len(b) > 0 {
		var typ uint64
		n = getVarint(b, &typ)
		for _, v := range b[n:] {
			if v == 0 {
				n++
			} else {
				break
			}
		}
	}
	*s = paddingFrame(n)
	return n, nil
}

func (s *paddingFrame) String() string {
	return fmt.Sprintf("padding{length=%d}", *s)
}

type pingFrame struct{}

func (s *pingFrame) encodedLen() int {
	return 1
}

func (s *pingFrame) encode(b []byte) (int, error) {
	if len(b) < 1 {
		return 0, errShortBuffer
	}
	b[0] = frameTypePing
	return 1, nil
}

func (s *pingFrame) decode(b []byte) (int, error) {
	n := 1
	if len(b) > 0 {
		var typ uint64
		n = getVarint(b, &typ)
	}
	return n, nil
}

func (s *pingFrame) String() string {
	return "ping{}"
}

// https://www.rfc-editor.org/rfc/rfc9000.html#section-19.6
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                          Offset (i)                         ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                          Length (i)                         ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Crypto Data (*)                      ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type cryptoFrame struct {
	offset uint64
	data   []byte
}

func newCryptoFrame(data []byte, offset uint64) *cryptoFrame {
	return &cryptoFrame{
		data:   data,
		offset: offset,
	}
}

func (s *cryptoFrame) encodedLen() int {
	return 1 +
		varintLen(s.offset) +
		varintLen(uint64(len(s.data))) +
		len(s.data)
}

func (s *cryptoFrame) encode(b []byte) (int, error) {
	enc := newCodec(b)
	ok := enc.writeVarint(frameTypeCrypto) &&
		enc.writeVarint(s.offset) &&
		enc.writeVarint(uint64(len(s.data))) &&
		enc.write(s.data)
	if !ok {
		return 0, errShortBuffer
	}
	return enc.offset(), nil
}

func (s *cryptoFrame) decode(b []byte) (int, error) {
	dec := newCodec(b)
	var typ uint64
	var length uint64
	ok := dec.readVarint(&typ) && // skip frame type
		dec.readVarint(&s.offset) &&
		dec.readVarint(&length) &&
		dec.read(&s.data, int(length))
	if !ok {
		return 0, newError(FrameEncodingError, "crypto")
	}
	return dec.offset(), nil
}

func (s *cryptoFrame) String() string {
	return fmt.Sprintf("crypto{offset=%d length=%d}", s.offset, len(s.data))
}

type ackRange struct {
	gap      uint64
	ackRange uint64
}

// Receivers send ACK frames (types 0x02 and 0x03) to inform senders of packets
// they have received and processed.
// https://www.rfc-editor.org/rfc/rfc9000.html#section-19.3
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Largest Acknowledged (i)                ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                          ACK Delay (i)                      ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       ACK Range Count (i)                   ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       First ACK Range (i)                   ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                          ACK Ranges (*)                     ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                          [ECN Counts]                       ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type ackFrame struct {
	largestAck    uint64 // Largest packet number acknowledging
	ackDelay      uint64 // Time in microseconds since when the largest acknowledged packet
	firstAckRange uint64 // Number of contiguous packets preceding the largest acknowledged
	ackRanges     []ackRange
	ecnCounts     *ecnCounts
}

type ecnCounts struct {
	ect0Count uint64
	ect1Count uint64
	ceCount   uint64
}

func newAckFrame(ackDelay uint64, r rangeSet) *ackFrame {
	f := &ackFrame{
		ackDelay: ackDelay,
	}
	f.fromRangeSet(r)
	return f
}

func (s *ackFrame) encodedLen() int {
	n := 1 + // type
		varintLen(s.largestAck) +
		varintLen(s.ackDelay) +
		varintLen(uint64(len(s.ackRanges))) +
		varintLen(s.firstAckRange)
	for _, r := range s.ackRanges {
		n += varintLen(r.gap) + varintLen(r.ackRange)
	}
	if s.ecnCounts != nil {
		n += varintLen(s.ecnCounts.ect0Count) + varintLen(s.ecnCounts.ect1Count) + varintLen(s.ecnCounts.ceCount)
	}
	return n
}

func (s *ackFrame) encode(b []byte) (int, error) {
	enc := newCodec(b)
	var typ uint64
	if s.ecnCounts == nil {
		typ = frameTypeAck
	} else {
		typ = frameTypeAckECN
	}
	ok := enc.writeVarint(typ) &&
		enc.writeVarint(s.largestAck) &&
		enc.writeVarint(s.ackDelay) &&
		enc.writeVarint(uint64(len(s.ackRanges))) &&
		enc.writeVarint(s.firstAckRange)
	if !ok {
		return 0, errShortBuffer
	}
	for _, r := range s.ackRanges {
		ok = enc.writeVarint(r.gap) && enc.writeVarint(r.ackRange)
		if !ok {
			return 0, errShortBuffer
		}
	}
	if s.ecnCounts != nil {
		ok = enc.writeVarint(s.ecnCounts.ect0Count) &&
			enc.writeVarint(s.ecnCounts.ect1Count) &&
			enc.writeVarint(s.ecnCounts.ceCount)
		if !ok {
			return 0, errShortBuffer
		}
	}
	return enc.offset(), nil
}

func (s *ackFrame) decode(b []byte) (int, error) {
	dec := newCodec(b)
	var typ uint64
	var rangeCount uint64
	ok := dec.readVarint(&typ) &&
		dec.readVarint(&s.largestAck) &&
		dec.readVarint(&s.ackDelay) &&
		dec.readVarint(&rangeCount) &&
		dec.readVarint(&s.firstAckRange)
	if !ok || rangeCount > maxAckRanges {
		return 0, newError(FrameEncodingError, "ack")
	}
	if rangeCount > 0 {
		s.ackRanges = make([]ackRange, int(rangeCount))
		for i := range s.ackRanges {
			r := &s.ackRanges[i]
			ok = dec.readVarint(&r.gap) && dec.readVarint(&r.ackRange)
			if !ok {
				return 0, newError(FrameEncodingError, "ack")
			}
		}
	} else {
		s.ackRanges = nil
	}
	if typ == frameTypeAckECN {
		counts := ecnCounts{}
		ok := dec.readVarint(&counts.ect0Count) &&
			dec.readVarint(&counts.ect1Count) &&
			dec.readVarint(&counts.ceCount)
		if !ok {
			return 0, newError(FrameEncodingError, "ack")
		}
		s.ecnCounts = &counts
	} else {
		s.ecnCounts = nil
	}
	return dec.offset(), nil
}

// toRangeSet converts ackRanges into ranges of acked packets
// [end, start] in descending order.
// https://www.rfc-editor.org/rfc/rfc9000.html#section-19.3.1
// Examples:
// 0 1 2 3 4 5 6 7 8 9
// o x x x o o x o o x
//               | `- largestAck = 8
//         ---   `- firstAckRange = 1
//          |  `- gap1 = 0 (1 lower than the previous smallest)
//   -----  `- ackRange1 = 1
// |   `- gap2 = 2
// `- ackRange2 = 0
func (s *ackFrame) toRangeSet() rangeSet {
	if s.largestAck < s.firstAckRange {
		return nil
	}
	n := len(s.ackRanges)
	ranges := make(rangeSet, n+1)
	smallest := s.largestAck - s.firstAckRange
	ranges[n] = numberRange{start: smallest, end: s.largestAck}
	for i, r := range s.ackRanges {
		if smallest < r.gap+2 {
			return nil
		}
		smallest -= r.gap + 2
		if smallest < r.ackRange {
			return nil
		}
		ranges[n-i-1] = numberRange{start: smallest - r.ackRange, end: smallest}
		smallest -= r.ackRange
	}
	return ranges
}

func (s *ackFrame) fromRangeSet(ranges rangeSet) {
	n := len(ranges)
	if n == 0 {
		return
	}
	r := ranges[n-1]
	s.largestAck = r.end
	s.firstAckRange = r.end - r.start
	if n > 1 {
		s.ackRanges = make([]ackRange, n-1)
		smallest := r.start
		for i := n - 2; i >= 0; i-- {
			r = ranges[i]
			if smallest-1 <= r.end || r.start > r.end {
				panic("invalid range set: " + ranges.String())
			}
			s.ackRanges[n-i-2] = ackRange{
				gap:      smallest - r.end - 2,
				ackRange: r.end - r.start,
			}
			smallest = r.start
		}
	}
}

func (s *ackFrame) String() string {
	return fmt.Sprintf("ack{delay=%d largest=%d first=%d ranges=%d}", s.ackDelay, s.largestAck, s.firstAckRange, len(s.ackRanges))
}

// An endpoint uses a RESET_STREAM frame (type=0x04) to abruptly terminate
// the sending part of a stream.
// https://www.rfc-editor.org/rfc/rfc9000.html#section-19.4
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Stream ID (i)                        ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                  Application Error Code (i)                 ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Final Size (i)                       ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type resetStreamFrame struct {
	streamID  uint64
	errorCode uint64
	finalSize uint64
}

func newResetStreamFrame(id, code, size uint64) *resetStreamFrame {
	return &resetStreamFrame{
		streamID:  id,
		errorCode: code,
		finalSize: size,
	}
}

func (s *resetStreamFrame) encodedLen() int {
	return 1 + varintLen(s.streamID) +
		varintLen(s.errorCode) +
		varintLen(s.finalSize)
}

func (s *resetStreamFrame) encode(b []byte) (int, error) {
	enc := newCodec(b)
	ok := enc.writeVarint(frameTypeResetStream) &&
		enc.writeVarint(s.streamID) &&
		enc.writeVarint(s.errorCode) &&
		enc.writeVarint(s.finalSize)
	if !ok {
		return 0, errShortBuffer
	}
	return enc.offset(), nil
}

func (s *resetStreamFrame) decode(b []byte) (int, error) {
	dec := newCodec(b)
	var typ uint64
	ok := dec.readVarint(&typ) && // Skip type
		dec.readVarint(&s.streamID) &&
		dec.readVarint(&s.errorCode) &&
		dec.readVarint(&s.finalSize)
	if !ok {
		return 0, newError(FrameEncodingError, "reset_stream")
	}
	return dec.offset(), nil
}

func (s *resetStreamFrame) String() string {
	return fmt.Sprintf("resetStream{id=%d error=%d final=%d}", s.streamID, s.errorCode, s.finalSize)
}

type stopSendingFrame struct {
	streamID  uint64
	errorCode uint64
}

func newStopSendingFrame(id, code uint64) *stopSendingFrame {
	return &stopSendingFrame{
		streamID:  id,
		errorCode: code,
	}
}

func (s *stopSendingFrame) encodedLen() int {
	return 1 + varintLen(s.streamID) + varintLen(s.errorCode)
}

func (s *stopSendingFrame) encode(b []byte) (int, error) {
	enc := newCodec(b)
	ok := enc.writeVarint(frameTypeStopSending) &&
		enc.writeVarint(s.streamID) &&
		enc.writeVarint(s.errorCode)
	if !ok {
		return 0, errShortBuffer
	}
	return enc.offset(), nil
}

func (s *stopSendingFrame) decode(b []byte) (int, error) {
	dec := newCodec(b)
	var typ uint64
	ok := dec.readVarint(&typ) && // Skip type
		dec.readVarint(&s.streamID) &&
		dec.readVarint(&s.errorCode)
	if !ok {
		return 0, newError(FrameEncodingError, "stop_sending")
	}
	return dec.offset(), nil
}

func (s *stopSendingFrame) String() string {
	return fmt.Sprintf("stopSending{id=%d error=%d}", s.streamID, s.errorCode)
}

// https://www.rfc-editor.org/rfc/rfc9000.html#section-19.8
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Stream ID (i)                       ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         [Offset (i)]                        ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         [Length (i)]                        ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Stream Data (*)                      ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type streamFrame struct {
	streamID uint64
	offset   uint64
	data     []byte
	fin      bool
}

func newStreamFrame(id uint64, data []byte, offset uint64, fin bool) *streamFrame {
	return &streamFrame{
		streamID: id,
		data:     data,
		offset:   offset,
		fin:      fin,
	}
}

func (s *streamFrame) encodedLen() int {
	n := 1 + varintLen(s.streamID) +
		varintLen(uint64(len(s.data))) +
		len(s.data)
	if s.offset > 0 {
		n += varintLen(s.offset)
	}
	return n
}

func (s *streamFrame) encode(b []byte) (int, error) {
	typ := uint64(frameTypeStream)
	if s.fin {
		typ |= 0x01
	}
	// Always include length
	typ |= 0x02
	if s.offset > 0 {
		typ |= 0x04
	}
	enc := newCodec(b)
	ok := enc.writeVarint(typ) &&
		enc.writeVarint(s.streamID)
	if !ok {
		return 0, errShortBuffer
	}
	if s.offset > 0 && !enc.writeVarint(s.offset) {
		return 0, errShortBuffer
	}
	ok = enc.writeVarint(uint64(len(s.data))) && enc.write(s.data)
	if !ok {
		return 0, errShortBuffer
	}
	return enc.offset(), nil
}

func (s *streamFrame) decode(b []byte) (int, error) {
	dec := newCodec(b)
	var typ uint64
	ok := dec.readVarint(&typ) && dec.readVarint(&s.streamID)
	if !ok {
		return 0, newError(FrameEncodingError, "stream")
	}
	s.fin = typ&0x01 != 0
	hasLength := typ&0x02 != 0
	hasOffset := typ&0x04 != 0
	if hasOffset {
		if !dec.readVarint(&s.offset) {
			return 0, newError(FrameEncodingError, "stream")
		}
	} else {
		s.offset = 0
	}
	if hasLength {
		var length uint64
		ok = dec.readVarint(&length) && dec.read(&s.data, int(length))
		if !ok {
			return 0, newError(FrameEncodingError, "stream")
		}
		return dec.offset(), nil
	}
	s.data = b[dec.offset():]
	return len(b), nil
}

func (s *streamFrame) String() string {
	return fmt.Sprintf("stream{id=%d offset=%d length=%d fin=%v}", s.streamID, s.offset, len(s.data), s.fin)
}

// https://www.rfc-editor.org/rfc/rfc9000.html#section-19.9
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Maximum Data (i)                     ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type maxDataFrame struct {
	maximumData uint64
}

func newMaxDataFrame(max uint64) *maxDataFrame {
	return &maxDataFrame{
		maximumData: max,
	}
}

func (s *maxDataFrame) encodedLen() int {
	return 1 + varintLen(s.maximumData)
}

func (s *maxDataFrame) encode(b []byte) (int, error) {
	enc := newCodec(b)
	ok := enc.writeVarint(frameTypeMaxData) &&
		enc.writeVarint(s.maximumData)
	if !ok {
		return 0, errShortBuffer
	}
	return enc.offset(), nil
}

func (s *maxDataFrame) decode(b []byte) (int, error) {
	dec := newCodec(b)
	var typ uint64
	ok := dec.readVarint(&typ) && // Skip type
		dec.readVarint(&s.maximumData)
	if !ok {
		return 0, newError(FrameEncodingError, "max_data")
	}
	return dec.offset(), nil
}

func (s *maxDataFrame) String() string {
	return fmt.Sprintf("maxData{maximum=%d}", s.maximumData)
}

// https://www.rfc-editor.org/rfc/rfc9000.html#section-19.10
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Stream ID (i)                        ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Maximum Stream Data (i)                  ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type maxStreamDataFrame struct {
	streamID    uint64
	maximumData uint64
}

func newMaxStreamDataFrame(id, max uint64) *maxStreamDataFrame {
	return &maxStreamDataFrame{
		streamID:    id,
		maximumData: max,
	}
}

func (s *maxStreamDataFrame) encodedLen() int {
	return 1 + varintLen(s.streamID) + varintLen(s.maximumData)
}

func (s *maxStreamDataFrame) encode(b []byte) (int, error) {
	enc := newCodec(b)
	ok := enc.writeVarint(frameTypeMaxStreamData) &&
		enc.writeVarint(s.streamID) &&
		enc.writeVarint(s.maximumData)
	if !ok {
		return 0, errShortBuffer
	}
	return enc.offset(), nil
}

func (s *maxStreamDataFrame) decode(b []byte) (int, error) {
	dec := newCodec(b)
	var typ uint64
	ok := dec.readVarint(&typ) && // Skip type
		dec.readVarint(&s.streamID) &&
		dec.readVarint(&s.maximumData)
	if !ok {
		return 0, newError(FrameEncodingError, "max_stream_data")
	}
	return dec.offset(), nil
}

func (s *maxStreamDataFrame) String() string {
	return fmt.Sprintf("maxStreamData{id=%d maximum=%d}", s.streamID, s.maximumData)
}

// https://www.rfc-editor.org/rfc/rfc9000.html#section-19.11
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Maximum Streams (i)                     ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type maxStreamsFrame struct {
	maximumStreams uint64
	bidi           bool
}

func newMaxStreamsFrame(max uint64, bidi bool) *maxStreamsFrame {
	return &maxStreamsFrame{
		maximumStreams: max,
		bidi:           bidi,
	}
}

func (s *maxStreamsFrame) encodedLen() int {
	return 1 + varintLen(s.maximumStreams)
}

func (s *maxStreamsFrame) encode(b []byte) (int, error) {
	enc := newCodec(b)
	var typ uint64
	if s.bidi {
		typ = frameTypeMaxStreamsBidi
	} else {
		typ = frameTypeMaxStreamsUni
	}
	ok := enc.writeVarint(typ) &&
		enc.writeVarint(s.maximumStreams)
	if !ok {
		return 0, errShortBuffer
	}
	return enc.offset(), nil
}

func (s *maxStreamsFrame) decode(b []byte) (int, error) {
	dec := newCodec(b)
	var typ uint64
	ok := dec.readVarint(&typ) &&
		dec.readVarint(&s.maximumStreams)
	if !ok {
		return 0, newError(FrameEncodingError, "max_streams")
	}
	s.bidi = typ == frameTypeMaxStreamsBidi
	return dec.offset(), nil
}

func (s *maxStreamsFrame) String() string {
	return fmt.Sprintf("maxStreams{maximum=%d}", s.maximumStreams)
}

// https://www.rfc-editor.org/rfc/rfc9000.html#section-19.12
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Data Limit (i)                        ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type dataBlockedFrame struct {
	dataLimit uint64
}

func newDataBlockedFrame(limit uint64) *dataBlockedFrame {
	return &dataBlockedFrame{
		dataLimit: limit,
	}
}

func (s *dataBlockedFrame) encodedLen() int {
	return 1 + varintLen(s.dataLimit)
}

func (s *dataBlockedFrame) encode(b []byte) (int, error) {
	enc := newCodec(b)
	ok := enc.writeVarint(frameTypeDataBlocked) &&
		enc.writeVarint(s.dataLimit)
	if !ok {
		return 0, errShortBuffer
	}
	return enc.offset(), nil
}

func (s *dataBlockedFrame) decode(b []byte) (int, error) {
	dec := newCodec(b)
	var typ uint64
	ok := dec.readVarint(&typ) && // Skip type
		dec.readVarint(&s.dataLimit)
	if !ok {
		return 0, newError(FrameEncodingError, "data_blocked")
	}
	return dec.offset(), nil
}

func (s *dataBlockedFrame) String() string {
	return fmt.Sprintf("dataBlocked{limit=%d}", s.dataLimit)
}

// https://www.rfc-editor.org/rfc/rfc9000.html#section-19.13
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Stream ID (i)                        ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Stream Data Limit (i)                    ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type streamDataBlockedFrame struct {
	streamID  uint64
	dataLimit uint64
}

func newStreamDataBlockedFrame(id, limit uint64) *streamDataBlockedFrame {
	return &streamDataBlockedFrame{
		streamID:  id,
		dataLimit: limit,
	}
}

func (s *streamDataBlockedFrame) encodedLen() int {
	return 1 + varintLen(s.streamID) + varintLen(s.dataLimit)
}

func (s *streamDataBlockedFrame) encode(b []byte) (int, error) {
	enc := newCodec(b)
	ok := enc.writeVarint(frameTypeStreamDataBlocked) &&
		enc.writeVarint(s.streamID) &&
		enc.writeVarint(s.dataLimit)
	if !ok {
		return 0, errShortBuffer
	}
	return enc.offset(), nil
}

func (s *streamDataBlockedFrame) decode(b []byte) (int, error) {
	dec := newCodec(b)
	var typ uint64
	ok := dec.readVarint(&typ) && // Skip type
		dec.readVarint(&s.streamID) &&
		dec.readVarint(&s.dataLimit)
	if !ok {
		return 0, newError(FrameEncodingError, "stream_data_blocked")
	}
	return dec.offset(), nil
}

func (s *streamDataBlockedFrame) String() string {
	return fmt.Sprintf("streamDataBlocked{id=%d limit=%d}", s.streamID, s.dataLimit)
}

// https://www.rfc-editor.org/rfc/rfc9000.html#section-19.14
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Stream Limit (i)                     ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type streamsBlockedFrame struct {
	streamLimit uint64
	bidi        bool
}

func newStreamsBlockedFrame(limit uint64, bidi bool) *streamsBlockedFrame {
	return &streamsBlockedFrame{
		streamLimit: limit,
		bidi:        bidi,
	}
}

func (s *streamsBlockedFrame) encodedLen() int {
	return 1 + varintLen(s.streamLimit)
}

func (s *streamsBlockedFrame) encode(b []byte) (int, error) {
	enc := newCodec(b)
	var typ uint64
	if s.bidi {
		typ = frameTypeStreamsBlockedBidi
	} else {
		typ = frameTypeStreamsBlockedUni
	}
	ok := enc.writeVarint(typ) &&
		enc.writeVarint(s.streamLimit)
	if !ok {
		return 0, errShortBuffer
	}
	return enc.offset(), nil
}

func (s *streamsBlockedFrame) decode(b []byte) (int, error) {
	dec := newCodec(b)
	var typ uint64
	ok := dec.readVarint(&typ) &&
		dec.readVarint(&s.streamLimit)
	if !ok {
		return 0, newError(FrameEncodingError, "streams_blocked")
	}
	s.bidi = typ == frameTypeStreamsBlockedBidi
	return dec.offset(), nil
}

func (s *streamsBlockedFrame) String() string {
	return fmt.Sprintf("streamsBlocked{limit=%d}", s.streamLimit)
}

// https://www.rfc-editor.org/rfc/rfc9000.html#section-19.15
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                      Sequence Number (i)                    ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                      Retire Prior To (i)                    ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   Length (8)  |                                               |
// +-+-+-+-+-+-+-+-+       Connection ID (8..160)                  +
// |                                                             ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                                                               +
// |                                                               |
// +                   Stateless Reset Token (128)                 +
// |                                                               |
// +                                                               +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type newConnectionIDFrame struct {
	sequenceNumber      uint64
	retirePriorTo       uint64
	connectionID        []byte
	statelessResetToken []byte
}

func (s *newConnectionIDFrame) encodedLen() int {
	return 1 + varintLen(s.sequenceNumber) + varintLen(s.retirePriorTo) + 1 + len(s.connectionID) + len(s.statelessResetToken)
}

func (s *newConnectionIDFrame) encode(b []byte) (int, error) {
	if len(s.connectionID) < 1 || len(s.connectionID) > MaxCIDLength || len(s.statelessResetToken) != 16 {
		return 0, newError(FrameEncodingError, "new_connection_id")
	}
	enc := newCodec(b)
	ok := enc.writeVarint(frameTypeNewConnectionID) &&
		enc.writeVarint(s.sequenceNumber) &&
		enc.writeVarint(s.retirePriorTo) &&
		enc.writeByte(uint8(len(s.connectionID))) &&
		enc.write(s.connectionID) &&
		enc.write(s.statelessResetToken)
	if !ok {
		return 0, errShortBuffer
	}
	return enc.offset(), nil
}

func (s *newConnectionIDFrame) decode(b []byte) (int, error) {
	dec := newCodec(b)
	var typ uint64
	var cil uint8
	ok := dec.readVarint(&typ) && // Skip type
		dec.readVarint(&s.sequenceNumber) &&
		dec.readVarint(&s.retirePriorTo) &&
		dec.readByte(&cil) &&
		dec.read(&s.connectionID, int(cil)) &&
		dec.read(&s.statelessResetToken, 16)
	if !ok || cil < 1 || cil > MaxCIDLength {
		return 0, newError(FrameEncodingError, "new_connection_id")
	}
	return dec.offset(), nil
}

func (s *newConnectionIDFrame) String() string {
	return fmt.Sprintf("newConnectionID{sequence=%d retire=%d cid=%x token=%x}",
		s.sequenceNumber, s.retirePriorTo, s.connectionID, s.statelessResetToken)
}

// https://www.rfc-editor.org/rfc/rfc9000.html#section-19.16
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                      Sequence Number (i)                    ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type retireConnectionIDFrame struct {
	sequenceNumber uint64
}

func (s *retireConnectionIDFrame) encodedLen() int {
	return 1 + varintLen(s.sequenceNumber)
}

func (s *retireConnectionIDFrame) encode(b []byte) (int, error) {
	enc := newCodec(b)
	ok := enc.writeVarint(frameTypeRetireConnectionID) &&
		enc.writeVarint(s.sequenceNumber)
	if !ok {
		return 0, errShortBuffer
	}
	return enc.offset(), nil
}

func (s *retireConnectionIDFrame) decode(b []byte) (int, error) {
	dec := newCodec(b)
	var typ uint64
	ok := dec.readVarint(&typ) && // Skip type
		dec.readVarint(&s.sequenceNumber)
	if !ok {
		return 0, newError(FrameEncodingError, "retire_connection_id")
	}
	return dec.offset(), nil
}

func (s *retireConnectionIDFrame) String() string {
	return fmt.Sprintf("retireConnectionID{sequence=%d}", s.sequenceNumber)
}

// https://www.rfc-editor.org/rfc/rfc9000.html#section-19.17
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// +                           Data (64)                           +
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type pathChallengeFrame struct {
	data []byte
}

func (s *pathChallengeFrame) encodedLen() int {
	return 1 + len(s.data)
}

func (s *pathChallengeFrame) encode(b []byte) (int, error) {
	if len(s.data) != 8 {
		return 0, newError(FrameEncodingError, "path_challenge")
	}
	enc := newCodec(b)
	ok := enc.writeVarint(frameTypePathChallenge) &&
		enc.write(s.data)
	if !ok {
		return 0, errShortBuffer
	}
	return enc.offset(), nil
}

func (s *pathChallengeFrame) decode(b []byte) (int, error) {
	dec := newCodec(b)
	var typ uint64
	ok := dec.readVarint(&typ) &&
		dec.read(&s.data, 8)
	if !ok {
		return 0, newError(FrameEncodingError, "path_challenge")
	}
	return dec.offset(), nil
}

func (s *pathChallengeFrame) String() string {
	return fmt.Sprintf("pathChallenge{data=%x}", s.data)
}

// https://www.rfc-editor.org/rfc/rfc9000.html#section-19.18
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// +                           Data (64)                           +
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type pathResponseFrame struct {
	data []byte
}

func newPathResponseFrame(data []byte) *pathResponseFrame {
	return &pathResponseFrame{
		data: data,
	}
}

func (s *pathResponseFrame) encodedLen() int {
	return 1 + len(s.data)
}

func (s *pathResponseFrame) encode(b []byte) (int, error) {
	if len(s.data) != 8 {
		return 0, newError(FrameEncodingError, "path_response")
	}
	enc := newCodec(b)
	ok := enc.writeVarint(frameTypePathResponse) &&
		enc.write(s.data)
	if !ok {
		return 0, errShortBuffer
	}
	return enc.offset(), nil
}

func (s *pathResponseFrame) decode(b []byte) (int, error) {
	dec := newCodec(b)
	var typ uint64
	ok := dec.readVarint(&typ) &&
		dec.read(&s.data, 8)
	if !ok {
		return 0, newError(FrameEncodingError, "path_response")
	}
	return dec.offset(), nil
}

func (s *pathResponseFrame) String() string {
	return fmt.Sprintf("pathResponse{data=%x}", s.data)
}

// https://www.rfc-editor.org/rfc/rfc9000.html#section-19.19
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Error Code (i)                      ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       [ Frame Type (i) ]                    ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Reason Phrase Length (i)                 ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Reason Phrase (*)                    ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type connectionCloseFrame struct {
	errorCode    uint64
	frameType    uint64
	reasonPhrase []byte
	application  bool // application type does not have frameType
}

func newConnectionCloseFrame(code, frame uint64, reason []byte, app bool) *connectionCloseFrame {
	return &connectionCloseFrame{
		errorCode:    code,
		frameType:    frame,
		reasonPhrase: reason,
		application:  app,
	}
}

func (s *connectionCloseFrame) encodedLen() int {
	n := 1 +
		varintLen(s.errorCode) +
		varintLen(uint64(len(s.reasonPhrase))) +
		len(s.reasonPhrase)
	if !s.application {
		n += varintLen(s.frameType)
	}
	return n
}

func (s *connectionCloseFrame) encode(b []byte) (int, error) {
	enc := newCodec(b)
	var ok bool
	if s.application {
		ok = enc.writeVarint(frameTypeApplicationClose) &&
			enc.writeVarint(s.errorCode) &&
			enc.writeVarint(uint64(len(s.reasonPhrase))) &&
			enc.write(s.reasonPhrase)
	} else {
		ok = enc.writeVarint(frameTypeConnectionClose) &&
			enc.writeVarint(s.errorCode) &&
			enc.writeVarint(s.frameType) &&
			enc.writeVarint(uint64(len(s.reasonPhrase))) &&
			enc.write(s.reasonPhrase)
	}
	if !ok {
		return 0, errShortBuffer
	}
	return enc.offset(), nil
}

func (s *connectionCloseFrame) decode(b []byte) (int, error) {
	dec := newCodec(b)
	// Check if it is a Application Close frame type
	var typ uint64
	ok := dec.readVarint(&typ) && dec.readVarint(&s.errorCode)
	if !ok {
		return 0, newError(FrameEncodingError, "connection_close")
	}
	if typ == frameTypeConnectionClose {
		if !dec.readVarint(&s.frameType) {
			return 0, newError(FrameEncodingError, "connection_close")
		}
	} else {
		s.application = true
	}
	var length uint64
	ok = dec.readVarint(&length) &&
		dec.read(&s.reasonPhrase, int(length))
	if !ok {
		return 0, newError(FrameEncodingError, "connection_close")
	}
	return dec.offset(), nil
}

func (s *connectionCloseFrame) String() string {
	return fmt.Sprintf("close{error=%d frame=%d reason=%s}", s.errorCode, s.frameType, s.reasonPhrase)
}

// https://www.rfc-editor.org/rfc/rfc9000.html#section-19.7
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Token Length (i)                     ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                            Token (*)                        ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type newTokenFrame struct {
	token []byte
}

func newNewTokenFrame(token []byte) *newTokenFrame {
	return &newTokenFrame{
		token: token,
	}
}

func (s *newTokenFrame) encodedLen() int {
	return 1 + varintLen(uint64(len(s.token))) + len(s.token)
}

func (s *newTokenFrame) encode(b []byte) (int, error) {
	enc := newCodec(b)
	ok := enc.writeVarint(frameTypeNewToken) &&
		enc.writeVarint(uint64(len(s.token))) &&
		enc.write(s.token)
	if !ok {
		return 0, errShortBuffer
	}
	return enc.offset(), nil
}

func (s *newTokenFrame) decode(b []byte) (int, error) {
	dec := newCodec(b)
	var typ uint64
	var length uint64
	ok := dec.readVarint(&typ) && // Skip type
		dec.readVarint(&length) &&
		dec.read(&s.token, int(length))
	if !ok || length == 0 {
		return 0, newError(FrameEncodingError, "new_token")
	}
	return dec.offset(), nil
}

func (s *newTokenFrame) String() string {
	return fmt.Sprintf("newToken{token=%x}", s.token)
}

// https://www.rfc-editor.org/rfc/rfc9000.html#section-19.20
type handshakeDoneFrame struct {
}

func (s *handshakeDoneFrame) encodedLen() int {
	return 1
}

func (s *handshakeDoneFrame) encode(b []byte) (int, error) {
	if len(b) < 1 {
		return 0, errShortBuffer
	}
	b[0] = frameTypeHanshakeDone
	return 1, nil
}

func (s *handshakeDoneFrame) decode(b []byte) (int, error) {
	n := 1
	if len(b) > 0 {
		var typ uint64
		n = getVarint(b, &typ)
	}
	return n, nil
}

func (s *handshakeDoneFrame) String() string {
	return "handshakeDone{}"
}

// DATAGRAM frames are used to transmit application data in an unreliable manner.
// https://quicwg.org/datagram/draft-ietf-quic-datagram.html
type datagramFrame struct {
	data []byte
}

func newDatagramFrame(data []byte) *datagramFrame {
	return &datagramFrame{
		data: data,
	}
}

func (s *datagramFrame) encodedLen() int {
	return 1 + varintLen(uint64(len(s.data))) + len(s.data)
}

func (s *datagramFrame) encode(b []byte) (int, error) {
	// Always include length
	enc := newCodec(b)
	ok := enc.writeVarint(frameTypeDatagramWithLength) &&
		enc.writeVarint(uint64(len(s.data))) &&
		enc.write(s.data)
	if !ok {
		return 0, errShortBuffer
	}
	return enc.offset(), nil
}

func (s *datagramFrame) decode(b []byte) (int, error) {
	dec := newCodec(b)
	var typ uint64
	if !dec.readVarint(&typ) {
		return 0, newError(FrameEncodingError, "datagram")
	}
	if typ == frameTypeDatagramWithLength {
		var length uint64
		ok := dec.readVarint(&length) &&
			dec.read(&s.data, int(length))
		if !ok {
			return 0, newError(FrameEncodingError, "datagram")
		}
		return dec.offset(), nil
	}
	s.data = b[dec.offset():]
	return len(b), nil
}

func (s *datagramFrame) String() string {
	return fmt.Sprintf("datagram{data=%x}", s.data)
}

func encodeFrames(b []byte, frames []frame) (int, error) {
	n := 0
	for _, f := range frames {
		i, err := f.encode(b[n:])
		if err != nil {
			return 0, fmt.Errorf("encode frame %s: %v", f, err)
		}
		n += i
	}
	return n, nil
}

func isFrameAckEliciting(typ uint64) bool {
	switch typ {
	case frameTypeAck, frameTypePadding, frameTypeConnectionClose, frameTypeApplicationClose:
		return false
	default:
		return true
	}
}

// https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4
func isFrameAllowedInPacket(typ uint64, pktType packetType) bool {
	switch pktType {
	case packetTypeInitial, packetTypeHandshake:
		return typ == frameTypePadding || typ == frameTypePing || typ == frameTypeAck ||
			typ == frameTypeCrypto || typ == frameTypeConnectionClose
	case packetTypeOneRTT:
		return true
	default:
		return false
	}
}
