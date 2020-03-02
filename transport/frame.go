package transport

import "fmt"

const (
	frameTypePadding     = 0x00
	frameTypePing        = 0x01
	frameTypeAck         = 0x02
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

	frameTypeConnectionClose  = 0x1c
	frameTypeApplicationClose = 0x1d
	frameTypeHanshakeDone     = 0x1e
)

const (
	maxCryptoFrameOverhead = 8
	maxStreamFrameOverhead = 12
	maxAckRanges           = 1024
)

// https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#frames
type frame interface {
	encodedLen() int
	encoder
	decoder
	String() string
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
	for i, v := range b {
		if v != 0 {
			return i, nil
		}
	}
	return len(b), nil
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
	return 1, nil
}

func (s *pingFrame) String() string {
	return "ping{}"
}

// https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#frame-crypto
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
	if !enc.writeByte(frameTypeCrypto) ||
		!enc.writeVarint(s.offset) ||
		!enc.writeVarint(uint64(len(s.data))) ||
		!enc.write(s.data) {
		return 0, errShortBuffer
	}
	return enc.offset(), nil
}

func (s *cryptoFrame) decode(b []byte) (int, error) {
	dec := newCodec(b)
	var length uint64
	if !dec.skip(1) || // skip frame type
		!dec.readVarint(&s.offset) ||
		!dec.readVarint(&length) {
		return 0, errInvalidFrame
	}
	if s.data = dec.read(int(length)); s.data == nil {
		return 0, errInvalidFrame
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
// https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#frame-ack
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
	// TODO: ECN
}

func newAckFrame(ackDelay uint64, r rangeSet) *ackFrame {
	f := &ackFrame{
		ackDelay: ackDelay,
	}
	f.fromRangeSet(r)
	return f
}

func (s *ackFrame) encodedLen() int {
	n := 1 +
		varintLen(s.largestAck) +
		varintLen(s.ackDelay) +
		varintLen(uint64(len(s.ackRanges))) +
		varintLen(s.firstAckRange)
	for _, r := range s.ackRanges {
		n += varintLen(r.gap) + varintLen(r.ackRange)
	}
	return n
}

func (s *ackFrame) encode(b []byte) (int, error) {
	enc := newCodec(b)
	if !enc.writeByte(frameTypeAck) ||
		!enc.writeVarint(s.largestAck) ||
		!enc.writeVarint(s.ackDelay) ||
		!enc.writeVarint(uint64(len(s.ackRanges))) ||
		!enc.writeVarint(s.firstAckRange) {
		return 0, errShortBuffer
	}
	for _, r := range s.ackRanges {
		if !enc.writeVarint(r.gap) || !enc.writeVarint(r.ackRange) {
			return 0, errShortBuffer
		}
	}
	return enc.offset(), nil
}

func (s *ackFrame) decode(b []byte) (int, error) {
	dec := newCodec(b)
	var rangeCount uint64
	if !dec.skip(1) || // skip frame type
		!dec.readVarint(&s.largestAck) ||
		!dec.readVarint(&s.ackDelay) ||
		!dec.readVarint(&rangeCount) ||
		!dec.readVarint(&s.firstAckRange) ||
		rangeCount > maxAckRanges {
		return 0, errInvalidFrame
	}
	if rangeCount > 0 {
		s.ackRanges = make([]ackRange, int(rangeCount))
		for i := range s.ackRanges {
			r := &s.ackRanges[i]
			if !dec.readVarint(&r.gap) || !dec.readVarint(&r.ackRange) {
				return 0, errInvalidFrame
			}
		}
	} else {
		s.ackRanges = nil
	}
	return dec.offset(), nil
}

// toRangeSet converts ackRanges into ranges of acked packets
// [end, start] in descending order.
// https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#ack-ranges
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
	smallest := s.largestAck - s.firstAckRange
	ranges := make(rangeSet, 0, 1+len(s.ackRanges))
	ranges = append(ranges, numberRange{end: s.largestAck, start: smallest})
	if len(s.ackRanges) > 0 {
		for _, r := range s.ackRanges {
			if smallest < r.gap+2 {
				return nil
			}
			smallest -= r.gap + 2
			if smallest < r.ackRange {
				return nil
			}
			ranges = append(ranges, numberRange{end: smallest, start: smallest - r.ackRange})
			smallest -= r.ackRange
		}
	}
	return rangeSet(ranges)
}

func (s *ackFrame) fromRangeSet(ranges rangeSet) {
	var smallest uint64
	if len(ranges) > 1 {
		s.ackRanges = make([]ackRange, len(ranges)-1)
	} else {
		s.ackRanges = nil
	}
	for i, r := range ranges {
		if i == 0 {
			s.largestAck = r.end
			s.firstAckRange = r.end - r.start
			smallest = r.start
		} else {
			if smallest-1 <= r.end || r.start > r.end {
				panic(fmt.Sprintf("invalid range set: %s", ranges))
			}
			s.ackRanges[i-1] = ackRange{
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
// https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#frame-reset-stream
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

func (s *resetStreamFrame) encodedLen() int {
	return 1 + varintLen(s.streamID) +
		varintLen(s.errorCode) +
		varintLen(s.finalSize)
}

func (s *resetStreamFrame) encode(b []byte) (int, error) {
	enc := newCodec(b)
	if !enc.writeByte(frameTypeResetStream) ||
		!enc.writeVarint(s.streamID) ||
		!enc.writeVarint(s.errorCode) ||
		!enc.writeVarint(s.finalSize) {
		return 0, errShortBuffer
	}
	return enc.offset(), nil
}

func (s *resetStreamFrame) decode(b []byte) (int, error) {
	dec := newCodec(b)
	if !dec.skip(1) || // Skip type
		!dec.readVarint(&s.streamID) ||
		!dec.readVarint(&s.errorCode) ||
		!dec.readVarint(&s.finalSize) {
		return 0, errInvalidFrame
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

func (s *stopSendingFrame) encodedLen() int {
	return 1 + varintLen(s.streamID) + varintLen(s.errorCode)
}

func (s *stopSendingFrame) encode(b []byte) (int, error) {
	enc := newCodec(b)
	if !enc.writeByte(frameTypeStopSending) ||
		!enc.writeVarint(s.streamID) ||
		!enc.writeVarint(s.errorCode) {
		return 0, errShortBuffer
	}
	return enc.offset(), nil
}

func (s *stopSendingFrame) decode(b []byte) (int, error) {
	dec := newCodec(b)
	if !dec.skip(1) || // Skip type
		!dec.readVarint(&s.streamID) ||
		!dec.readVarint(&s.errorCode) {
		return 0, errInvalidFrame
	}
	return dec.offset(), nil
}

func (s *stopSendingFrame) String() string {
	return fmt.Sprintf("stopSending{id=%d error=%d}", s.streamID, s.errorCode)
}

// https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#frame-stream
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
	typ := uint8(frameTypeStream)
	if s.fin {
		typ |= 0x01
	}
	// Always include length
	typ |= 0x02
	if s.offset > 0 {
		typ |= 0x04
	}
	enc := newCodec(b)
	if !enc.writeByte(typ) || !enc.writeVarint(s.streamID) {
		return 0, errShortBuffer
	}
	if s.offset > 0 && !enc.writeVarint(s.offset) {
		return 0, errShortBuffer
	}
	if !enc.writeVarint(uint64(len(s.data))) || !enc.write(s.data) {
		return 0, errShortBuffer
	}
	return enc.offset(), nil
}

func (s *streamFrame) decode(b []byte) (int, error) {
	dec := newCodec(b)
	var typ uint8
	if !dec.readByte(&typ) || !dec.readVarint(&s.streamID) {
		return 0, errInvalidFrame
	}
	s.fin = typ&0x01 != 0
	hasLength := typ&0x02 != 0
	hasOffset := typ&0x04 != 0
	if hasOffset {
		if !dec.readVarint(&s.offset) {
			return 0, errInvalidFrame
		}
	} else {
		s.offset = 0
	}
	if hasLength {
		var length uint64
		if !dec.readVarint(&length) {
			return 0, errInvalidFrame
		}
		if s.data = dec.read(int(length)); s.data == nil {
			return 0, errInvalidFrame
		}
		return dec.offset(), nil
	}
	s.data = b[dec.offset():]
	return len(b), nil
}

func (s *streamFrame) String() string {
	return fmt.Sprintf("stream{id=%d offset=%d length=%d fin=%v}", s.streamID, s.offset, len(s.data), s.fin)
}

// https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#frame-max-data
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Maximum Data (i)                     ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type maxDataFrame struct {
	maximumData uint64
}

func (s *maxDataFrame) encodedLen() int {
	return 1 + varintLen(s.maximumData)
}

func (s *maxDataFrame) encode(b []byte) (int, error) {
	enc := newCodec(b)
	if !enc.writeByte(frameTypeMaxData) ||
		!enc.writeVarint(s.maximumData) {
		return 0, errShortBuffer
	}
	return enc.offset(), nil
}

func (s *maxDataFrame) decode(b []byte) (int, error) {
	dec := newCodec(b)
	if !dec.skip(1) || // Skip type
		!dec.readVarint(&s.maximumData) {
		return 0, errInvalidFrame
	}
	return dec.offset(), nil
}

func (s *maxDataFrame) String() string {
	return fmt.Sprintf("maxData{maximum=%d}", s.maximumData)
}

// https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#frame-max-stream-data
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Stream ID (i)                        ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Maximum Stream Data (i)                  ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type maxStreamDataFrame struct {
	streamID    uint64
	maximumData uint64
}

func (s *maxStreamDataFrame) encodedLen() int {
	return 1 + varintLen(s.streamID) + varintLen(s.maximumData)
}

func (s *maxStreamDataFrame) encode(b []byte) (int, error) {
	enc := newCodec(b)
	if !enc.writeByte(frameTypeMaxStreamData) ||
		!enc.writeVarint(s.streamID) ||
		!enc.writeVarint(s.maximumData) {
		return 0, errShortBuffer
	}
	return enc.offset(), nil
}

func (s *maxStreamDataFrame) decode(b []byte) (int, error) {
	dec := newCodec(b)
	if !dec.skip(1) || // Skip type
		!dec.readVarint(&s.streamID) ||
		!dec.readVarint(&s.maximumData) {
		return 0, errInvalidFrame
	}
	return dec.offset(), nil
}

func (s *maxStreamDataFrame) String() string {
	return fmt.Sprintf("maxStreamData{id=%d maximum=%d}", s.streamID, s.maximumData)
}

// https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#frame-max-streams
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Maximum Streams (i)                     ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type maxStreamsFrame struct {
	maximumStreams uint64
	bidi           bool
}

func (s *maxStreamsFrame) encodedLen() int {
	return 1 + varintLen(s.maximumStreams)
}

func (s *maxStreamsFrame) encode(b []byte) (int, error) {
	enc := newCodec(b)
	var typ uint8
	if s.bidi {
		typ = frameTypeMaxStreamsBidi
	} else {
		typ = frameTypeMaxStreamsUni
	}
	if !enc.writeByte(typ) ||
		!enc.writeVarint(s.maximumStreams) {
		return 0, errShortBuffer
	}
	return enc.offset(), nil
}

func (s *maxStreamsFrame) decode(b []byte) (int, error) {
	dec := newCodec(b)
	var typ uint8
	if !dec.readByte(&typ) || // Skip type
		!dec.readVarint(&s.maximumStreams) {
		return 0, errInvalidFrame
	}
	s.bidi = typ == frameTypeMaxStreamsBidi
	return dec.offset(), nil
}

func (s *maxStreamsFrame) String() string {
	return fmt.Sprintf("maxStreams{maximum=%d}", s.maximumStreams)
}

// https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#frame-data-blocked
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Data Limit (i)                        ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type dataBlockedFrame struct {
	dataLimit uint64
}

func (s *dataBlockedFrame) encodedLen() int {
	return 1 + varintLen(s.dataLimit)
}

func (s *dataBlockedFrame) encode(b []byte) (int, error) {
	enc := newCodec(b)
	if !enc.writeByte(frameTypeDataBlocked) ||
		!enc.writeVarint(s.dataLimit) {
		return 0, errShortBuffer
	}
	return enc.offset(), nil
}

func (s *dataBlockedFrame) decode(b []byte) (int, error) {
	dec := newCodec(b)
	if !dec.skip(1) || // Skip type
		!dec.readVarint(&s.dataLimit) {
		return 0, errInvalidFrame
	}
	return dec.offset(), nil
}

func (s *dataBlockedFrame) String() string {
	return fmt.Sprintf("dataBlocked{limit=%d}", s.dataLimit)
}

// https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#frame-stream-data-blocked
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Stream ID (i)                        ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Stream Data Limit (i)                    ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type streamDataBlockedFrame struct {
	streamID  uint64
	dataLimit uint64
}

func (s *streamDataBlockedFrame) encodedLen() int {
	return 1 + varintLen(s.streamID) + varintLen(s.dataLimit)
}

func (s *streamDataBlockedFrame) encode(b []byte) (int, error) {
	enc := newCodec(b)
	if !enc.writeByte(frameTypeStreamDataBlocked) ||
		!enc.writeVarint(s.streamID) ||
		!enc.writeVarint(s.dataLimit) {
		return 0, errShortBuffer
	}
	return enc.offset(), nil
}

func (s *streamDataBlockedFrame) decode(b []byte) (int, error) {
	dec := newCodec(b)
	if !dec.skip(1) || // Skip type
		!dec.readVarint(&s.streamID) ||
		!dec.readVarint(&s.dataLimit) {
		return 0, errInvalidFrame
	}
	return dec.offset(), nil
}

func (s *streamDataBlockedFrame) String() string {
	return fmt.Sprintf("streamDataBlocked{id=%d limit=%d}", s.streamID, s.dataLimit)
}

type streamsBlockedFrame struct {
	streamLimit uint64
	bidi        bool
}

func (s *streamsBlockedFrame) encodedLen() int {
	return 1 + varintLen(s.streamLimit)
}

func (s *streamsBlockedFrame) encode(b []byte) (int, error) {
	enc := newCodec(b)
	var typ uint8
	if s.bidi {
		typ = frameTypeStreamsBlockedBidi
	} else {
		typ = frameTypeStreamsBlockedUni
	}
	if !enc.writeByte(typ) ||
		!enc.writeVarint(s.streamLimit) {
		return 0, errShortBuffer
	}
	return enc.offset(), nil
}

func (s *streamsBlockedFrame) decode(b []byte) (int, error) {
	dec := newCodec(b)
	var typ uint8
	if !dec.readByte(&typ) || // Skip type
		!dec.readVarint(&s.streamLimit) {
		return 0, errInvalidFrame
	}
	s.bidi = typ == frameTypeStreamsBlockedBidi
	return dec.offset(), nil
}

func (s *streamsBlockedFrame) String() string {
	return fmt.Sprintf("streamsBlocked{limit=%d}", s.streamLimit)
}

// https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#frame-connection-close
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
		ok = enc.writeByte(frameTypeApplicationClose) &&
			enc.writeVarint(s.errorCode) &&
			enc.writeVarint(uint64(len(s.reasonPhrase))) &&
			enc.write(s.reasonPhrase)
	} else {
		ok = enc.writeByte(frameTypeConnectionClose) &&
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
	var length uint64
	if !dec.readVarint(&length) || !dec.readVarint(&s.errorCode) {
		return 0, errInvalidFrame
	}
	if length == frameTypeConnectionClose {
		if !dec.readVarint(&s.frameType) {
			return 0, errInvalidFrame
		}
	} else {
		s.application = true
	}
	if !dec.readVarint(&length) {
		return 0, errInvalidFrame
	}
	if s.reasonPhrase = dec.read(int(length)); s.reasonPhrase == nil {
		return 0, errInvalidFrame
	}
	return dec.offset(), nil
}

func (s *connectionCloseFrame) String() string {
	return fmt.Sprintf("close{error=%d frame=%d reason=%s}", s.errorCode, s.frameType, s.reasonPhrase)
}

// https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#frame-new-token
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Token Length (i)                     ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                            Token (*)                        ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type newTokenFrame struct {
	token []byte
}

func (s *newTokenFrame) encodedLen() int {
	return 1 + varintLen(uint64(len(s.token))) + len(s.token)
}

func (s *newTokenFrame) encode(b []byte) (int, error) {
	enc := newCodec(b)
	if !enc.writeByte(frameTypeNewToken) ||
		!enc.writeVarint(uint64(len(s.token))) ||
		!enc.write(s.token) {
		return 0, errShortBuffer
	}
	return enc.offset(), nil
}

func (s *newTokenFrame) decode(b []byte) (int, error) {
	dec := newCodec(b)
	var length uint64
	if !dec.skip(1) || // Skip type
		!dec.readVarint(&length) ||
		length == 0 {
		return 0, errInvalidFrame
	}
	if s.token = dec.read(int(length)); s.token == nil {
		return 0, errInvalidFrame
	}
	return dec.offset(), nil
}

func (s *newTokenFrame) String() string {
	return fmt.Sprintf("newToken{token=%x}", s.token)
}

// https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#name-handshake_done-frame
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
	return 1, nil
}

func (s *handshakeDoneFrame) String() string {
	return "handshakeDone{}"
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
