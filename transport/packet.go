package transport

import (
	"errors"
	"fmt"
	"time"
)

type packetSpace int

const (
	packetSpaceInitial packetSpace = iota
	packetSpaceHandshake
	packetSpaceApplication
	packetSpaceCount
)

type packetType int

const (
	packetTypeInitial packetType = iota
	packetTypeZeroRTT
	packetTypeHandshake
	packetTypeRetry
	packetTypeVersionNegotiation
	packetTypeShort
)

var packetTypeNames = [...]string{
	packetTypeInitial:            "initial",
	packetTypeZeroRTT:            "zeroRTT",
	packetTypeHandshake:          "handshake",
	packetTypeRetry:              "retry",
	packetTypeVersionNegotiation: "version",
	packetTypeShort:              "short",
}

func (s packetType) String() string {
	return packetTypeNames[s]
}

const (
	maxPacketNumberLength = 4
)

func isLongHeader(b byte) bool {
	return b&0x80 != 0
}

func packetTypeFromLongHeader(b uint8) packetType {
	switch b & 0x30 >> 4 {
	case 0:
		return packetTypeInitial
	case 1:
		return packetTypeZeroRTT
	case 2:
		return packetTypeHandshake
	case 3:
		return packetTypeRetry
	default:
		panic(fmt.Sprintf("unsupported packet type: 0x%x", b))
	}
}

func packetTypeFromSpace(space packetSpace) packetType {
	switch space {
	case packetSpaceInitial:
		return packetTypeInitial
	case packetSpaceHandshake:
		return packetTypeHandshake
	case packetSpaceApplication:
		return packetTypeShort
	default:
		panic(fmt.Sprintf("invalid state: space=%d", space))
	}
}

// Packet number length bits are same position in both short and long header packet.
func packetNumberLenFromHeader(b uint8) int {
	return int(b&0x03) + 1
}

func packetNumberLenHeaderFlag(n int) uint8 {
	return uint8(n - 1)
}

// Header is the version-independent header of QUIC packets.
//
// Long header:
//
// +-+-+-+-+-+-+-+-+
// |1|X X X X X X X|
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Version (32)                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | DCID Len (8)  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |               Destination Connection ID (0..2040)           ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | SCID Len (8)  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                 Source Connection ID (0..2040)              ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Short header:
// +-+-+-+-+-+-+-+-+
// |0|X X X X X X X|
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                 Destination Connection ID (*)               ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type Header struct {
	Flags   uint8
	Version uint32
	DCID    []byte
	SCID    []byte

	dcil uint8 // Used when decoding
}

func (s *Header) encodedLen() int {
	if isLongHeader(s.Flags) {
		return s.encodedLenLong()
	}
	return s.encodedLenShort()
}

func (s *Header) encodedLenLong() int {
	return 7 + len(s.DCID) + len(s.SCID)
}

func (s *Header) encodedLenShort() int {
	return 1 + len(s.DCID)
}

func (s *Header) encode(b []byte) (int, error) {
	if len(s.DCID) > MaxCIDLength {
		return 0, errors.New("destination CID too long")
	}
	if len(s.SCID) > MaxCIDLength {
		return 0, errors.New("source CID too long")
	}
	// Buffer length checking is done in packet encoder
	enc := newCodec(b)
	ok := enc.writeByte(s.Flags)
	if !ok {
		return 0, errShortBuffer
	}
	if isLongHeader(s.Flags) {
		ok = enc.writeUint32(s.Version) &&
			enc.writeByte(uint8(len(s.DCID))) &&
			enc.write(s.DCID) &&
			enc.writeByte(uint8(len(s.SCID))) &&
			enc.write(s.SCID)
	} else {
		ok = enc.write(s.DCID)
	}
	if !ok {
		return 0, errShortBuffer
	}
	return enc.offset(), nil
}

func (s *Header) decode(b []byte) (int, error) {
	dec := newCodec(b)
	if !dec.readByte(&s.Flags) {
		return 0, errInvalidPacket
	}
	if isLongHeader(s.Flags) {
		if !dec.readUint32(&s.Version) {
			return 0, errInvalidPacket
		}
		// DCID
		var length uint8
		if !dec.readByte(&length) || length > MaxCIDLength {
			return 0, errInvalidPacket
		}
		if s.DCID = dec.read(int(length)); s.DCID == nil {
			return 0, errInvalidPacket
		}
		// SCID
		if !dec.readByte(&length) || length > MaxCIDLength {
			return 0, errInvalidPacket
		}
		if s.SCID = dec.read(int(length)); s.SCID == nil {
			return 0, errInvalidPacket
		}
	} else {
		if s.DCID = dec.read(int(s.dcil)); s.DCID == nil {
			return 0, errInvalidPacket
		}
	}
	return dec.offset(), nil
}

func (s *Header) String() string {
	var typ packetType
	if isLongHeader(s.Flags) {
		if s.Version == 0 {
			typ = packetTypeVersionNegotiation
		} else {
			typ = packetTypeFromLongHeader(s.Flags)
		}
	} else {
		typ = packetTypeShort
	}
	return fmt.Sprintf("type=%s version=%d dcid=%x scid=%x", typ, s.Version, s.DCID, s.SCID)
}

// packet is an union of all QUIC packets.
type packet struct {
	typ       packetType
	header    Header
	headerLen int // decoded header length (set by decodeHeader)

	supportedVersions      []uint32 // Only in Version negotiation
	token                  []byte   // Only in Initial and Retry
	originalDestinationCID []byte   // Only in Retry

	packetNumber uint64
	payloadLen   int
}

var packetEncodedLenFuncs = [...]func(*packet) int{
	packetTypeInitial:            packetInitialEncodedLen,
	packetTypeZeroRTT:            packetLongEncodedLen,
	packetTypeHandshake:          packetLongEncodedLen,
	packetTypeRetry:              packetRetryEncodedLen,
	packetTypeVersionNegotiation: packetVersionEncodedLen,
	packetTypeShort:              packetShortEncodedLen,
}

var packetEncodeFuncs = [...]func(*packet, []byte) (int, error){
	packetTypeInitial:            packetInitialEncode,
	packetTypeZeroRTT:            packetLongEncode,
	packetTypeHandshake:          packetLongEncode,
	packetTypeRetry:              packetRetryEncode,
	packetTypeVersionNegotiation: packetVersionEncode,
	packetTypeShort:              packetShortEncode,
}

var packetDecodeFuncs = [...]func(*packet, []byte) (int, error){
	packetTypeInitial:            packetInitialDecode,
	packetTypeZeroRTT:            packetLongDecode,
	packetTypeHandshake:          packetLongDecode,
	packetTypeRetry:              packetRetryDecode,
	packetTypeVersionNegotiation: packetVersionDecode,
	packetTypeShort:              packetShortDecode,
}

func (s *packet) encodedLen() int {
	return packetEncodedLenFuncs[s.typ](s)
}

func (s *packet) encode(b []byte) (int, error) {
	switch s.typ {
	case packetTypeInitial:
		s.header.Flags = 0xc0 | packetNumberLenHeaderFlag(packetNumberLen(s.packetNumber))
	case packetTypeZeroRTT:
		s.header.Flags = 0xd0 | packetNumberLenHeaderFlag(packetNumberLen(s.packetNumber))
	case packetTypeHandshake:
		s.header.Flags = 0xe0 | packetNumberLenHeaderFlag(packetNumberLen(s.packetNumber))
	case packetTypeRetry:
		s.header.Flags = 0xf0
	case packetTypeVersionNegotiation:
		s.header.Flags = 0xc0
	case packetTypeShort:
		s.header.Flags = 0x00 | packetNumberLenHeaderFlag(packetNumberLen(s.packetNumber))
	default:
		return 0, fmt.Errorf("unsupported packet type: %d", s.typ)
	}
	n, err := s.header.encode(b)
	if err != nil {
		return 0, err
	}
	m, err := packetEncodeFuncs[s.typ](s, b[n:])
	if err != nil {
		return 0, err
	}
	return n + m, nil
}

// decodeHeader decodes header and packet type
func (s *packet) decodeHeader(b []byte) (int, error) {
	n, err := s.header.decode(b)
	if err != nil {
		return 0, err
	}
	if isLongHeader(s.header.Flags) {
		if s.header.Version == 0 {
			s.typ = packetTypeVersionNegotiation
		} else {
			s.typ = packetTypeFromLongHeader(s.header.Flags)
		}
	} else {
		s.typ = packetTypeShort
	}
	s.headerLen = n
	return n, nil
}

// decodeBody decodes packet until payload. It returns payload offset relatively to header.
func (s *packet) decodeBody(b []byte) (int, error) {
	return packetDecodeFuncs[s.typ](s, b)
}

// packetNumberOffset returns index offset of packet number for decrypting.
func (s *packet) packetNumberOffset(b []byte, headerLen int) (int, error) {
	if s.typ == packetTypeShort {
		return headerLen, nil
	}
	var length uint64
	dec := newCodec(b[headerLen:])
	if s.typ == packetTypeInitial {
		// Skip token
		if !dec.readVarint(&length) || !dec.skip(int(length)) {
			return 0, errInvalidPacket
		}
	}
	// Remainder Length
	if !dec.readVarint(&length) {
		return 0, errInvalidPacket
	}
	return headerLen + dec.offset(), nil
}

func (s *packet) String() string {
	switch s.typ {
	case packetTypeInitial:
		return fmt.Sprintf("type=%s version=%d dcid=%x scid=%x token=%x number=%d",
			s.typ, s.header.Version, s.header.DCID, s.header.SCID, s.token, s.packetNumber)
	case packetTypeRetry:
		return fmt.Sprintf("type=%s version=%d dcid=%x scid=%x odcid=%x token=%x number=%d",
			s.typ, s.header.Version, s.header.DCID, s.header.SCID, s.originalDestinationCID, s.token, s.packetNumber)
	case packetTypeShort:
		return fmt.Sprintf("type=%s dcid=%x number=%d",
			s.typ, s.header.DCID, s.packetNumber)
	default:
		return fmt.Sprintf("type=%s version=%d dcid=%x scid=%x number=%d",
			s.typ, s.header.Version, s.header.DCID, s.header.SCID, s.packetNumber)
	}
}

// +-+-+-+-+-+-+-+-+
// |1|  Unused (7) |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                          Version (32)                         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | DCID Len (8)  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |               Destination Connection ID (0..2040)           ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | SCID Len (8)  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                 Source Connection ID (0..2040)              ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Supported Version 1 (32)                 ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                   [Supported Version 2 (32)]                ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//                                ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                   [Supported Version N (32)]                ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
func packetVersionEncodedLen(s *packet) int {
	return s.header.encodedLenLong() + 4*len(s.supportedVersions)
}

func packetVersionEncode(s *packet, b []byte) (int, error) {
	if len(s.supportedVersions) == 0 {
		return 0, errors.New("supported versions must not be empty")
	}
	enc := newCodec(b)
	for _, v := range s.supportedVersions {
		if !enc.writeUint32(v) {
			return 0, errShortBuffer
		}
	}
	return enc.offset(), nil
}

func packetVersionDecode(s *packet, b []byte) (int, error) {
	dec := newCodec(b)
	var vers uint32
	if !dec.readUint32(&vers) {
		return 0, errInvalidPacket
	}
	s.supportedVersions = make([]uint32, 0, 1+dec.len()/4)
	s.supportedVersions = append(s.supportedVersions, vers)
	for dec.len() > 0 {
		if !dec.readUint32(&vers) {
			return dec.offset(), errInvalidPacket
		}
		s.supportedVersions = append(s.supportedVersions, vers)
	}
	return dec.offset(), nil
}

// NegotiateVersion writes version negotiation packet to b.
func NegotiateVersion(b, dcid, scid []byte) (int, error) {
	p := &packet{
		typ: packetTypeVersionNegotiation,
		header: Header{
			DCID: dcid,
			SCID: scid,
		},
		supportedVersions: []uint32{ProtocolVersion},
	}
	return p.encode(b)
}

// https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#packet-initial
// +-+-+-+-+-+-+-+-+
// |1|1| 0 |R R|P P|
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Version (32)                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | DCID Len (8)  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |               Destination Connection ID (0..160)            ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | SCID Len (8)  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                 Source Connection ID (0..160)               ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Token Length (i)                    ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                            Token (*)                        ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                           Length (i)                        ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Packet Number (8/16/24/32)               ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                          Payload (*)                        ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
func packetInitialEncodedLen(s *packet) int {
	return packetLongEncodedLen(s) +
		varintLen(uint64(len(s.token))) +
		len(s.token)
}

func packetInitialEncode(s *packet, b []byte) (int, error) {
	pnLen := packetNumberLenFromHeader(s.header.Flags)
	enc := newCodec(b)
	if !enc.writeVarint(uint64(len(s.token))) ||
		!enc.write(s.token) ||
		!enc.writeVarint(uint64(pnLen+s.payloadLen)) ||
		!enc.writePacketNumber(s.packetNumber, pnLen) {
		return 0, errShortBuffer
	}
	return enc.offset(), nil
}

func packetInitialDecode(s *packet, b []byte) (int, error) {
	dec := newCodec(b)
	// Token
	var length uint64
	if !dec.readVarint(&length) {
		return 0, errInvalidPacket
	}
	if s.token = dec.read(int(length)); s.token == nil {
		return 0, errInvalidPacket
	}
	// Remainder length includes Packet Number and Payload
	pnLen := packetNumberLenFromHeader(s.header.Flags)
	if !dec.readVarint(&length) || int(length) < pnLen {
		return 0, errInvalidPacket
	}
	if !dec.readPacketNumber(&s.packetNumber, pnLen) {
		return 0, errInvalidPacket
	}
	s.payloadLen = int(length) - pnLen
	if s.payloadLen < 0 || dec.len() < s.payloadLen {
		return 0, errInvalidPacket
	}
	return dec.offset(), nil
}

// Other long header packets:
//
// Zero RTT:
// +-+-+-+-+-+-+-+-+
// |1|1| 1 |R R|P P|
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Version (32)                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | DCID Len (8)  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |               Destination Connection ID (0..160)            ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | SCID Len (8)  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                 Source Connection ID (0..160)               ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                           Length (i)                        ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Packet Number (8/16/24/32)               ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                          Payload (*)                        ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Handshake:
// +-+-+-+-+-+-+-+-+
// |1|1| 2 |R R|P P|
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Version (32)                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | DCID Len (8)  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |               Destination Connection ID (0..160)            ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | SCID Len (8)  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                 Source Connection ID (0..160)               ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                           Length (i)                        ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Packet Number (8/16/24/32)               ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                          Payload (*)                        ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
func packetLongEncodedLen(s *packet) int {
	pnLen := packetNumberLen(s.packetNumber)
	return s.header.encodedLenLong() +
		varintLen(uint64(pnLen+s.payloadLen)) +
		pnLen +
		s.payloadLen
}

func packetLongEncode(s *packet, b []byte) (int, error) {
	pnLen := packetNumberLenFromHeader(s.header.Flags)
	enc := newCodec(b)
	if !enc.writeVarint(uint64(pnLen+s.payloadLen)) ||
		!enc.writePacketNumber(s.packetNumber, pnLen) {
		return 0, errShortBuffer
	}
	return enc.offset(), nil
}

func packetLongDecode(s *packet, b []byte) (int, error) {
	dec := newCodec(b)
	var length uint64
	// Remainder length includes Packet Number and Payload
	pnLen := packetNumberLenFromHeader(s.header.Flags)
	if !dec.readVarint(&length) || int(length) < pnLen {
		return 0, errInvalidPacket
	}
	if !dec.readPacketNumber(&s.packetNumber, pnLen) {
		return 0, errInvalidPacket
	}
	s.payloadLen = int(length) - pnLen
	if s.payloadLen < 0 || dec.len() < s.payloadLen {
		return 0, errInvalidPacket
	}
	return dec.offset(), nil
}

// +-+-+-+-+-+-+-+-+
// |1|1| 3 | Unused|
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Version (32)                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | DCID Len (8)  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |               Destination Connection ID (0..160)            ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | SCID Len (8)  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                 Source Connection ID (0..160)               ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | ODCID Len (8) |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          Original Destination Connection ID (0..160)        ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Retry Token (*)                      ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
func packetRetryEncodedLen(s *packet) int {
	return s.header.encodedLenLong() +
		1 + len(s.originalDestinationCID) +
		len(s.token)
}

func packetRetryEncode(s *packet, b []byte) (int, error) {
	if len(s.originalDestinationCID) > MaxCIDLength {
		return 0, errors.New("Original destination CID too long")
	}
	enc := newCodec(b)
	if !enc.writeByte(byte(len(s.originalDestinationCID))) ||
		!enc.write(s.originalDestinationCID) ||
		!enc.write(s.token) {
		return 0, errShortBuffer
	}
	return enc.offset(), nil
}

func packetRetryDecode(s *packet, b []byte) (int, error) {
	dec := newCodec(b)
	var length uint8
	if !dec.readByte(&length) || length > MaxCIDLength {
		return 0, errInvalidPacket
	}
	if s.originalDestinationCID = dec.read(int(length)); s.originalDestinationCID == nil {
		return 0, errInvalidPacket
	}
	s.token = b[dec.offset():]
	return len(b), nil
}

// Retry writes retry packet to b.
func Retry(b, dcid, scid, odcid, token []byte) (int, error) {
	p := &packet{
		typ: packetTypeRetry,
		header: Header{
			Version: ProtocolVersion,
			DCID:    dcid,
			SCID:    scid,
		},
		originalDestinationCID: odcid,
		token:                  token,
	}
	return p.encode(b)
}

// https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#short-header
// +-+-+-+-+-+-+-+-+
// |0|1|S|R|R|K|P P|
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                Destination Connection ID (0..160)           ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Packet Number (8/16/24/32)              ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Protected Payload (*)                   ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
func packetShortEncodedLen(s *packet) int {
	return s.header.encodedLenShort() +
		packetNumberLen(s.packetNumber) +
		s.payloadLen
}

func packetShortEncode(s *packet, b []byte) (int, error) {
	pnLen := packetNumberLenFromHeader(s.header.Flags)
	enc := newCodec(b)
	if !enc.writePacketNumber(s.packetNumber, pnLen) {
		return 0, errShortBuffer
	}
	return enc.offset(), nil
}

func packetShortDecode(s *packet, b []byte) (int, error) {
	pnLen := packetNumberLenFromHeader(s.header.Flags)
	dec := newCodec(b)
	dec.readPacketNumber(&s.packetNumber, pnLen)
	s.payloadLen = dec.len()
	return dec.offset(), nil
}

// DecodeHeader decodes QUIC header.
func DecodeHeader(b []byte, dcil int) (*Header, error) {
	h := &Header{
		dcil: uint8(dcil),
	}
	_, err := h.decode(b)
	if err != nil {
		return nil, err
	}
	return h, nil
}

// packetNumberWindow stores the availability of packet numbers received.
// Only 64 packet numbers can be tracked.
type packetNumberWindow struct {
	lower  uint64 // start number
	window uint64 // next 64 numbers availability are represented as bits of the window
}

func (s *packetNumberWindow) push(n uint64) {
	if n < s.lower {
		return
	}
	if n > s.upper() {
		// Shift window so that right end is the provided number
		diff := n - s.upper()
		s.lower += diff
		s.window <<= diff
	}
	mask := uint64(1) << (s.upper() - n)
	s.window |= mask
}

func (s *packetNumberWindow) contains(n uint64) bool {
	if n < s.lower {
		return true
	}
	if n > s.upper() {
		return false
	}
	mask := uint64(1) << (s.upper() - n)
	return s.window&mask != 0
}

func (s *packetNumberWindow) upper() uint64 {
	return s.lower + 63
}

func (s *packetNumberWindow) String() string {
	return fmt.Sprintf("%d+0x%x", s.lower, s.window)
}

type packetNumberSpace struct {
	largestRecvPacketNumber uint64
	largestRecvPacketTime   time.Time

	nextPacketNumber uint64
	// recvPacketNeedAck contains received packet numbers that need to acknowledge in ACK frame.
	// A packet number is added when receiving a packet is received and removed when receiving an ACK frame.
	recvPacketNeedAck rangeSet
	// recvPacketNumbers tracks packet numbers received.
	recvPacketNumbers packetNumberWindow
	// ackElicited indicates received packets need to be acknowledged.
	ackElicited      bool
	firstPacketAcked bool

	opener packetProtection
	sealer packetProtection

	cryptoStream Stream
}

func (s *packetNumberSpace) init() {
	s.cryptoStream.init(defaultStreamMaxData, defaultStreamMaxData)
}

func (s *packetNumberSpace) reset() {
	s.cryptoStream.reset()
	s.ackElicited = false
}

func (s *packetNumberSpace) drop() {
	*s = packetNumberSpace{}
}

func (s *packetNumberSpace) canEncrypt() bool {
	return s.sealer.aead != nil
}

// length of b and payloadLen must include overhead.
func (s *packetNumberSpace) encryptPacket(b []byte, p *packet) {
	payload := s.sealer.encryptPayload(b, p.packetNumber, p.payloadLen)
	if len(payload) != p.payloadLen {
		panic(fmt.Errorf("encrypted payload length %d does not equal %d", len(payload), p.payloadLen))
	}
	pnOffset := len(b) - p.payloadLen - packetNumberLen(p.packetNumber)
	s.sealer.encryptHeader(b, pnOffset)
}

func (s *packetNumberSpace) canDecrypt() bool {
	return s.opener.aead != nil
}

func (s *packetNumberSpace) decryptPacket(b []byte, p *packet) ([]byte, int, error) {
	pnOffset, err := p.packetNumberOffset(b, p.headerLen)
	if err != nil {
		return nil, 0, err
	}
	err = s.opener.decryptHeader(b, pnOffset)
	if err != nil {
		return nil, 0, err
	}
	p.header.Flags = b[0]
	n, err := p.decodeBody(b[p.headerLen:])
	if err != nil {
		return nil, 0, err
	}
	pnLen := packetNumberLenFromHeader(p.header.Flags)
	p.packetNumber = decodePacketNumber(s.largestRecvPacketNumber, p.packetNumber, pnLen)
	length := p.headerLen + n + p.payloadLen
	payload, err := s.opener.decryptPayload(b[:length], p.packetNumber, p.payloadLen)
	if err != nil {
		return nil, 0, err
	}
	return payload, length, nil
}

func (s *packetNumberSpace) onCryptoReceived(b []byte, offset uint64) {
	// Push the data to the stream so it can be re-ordered.
	s.cryptoStream.recv.push(b, offset, false)
}

func (s *packetNumberSpace) isPacketReceived(pn uint64) bool {
	return s.recvPacketNumbers.contains(pn)
}

func (s *packetNumberSpace) onPacketReceived(pn uint64, now time.Time) {
	if s.largestRecvPacketTime.IsZero() || s.recvPacketNeedAck.largest() < pn {
		s.largestRecvPacketTime = now
	}
	s.recvPacketNumbers.push(pn)
	s.recvPacketNeedAck.push(pn)
	if pn > s.largestRecvPacketNumber {
		s.largestRecvPacketNumber = pn
	}
}

func (s *packetNumberSpace) ready() bool {
	return s.ackElicited || s.cryptoStream.send.ready()
}

// https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#sample-packet-number-decoding
func decodePacketNumber(largest, truncated uint64, length int) uint64 {
	expected := largest + 1
	win := uint64(1) << (uint(length) * 8)
	hwin := win / 2
	// The incoming packet number should be greater than (expected - hwin)
	// and less than or equal to (expected + hwin)
	candidate := (expected & ^(win - 1)) | truncated
	if candidate+hwin <= expected {
		return candidate + win
	}
	if candidate > expected+hwin && candidate > win {
		return candidate - win
	}
	return candidate
}
