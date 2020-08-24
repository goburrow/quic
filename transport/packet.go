package transport

import (
	"fmt"
	"time"
)

type packetSpace uint8

const (
	packetSpaceInitial packetSpace = iota
	packetSpaceHandshake
	packetSpaceApplication
	packetSpaceCount
)

var packetSpaceNames = [...]string{
	packetSpaceInitial:     "initial",
	packetSpaceHandshake:   "handshake",
	packetSpaceApplication: "application_data",
	packetSpaceCount:       "",
}

func (s packetSpace) String() string {
	return packetSpaceNames[s]
}

type packetType uint8

const (
	packetTypeInitial packetType = iota
	packetTypeZeroRTT
	packetTypeHandshake
	packetTypeRetry
	packetTypeVersionNegotiation
	packetTypeOneRTT
)

var packetTypeNames = [...]string{
	packetTypeInitial:            "initial",
	packetTypeZeroRTT:            "0rtt",
	packetTypeHandshake:          "handshake",
	packetTypeRetry:              "retry",
	packetTypeVersionNegotiation: "version_negotiation",
	packetTypeOneRTT:             "1rtt",
}

func (s packetType) String() string {
	return packetTypeNames[s]
}

const (
	maxPacketNumberLength  = 4
	minPacketPayloadLength = 4
)

func isLongHeader(b byte) bool {
	return b&0x80 != 0
}

func packetTypeFromLongHeader(b uint8) packetType {
	switch (b >> 4) & 0x3 {
	case 0:
		return packetTypeInitial
	case 1:
		return packetTypeZeroRTT
	case 2:
		return packetTypeHandshake
	case 3:
		return packetTypeRetry
	default:
		panic("unreachable")
	}
}

func packetTypeFromSpace(space packetSpace) packetType {
	switch space {
	case packetSpaceInitial:
		return packetTypeInitial
	case packetSpaceHandshake:
		return packetTypeHandshake
	case packetSpaceApplication:
		return packetTypeOneRTT
	default:
		panic("unsupported packet space")
	}
}

// Packet number length bits are same position in both short and long header packet.
func packetNumberLenFromHeader(b uint8) int {
	return int(b&0x03) + 1
}

func packetNumberLenHeaderFlag(n int) uint8 {
	return uint8(n - 1)
}

// packetHeader is the version-independent header of QUIC packets.
// https://quicwg.org/base-drafts/draft-ietf-quic-invariants.html#name-quic-packet-headers
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
type packetHeader struct {
	flags   uint8
	version uint32
	dcid    []byte
	scid    []byte

	dcil uint8 // Used when decoding
}

func (s *packetHeader) encodedLen() int {
	if isLongHeader(s.flags) {
		return s.encodedLenLong()
	}
	return s.encodedLenShort()
}

func (s *packetHeader) encodedLenLong() int {
	return 7 + len(s.dcid) + len(s.scid)
}

func (s *packetHeader) encodedLenShort() int {
	return 1 + len(s.dcid)
}

func (s *packetHeader) encode(b []byte) (int, error) {
	if len(s.dcid) > MaxCIDLength || len(s.scid) > MaxCIDLength {
		return 0, errInvalidPacket
	}
	// Buffer length checking is done in packet encoder
	enc := newCodec(b)
	ok := enc.writeByte(s.flags)
	if !ok {
		return 0, errShortBuffer
	}
	if isLongHeader(s.flags) {
		ok = enc.writeUint32(s.version) &&
			enc.writeByte(uint8(len(s.dcid))) &&
			enc.write(s.dcid) &&
			enc.writeByte(uint8(len(s.scid))) &&
			enc.write(s.scid)
	} else {
		ok = enc.write(s.dcid)
	}
	if !ok {
		return 0, errShortBuffer
	}
	return enc.offset(), nil
}

func (s *packetHeader) decode(b []byte) (int, error) {
	dec := newCodec(b)
	if !dec.readByte(&s.flags) {
		return 0, errInvalidPacket
	}
	if isLongHeader(s.flags) {
		if !dec.readUint32(&s.version) {
			return 0, errInvalidPacket
		}
		// DCID
		var length uint8
		ok := dec.readByte(&length) && dec.read(&s.dcid, int(length))
		if !ok || length > MaxCIDLength {
			return 0, errInvalidPacket
		}
		// SCID
		ok = dec.readByte(&length) && dec.read(&s.scid, int(length))
		if !ok || length > MaxCIDLength {
			return 0, errInvalidPacket
		}
	} else {
		if !dec.read(&s.dcid, int(s.dcil)) {
			return 0, errInvalidPacket
		}
	}
	return dec.offset(), nil
}

func (s *packetHeader) String() string {
	return fmt.Sprintf("packet_type=%s version=%d dcid=%x scid=%x", s.packetType(), s.version, s.dcid, s.scid)
}

// packetType returns type of the packet basing on header flags.
func (s *packetHeader) packetType() packetType {
	if isLongHeader(s.flags) {
		if s.version == 0 {
			return packetTypeVersionNegotiation
		}
		return packetTypeFromLongHeader(s.flags)
	}
	return packetTypeOneRTT
}

// packet is an internal structure for all QUIC packet types.
type packet struct {
	typ       packetType
	header    packetHeader
	headerLen int // decoded header length (set by decodeHeader)

	supportedVersions []uint32 // Only in Version negotiation
	token             []byte   // Only in Initial and Retry

	packetNumber uint64
	packetSize   int
	payloadLen   int
}

func (s *packet) encodedLen() int {
	switch s.typ {
	case packetTypeInitial:
		return s.encodedLenInitial()
	case packetTypeZeroRTT, packetTypeHandshake:
		return s.encodedLenLong()
	case packetTypeRetry:
		return s.encodedLenRetry()
	case packetTypeVersionNegotiation:
		return s.encodedLenVersionNegotiation()
	case packetTypeOneRTT:
		return s.encodedLenShort()
	default:
		panic("unreachable")
	}
}

func (s *packet) encode(b []byte) (int, error) {
	// Header
	switch s.typ {
	case packetTypeInitial:
		s.header.flags = 0xc0 | packetNumberLenHeaderFlag(packetNumberLen(s.packetNumber))
	case packetTypeZeroRTT:
		s.header.flags = 0xd0 | packetNumberLenHeaderFlag(packetNumberLen(s.packetNumber))
	case packetTypeHandshake:
		s.header.flags = 0xe0 | packetNumberLenHeaderFlag(packetNumberLen(s.packetNumber))
	case packetTypeRetry:
		// XXX: Unused bits are suggested being random
		s.header.flags = 0xf0
	case packetTypeVersionNegotiation:
		s.header.flags = 0xc0
	case packetTypeOneRTT:
		s.header.flags = 0x40 | packetNumberLenHeaderFlag(packetNumberLen(s.packetNumber))
	}
	n, err := s.header.encode(b)
	if err != nil {
		return 0, err
	}
	// Body
	b = b[n:]
	var m int
	switch s.typ {
	case packetTypeInitial:
		m, err = s.encodeInitial(b)
	case packetTypeZeroRTT, packetTypeHandshake:
		m, err = s.encodeLong(b)
	case packetTypeRetry:
		m, err = s.encodeRetry(b)
	case packetTypeVersionNegotiation:
		m, err = s.encodeVersionNegotiation(b)
	case packetTypeOneRTT:
		m, err = s.encodeShort(b)
	default:
		panic("unreachable")
	}
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
	s.headerLen = n
	s.typ = s.header.packetType()
	return n, nil
}

// decodeBody decodes packet until payload. It returns payload offset relatively to header.
// b is entire packet, including header. decodeHeader must be called before so that headerLen is set.
func (s *packet) decodeBody(b []byte) (int, error) {
	b = b[s.headerLen:]
	switch s.typ {
	case packetTypeInitial:
		return s.decodeInitial(b)
	case packetTypeZeroRTT, packetTypeHandshake:
		return s.decodeLong(b)
	case packetTypeRetry:
		return s.decodeRetry(b)
	case packetTypeVersionNegotiation:
		return s.decodeVersionNegotiation(b)
	case packetTypeOneRTT:
		return s.decodeShort(b)
	default:
		panic("unreachable")
	}
}

// packetNumberOffset returns index offset of packet number for decrypting.
// decodeHeader must be called before so that headerLen is set.
func (s *packet) packetNumberOffset(b []byte) (int, error) {
	if s.typ == packetTypeOneRTT {
		return s.headerLen, nil
	}
	var length uint64
	dec := newCodec(b[s.headerLen:])
	if s.typ == packetTypeInitial {
		// Skip token
		ok := dec.readVarint(&length) && dec.skip(int(length))
		if !ok {
			return 0, errInvalidPacket
		}
	}
	// Remainder Length
	if !dec.readVarint(&length) {
		return 0, errInvalidPacket
	}
	return s.headerLen + dec.offset(), nil
}

func (s *packet) String() string {
	switch s.typ {
	case packetTypeInitial, packetTypeRetry:
		return fmt.Sprintf("packet_type=%s version=%d dcid=%x scid=%x token=%x packet_number=%d",
			s.typ, s.header.version, s.header.dcid, s.header.scid, s.token, s.packetNumber)
	case packetTypeOneRTT:
		return fmt.Sprintf("packet_type=%s dcid=%x packet_number=%d",
			s.typ, s.header.dcid, s.packetNumber)
	default:
		return fmt.Sprintf("packet_type=%s version=%d dcid=%x scid=%x packet_number=%d",
			s.typ, s.header.version, s.header.dcid, s.header.scid, s.packetNumber)
	}
}

// Header is for decoding public information of a QUIC packet.
// This data allows to process packet prior to decryption.
type Header struct {
	Type    string
	Flags   byte
	Version uint32
	DCID    []byte
	SCID    []byte
	Token   []byte // Only in Initial and Retry packet
}

// Decode decodes public information from a QUIC packet.
// dcil is the length of connection id in short header packets.
// Note: all resulted slices (CIDs) are references to data in b so they will be invalid
// when b is modified.
func (s *Header) Decode(b []byte, dcil int) (int, error) {
	h := packetHeader{
		dcil: uint8(dcil),
	}
	n, err := h.decode(b)
	if err != nil {
		return 0, err
	}
	typ := h.packetType()
	s.Type = typ.String()
	s.Flags = h.flags
	s.Version = h.version
	s.DCID = h.dcid
	s.SCID = h.scid
	// Try to decode token
	dec := newCodec(b[n:])
	switch typ {
	case packetTypeInitial:
		// See decodeInitial
		var length uint64
		ok := dec.readVarint(&length) && dec.read(&s.Token, int(length))
		if !ok {
			return 0, errInvalidPacket
		}
	case packetTypeRetry:
		// See decodeRetry
		length := dec.len() - retryIntegrityTagLen
		if length < 0 || !dec.read(&s.Token, length) {
			return 0, errInvalidPacket
		}
	}
	return n + dec.offset(), nil
}

func (s *Header) String() string {
	return fmt.Sprintf("packet_type=%s version=%d dcid=%x scid=%x token=%x",
		s.Type, s.Version, s.DCID, s.SCID, s.Token)
}

// Version Negotiation Packet: https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#packet-version
//
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
func (s *packet) encodedLenVersionNegotiation() int {
	return s.header.encodedLenLong() + 4*len(s.supportedVersions)
}

func (s *packet) encodeVersionNegotiation(b []byte) (int, error) {
	if len(s.supportedVersions) == 0 {
		return 0, errInvalidPacket
	}
	enc := newCodec(b)
	for _, v := range s.supportedVersions {
		if !enc.writeUint32(v) {
			return 0, errShortBuffer
		}
	}
	return enc.offset(), nil
}

func (s *packet) decodeVersionNegotiation(b []byte) (int, error) {
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
	if len(dcid) > MaxCIDLength || len(scid) > MaxCIDLength {
		return 0, newError(ProtocolViolation, "cid too long")
	}
	p := packet{
		typ: packetTypeVersionNegotiation,
		header: packetHeader{
			dcid: dcid,
			scid: scid,
		},
		supportedVersions: []uint32{ProtocolVersion},
	}
	return p.encode(b)
}

// Initial Packet: https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#packet-initial
//
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
func (s *packet) encodedLenInitial() int {
	return s.encodedLenLong() +
		varintLen(uint64(len(s.token))) +
		len(s.token)
}

func (s *packet) encodeInitial(b []byte) (int, error) {
	pnLen := packetNumberLenFromHeader(s.header.flags)
	enc := newCodec(b)
	ok := enc.writeVarint(uint64(len(s.token))) &&
		enc.write(s.token) &&
		enc.writeVarint(uint64(pnLen+s.payloadLen)) &&
		enc.writePacketNumber(s.packetNumber, pnLen)
	if !ok {
		return 0, errShortBuffer
	}
	return enc.offset(), nil
}

func (s *packet) decodeInitial(b []byte) (int, error) {
	dec := newCodec(b)
	// Token
	var length uint64
	ok := dec.readVarint(&length) &&
		dec.read(&s.token, int(length))
	if !ok {
		return 0, errInvalidPacket
	}
	// Remainder length includes Packet Number and Payload
	pnLen := packetNumberLenFromHeader(s.header.flags)
	ok = dec.readVarint(&length) &&
		dec.readPacketNumber(&s.packetNumber, pnLen)
	if !ok || int(length) < pnLen {
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
func (s *packet) encodedLenLong() int {
	pnLen := packetNumberLen(s.packetNumber)
	return s.header.encodedLenLong() +
		varintLen(uint64(pnLen+s.payloadLen)) +
		pnLen +
		s.payloadLen
}

func (s *packet) encodeLong(b []byte) (int, error) {
	pnLen := packetNumberLenFromHeader(s.header.flags)
	enc := newCodec(b)
	ok := enc.writeVarint(uint64(pnLen+s.payloadLen)) &&
		enc.writePacketNumber(s.packetNumber, pnLen)
	if !ok {
		return 0, errShortBuffer
	}
	return enc.offset(), nil
}

func (s *packet) decodeLong(b []byte) (int, error) {
	dec := newCodec(b)
	var length uint64
	// Remainder length includes Packet Number and Payload
	pnLen := packetNumberLenFromHeader(s.header.flags)
	ok := dec.readVarint(&length) &&
		dec.readPacketNumber(&s.packetNumber, pnLen)
	if !ok || int(length) < pnLen {
		return 0, errInvalidPacket
	}
	s.payloadLen = int(length) - pnLen
	if s.payloadLen < 0 || dec.len() < s.payloadLen {
		return 0, errInvalidPacket
	}
	return dec.offset(), nil
}

// Retry Packet: https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#packet-retry
//
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
// |                        Retry Token (*)                      ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                                                               +
// |                                                               |
// +                   Retry Integrity Tag (128)                   +
// |                                                               |
// +                                                               +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
func (s *packet) encodedLenRetry() int {
	return s.header.encodedLenLong() +
		len(s.token) + retryIntegrityTagLen
}

// encodeRetry does not add Integrity tag.
func (s *packet) encodeRetry(b []byte) (int, error) {
	enc := newCodec(b)
	if !enc.write(s.token) {
		return 0, errShortBuffer
	}
	return enc.offset(), nil
}

// decodeRetry does not decode Integrity tag.
func (s *packet) decodeRetry(b []byte) (int, error) {
	dec := newCodec(b)
	length := dec.len() - retryIntegrityTagLen
	if length < 0 || !dec.read(&s.token, length) {
		return 0, errInvalidPacket
	}
	return dec.offset(), nil
}

// Retry Pseudo-Packet: https://quicwg.org/base-drafts/draft-ietf-quic-tls.html#name-retry-packet-integrity
//
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | ODCID Len (8) |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          Original Destination Connection ID (0..160)        ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
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
// |                        Retry Token (*)                      ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// Retry writes retry packet to b.
func Retry(b, dcid, scid, odcid, token []byte) (int, error) {
	if len(dcid) > MaxCIDLength || len(scid) > MaxCIDLength || len(odcid) > MaxCIDLength {
		return 0, newError(ProtocolViolation, "cid too long")
	}
	// Use the provided buffer to write Retry Pseudo-Packet, which is computed by taking the transmitted Retry packet,
	// removing the Retry Integrity Tag and prepending the ODCID.
	enc := newCodec(b)
	ok := enc.writeByte(uint8(len(odcid))) && enc.write(odcid)
	if !ok {
		return 0, errShortBuffer
	}
	offset := enc.offset()
	p := packet{
		typ: packetTypeRetry,
		header: packetHeader{
			version: ProtocolVersion,
			dcid:    dcid,
			scid:    scid,
		},
		token: token,
	}
	n, err := p.encode(b[offset:])
	if err != nil {
		return 0, err
	}
	out, err := computeRetryIntegrity(b[:offset+n])
	if err != nil {
		return 0, err
	}
	if len(out) != offset+n+retryIntegrityTagLen {
		panic("invalid length of integrity tag generated")
	}
	n = copy(b, out[offset:])
	return n, nil
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
func (s *packet) encodedLenShort() int {
	return s.header.encodedLenShort() +
		packetNumberLen(s.packetNumber) +
		s.payloadLen
}

func (s *packet) encodeShort(b []byte) (int, error) {
	pnLen := packetNumberLenFromHeader(s.header.flags)
	enc := newCodec(b)
	if !enc.writePacketNumber(s.packetNumber, pnLen) {
		return 0, errShortBuffer
	}
	return enc.offset(), nil
}

func (s *packet) decodeShort(b []byte) (int, error) {
	pnLen := packetNumberLenFromHeader(s.header.flags)
	dec := newCodec(b)
	dec.readPacketNumber(&s.packetNumber, pnLen)
	s.payloadLen = dec.len()
	return dec.offset(), nil
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
	// A packet number is added when receiving a packet and removed when receiving an ACK frame.
	recvPacketNeedAck rangeSet
	// recvPacketNumbers tracks packet numbers received.
	recvPacketNumbers packetNumberWindow
	// ackElicited indicates received packets need to be acknowledged.
	ackElicited bool

	opener packetProtection
	sealer packetProtection

	cryptoStream Stream
}

func (s *packetNumberSpace) init() {
	s.cryptoStream.init(true, true)
	s.cryptoStream.flow.init(cryptoMaxData, cryptoMaxData)
}

func (s *packetNumberSpace) reset() {
	s.cryptoStream = Stream{}
	s.init()
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
		panic("encrypted payload length not expected")
	}
	pnOffset := len(b) - p.payloadLen - packetNumberLen(p.packetNumber)
	s.sealer.encryptHeader(b, pnOffset)
}

func (s *packetNumberSpace) canDecrypt() bool {
	return s.opener.aead != nil
}

func (s *packetNumberSpace) decryptPacket(b []byte, p *packet) ([]byte, error) {
	pnOffset, err := p.packetNumberOffset(b)
	if err != nil {
		return nil, err
	}
	err = s.opener.decryptHeader(b, pnOffset)
	if err != nil {
		return nil, err
	}
	p.header.flags = b[0]
	n, err := p.decodeBody(b)
	if err != nil {
		return nil, err
	}
	pnLen := packetNumberLenFromHeader(p.header.flags)
	p.packetNumber = decodePacketNumber(s.largestRecvPacketNumber, p.packetNumber, pnLen)
	p.packetSize = p.headerLen + n + p.payloadLen
	payload, err := s.opener.decryptPayload(b[:p.packetSize], p.packetNumber, p.payloadLen)
	if err != nil {
		return nil, err
	}
	return payload, nil
}

func (s *packetNumberSpace) isPacketReceived(pn uint64) bool {
	return s.recvPacketNumbers.contains(pn)
}

func (s *packetNumberSpace) onPacketReceived(pn uint64, now time.Time) {
	if s.largestRecvPacketTime.IsZero() || s.recvPacketNeedAck.largest() < pn {
		s.largestRecvPacketTime = now
	}
	s.recvPacketNumbers.push(pn)
	s.recvPacketNeedAck.push(pn, pn)
	if pn > s.largestRecvPacketNumber {
		s.largestRecvPacketNumber = pn
	}
}

func (s *packetNumberSpace) ready() bool {
	return s.ackElicited || s.cryptoStream.isFlushable()
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
