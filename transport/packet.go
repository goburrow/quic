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
	if len(s.dcid) > MaxCIDLength {
		return 0, errors.New("destination CID too long")
	}
	if len(s.scid) > MaxCIDLength {
		return 0, errors.New("source CID too long")
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
		if !dec.readByte(&length) || length > MaxCIDLength {
			return 0, errInvalidPacket
		}
		if s.dcid = dec.read(int(length)); s.dcid == nil {
			return 0, errInvalidPacket
		}
		// SCID
		if !dec.readByte(&length) || length > MaxCIDLength {
			return 0, errInvalidPacket
		}
		if s.scid = dec.read(int(length)); s.scid == nil {
			return 0, errInvalidPacket
		}
	} else {
		if s.dcid = dec.read(int(s.dcil)); s.dcid == nil {
			return 0, errInvalidPacket
		}
	}
	return dec.offset(), nil
}

func (s *packetHeader) String() string {
	return fmt.Sprintf("type=%s version=%d dcid=%x scid=%x", s.packetType(), s.version, s.dcid, s.scid)
}

// packetType returns type of the packet basing on header flags.
func (s *packetHeader) packetType() packetType {
	if isLongHeader(s.flags) {
		if s.version == 0 {
			return packetTypeVersionNegotiation
		}
		return packetTypeFromLongHeader(s.flags)
	}
	return packetTypeShort
}

// packet is an internal structure for all QUIC packet types.
type packet struct {
	typ       packetType
	header    packetHeader
	headerLen int // decoded header length (set by decodeHeader)

	supportedVersions []uint32 // Only in Version negotiation
	token             []byte   // Only in Initial and Retry

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
	case packetTypeShort:
		s.header.flags = 0x00 | packetNumberLenHeaderFlag(packetNumberLen(s.packetNumber))
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
	s.headerLen = n
	s.typ = s.header.packetType()
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
	case packetTypeInitial, packetTypeRetry:
		return fmt.Sprintf("type=%s version=%d dcid=%x scid=%x token=%x number=%d",
			s.typ, s.header.version, s.header.dcid, s.header.scid, s.token, s.packetNumber)
	case packetTypeShort:
		return fmt.Sprintf("type=%s dcid=%x number=%d",
			s.typ, s.header.dcid, s.packetNumber)
	default:
		return fmt.Sprintf("type=%s version=%d dcid=%x scid=%x number=%d",
			s.typ, s.header.version, s.header.dcid, s.header.scid, s.packetNumber)
	}
}

// Header is for decoding public information of a QUIC packet.
// This data allows to process packet prior to decryption.
type Header struct {
	Type    int // XXX: Need to export packetType?
	Flags   byte
	Version uint32
	DCID    []byte
	SCID    []byte
	Token   []byte // Only in Initial and Retry packet
}

// Decode decodes public information from a QUIC packet.
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
	s.Type = int(typ)
	s.Flags = h.flags
	s.Version = h.version
	s.DCID = h.dcid
	s.SCID = h.scid
	// Try to decode token
	dec := newCodec(b[n:])
	switch typ {
	case packetTypeInitial:
		// See packetInitialDecode
		var length uint64
		if !dec.readVarint(&length) {
			return 0, errInvalidPacket
		}
		if s.Token = dec.read(int(length)); s.Token == nil {
			return 0, errInvalidPacket
		}
	case packetTypeRetry:
		// See packetRetryDecode
		length := dec.len() - retryIntegrityTagLen
		if length < 0 {
			return 0, errInvalidPacket
		}
		s.Token = dec.read(length)
	}
	return n + dec.offset(), nil
}

func (s *Header) String() string {
	return fmt.Sprintf("type=%s version=%d dcid=%x scid=%x token=%x",
		packetType(s.Type), s.Version, s.DCID, s.SCID, s.Token)
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
func packetInitialEncodedLen(s *packet) int {
	return packetLongEncodedLen(s) +
		varintLen(uint64(len(s.token))) +
		len(s.token)
}

func packetInitialEncode(s *packet, b []byte) (int, error) {
	pnLen := packetNumberLenFromHeader(s.header.flags)
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
	pnLen := packetNumberLenFromHeader(s.header.flags)
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
	pnLen := packetNumberLenFromHeader(s.header.flags)
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
	pnLen := packetNumberLenFromHeader(s.header.flags)
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
func packetRetryEncodedLen(s *packet) int {
	return s.header.encodedLenLong() +
		len(s.token) + retryIntegrityTagLen
}

// packetRetryEncode does not add Integrity tag.
func packetRetryEncode(s *packet, b []byte) (int, error) {
	enc := newCodec(b)
	if !enc.write(s.token) {
		return 0, errShortBuffer
	}
	return enc.offset(), nil
}

// packetRetryDecode does not decode Integrity tag.
func packetRetryDecode(s *packet, b []byte) (int, error) {
	dec := newCodec(b)
	tokenLen := dec.len() - retryIntegrityTagLen
	if tokenLen < 0 {
		return 0, errInvalidPacket
	}
	s.token = dec.read(tokenLen)
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
	if len(odcid) > MaxCIDLength {
		return 0, errInvalidPacket
	}
	// Use the provided buffer to write Retry Pseudo-Packet, which is computed by taking the transmitted Retry packet,
	// removing the Retry Integrity Tag and prepending the ODCID.
	enc := newCodec(b)
	if !enc.writeByte(byte(len(odcid))) || !enc.write(odcid) {
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
		return 0, fmt.Errorf("invalid integrity tag length generated: %d", len(out)-offset-n)
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
func packetShortEncodedLen(s *packet) int {
	return s.header.encodedLenShort() +
		packetNumberLen(s.packetNumber) +
		s.payloadLen
}

func packetShortEncode(s *packet, b []byte) (int, error) {
	pnLen := packetNumberLenFromHeader(s.header.flags)
	enc := newCodec(b)
	if !enc.writePacketNumber(s.packetNumber, pnLen) {
		return 0, errShortBuffer
	}
	return enc.offset(), nil
}

func packetShortDecode(s *packet, b []byte) (int, error) {
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
	p.header.flags = b[0]
	n, err := p.decodeBody(b[p.headerLen:])
	if err != nil {
		return nil, 0, err
	}
	pnLen := packetNumberLenFromHeader(p.header.flags)
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
