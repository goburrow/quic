package transport

import (
	"encoding/binary"
)

type encoder interface {
	encode(b []byte) (int, error)
}

type decoder interface {
	decode(b []byte) (int, error)
}

type codec struct {
	b []byte // input slice
	i int    // read/write index
}

func newCodec(b []byte) codec {
	return codec{b: b}
}

func (s *codec) write(b []byte) bool {
	n := copy(s.b[s.i:], b)
	if n < len(b) {
		return false
	}
	s.i += n
	return true
}

func (s *codec) read(b *[]byte, n int) bool {
	n += s.i
	if n > len(s.b) {
		return false
	}
	*b = s.b[s.i:n]
	s.i = n
	return true
}

func (s *codec) writeByte(b byte) bool {
	if s.i+1 > len(s.b) {
		return false
	}
	s.b[s.i] = b
	s.i++
	return true
}

func (s *codec) readByte(v *byte) bool {
	if s.i >= len(s.b) {
		return false
	}
	*v = s.b[s.i]
	s.i++
	return true
}

func (s *codec) writeUint32(v uint32) bool {
	if s.i+4 > len(s.b) {
		return false
	}
	binary.BigEndian.PutUint32(s.b[s.i:], v)
	s.i += 4
	return true
}

func (s *codec) readUint32(v *uint32) bool {
	var b []byte
	if !s.read(&b, 4) {
		return false
	}
	*v = binary.BigEndian.Uint32(b)
	return true
}

func (s *codec) writeVarint(v uint64) bool {
	n := varintLen(v)
	if s.i+n > len(s.b) {
		return false
	}
	putVarint(s.b[s.i:], v, n)
	s.i += n
	return true
}

func (s *codec) readVarint(v *uint64) bool {
	if s.i >= len(s.b) {
		return false
	}
	n := getVarint(s.b[s.i:], v)
	if n == 0 {
		return false
	}
	s.i += n
	return true
}

func (s *codec) writePacketNumber(v uint64, length int) bool {
	if s.i+length > len(s.b) {
		return false
	}
	putPacketNumber(s.b[s.i:], v, length)
	s.i += length
	return true
}

func (s *codec) readPacketNumber(v *uint64, length int) bool {
	var b []byte
	if !s.read(&b, length) {
		return false
	}
	*v = getPacketNumber(b, length)
	return true
}

func (s *codec) skip(n int) bool {
	if s.i+n > len(s.b) {
		return false
	}
	s.i += n
	return true
}

// len returns number of unread bytes
func (s *codec) len() int {
	i := len(s.b) - s.i
	if i < 0 {
		return 0
	}
	return i
}

func (s *codec) offset() int {
	return s.i
}

// https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#integer-encoding
func varintLen(v uint64) int {
	if v>>14 == 0 {
		if v>>6 == 0 {
			return 1
		}
		return 2
	}
	if v>>30 == 0 {
		return 4
	}
	return 8
}

func putVarint(b []byte, v uint64, n int) {
	switch n {
	case 1:
		b[0] = uint8(v)
	case 2:
		b[1] = uint8(v)
		b[0] = uint8(v>>8) | 0x40
	case 4:
		b[3] = uint8(v)
		b[2] = uint8(v >> 8)
		b[1] = uint8(v >> 16)
		b[0] = uint8(v>>24) | 0x80
	case 8:
		b[7] = uint8(v)
		b[6] = uint8(v >> 8)
		b[5] = uint8(v >> 16)
		b[4] = uint8(v >> 24)
		b[3] = uint8(v >> 32)
		b[2] = uint8(v >> 40)
		b[1] = uint8(v >> 48)
		b[0] = uint8(v>>56) | 0xc0
	}
}

func appendVarint(b []byte, v uint64, n int) []byte {
	switch n {
	case 1:
		b = append(b, uint8(v))
	case 2:
		b = append(b, uint8(v>>8)|0x40, uint8(v))
	case 4:
		b = append(b, uint8(v>>24)|0x80, uint8(v>>16), uint8(v>>8), uint8(v))
	case 8:
		b = append(b, uint8(v>>56)|0xc0, uint8(v>>48), uint8(v>>40), uint8(v>>32),
			uint8(v>>24), uint8(v>>16), uint8(v>>8), uint8(v))
	}
	return b
}

func getVarint(b []byte, v *uint64) int {
	switch b[0] >> 6 {
	case 0:
		*v = uint64(b[0] & 0x3f)
		return 1
	case 1:
		if len(b) < 2 {
			return 0
		}
		*v = uint64(b[1]) | uint64(b[0]&0x3f)<<8
		return 2
	case 2:
		if len(b) < 4 {
			return 0
		}
		*v = uint64(b[3]) | uint64(b[2])<<8 | uint64(b[1])<<16 | uint64(b[0]&0x3f)<<24
		return 4
	case 3:
		if len(b) < 8 {
			return 0
		}
		*v = uint64(b[7]) | uint64(b[6])<<8 | uint64(b[5])<<16 | uint64(b[4])<<24 |
			uint64(b[3])<<32 | uint64(b[2])<<40 | uint64(b[1])<<48 | uint64(b[0]&0x3f)<<56
		return 8
	default:
		panic("unreachable")
	}
}

func packetNumberLen(v uint64) int {
	if v>>16 == 0 {
		if v>>8 == 0 {
			return 1
		}
		return 2
	}
	if v>>24 == 0 {
		return 3
	}
	return 4
}

func getPacketNumber(b []byte, length int) uint64 {
	switch length {
	case 1:
		return uint64(b[0])
	case 2:
		return uint64(b[1]) | uint64(b[0])<<8
	case 3:
		return uint64(b[2]) | uint64(b[1])<<8 | uint64(b[0])<<16
	case 4:
		return uint64(b[3]) | uint64(b[2])<<8 | uint64(b[1])<<16 | uint64(b[0])<<24
	default:
		panic("unexpected packet number length")
	}
}

func putPacketNumber(b []byte, v uint64, length int) {
	switch length {
	case 1:
		b[0] = uint8(v)
	case 2:
		b[1] = uint8(v)
		b[0] = uint8(v >> 8)
	case 3:
		b[2] = uint8(v)
		b[1] = uint8(v >> 8)
		b[0] = uint8(v >> 16)
	case 4:
		b[3] = uint8(v)
		b[2] = uint8(v >> 8)
		b[1] = uint8(v >> 16)
		b[0] = uint8(v >> 24)
	default:
		panic("unexpected packet number length")
	}
}
