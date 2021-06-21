package transport

import (
	"bytes"
	"testing"
)

func TestCodecDecode(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5, 0xc6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	x := codecTest{t: t, c: newCodec(b)}
	x.assertOffset(0)
	x.assertLen(len(b))
	var (
		v   []byte
		v8  byte
		v32 uint32
		v64 uint64
	)
	if !x.c.readByte(&v8) || v8 != 1 {
		t.Fatalf("read byte: 0x%x", v)
	}
	x.assertOffset(1)
	x.assertLen(len(b) - 1)

	if !x.c.readUint32(&v32) || v32 != 0x02030405 {
		t.Fatalf("read uint32: 0x%x", v)
	}
	x.assertOffset(5)
	x.assertLen(len(b) - 5)

	if !x.c.readVarint(&v64) || v64 != 0x060708090a0b0c0d {
		t.Fatalf("read varint: 0x%x", v)
	}
	x.assertOffset(13)
	x.assertLen(len(b) - 13)

	if !x.c.read(&v, 3) || !bytes.Equal(v, b[13:16]) {
		t.Fatalf("read: %x, actual: %x", v, b[13:16])
	}
	x.assertOffset(16)
	x.assertLen(len(b) - 16)

	if x.c.read(&v, 2) || x.c.readByte(&v8) || x.c.readUint32(&v32) || x.c.readVarint(&v64) {
		t.Fatal("read should fail")
	}
}

func TestCodecEncode(t *testing.T) {
	b := make([]byte, 16)
	x := codecTest{t: t, c: newCodec(b)}
	if !x.c.writeByte(1) {
		t.Fatalf("write byte: %x", b)
	}
	x.assertOffset(1)

	if !x.c.writeUint32(0x02030405) {
		t.Fatalf("write byte: %x", b)
	}
	x.assertOffset(5)

	if !x.c.writeVarint(0x060708090a0b0c0d) {
		t.Fatalf("write varint: %x", b)
	}
	x.assertOffset(13)

	if !x.c.write([]byte{0xe, 0xf, 0x10}) {
		t.Fatalf("write: %x", b)
	}
	x.assertOffset(16)

	expected := []byte{1, 2, 3, 4, 5, 0xc6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	if !bytes.Equal(expected, b) {
		t.Fatalf("expect encode: %x, actual: %x", expected, b)
	}

	if x.c.write([]byte{1}) || x.c.writeByte(1) || x.c.writeUint32(1) || x.c.writeVarint(1) {
		t.Fatalf("write should fail")
	}
}

func TestVarintDecode(t *testing.T) {
	b := []byte{0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c}
	var v uint64
	n := getVarint(b, &v)
	if n != 8 || v != 151288809941952652 {
		t.Fatalf("expect decode: %v %v, actual: %v %v", 8, 151288809941952652, n, v)
	}
	n = getVarint(b[:len(b)-1], &v)
	if n != 0 {
		t.Fatalf("expect decode: %v, actual: %v", 0, n)
	}
	b = []byte{0x9d, 0x7f, 0x3e, 0x7d}
	n = getVarint(b, &v)
	if n != 4 || v != 494878333 {
		t.Fatalf("expect decode: %v %v, actual: %v %v", 4, 494878333, n, v)
	}
	n = getVarint(b[:len(b)-1], &v)
	if n != 0 {
		t.Fatalf("expect decode: %v, actual: %v", 0, n)
	}
	b = []byte{0x40, 0x25}
	n = getVarint(b, &v)
	if n != 2 || v != 37 {
		t.Fatalf("expect decode: %v %v, actual: %v %v", 2, 37, n, v)
	}
	n = getVarint(b[:len(b)-1], &v)
	if n != 0 {
		t.Fatalf("expect decode: %v, actual: %v", 0, n)
	}
	b = []byte{0x25}
	n = getVarint(b, &v)
	if n != 1 || v != 37 {
		t.Fatalf("expect decode: %v %v, actual: %v %v", 1, 37, n, v)
	}
}

func TestVarintCodec(t *testing.T) {
	data := []struct {
		v uint64
		o int
	}{
		{0, 1},
		{63, 1},
		{64, 2},
		{16383, 2},
		{16384, 4},
		{1073741823, 4},
		{1073741824, 8},
		{4611686018427387903, 8},
	}
	b := make([]byte, 8)
	x := codecTest{t: t}
	for _, d := range data {
		x.c = newCodec(b)
		if !x.c.writeVarint(d.v) {
			t.Fatalf("write varint: %x", b)
		}
		x.assertOffset(d.o)

		x.c = newCodec(b)
		var v uint64
		if !x.c.readVarint(&v) {
			t.Fatalf("read varint: %x", b)
		}
		if v != d.v {
			t.Fatalf("expect: %x, actual: %x", d.v, v)
		}
	}
}

type codecTest struct {
	t *testing.T
	c codec
}

func (t *codecTest) assertLen(n int) {
	if t.c.len() != n {
		t.t.Fatalf("expect length: %d, actual: %d", n, t.c.len())
	}
}

func (t *codecTest) assertOffset(n int) {
	if t.c.offset() != n {
		t.t.Fatalf("expect offset: %d, actual: %d", n, t.c.offset())
	}
}

func TestDecodePacketNumber(t *testing.T) {
	data := []struct {
		pn        uint64
		largest   uint64
		truncated uint64
		len       int
	}{
		{0xa82f9b32, 0xa82f30ea, 0x9b32, 2},
		{0, 0, 0, 1},
		{1, 0, 1, 1},
		{2, 0, 2, 4},
	}
	for _, d := range data {
		pn := decodePacketNumber(d.largest, d.truncated, d.len)
		if pn != d.pn {
			t.Fatalf("expect packet number 0x%x actual 0x%x", d.pn, pn)
		}
	}
}
