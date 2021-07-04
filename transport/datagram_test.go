package transport

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"testing"
)

func TestDatagramBuffer(t *testing.T) {
	x := datagramBufferTest{t: t}
	x.assertPopNil()
	x.assertAvail(0)
	b := []byte("data")
	x.b.write(b)
	x.assertSnapshot("length=1 write=1 read=0")
	x.assertPop(b)
	x.assertSnapshot("length=0 write=1 read=1")
	x.b.write(b)
	x.b.write(b)
	x.assertSnapshot("length=2 write=3 read=1")
	x.assertPop(b)
	x.assertPop(b)
	x.assertSnapshot("length=0 write=3 read=3")
}

func TestDatagramOverrun(t *testing.T) {
	x := datagramBufferTest{t: t}
	b := []byte{0}
	for i := 0; i < 31; i++ {
		b[0] = uint8(i)
		x.b.write(b)
		x.assertSnapshot(fmt.Sprintf("length=%d write=%d read=0", i+1, i+1))
	}
	b[0] = 31
	x.b.write(b)
	x.assertSnapshot("length=31 write=0 read=1")
	for i := 0; i < 31; i++ {
		b[0] = uint8(i)
		x.b.write(b)
		x.assertSnapshot(fmt.Sprintf("length=31 write=%d read=%d", i+1, (i+2)%32))
	}
	x.assertSnapshot("length=31 write=31 read=0")
	for i := 0; i < 30; i++ {
		b[0] = uint8(i)
		x.assertPop(b)
		x.assertSnapshot(fmt.Sprintf("length=%d write=31 read=%d", 31-i-1, i+1))
	}
	x.assertSnapshot("length=1 write=31 read=30")
	b[0] = 30
	x.assertPop(b)
	x.assertSnapshot("length=0 write=31 read=31")
	b[0] = 31
	x.b.write(b)
	x.assertPop(b)
	x.assertPopNil()
	x.assertSnapshot("length=0 write=0 read=0")
}

func TestDatagramRandom(t *testing.T) {
	x := datagramBufferTest{t: t}
	d := []byte("data")
	for i := 0; i < 1000; i++ {
		j := rand.Intn(100)
		for ; j >= 0; j-- {
			x.b.write(d)
		}
		if x.b.data[x.b.w] != nil {
			t.Fatalf("expect data at %v nil, actual %x", x.b.w, x.b.data[x.b.w])
		}
		j = rand.Intn(100)
		for ; j >= 0; j-- {
			x.b.pop()
		}
	}
	// Read all
	for j := 0; j < maxDatagramBufferLen; j++ {
		x.b.pop()
	}
	if x.b.w != x.b.r {
		t.Fatalf("expect write and read at same position, actual %v %v", x.b.w, x.b.r)
	}
	for i, v := range x.b.data {
		if v != nil {
			t.Fatalf("expect data at %v nil, actual %x", i, v)
		}
	}
}

func TestDatagramSend(t *testing.T) {
	x := Datagram{}
	n, err := x.Write([]byte("write"))
	if err == nil || err.Error() != "error_code=application_error reason=datagram: payload size exceeded limit 0" || n != 0 {
		t.Fatalf("expect error %v, actual %v %v", "application_error", n, err)
	}
	x.setMaxSend(6)
	n, err = x.Write([]byte("writelong"))
	if err == nil || err.Error() != "error_code=application_error reason=datagram: payload size exceeded limit 6" || n != 0 {
		t.Fatalf("expect error %v, actual %v %v", "application_error", n, err)
	}
	if x.isFlushable() {
		t.Fatalf("expect flushable %v, actual %v", false, x.isFlushable())
	}
	n, err = x.Write([]byte("write1"))
	if n != 6 || err != nil {
		t.Fatalf("expect write %v %v, actual %v %v", 6, nil, n, err)
	}
	n, err = x.Write([]byte("wr2"))
	if n != 3 || err != nil {
		t.Fatalf("expect write %v %v, actual %v %v", 3, nil, n, err)
	}
	if !x.isFlushable() {
		t.Fatalf("expect flushable %v, actual %v", true, x.isFlushable())
	}
	b := x.popSend(3)
	if b != nil {
		t.Fatalf("expect pop %v, actual %v", nil, b)
	}
	b = x.popSend(6)
	if string(b) != "write1" {
		t.Fatalf("expect pop %v, actual %v", "write1", b)
	}
	if !x.isFlushable() {
		t.Fatalf("expect flushable %v, actual %v", true, x.isFlushable())
	}
	b = x.popSend(5)
	if string(b) != "wr2" {
		t.Fatalf("expect pop %v, actual %v", "wr2", b)
	}
	if x.isFlushable() {
		t.Fatalf("expect flushable %v, actual %v", false, x.isFlushable())
	}
	b = x.popSend(10)
	if b != nil {
		t.Fatalf("expect pop %v, actual %v", nil, b)
	}
}

func TestDatagramRecv(t *testing.T) {
	x := Datagram{}
	err := x.pushRecv([]byte("read"))
	if err == nil || err.Error() != "error_code=protocol_violation reason=datagram: payload size exceeded limit 0" {
		t.Fatalf("expect error %v, actual %v", "protocol_violation", err)
	}
	x.setMaxRecv(5)
	err = x.pushRecv([]byte("readlong"))
	if err == nil || err.Error() != "error_code=protocol_violation reason=datagram: payload size exceeded limit 5" {
		t.Fatalf("expect error %v, actual %v", "protocol_violation", err)
	}
	if x.isReadable() {
		t.Fatalf("expect readable %v, actual %v", false, x.isReadable())
	}
	b := []byte("read1")
	err = x.pushRecv(b)
	if err != nil {
		t.Fatalf("expect push %v, actual %v", nil, err)
	}
	b[4] = '2' // later ensure received data is intact.
	err = x.pushRecv([]byte("rd2"))
	if err != nil {
		t.Fatalf("expect push %v, actual %v", nil, err)
	}
	if !x.isReadable() {
		t.Fatalf("expect readable %v, actual %v", true, x.isReadable())
	}
	b = make([]byte, 10)
	n, err := x.Read(b)
	if n != 5 || err != nil || string(b[:n]) != "read1" {
		t.Fatalf("expect read %v %v, actual %v %v %s", 5, nil, n, err, b[:n])
	}
	if !x.isReadable() {
		t.Fatalf("expect readable %v, actual %v", true, x.isReadable())
	}
	n, err = x.Read(b[:2])
	if n != 0 || err != io.ErrShortBuffer {
		t.Fatalf("expect read %v %v, actual %v %v", 0, io.ErrShortBuffer, n, err)
	}
	n, err = x.Read(b)
	if n != 3 || err != nil || string(b[:n]) != "rd2" {
		t.Fatalf("expect read %v %v, actual %v %v %s", 3, nil, n, err, b[:n])
	}
	if x.isReadable() {
		t.Fatalf("expect readable %v, actual %v", false, x.isReadable())
	}
	n, err = x.Read(b)
	if n != 0 || err != nil {
		t.Fatalf("expect read %v %v, actual %v %v", 0, nil, n, err)
	}
}

func BenchmarkDatagramSend(b *testing.B) {
	b.ReportAllocs()
	x := Datagram{}
	x.setMaxSend(100)
	data := make([]byte, 100)
	for i := 0; i < b.N; i++ {
		n, err := x.Write(data)
		if n != 100 || err != nil {
			b.Fatalf("expect write: %v %v, actual: %v %v", 100, nil, n, err)
		}
		n = x.send.read(data)
		if n != 100 {
			b.Fatalf("expect read: %v, actual: %v", 100, n)
		}
	}
}

func BenchmarkDatagramRecv(b *testing.B) {
	b.ReportAllocs()
	x := Datagram{}
	x.setMaxRecv(100)
	data := make([]byte, 100)
	for i := 0; i < b.N; i++ {
		err := x.pushRecv(data)
		if err != nil {
			b.Fatalf("push: %v", err)
		}
		n, err := x.Read(data)
		if n != 100 || err != nil {
			b.Fatalf("expect read: %v %v, actual: %v %v", 100, nil, n, err)
		}
	}
}

type datagramBufferTest struct {
	t *testing.T
	b datagramBuffer
}

func (t *datagramBufferTest) assertSnapshot(expect string) {
	actual := t.b.String()
	if actual != expect {
		t.t.Helper()
		t.t.Fatalf("snapshot does not match:\nexpect: %s\nactual: %s", expect, actual)
	}
}

func (t *datagramBufferTest) assertPop(expect []byte) {
	actual := t.b.pop()
	if !bytes.Equal(actual, expect) {
		t.t.Helper()
		t.t.Fatalf("pop does not match:\nexpect: %x\nactual: %x", expect, actual)
	}
}

func (t *datagramBufferTest) assertPopNil() {
	actual := t.b.pop()
	if actual != nil {
		t.t.Helper()
		t.t.Fatalf("pop does not match:\nexpect: %v\nactual: %x", nil, actual)
	}
}

func (t *datagramBufferTest) assertAvail(expect int) {
	actual := t.b.avail()
	if actual != expect {
		t.t.Helper()
		t.t.Fatalf("avail does not match:\nexpect: %x\nactual: %x", expect, actual)
	}
}
