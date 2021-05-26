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
	x.b.push(b)
	x.assertSnapshot("length=1 read=0 write=1")
	x.assertPop(b)
}

func TestDatagramOverrun(t *testing.T) {
	x := datagramBufferTest{t: t}
	for i := 0; i < maxDatagramBufferLen-1; i++ {
		b := []byte{uint8(i)}
		x.b.push(b)
	}
	x.assertSnapshot("length=31 read=0 write=31")
	x.b.push([]byte{maxDatagramBufferLen - 1})
	for i := 1; i < maxDatagramBufferLen; i++ {
		x.assertSnapshot(fmt.Sprintf("length=32 read=%d write=0", i))
		x.assertPop([]byte{uint8(i)})
	}
	x.assertPopNil()
	x.assertSnapshot("length=32 read=0 write=0")
}

func TestDatagramRandom(t *testing.T) {
	x := datagramBufferTest{t: t}
	d := []byte("data")
	for i := 0; i < 1000; i++ {
		j := rand.Intn(100)
		for ; j >= 0; j-- {
			x.b.push(d)
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

func BenchmarkDatagramBuffer(b *testing.B) {
	x := datagramBuffer{}
	data := make([]byte, 100)
	for i := 0; i < b.N; i++ {
		for j := 0; j < 100; j++ {
			x.push(data)
		}
		for j := 0; j < 100; j++ {
			x.pop()
		}
	}
}

func TestDatagramSend(t *testing.T) {
	x := Datagram{}
	n, err := x.Write([]byte("write"))
	if err == nil || err.Error() != "application_error max_datagram_payload_size 0" || n != 0 {
		t.Fatalf("expect error %v, actual %v %v", "application_error", n, err)
	}
	x.setMaxSend(6)
	n, err = x.Write([]byte("writelong"))
	if err == nil || err.Error() != "application_error max_datagram_payload_size 6" || n != 0 {
		t.Fatalf("expect error %v, actual %v %v", "application_error", n, err)
	}
	if x.isFlushable() {
		t.Fatalf("expect flushable %v, actual %v", false, x.isFlushable())
	}
	n, err = x.Write([]byte("write1"))
	if n != 6 || err != nil {
		t.Fatalf("expect write %v %v, actual %v %v", 6, nil, n, err)
	}
	err = x.Push([]byte("wr2"))
	if err != nil {
		t.Fatalf("expect push %v, actual %v", nil, err)
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
	if err == nil || err.Error() != "protocol_violation max_datagram_payload_size 0" {
		t.Fatalf("expect error %v, actual %v", "application_error", err)
	}
	x.setMaxRecv(5)
	err = x.pushRecv([]byte("readlong"))
	if err == nil || err.Error() != "protocol_violation max_datagram_payload_size 5" {
		t.Fatalf("expect error %v, actual %v", "application_error", err)
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
	b = x.Pop()
	if string(b) != "rd2" {
		t.Fatalf("expect read %v, actual %v", "rd2", b)
	}
	if x.isReadable() {
		t.Fatalf("expect readable %v, actual %v", false, x.isReadable())
	}
	n, err = x.Read(b)
	if n != 0 || err != nil {
		t.Fatalf("expect read %v %v, actual %v %v", 0, nil, n, err)
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
