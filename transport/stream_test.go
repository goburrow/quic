package transport

import (
	"io"
	"testing"
)

func TestStreamRecv(t *testing.T) {
	s := Stream{}
	s.init(false, true)
	s.flow.init(10, 0)
	// Receive data
	b := []byte("recvstream")
	err := s.pushRecv(b, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if !s.isReadable() {
		t.Fatalf("expect readable: %v", &s)
	}
	// Consume
	b = make([]byte, 10)
	n, err := s.Read(b[:4])
	if err != nil || n != 4 || string(b[:n]) != "recv" {
		t.Fatalf("expect read %v %v %s, actual %v %v %s", 4, nil, "recv", n, err, b[:n])
	}
	// Continue consume
	n, err = s.Read(b)
	if err != nil || n != 6 || string(b[:n]) != "stream" {
		t.Fatalf("expect read %v %v %s, actual %v %v %s", 6, nil, "stream", n, err, b[:n])
	}
	// End
	if !s.isReadable() {
		t.Fatalf("expect readable: %v", &s)
	}
	_, err = s.Read(b)
	if err != io.EOF {
		t.Fatalf("expect error %v, actual %v", io.EOF, err)
	}
	if s.isReadable() {
		t.Fatalf("expect not readable: %v", &s)
	}
	// Receive wrong offset
	s.flow.maxRecv++
	err = s.pushRecv(b[:1], 10, true)
	if err != errFinalSize {
		t.Fatalf("expect error %v, actual %v", errFinalSize, err)
	}
}

func TestStreamSend(t *testing.T) {
	s := Stream{}
	s.init(false, true)
	s.flow.init(0, 10)
	// Send
	b := []byte("sendstream")
	n, err := s.Write(b[:4])
	if err != nil || n != 4 {
		t.Fatalf("expect write %v %v, actual %v %v", 4, nil, n, err)
	}
	if !s.isWriteable() {
		t.Fatalf("expect writeable: %v", &s)
	}
	n, err = s.Write(b[4:])
	if err != nil || n != 6 {
		t.Fatalf("expect write %v %v, actual %v %v", 6, nil, n, err)
	}
	if s.isWriteable() {
		t.Fatalf("expect not writeable: %v", &s)
	}
	// Done sending
	err = s.Close()
	if err != nil {
		t.Fatal(err)
	}
	if s.isWriteable() {
		t.Fatalf("expect not writeable: %v", &s)
	}
	// Consume
	b, off, fin := s.popSend(4)
	if string(b) != "send" || off != 0 || fin != false {
		t.Fatalf("expect pop %q %v %v, actual %s %v %v", "send", 0, false, b, off, fin)
	}
	// Continue consume
	b, off, fin = s.popSend(20)
	if string(b) != "stream" || off != 4 || fin != true {
		t.Fatalf("expect pop %q %v %v, actual %s %v %v", "stream", 4, true, b, off, fin)
	}
	// Stream is empty now
	if s.isFlushable() {
		t.Fatalf("expect flushable %v, actual %v", false, s.isFlushable())
	}
	// Cannot send more data
	s.flow.maxSend++
	n, err = s.Write(b[:1])
	if n != 0 || err != errFinalSize {
		t.Fatalf("expect write %v %v, actual %v %v", 0, errFinalSize, n, err)
	}
}

func TestStreamClose(t *testing.T) {
	s := Stream{}
	s.init(false, true)
	s.flow.init(0, 10)

	_, err := s.Write([]byte("stream"))
	if err != nil {
		t.Fatal(err)
	}
	// Read all data before close
	b, off, fin := s.popSend(20)
	if string(b) != "stream" || off != 0 || fin != false {
		t.Fatalf("expect pop %q %v %v, actual %s %v %v", "stream", 0, false, b, off, fin)
	}
	err = s.Close()
	if err != nil {
		t.Fatalf("close stream: %v", err)
	}
	if !s.isFlushable() {
		t.Fatalf("expect flushable: %+v", &s)
	}
	b, off, fin = s.popSend(20)
	if len(b) != 0 || off != 6 || fin != true {
		t.Fatalf("expect pop %q %v %v, actual %s %v %v", "", 6, true, b, off, fin)
	}
}

func TestStreamType(t *testing.T) {
	data := []struct {
		id     uint64
		client bool
		local  bool
	}{
		{4, true, true},
		{3, true, false},
		{4, false, false},
		{3, false, true},
	}
	for _, d := range data {
		local := isStreamLocal(d.id, d.client)
		if local != d.local {
			t.Fatalf("expect %+v", d)
		}
	}
}

func TestStreamLocalBidi(t *testing.T) {
	s := Stream{}
	s.init(true, true)
	s.flow.init(10, 10)

	b := make([]byte, 10)
	// Send data
	n, err := s.Write(b)
	if err != nil || n != 10 {
		t.Fatalf("expect write %v %v, actual %v %v", 10, nil, n, err)
	}
	if s.flow.totalSend != 10 {
		t.Fatalf("expect flow send %v, actual %v", 10, s.flow.totalSend)
	}
	// Send too much data
	n, err = s.Write(b[:1])
	if err != nil || n != 0 {
		t.Fatalf("expect nothing written, actual %v %v", n, err)
	}
	if s.flow.totalSend != 10 {
		t.Fatalf("expect flow send %v, actual %v", 10, s.flow.totalSend)
	}
	// Receive data
	err = s.pushRecv(b[:4], 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if s.flow.totalRecv != 4 {
		t.Fatalf("expect flow recv %d, actual %v", 4, s.flow.totalRecv)
	}
	n, err = s.Read(b)
	if n != 4 || err != nil {
		t.Fatalf("expect read %v %v, actual %v %v", 4, nil, n, err)
	}
	if s.flow.maxRecvNext != 14 {
		t.Fatalf("expect flow recv next %v, actual %v", 14, s.flow.maxRecvNext)
	}
}

func TestStreamRemoteBidi(t *testing.T) {
	s := Stream{}
	s.init(false, true)
	s.flow.init(20, 20)

	b := make([]byte, 10)
	// Send data
	n, err := s.Write(b)
	if err != nil || n != 10 {
		t.Fatalf("expect write %v %v, actual %v %v", 10, nil, n, err)
	}
	s.send.pop(5)
	// Resend data
	err = s.send.push(b[:1], 2, false)
	if err != nil {
		t.Fatal(err)
	}
	if !s.isFlushable() {
		t.Fatalf("expect flushable %v, actual %v", true, s.isFlushable())
	}
	b, off, fin := s.send.pop(5)
	if len(b) != 1 || off != 2 || fin {
		t.Fatalf("expect pop %v %v %v, actual %v %v %v", 1, 2, false, len(b), off, fin)
	}
}

func TestStreamRemoteUni(t *testing.T) {
	s := Stream{}
	s.init(false, false)
	s.flow.init(20, 20)
	b := make([]byte, 10)
	// Not allow writing to remote unidirectional stream
	_, err := s.Write(b[:1])
	if err, ok := err.(*Error); !ok || err.Code != StreamStateError {
		t.Fatalf("expect error %+v, actual %+v", errorText[StreamStateError], err)
	}
	err = s.Close()
	if err, ok := err.(*Error); !ok || err.Code != StreamStateError {
		t.Fatalf("expect error %+v, actual %+v", errorText[StreamStateError], err)
	}
	// Receive data out of order
	err = s.pushRecv(b, 5, false)
	if err != nil {
		t.Fatal(err)
	}
	if s.flow.totalRecv != 15 {
		t.Fatalf("expect flow recv %v, actual %v", 15, s.flow.totalRecv)
	}
	err = s.pushRecv(b, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if s.flow.totalRecv != 15 {
		t.Fatalf("expect flow recv %v, actual %v", 15, s.flow.totalRecv)
	}
	// Exceeds limits
	err = s.pushRecv(b, 11, false)
	if err != errFlowControl {
		t.Fatalf("expect error %v, actual %v", errFinalSize, err)
	}
}
