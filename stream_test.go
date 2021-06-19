package quic

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/goburrow/quic/transport"
)

type limitedReadWriter struct {
	buf []byte // write at buf[len(buf):]
	n   int
}

func newLimitedReadWriter(n int) *limitedReadWriter {
	return &limitedReadWriter{
		buf: make([]byte, 0, 100),
		n:   n,
	}
}

func (s *limitedReadWriter) Write(b []byte) (int, error) {
	if len(b) > s.n {
		b = b[:s.n]
	}
	n := len(b)
	m := len(s.buf)
	if m+n > cap(s.buf) {
		panic(io.ErrShortBuffer)
	}
	s.buf = s.buf[:m+n]
	copy(s.buf[m:], b)
	return n, nil
}

func (s *limitedReadWriter) Read(b []byte) (int, error) {
	if len(b) > s.n {
		b = b[:s.n]
	}
	m := len(s.buf)
	n := copy(b, s.buf)
	if n > 0 {
		copy(s.buf, s.buf[n:])
		s.buf = s.buf[:m-n]
	}
	return n, nil
}

func (s *limitedReadWriter) grow(n int) {
	if n > cap(s.buf) {
		b := make([]byte, n)
		copy(b, s.buf)
		s.buf = b
	} else {
		s.buf = s.buf[:n]
	}
}

func (s *limitedReadWriter) String() string {
	return string(s.buf)
}

func TestDataBufferWrite(t *testing.T) {
	s := dataBuffer{}
	s.setBuf([]byte("0123456789"))

	w := newLimitedReadWriter(6)
	done, err := s.writeTo(w)
	if done || s.off != 6 || err != nil {
		t.Fatalf("expect write: %v %v %v, actual: %v %v %v", false, 6, nil, done, s.off, err)
	}
	w.n = 10
	done, err = s.writeTo(w)
	if !done || s.off != 10 || err != nil {
		t.Fatalf("expect write: %v %v %v, actual: %v %v %v", true, 10, nil, done, s.off, err)
	}
	if w.String() != string(s.buf) {
		t.Fatalf("expect data: %s, actual: %s", w, s.buf)
	}
	done, err = s.writeTo(w)
	if !done || s.off != 10 || err != nil {
		t.Fatalf("expect write: %v %v %v, actual: %v %v %v", true, 10, nil, done, s.off, err)
	}
}

func TestDataBufferRead(t *testing.T) {
	s := dataBuffer{}
	s.setBuf(make([]byte, 10))

	r := newLimitedReadWriter(20)
	r.Write([]byte("01234567890123456789"))
	r.n = 4

	done, err := s.readFrom(r)
	if !done || s.off != 4 || err != nil {
		t.Fatalf("expect read: %v %v %v, actual: %v %v %v", true, 4, nil, done, s.off, err)
	}
	r.n = 10
	done, err = s.readFrom(r)
	if !done || s.off != 10 || err != nil {
		t.Fatalf("expect read: %v %v %v, actual: %v %v %v", true, 10, nil, done, s.off, err)
	}
	if string(s.buf) != "0123456789" {
		t.Fatalf("expect read: %s, actual: %s", "0123456789", s.buf)
	}
}

func TestStreamWrite(t *testing.T) {
	conn := newRemoteConn(nil, nil, nil, true)
	defer close(conn.cmdCh)
	st := newStream(conn, 1)
	data1 := "write1"
	data2 := "write2"

	go func() {
		c := <-conn.cmdCh
		if c.cmd != cmdStreamWrite || c.id != 1 {
			t.Errorf("unexpected command: %+v", c)
		}

		buf := &bytes.Buffer{}
		st.recvWriteData(buf)
		if buf.String() != data1 {
			t.Errorf("unexpected data: %s", &st.wrData.buf)
		}
		st.sendWriteResult(nil)

		c = <-conn.cmdCh
		if c.cmd != cmdStreamWrite || c.id != 1 {
			t.Errorf("unexpected command: %+v", c)
		}
		st.recvWriteData(buf)
		if buf.String() != data1+data2 {
			t.Errorf("unexpected data: %s", &st.wrData.buf)
		}
		st.sendWriteResult(nil)

		c = <-conn.cmdCh
		if c.cmd != cmdStreamWrite || c.id != 1 {
			t.Errorf("unexpected command: %+v", c)
		}
		st.sendWriteResult(io.EOF)
	}()

	n, err := st.Write([]byte(data1))
	if n != len(data1) || err != nil {
		t.Fatalf("expect write: %v %v, actual: %v %v", len(data1), nil, n, err)
	}
	n, err = st.Write([]byte(data2))
	if n != len(data2) || err != nil {
		t.Fatalf("expect write: %v %v, actual: %v %v", 0, nil, n, err)
	}
	n, err = st.Write(nil)
	if n != 0 || err != io.EOF {
		t.Fatalf("expect write: %v %v, actual: %v %v", 0, io.EOF, n, err)
	}
}

func TestStreamWriteTimeout(t *testing.T) {
	conn := newRemoteConn(nil, nil, nil, true)
	defer close(conn.cmdCh)
	st := newStream(conn, 1)
	done := make(chan struct{})

	go func() {
		c := <-conn.cmdCh
		if c.cmd != cmdStreamWrite || c.id != 1 {
			t.Errorf("unexpected command: %+v", c)
		}
		st.sendWriteResult(errWait)
		done <- struct{}{}
	}()

	st.SetWriteDeadline(time.Now().Add(10 * time.Millisecond))
	n, err := st.Write([]byte("write"))
	if n != 0 || err != errDeadlineExceeded {
		t.Fatalf("expect write error: %v %v, actual: %v %v", 0, errDeadlineExceeded, n, err)
	}

	st.setClosed()
	n, err = st.Write(nil)
	if n != 0 || err != errClosed {
		t.Fatalf("expect write error: %v, actual %v", errClosed, err)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out")
	}
}

func TestStreamWriteBlock(t *testing.T) {
	conn := newRemoteConn(nil, nil, nil, true)
	defer close(conn.cmdCh)
	st := newStream(conn, 1)
	data := "write"

	go func() {
		c := <-conn.cmdCh
		if c.cmd != cmdStreamWrite || c.id != 1 {
			t.Errorf("unexpected command: %+v", c)
		}
		st.sendWriteResult(errWait)
		time.Sleep(10 * time.Millisecond)

		writing := st.isWriting()
		if !writing {
			t.Errorf("expected writing: %v, actual: %v", true, writing)
		}
		st.recvWriteData(io.Discard)
		st.sendWriteResult(nil)
	}()

	n, err := st.Write([]byte(data))
	if n != len(data) || err != nil {
		t.Fatalf("expect write: %v %v, actual: %v %v", len(data), nil, n, err)
	}
}

func TestStreamRead(t *testing.T) {
	conn := newRemoteConn(nil, nil, nil, false)
	defer close(conn.cmdCh)
	st := newStream(conn, 1)
	data := make([]byte, 10)

	go func() {
		c := <-conn.cmdCh
		if c.cmd != cmdStreamRead || c.id != 1 {
			t.Errorf("unexpected command: %+v", c)
		}
		st.recvReadData(bytes.NewReader([]byte("read")))
		st.sendReadResult(nil)
		c = <-conn.cmdCh
		if c.cmd != cmdStreamRead || c.id != 1 {
			t.Errorf("unexpected command: %+v", c)
		}
		st.sendReadResult(io.EOF)
	}()

	n, err := st.Read(data)
	if n != 4 || err != nil {
		t.Fatalf("expect read: %v %v, actual: %v %v", 4, nil, n, err)
	}
	if string(data[:n]) != "read" {
		t.Fatalf("expect read: %s, actual: %s", "read", data[:n])
	}
	n, err = st.Read(data[:0])
	if n != 0 || err != io.EOF {
		t.Fatalf("expect read: %v %v, actual: %v %v", 0, io.EOF, n, err)
	}
}

func TestStreamReadTimeout(t *testing.T) {
	conn := newRemoteConn(nil, nil, nil, false)
	defer close(conn.cmdCh)
	st := newStream(conn, 1)
	done := make(chan struct{})
	data := make([]byte, 10)

	go func() {
		c := <-conn.cmdCh
		if c.cmd != cmdStreamRead || c.id != 1 {
			t.Errorf("unexpected command: %+v", c)
		}
		st.sendReadResult(errWait)
		done <- struct{}{}
	}()

	st.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	n, err := st.Read(data)
	if n != 0 || err != errDeadlineExceeded {
		t.Fatalf("expect read error: %v %v, actual: %v %v", 0, errDeadlineExceeded, n, err)
	}

	st.setClosed()
	n, err = st.Read(nil)
	if n != 0 || err != errClosed {
		t.Fatalf("expect read error: %v, actual %v", errClosed, err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out")
	}
}

func TestStreamReadBlock(t *testing.T) {
	conn := newRemoteConn(nil, nil, nil, false)
	defer close(conn.cmdCh)
	st := newStream(conn, 1)
	data := make([]byte, 10)

	go func() {
		c := <-conn.cmdCh
		if c.cmd != cmdStreamRead || c.id != 1 {
			t.Errorf("unexpected command: %+v", c)
		}
		st.sendReadResult(errWait)
		time.Sleep(10 * time.Millisecond)

		reading := st.isReading()
		if !reading {
			t.Errorf("expect reading: %v, actual: %v", true, reading)
		}
		st.recvReadData(bytes.NewReader([]byte("read")))
		st.sendReadResult(io.EOF)
	}()

	n, err := st.Read(data)
	if err != io.EOF || string(data[:n]) != "read" {
		t.Fatalf("expect read: %v %v (%s), actual: %v %v (%s)", 4, io.EOF, "data", n, err, data[:n])
	}
}

func TestStreamClose(t *testing.T) {
	conn := newRemoteConn(nil, nil, nil, true)
	defer close(conn.cmdCh)
	st := newStream(conn, 1)
	go func() {
		c := <-conn.cmdCh
		if c.cmd != cmdStreamCloseWrite || c.id != 1 || c.n != 10 {
			t.Errorf("unexpected command: %+v", c)
		}
		st.sendCloseResult(nil)
		c = <-conn.cmdCh
		if c.cmd != cmdStreamCloseRead || c.id != 1 || c.n != 20 {
			t.Errorf("unexpected command: %+v", c)
		}
		st.sendCloseResult(nil)
		c = <-conn.cmdCh
		if c.cmd != cmdStreamClose || c.id != 1 {
			t.Errorf("unexpected command: %+v", c)
		}
		st.sendCloseResult(nil)
	}()

	err := st.CloseWrite(10)
	if err != nil {
		t.Fatalf("close write: %v", err)
	}
	err = st.CloseRead(20)
	if err != nil {
		t.Fatalf("close read: %v", err)
	}
	err = st.Close()
	if err != nil {
		t.Fatalf("close: %v", err)
	}

	st.setClosed()
	err = st.Close()
	if err != errClosed {
		t.Fatalf("expect close error: %v, actual %v", errClosed, err)
	}
}

func TestStream(t *testing.T) {
	s, c := newPipe(nil, nil)
	defer s.Close()
	go s.Serve()

	defer c.Close()
	go c.Serve()

	recvFn := func(st *Stream) {
		st.SetDeadline(time.Now().Add(2 * time.Second))
		n, err := io.Copy(st, st)
		if n == 0 || err != nil {
			t.Errorf("server stream copy: %v %v", n, err)
			st.CloseRead(1)
			return
		}
		err = st.Close()
		if err != nil {
			t.Errorf("server stream close: %v", err)
			return
		}
	}

	sendData := make([]byte, 10000)
	for i := range sendData {
		sendData[i] = uint8(i)
	}
	var recvData []byte
	done := make(chan struct{})

	sendFn := func(st *Stream) {
		st.SetDeadline(time.Now().Add(2 * time.Second))
		n, err := st.Write(sendData)
		if n != len(sendData) || err != nil {
			t.Errorf("client stream write: %v %v", n, err)
			return
		}
		err = st.Close()
		if err != nil {
			t.Errorf("client stream close: %v", err)
			return
		}
		recvData, err = io.ReadAll(st)
		if err != nil {
			t.Errorf("client stream read: %v", err)
			return
		}
		done <- struct{}{}
	}

	serverHandler := func(conn *Conn, events []transport.Event) {
		t.Logf("server events: cid=%x %v", conn.scid, events)
		for _, e := range events {
			switch e.Type {
			case transport.EventStreamOpen:
				st, err := conn.Stream(e.ID)
				if err != nil {
					t.Errorf("server stream %v: %v", e.ID, err)
					conn.Close()
					return
				}
				go recvFn(st)
			}
		}
	}
	clientHandler := func(conn *Conn, events []transport.Event) {
		t.Logf("client events: cid=%x %v", conn.scid, events)
		for _, e := range events {
			switch e.Type {
			case transport.EventConnOpen:
				id, ok := conn.NewStream(true)
				if !ok {
					t.Error("client newstream failed")
					conn.Close()
					return
				}
				st, err := conn.Stream(id)
				if err != nil {
					t.Errorf("client stream: %d %v", id, err)
					conn.Close()
					return
				}
				go sendFn(st)
			}
		}
	}

	s.SetHandler(handlerFunc(serverHandler))
	c.SetHandler(handlerFunc(clientHandler))
	err := c.Connect(s.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out")
		return
	}
	if !bytes.Equal(recvData, sendData) {
		t.Fatalf("received data different: send=%v recv=%v", len(sendData), len(recvData))
	}
}
