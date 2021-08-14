package quic

import (
	"bytes"
	"io"
	"math/rand"
	"net"
	"os"
	"testing"
	"time"

	"github.com/goburrow/quic/transport"
)

type stubReadWriter struct {
	n int
	e error
}

func (s stubReadWriter) Read([]byte) (int, error) {
	return s.n, s.e
}

func (s stubReadWriter) Write([]byte) (int, error) {
	return s.n, s.e
}

type sizedReader struct {
	size int
	read int
}

func (s *sizedReader) Read(b []byte) (int, error) {
	n := len(b)
	if n+s.read > s.size {
		n = s.size - s.read
	}
	s.read += n
	if s.read == s.size {
		return n, io.EOF
	}
	return n, nil
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
		st.sendWriter(buf)
		if buf.String() != data1 {
			t.Errorf("unexpected data: %s", buf)
		}

		c = <-conn.cmdCh
		if c.cmd != cmdStreamWrite || c.id != 1 {
			t.Errorf("unexpected command: %+v", c)
		}
		st.sendWriter(buf)
		if buf.String() != data1+data2 {
			t.Errorf("unexpected data: %s", buf)
		}

		c = <-conn.cmdCh
		if c.cmd != cmdStreamWrite || c.id != 1 {
			t.Errorf("unexpected command: %+v", c)
		}
		st.sendWriter(stubReadWriter{0, io.EOF})
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
		done <- struct{}{}
	}()

	st.SetWriteDeadline(time.Now().Add(10 * time.Millisecond))
	n, err := st.Write([]byte("write"))
	if n != 0 || err != os.ErrDeadlineExceeded {
		t.Fatalf("expect write error: %v %v, actual: %v %v", 0, os.ErrDeadlineExceeded, n, err)
	}

	st.setClosed(io.ErrUnexpectedEOF, nil)
	n, err = st.Write(nil)
	if n != 0 || err != io.ErrUnexpectedEOF {
		t.Fatalf("expect write error: %v, actual %v", io.ErrUnexpectedEOF, err)
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
		time.Sleep(10 * time.Millisecond)
		st.sendWriter(io.Discard)
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
		r := bytes.NewReader([]byte("read"))
		st.sendReader(r)
		c = <-conn.cmdCh
		if c.cmd != cmdStreamRead || c.id != 1 {
			t.Errorf("unexpected command: %+v", c)
		}
		st.sendReader(r)
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
		done <- struct{}{}
	}()

	st.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	n, err := st.Read(data)
	if n != 0 || err != os.ErrDeadlineExceeded {
		t.Fatalf("expect read error: %v %v, actual: %v %v", 0, os.ErrDeadlineExceeded, n, err)
	}

	st.setClosed(io.ErrUnexpectedEOF, nil)
	n, err = st.Read(nil)
	if n != 0 || err != io.ErrUnexpectedEOF {
		t.Fatalf("expect read error: %v, actual %v", io.ErrUnexpectedEOF, err)
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
		time.Sleep(10 * time.Millisecond)
		r := bytes.NewReader([]byte("read"))
		st.sendReader(r)
	}()

	n, err := st.Read(data)
	if err != nil || string(data[:n]) != "read" {
		t.Fatalf("expect read: %v %v (%s), actual: %v %v (%s)", 4, nil, "data", n, err, data[:n])
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

	st.setClosed(io.EOF, nil)
	err = st.Close()
	if err != io.EOF {
		t.Fatalf("expect close error: %v, actual %v", io.EOF, err)
	}
}

func TestStreamConnectionClose(t *testing.T) {
	conn := newRemoteConn(nil, nil, nil, false)
	defer close(conn.cmdCh)
	st := newStream(conn, 1)

	go func() {
		c := <-conn.cmdCh
		if c.cmd != cmdStreamRead || c.id != 1 {
			t.Errorf("unexpected command: %+v", c)
		}
		r := bytes.NewReader([]byte("readclose"))
		st.sendReader(r)
		st.setClosed(net.ErrClosed, r)
	}()

	data := make([]byte, 4)
	n, err := st.Read(data)
	if n != 4 || err != nil || string(data[:n]) != "read" {
		t.Fatalf("expect read: %v %v %q, actual: %v %v %q", 4, nil, "read", n, err, string(data[:n]))
	}
	n, err = st.Read(data)
	if n != 4 || err != nil || string(data[:n]) != "clos" {
		t.Fatalf("expect read: %v %v %q, actual: %v %v %q", 4, nil, "clos", n, err, string(data[:n]))
	}
	n, err = st.Read(data)
	if n != 1 || err != nil || string(data[:n]) != "e" {
		t.Fatalf("expect read: %v %v %q, actual: %v %v %q", 1, nil, "e", n, err, string(data[:n]))
	}
	n, err = st.Read(data)
	if n != 0 || err != io.EOF {
		t.Fatalf("expect read: %v %v, actual: %v %v", 0, io.EOF, n, err)
	}
	n, err = st.Read(data)
	if n != 0 || err != io.EOF {
		t.Fatalf("expect read: %v %v, actual: %v %v", 0, io.EOF, n, err)
	}
	n, err = st.Write(nil)
	if n != 0 || err != net.ErrClosed {
		t.Fatalf("expect write: %v %v, actual: %v %v", 0, net.ErrClosed, n, err)
	}
}

func TestStreamConnectionTerminate(t *testing.T) {
	conn := newRemoteConn(nil, nil, nil, false)
	defer close(conn.cmdCh)
	st := newStream(conn, 1)

	go func() {
		c := <-conn.cmdCh
		if c.cmd != cmdStreamRead || c.id != 1 {
			t.Errorf("unexpected command: %+v", c)
		}
		r := bytes.NewReader([]byte("read"))
		st.sendReader(r)
		st.setClosed(net.ErrClosed, nil)
	}()

	data := make([]byte, 4)
	n, err := st.Read(data)
	if n != 4 || err != nil || string(data[:n]) != "read" {
		t.Fatalf("expect read: %v %v %q, actual: %v %v %q", 4, nil, "read", n, err, string(data[:n]))
	}
	n, err = st.Read(data)
	if n != 0 || err != net.ErrClosed {
		t.Fatalf("expect read: %v %v, actual: %v %v", 0, net.ErrClosed, n, err)
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

	sendData := make([]byte, 100000)
	rand.Read(sendData)
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
		// t.Logf("server events: cid=%x %v", conn.scid, events)
		for _, e := range events {
			switch e.Type {
			case transport.EventStreamOpen:
				st, err := conn.Stream(e.Data)
				if err != nil {
					t.Errorf("server stream %v: %v", e.Data, err)
					conn.Close()
					return
				}
				go recvFn(st)
			}
		}
	}
	clientHandler := func(conn *Conn, events []transport.Event) {
		// t.Logf("client events: cid=%x %v", conn.scid, events)
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

func BenchmarkStream(b *testing.B) {
	streams := b.N
	size := 1000000

	serverConfig := newServerConfig()
	serverConfig.Params.InitialMaxStreamsBidi = 0
	serverConfig.Params.InitialMaxStreamsUni = uint64(streams)
	serverConfig.Params.InitialMaxStreamDataUni = uint64(size)
	serverConfig.Params.InitialMaxData = uint64(size)
	s, c := newPipe(serverConfig, nil)
	defer s.Close()
	go s.Serve()

	defer c.Close()
	go c.Serve()

	done := make(chan struct{}, streams)

	recvFn := func(st *Stream) {
		n, err := io.Copy(io.Discard, st)
		if int(n) != size || err != nil {
			b.Errorf("expect server write to: %v %v, actual: %v %v", size, nil, n, err)
			st.CloseRead(1)
			return
		}
		st.Close()
	}
	sendFn := func(st *Stream) {
		data := sizedReader{size: size}
		n, err := io.Copy(st, &data)
		if int(n) != size || err != nil {
			b.Errorf("expect client read from: %v %v, actual: %v %v", size, nil, n, err)
			return
		}
		st.Close()
	}

	s.SetHandler(handlerFunc(func(conn *Conn, events []transport.Event) {
		for _, e := range events {
			switch e.Type {
			case transport.EventStreamOpen:
				st, _ := conn.Stream(e.Data)
				go recvFn(st)
			}
		}
	}))

	c.SetHandler(handlerFunc(func(conn *Conn, events []transport.Event) {
		for _, e := range events {
			switch e.Type {
			case transport.EventStreamOpen:
				b.ResetTimer()
			case transport.EventStreamCreatable:
				if e.Data != 0 { // uni stream
					count := 0
					if conn.UserData() != nil {
						count = conn.UserData().(int)
					}
					if count < streams {
						id, ok := conn.NewStream(false)
						if ok {
							st, _ := conn.Stream(id)
							go sendFn(st)
							count++
							conn.SetUserData(count)
						}
					}
				}
			case transport.EventStreamComplete:
				done <- struct{}{}
			}
		}
	}))

	//c.SetLogger(int(levelDebug), os.Stdout)
	err := c.Connect(s.LocalAddr().String())
	if err != nil {
		b.Fatal(err)
	}

	for i := streams; i > 0; i-- {
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			b.Fatal("timed out")
			return
		}
	}
	b.StopTimer()
}
