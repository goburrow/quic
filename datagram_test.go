package quic

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/goburrow/quic/transport"
)

func TestDatagramWrite(t *testing.T) {
	conn := newRemoteConn(nil, nil, nil, true)
	defer close(conn.cmdCh)
	dg := newDatagram(conn)
	data := "datagram"

	go func() {
		c := <-conn.cmdCh
		if c.cmd != cmdDatagramWrite {
			t.Errorf("unexpected command: %+v", c)
		}
		buf := bytes.Buffer{}
		dg.recvWriteData(&buf)
		if buf.String() != data {
			t.Errorf("unexpected write data: %s, actual: %s", data, &buf)
		}
		dg.sendWriteResult(nil)
		c = <-conn.cmdCh
		if c.cmd != cmdDatagramWrite {
			t.Errorf("unexpected command: %+v", c)
		}
		dg.sendWriteResult(io.EOF)
	}()

	n, err := dg.Write([]byte(data))
	if n != len(data) || err != nil {
		t.Fatalf("expect write: %v %v, actual: %v %v", len(data), nil, n, err)
	}
	n, err = dg.Write(nil)
	if n != 0 || err != io.EOF {
		t.Fatalf("expect write: %v %v, actual: %v %v", 0, io.EOF, n, err)
	}
}

func TestDatagramWriteTimeout(t *testing.T) {
	conn := newRemoteConn(nil, nil, nil, true)
	defer close(conn.cmdCh)
	dg := newDatagram(conn)
	data := "datagram"
	done := make(chan struct{})

	go func() {
		c := <-conn.cmdCh
		if c.cmd != cmdDatagramWrite {
			t.Errorf("unexpected command: %+v", c)
		}
		dg.sendWriteResult(errWait)
		done <- struct{}{}
	}()

	dg.SetWriteDeadline(time.Now().Add(10 * time.Millisecond))
	n, err := dg.Write([]byte(data))
	if n != 0 || err != errDeadlineExceeded {
		t.Fatalf("expect write error: %v %v, actual: %v %v", 0, errDeadlineExceeded, n, err)
	}

	dg.setClosed()
	n, err = dg.Write(nil)
	if n != 0 || err != errClosed {
		t.Fatalf("expect write error: %v, actual %v", errClosed, err)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out")
	}
}

func TestDatagramRead(t *testing.T) {
	conn := newRemoteConn(nil, nil, nil, false)
	defer close(conn.cmdCh)
	dg := newDatagram(conn)
	data := make([]byte, 10)

	go func() {
		c := <-conn.cmdCh
		if c.cmd != cmdDatagramRead {
			t.Errorf("unexpected command: %+v", c)
		}
		dg.recvReadData(bytes.NewReader([]byte("datagram")))
		dg.sendReadResult(nil)
		c = <-conn.cmdCh
		if c.cmd != cmdDatagramRead || c.n != 0 {
			t.Errorf("unexpected command: %+v", c)
		}
		dg.sendReadResult(io.EOF)
	}()

	n, err := dg.Read(data)
	if n != 8 || err != nil {
		t.Fatalf("expect read: %v %v, actual: %v %v", 8, nil, n, err)
	}
	if string(data[:n]) != "datagram" {
		t.Fatalf("expect read: %s, actual: %s", "datagram", data[:n])
	}
	n, err = dg.Read(nil)
	if n != 0 || err != io.EOF {
		t.Fatalf("expect read: %v %v, actual: %v %v", 0, io.EOF, n, err)
	}
}

func TestDatagramReadTimeout(t *testing.T) {
	conn := newRemoteConn(nil, nil, nil, true)
	defer close(conn.cmdCh)
	dg := newDatagram(conn)
	data := make([]byte, 10)
	done := make(chan struct{})

	go func() {
		c := <-conn.cmdCh
		if c.cmd != cmdDatagramRead {
			t.Errorf("unexpected command: %+v", c)
		}
		dg.sendReadResult(errWait)
		done <- struct{}{}
	}()

	dg.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	n, err := dg.Read([]byte(data))
	if n != 0 || err != errDeadlineExceeded {
		t.Fatalf("expect read error: %v %v, actual: %v %v", 0, errDeadlineExceeded, n, err)
	}

	dg.setClosed()
	n, err = dg.Read(nil)
	if n != 0 || err != errClosed {
		t.Fatalf("expect read error: %v, actual %v", errClosed, err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out")
	}
}

func TestDatagram(t *testing.T) {
	sc := newServerConfig()
	sc.Params.MaxDatagramPayloadSize = 100
	cc := newClientConfig()
	cc.Params.MaxDatagramPayloadSize = 100

	s, c := newPipe(sc, cc)
	defer s.Close()
	go s.Serve()

	defer c.Close()
	go c.Serve()

	recvFn := func(dg *Datagram) {
		n, err := io.Copy(dg, dg)
		if n == 0 || (err != nil && err != errClosed) {
			t.Errorf("server datagram copy: %v %v", n, err)
			return
		}
	}

	sendData := []string{
		"datagram1", "datagram2",
	}
	done := make(chan struct{})

	sendFn := func(dg *Datagram) {
		buf := make([]byte, 10)
		for _, d := range sendData {
			n, err := dg.Write([]byte(d))
			if n != len(d) || err != nil {
				t.Errorf("client datagram write: %v %v", n, err)
				return
			}
			n, err = dg.Read(buf)
			if n != len(d) || err != nil || string(buf[:n]) != d {
				t.Errorf("client datagram read: %v %v", n, err)
				return
			}
		}
		done <- struct{}{}
	}

	serverHandler := func(conn *Conn, events []transport.Event) {
		t.Logf("server events: %v", events)
		for _, e := range events {
			switch e.Type {
			case transport.EventDatagramWritable:
				dg := conn.Datagram()
				go recvFn(dg)
			}
		}
	}
	clientHandler := func(conn *Conn, events []transport.Event) {
		t.Logf("client events: %v", events)
		for _, e := range events {
			switch e.Type {
			case transport.EventDatagramWritable:
				dg := conn.Datagram()
				go sendFn(dg)
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
}
