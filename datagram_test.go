package quic

import (
	"bytes"
	"io"
	"net"
	"os"
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
		dg.sendWriter(&buf)
		if buf.String() != data {
			t.Errorf("unexpected write data: %s, actual: %s", data, &buf)
		}
		c = <-conn.cmdCh
		if c.cmd != cmdDatagramWrite {
			t.Errorf("unexpected command: %+v", c)
		}
		dg.sendWriter(stubReadWriter{0, io.EOF})
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
		done <- struct{}{}
	}()

	dg.SetWriteDeadline(time.Now().Add(10 * time.Millisecond))
	n, err := dg.Write([]byte(data))
	if n != 0 || err != os.ErrDeadlineExceeded {
		t.Fatalf("expect write error: %v %v, actual: %v %v", 0, os.ErrDeadlineExceeded, n, err)
	}

	dg.setClosed(net.ErrClosed, nil)
	n, err = dg.Write(nil)
	if n != 0 || err != net.ErrClosed {
		t.Fatalf("expect write error: %v, actual %v", net.ErrClosed, err)
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
		r := bytes.NewReader([]byte("datagram"))
		dg.sendReader(r)
		c = <-conn.cmdCh
		if c.cmd != cmdDatagramRead || c.n != 0 {
			t.Errorf("unexpected command: %+v", c)
		}
		dg.sendReader(r)
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
		done <- struct{}{}
	}()

	dg.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	n, err := dg.Read([]byte(data))
	if n != 0 || err != os.ErrDeadlineExceeded {
		t.Fatalf("expect read error: %v %v, actual: %v %v", 0, os.ErrDeadlineExceeded, n, err)
	}

	dg.setClosed(net.ErrClosed, nil)
	n, err = dg.Read(nil)
	if n != 0 || err != net.ErrClosed {
		t.Fatalf("expect read error: %v, actual %v", net.ErrClosed, err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out")
	}
}

func TestDatagramReadBlock(t *testing.T) {
	conn := newRemoteConn(nil, nil, nil, true)
	defer close(conn.cmdCh)
	dg := newDatagram(conn)
	data := make([]byte, 10)

	go func() {
		c := <-conn.cmdCh
		if c.cmd != cmdDatagramRead {
			t.Errorf("unexpected command: %+v", c)
		}
		time.Sleep(10 * time.Millisecond)
		r := bytes.NewReader([]byte("datagram"))
		dg.sendReader(r)
	}()

	n, err := dg.Read(data)
	if err != nil || string(data[:n]) != "datagram" {
		t.Fatalf("expect read error: %v %v (%s), actual: %v %v (%s)", len(data), io.EOF, "datagram", n, err, data[:n])
	}
}

func TestDatagramConnectionClose(t *testing.T) {
	conn := newRemoteConn(nil, nil, nil, false)
	defer close(conn.cmdCh)
	dg := newDatagram(conn)

	go func() {
		c := <-conn.cmdCh
		if c.cmd != cmdDatagramRead {
			t.Errorf("unexpected command: %+v", c)
		}
		r := bytes.NewReader([]byte("datagramdatagram"))
		dg.sendReader(r)
		dg.setClosed(net.ErrClosed, r)
	}()

	data := make([]byte, 8)
	n, err := dg.Read(data)
	if n != 8 || err != nil || string(data[:n]) != "datagram" {
		t.Fatalf("expect read: %v %v %q, actual: %v %v %q", 8, nil, "datagram", n, err, string(data[:n]))
	}
	n, err = dg.Read(data)
	if n != 8 || err != nil || string(data[:n]) != "datagram" {
		t.Fatalf("expect read: %v %v %q, actual: %v %v %q", 8, nil, "datagram", n, err, string(data[:n]))
	}
	n, err = dg.Read(data)
	if n != 0 || err != io.EOF {
		t.Fatalf("expect read: %v %v, actual: %v %v", 0, io.EOF, n, err)
	}
	n, err = dg.Write(nil)
	if n != 0 || err != net.ErrClosed {
		t.Fatalf("expect write: %v %v, actual: %v %v", 0, net.ErrClosed, n, err)
	}
}

func TestDatagramConnectionTerminate(t *testing.T) {
	conn := newRemoteConn(nil, nil, nil, false)
	defer close(conn.cmdCh)
	dg := newDatagram(conn)

	go func() {
		c := <-conn.cmdCh
		if c.cmd != cmdDatagramRead {
			t.Errorf("unexpected command: %+v", c)
		}
		r := bytes.NewReader([]byte("datagram"))
		dg.sendReader(r)
		dg.setClosed(net.ErrClosed, stubReadWriter{0, nil})
	}()

	data := make([]byte, 8)
	n, err := dg.Read(data)
	if n != 8 || err != nil || string(data[:n]) != "datagram" {
		t.Fatalf("expect read: %v %v %q, actual: %v %v %q", 8, nil, "datagram", n, err, string(data[:n]))
	}
	n, err = dg.Read(data)
	if n != 0 || err != net.ErrClosed {
		t.Fatalf("expect read: %v %v, actual: %v %v", 0, net.ErrClosed, n, err)
	}
}

func TestDatagram(t *testing.T) {
	sc := newServerConfig()
	sc.Params.MaxDatagramFramePayloadSize = 100
	sc.Params.InitialMaxStreamsBidi = 0
	sc.Params.InitialMaxStreamsUni = 0
	cc := newClientConfig()
	cc.Params.MaxDatagramFramePayloadSize = 100
	cc.Params.InitialMaxStreamsBidi = 0
	cc.Params.InitialMaxStreamsUni = 0

	s, c := newPipe(sc, cc)
	defer s.Close()
	go s.Serve()

	defer c.Close()
	go c.Serve()

	done := make(chan struct{}, 2)

	recvFn := func(dg *Datagram) {
		defer func() {
			done <- struct{}{}
		}()
		n, err := io.Copy(dg, dg)
		if n == 0 || err != net.ErrClosed {
			t.Errorf("server datagram copy: %v %v", n, err)
			return
		}
	}

	sendData := []string{
		"datagram1", "datagram2",
	}

	sendFn := func(dg *Datagram) {
		defer func() {
			done <- struct{}{}
		}()
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
	}

	serverHandler := func(conn *Conn, events []transport.Event) {
		t.Logf("server events: %v", events)
		for _, e := range events {
			switch e.Type {
			case transport.EventDatagramOpen:
				dg := conn.Datagram()
				go recvFn(dg)
			}
		}
	}
	clientHandler := func(conn *Conn, events []transport.Event) {
		t.Logf("client events: %v", events)
		for _, e := range events {
			switch e.Type {
			case transport.EventDatagramOpen:
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

	for i := 0; i < 2; i++ {
		select {
		case <-done:
			if i == 0 { // Initiate closing client
				c.Close()
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timed out")
			return
		}
	}
}
