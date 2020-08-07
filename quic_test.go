package quic

import (
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/goburrow/quic/transport"
)

type handlerFunc func(*Conn, []transport.Event)

func (f handlerFunc) Serve(c *Conn, e []transport.Event) {
	f(c, e)
}

func TestServerAndClient(t *testing.T) {
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := newServer()
	s.SetListener(socket)
	s.SetHandler(handlerFunc(func(conn *Conn, events []transport.Event) {
		for _, e := range events {
			switch e.Type {
			case EventConnAccept:
			case transport.EventStreamReadable:
				st := conn.Stream(e.ID)
				buf := make([]byte, 8)
				n, err := st.Read(buf)
				if err != nil {
					t.Errorf("server stream receive: %v", err)
					conn.Close()
					return
				}
				if string(buf[:n]) != "ping" {
					t.Errorf("expect server receive: ping. Got %s", buf[:n])
				}
				n, err = st.Write([]byte("pong"))
				if err != nil {
					t.Errorf("server stream send: %v", err)
					conn.Close()
					return
				}
			case transport.EventStreamWritable:
				if e.ID != 4 {
					t.Errorf("expect writable stream %d, actual %d", 4, e.ID)
				}
			case EventConnClose:
			default:
				t.Errorf("unexpected event: %#v", e)
			}
		}
	}))
	defer func() {
		err := s.Close()
		if err != nil {
			t.Errorf("server close: %v", err)
		}
	}()
	go func() {
		err := s.Serve()
		if err != nil {
			t.Logf("server serve: %v", err)
		}
	}()
	recvData := make(chan []byte, 1)
	c := newClient()
	c.SetHandler(handlerFunc(func(conn *Conn, events []transport.Event) {
		for _, e := range events {
			switch e.Type {
			case EventConnAccept:
				st := conn.Stream(4)
				if st == nil {
					t.Errorf("expect client stream created, actual %v", st)
					conn.Close()
				} else {
					st.Write([]byte("ping"))
					st.Close()
				}
			case transport.EventStreamReadable:
				st := conn.Stream(e.ID)
				buf := make([]byte, 8)
				n, err := st.Read(buf)
				if err == nil {
					recvData <- buf[:n]
				} else {
					t.Errorf("client stream receive: %v", err)
					recvData <- nil
				}
				conn.Close()
			case transport.EventStreamWritable:
				if e.ID != 4 {
					t.Errorf("expect writable stream %d, actual %d", 4, e.ID)
				}
			case transport.EventStreamComplete:
				close(recvData)
			case EventConnClose:
			default:
				t.Errorf("unexpected event: %#v", e)
			}
		}
	}))
	err = c.ListenAndServe("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err := c.Close()
		if err != nil {
			t.Errorf("client close: %v", err)
		}
	}()
	err = c.Connect(socket.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	select {
	case d := <-recvData:
		if string(d) != "pong" {
			t.Errorf("expect receive: pong. Got %s", d)
		}
	case <-time.After(5 * time.Second):
		t.Errorf("receive timed out")
	}
}

func newServer() *Server {
	cert, err := tls.LoadX509KeyPair("testdata/cert.pem", "testdata/key.pem")
	if err != nil {
		panic(err)
	}
	config := transport.NewConfig()
	config.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	return NewServer(config)
}

func newClient() *Client {
	config := transport.NewConfig()
	config.TLS = &tls.Config{
		InsecureSkipVerify: true,
	}
	return NewClient(config)
}
