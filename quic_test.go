package quic

import (
	"crypto/tls"
	"io"
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
	s, c := newPipe(nil, nil)
	// Server
	s.SetHandler(handlerFunc(func(conn *Conn, events []transport.Event) {
		for _, e := range events {
			switch e.Type {
			case transport.EventConnOpen:
			case transport.EventStreamOpen:
				if e.ID != 4 || e.Data != 1 {
					t.Errorf("expect client open stream %d, actual %v", 4, e)
				}
			case transport.EventStreamReadable:
				buf := make([]byte, 8)
				n, err := conn.StreamRead(e.ID, buf)
				if err != io.EOF {
					t.Errorf("server stream receive: %v", err)
					conn.Close()
					return
				}
				if string(buf[:n]) != "ping" {
					t.Errorf("expect server receive: ping. Got %s", buf[:n])
				}
				n, err = conn.StreamWrite(e.ID, []byte("pong"))
				if n != 4 || err != nil {
					t.Errorf("server stream send: %v %v", n, err)
					conn.Close()
					return
				}
			case transport.EventStreamWritable:
				if e.ID != 4 {
					t.Errorf("expect writable stream %d, actual %d", 4, e.ID)
				}
			case transport.EventConnClosed:
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
	go s.Serve()

	// Client
	recvData := make(chan []byte, 1)
	c.SetHandler(handlerFunc(func(conn *Conn, events []transport.Event) {
		for _, e := range events {
			switch e.Type {
			case transport.EventConnOpen:
				_, err := conn.StreamWrite(4, []byte("ping"))
				if err != nil {
					t.Errorf("write stream %v", err)
					conn.Close()
					return
				}
				conn.StreamClose(4)
			case transport.EventStreamReadable:
				buf := make([]byte, 8)
				n, err := conn.StreamRead(e.ID, buf)
				if n > 0 {
					recvData <- buf[:n]
				} else {
					t.Errorf("client stream receive: %v %v", n, err)
					recvData <- nil
				}
				conn.Close()
			case transport.EventStreamWritable:
				if e.ID != 4 {
					t.Errorf("expect writable stream %d, actual %d", 4, e.ID)
				}
			case transport.EventStreamComplete:
				if e.ID != 4 {
					t.Errorf("expect stream send complete %d, actual %d", 4, e.ID)
				}
			case transport.EventConnClosed:
			default:
				t.Errorf("unexpected event: %#v", e)
			}
		}
	}))
	defer func() {
		err := c.Close()
		if err != nil {
			t.Errorf("client close: %v", err)
		}
	}()
	go c.Serve()
	err := c.Connect(s.LocalAddr().String())
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

func TestClientCloseHandshake(t *testing.T) {
	clientConfig := transport.NewConfig()
	clientConfig.TLS = &tls.Config{
		ServerName: "quic",
	}
	s, c := newPipe(nil, clientConfig)

	closeCh := make(chan struct{}, 2)
	s.SetHandler(handlerFunc(func(conn *Conn, events []transport.Event) {
		if len(events) != 1 || events[0].Type != transport.EventConnClosed {
			t.Errorf("expect only close event, got %v", events)
		}
		closeCh <- struct{}{}
	}))
	defer s.Close()
	go s.Serve()

	c.SetHandler(handlerFunc(func(conn *Conn, events []transport.Event) {
		if len(events) != 1 || events[0].Type != transport.EventConnClosed {
			t.Errorf("expect only close event, got %v", events)
		}
		closeCh <- struct{}{}
	}))
	defer c.Close()
	go c.Serve()

	err := c.Connect(s.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	timeout := time.After(5 * time.Second)
	for i := 0; i < 2; i++ {
		select {
		case <-closeCh:
		case <-timeout:
			t.Errorf("receive timed out")
		}
	}
}

func newPipe(serverConfig, clientConfig *transport.Config) (*Server, *Client) {
	ss, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	cs, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	if serverConfig == nil {
		serverConfig = newServerConfig()
	}
	if clientConfig == nil {
		clientConfig = newClientConfig()
	}
	s := NewServer(serverConfig)
	s.SetListener(ss)
	c := NewClient(clientConfig)
	c.SetListener(cs)
	return s, c
}

func newServerConfig() *transport.Config {
	cert, err := tls.LoadX509KeyPair("testdata/cert.pem", "testdata/key.pem")
	if err != nil {
		panic(err)
	}
	config := transport.NewConfig()
	config.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	return config
}

func newClientConfig() *transport.Config {
	config := transport.NewConfig()
	config.TLS = &tls.Config{
		InsecureSkipVerify: true,
	}
	return config
}
