package quic

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"
)

// stubAddr implements net.Addr
type stubAddr string

func (s stubAddr) Network() string {
	return "udp"
}

func (s stubAddr) String() string {
	return string(s)
}

func TestAddressValidator(t *testing.T) {
	addr1 := stubAddr("1.2.3.4:50")
	addr2 := stubAddr("5.6.7.8:90")
	odcid := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}
	s, err := newAddressValidator()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	s.timeFn = func() time.Time {
		return now
	}
	token := s.GenerateToken(addr1, odcid)
	t.Logf("token: %d %x", len(token), token)
	cid := s.ValidateToken(addr1, token)
	if !bytes.Equal(odcid, cid) {
		t.Fatalf("expect cid: %x\nactual: %x", odcid, cid)
	}
	// Still valid
	now = now.Add(10 * time.Second)
	cid = s.ValidateToken(addr1, token)
	if !bytes.Equal(odcid, cid) {
		t.Fatalf("expect cid: %x\nactual: %x", odcid, cid)
	}
	// Wrong address
	cid = s.ValidateToken(addr2, token)
	if cid != nil {
		t.Fatalf("expect cid: <nil>\nactual: %x", cid)
	}
	// Expired
	now = now.Add(1 * time.Second)
	cid = s.ValidateToken(addr2, token)
	if cid != nil {
		t.Fatalf("expect cid: <nil>\nactual: %x", cid)
	}
}

func BenchmarkAddressValidator(b *testing.B) {
	addr := stubAddr("10.0.0.1:7890")
	odcid := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6}
	s := NewAddressValidator()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		token := s.GenerateToken(addr, odcid)
		cid := s.ValidateToken(addr, token)
		if cid == nil {
			b.Fatal("invalid token")
		}
	}
}

func TestServerNoConnection(t *testing.T) {
	socket, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(newServerConfig())
	s.SetListener(socket)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := s.Close()
		if err != nil {
			t.Errorf("server close: %v", err)
		}
		// Close again should not panic
		err = s.Close()
		if err != nil {
			t.Logf("server close: %v", err)
		}
	}()
	err = s.Serve()
	if err != nil {
		t.Logf("server serve: %v", err)
	}
	wg.Wait()
}
