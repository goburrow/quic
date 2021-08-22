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

func TestAddressVerifier(t *testing.T) {
	addr1 := stubAddr("1.2.3.4:50")
	addr2 := stubAddr("5.6.7.8:90")
	odcid := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}
	rscid := []byte{4, 3, 2, 1}
	s, err := newAddressVerifier()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	s.timeFn = func() time.Time {
		return now
	}
	token := s.NewToken(addr1, rscid, odcid)
	t.Logf("token: %d %x", len(token), token)
	cid := s.VerifyToken(addr1, rscid, token)
	if !bytes.Equal(odcid, cid) {
		t.Fatalf("expect cid: %x\nactual: %x", odcid, cid)
	}
	// Still valid
	now = now.Add(10 * time.Second)
	cid = s.VerifyToken(addr1, rscid, token)
	if !bytes.Equal(odcid, cid) {
		t.Fatalf("expect cid: %x\nactual: %x", odcid, cid)
	}
	// Wrong address
	cid = s.VerifyToken(addr2, rscid, token)
	if cid != nil {
		t.Fatalf("expect cid: <nil>\nactual: %x", cid)
	}
	// Wrong SCID
	cid = s.VerifyToken(addr1, rscid[:len(rscid)-1], token)
	if cid != nil {
		t.Fatalf("expect cid: <nil>\nactual: %x", cid)
	}
	// Wrong token
	cid = s.VerifyToken(addr1, rscid, token[:len(token)-1])
	if cid != nil {
		t.Fatalf("expect cid: <nil>\nactual: %x", cid)
	}
	// Expired
	now = now.Add(1 * time.Second)
	cid = s.VerifyToken(addr1, rscid, token)
	if cid != nil {
		t.Fatalf("expect cid: <nil>\nactual: %x", cid)
	}
}

func BenchmarkAddressVerifier(b *testing.B) {
	addr := stubAddr("10.0.0.1:7890")
	odcid := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6}
	rscid := []byte{0, 0, 0, 0}
	s := NewAddressVerifier()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		token := s.NewToken(addr, rscid, odcid)
		cid := s.VerifyToken(addr, rscid, token)
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

func TestServerCIDIssuer(t *testing.T) {
	const id = 10000
	s := NewServerCIDIssuer(id)

	cid1, err := s.NewCID()
	if err != nil {
		t.Fatal(err)
	}
	if int(cid1[0]) != cidLength {
		t.Fatalf("expect cid length: %d, actual: %d", cidLength, cid1[0])
	}
	sid, n := decodeServerID(cid1[1:])
	if n != 2 {
		t.Fatalf("expect decoded length: %d, actual: %d", 2, n)
	}
	if sid != id {
		t.Fatalf("expect sid: %d, actual: %d", id, sid)
	}

	cid2, err := s.NewCID()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cid1[:1+n], cid2[:1+n]) {
		t.Fatalf("expect cid same prefix: %x %x", cid1, cid2)
	}
	if bytes.Equal(cid1[1+n:], cid2[1+n:]) {
		t.Fatalf("expect cid suffix different: %x %x", cid1, cid2)
	}
}
