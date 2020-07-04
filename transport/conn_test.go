package transport

import (
	"bytes"
	"crypto/tls"
	"testing"
	"time"
)

func newConfigWithCert() *Config {
	const certPEM = `-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaTAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE3MTAyMDE5NDMwNloXDTE4MTAyMDE5NDMwNlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD0d
7VNhbWvZLWPuj/RtHFjvtJBEwOkhbN/BnnE8rnZR8+sbwnc/KhCk3FhnpHZnQz7B
5aETbbIgmuvewdjvSBSjYzBhMA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggr
BgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MCkGA1UdEQQiMCCCDmxvY2FsaG9zdDo1
NDUzgg4xMjcuMC4wLjE6NTQ1MzAKBggqhkjOPQQDAgNIADBFAiEA2zpJEPQyz6/l
Wf86aX6PepsntZv2GYlA5UpabfT2EZICICpJ5h/iI+i341gBmLiAFQOyTDT+/wQc
6MF9+Yw1Yy0t
-----END CERTIFICATE-----`
	const keyPEM = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIrYSSNQFaA2Hwf1duRSxKtLYX5CB04fSeQ6tF1aY/PuoAoGCCqGSM49
AwEHoUQDQgAEPR3tU2Fta9ktY+6P9G0cWO+0kETA6SFs38GecTyudlHz6xvCdz8q
EKTcWGekdmdDPsHloRNtsiCa697B2O9IFA==
-----END EC PRIVATE KEY-----`

	c := NewConfig()
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		panic(err)
	}
	c.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	return c
}

func TestClientConnInitialState(t *testing.T) {
	config := newConfigWithCert()
	config.Params.OriginalDestinationCID = []byte{0}
	config.Params.InitialSourceCID = []byte{0}
	config.Params.RetrySourceCID = []byte{0}
	config.Params.StatelessResetToken = []byte{0}
	scid := []byte{1, 2, 3}

	c, err := Connect(scid, config)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(scid, c.scid) {
		t.Fatalf("expect scid %x, actual %x", scid, c.scid)
	}
	if !bytes.Equal(scid, c.localParams.InitialSourceCID) {
		t.Fatalf("expect initial source cid %x, actual %#v", scid, c.localParams)
	}
	if len(c.dcid) != MaxCIDLength {
		t.Fatalf("expect dcid generated, actual %x", c.dcid)
	}
	if c.localParams.OriginalDestinationCID != nil || c.localParams.RetrySourceCID != nil ||
		c.localParams.StatelessResetToken != nil {
		t.Fatalf("expect empty cid, actual %#v", c.localParams)
	}
}

func TestServerConnInitialState(t *testing.T) {
	config := newConfigWithCert()
	config.Params.OriginalDestinationCID = []byte{0}
	config.Params.InitialSourceCID = []byte{0}
	config.Params.RetrySourceCID = []byte{0}
	config.Params.StatelessResetToken = []byte{8, 9}
	scid := []byte{1, 2, 3}
	odcid := []byte{4, 5}

	c, err := Accept(scid, odcid, config)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(scid, c.scid) {
		t.Fatalf("expect scid %x, actual %x", scid, c.scid)
	}
	if !bytes.Equal(scid, c.localParams.InitialSourceCID) {
		t.Fatalf("expect initial source cid %x, actual %#v", scid, c.localParams)
	}
	if !bytes.Equal(odcid, c.localParams.OriginalDestinationCID) {
		t.Fatalf("expect original destination cid %x, actual %#v", odcid, c.localParams)
	}
	if !bytes.Equal(scid, c.localParams.RetrySourceCID) {
		t.Fatalf("expect retry source cid %x, actual %#v", scid, c.localParams)
	}
	if !bytes.Equal(config.Params.StatelessResetToken, c.localParams.StatelessResetToken) {
		t.Fatalf("expect reset token %x, actual %#v", config.Params.StatelessResetToken, c.localParams)
	}
}

func TestHandshake(t *testing.T) {
	clientConfig := NewConfig()
	clientConfig.TLS = &tls.Config{
		InsecureSkipVerify: true,
	}
	client, err := Connect([]byte{1, 2, 3, 4}, clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := newConfigWithCert()
	server, err := Accept(client.dcid, nil, serverConfig)
	if err != nil {
		t.Fatal(err)
	}

	b := make([]byte, 1200)
	start := time.Now()
	for !client.IsEstablished() && !server.IsEstablished() {
		n, err := client.Read(b)
		if n == 0 || err != nil {
			t.Fatalf("client read: %v %v", n, err)
		}
		m, err := server.Write(b[:n])
		if m != n || err != nil {
			t.Fatalf("server write: %v/%v %v", m, n, err)
		}
		n, err = server.Read(b)
		if n == 0 || err != nil {
			t.Fatalf("server read: %v %v", n, err)
		}
		m, err = client.Write(b[:n])
		if m != n || err != nil {
			t.Fatalf("client write: %v/%v %v", m, n, err)
		}
		t.Logf("client received %d bytes", m)
		elapsed := time.Since(start)
		if elapsed > 2*time.Second {
			t.Fatalf("handshake too slow: %v", elapsed)
		}
	}
}

func BenchmarkConnEvents(b *testing.B) {
	config := NewConfig()
	conn, err := Connect([]byte{1, 2, 3, 4}, config)
	if err != nil {
		b.Fatal(err)
	}
	events := make([]interface{}, 0, 2)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		conn.addEvent(StreamRecvEvent{
			StreamID: uint64(i),
		})
		conn.addEvent(&StreamRecvEvent{
			StreamID: uint64(i),
		})
		events = conn.Events(events)
		if len(events) != 2 {
			b.Fatalf("expect %d events. got %d", 2, len(events))
		}
		for _, e := range events {
			switch e := e.(type) {
			case StreamRecvEvent:
				_ = e
			case *StreamRecvEvent:
				_ = e
			}
		}
		events = events[:0]
	}
}
