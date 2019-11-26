package tls13

import (
	"crypto/x509"
	"testing"
	"time"
	"reflect"
)

func TestConvertClientSessionState(t *testing.T) {
	cert := &x509.Certificate{}
	s := &clientSessionState{
		sessionTicket: []byte{1, 2, 3},
		vers: 4,
		cipherSuite: 5,
		masterSecret: []byte{7, 8, 9},
		serverCertificates: []*x509.Certificate{ cert },
		verifiedChains: [][]*x509.Certificate{ { cert} },
		receivedAt: time.Now(),
		nonce: []byte{2, 4},
		useBy: time.Now(),
		ageAdd: 6,
	}
	ts := s.toTLS()

	s2 := &clientSessionState{}
	s2.fromTLS(ts)

	if !reflect.DeepEqual(s, s2) {
		t.Fatalf("unexpected clientSessionState:\n%+v\n%+v\n%+v", s, ts, s2)
	}
}