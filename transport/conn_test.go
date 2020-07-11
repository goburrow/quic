package transport

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"testing"
	"time"
)

func TestClientConnInitialState(t *testing.T) {
	config := NewConfig()
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
	config := NewConfig()
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
	// Not use stub random and time
	clientConfig := NewConfig()
	clientConfig.Version = 0xffffffff
	clientConfig.TLS = &tls.Config{
		InsecureSkipVerify: true,
	}
	client, err := Connect([]byte("client-cid"), clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	err = negotiateClient(client)
	if err != nil {
		t.Fatal(err)
	}
	if client.version != ProtocolVersion {
		t.Fatalf("expect negotiated version %v, actual %v", ProtocolVersion, client.version)
	}
	err = retryClient(client)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("client retried scid=%x dcid=%x odcid=%x", client.scid, client.dcid, client.odcid)
	serverConfig := NewConfig()
	serverConfig.TLS = &tls.Config{
		Certificates: testCerts,
	}
	server, err := Accept([]byte("server-cid"), client.odcid, serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	err = handshake(client, server)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("server handshaked scid=%x dcid=%x odcid=%x", server.scid, server.dcid, server.odcid)
}

func TestConnStream(t *testing.T) {
	client, server, err := newTestConn()
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 1400)
	ct, err := client.Stream(4)
	if err != nil {
		t.Fatal(err)
	}
	n, err := ct.Write([]byte("hello"))
	if n != 5 || err != nil {
		t.Fatalf("stream write: %v %v", n, err)
	}
	err = ct.Close()
	if err != nil {
		t.Fatal(err)
	}
	n, err = client.Read(b)
	if err != nil {
		t.Fatalf("client read: %v %v", n, err)
	}
	n, err = server.Write(b[:n])
	if err != nil {
		t.Fatalf("server write: %v %v", n, err)
	}
	events := server.Events(nil)
	if len(events) != 1 {
		t.Fatalf("events %#v", events)
	}
	e, ok := events[0].(StreamRecvEvent)
	if !ok || e.StreamID != 4 {
		t.Fatalf("events %#v", events)
	}
	st, err := server.Stream(e.StreamID)
	if err != nil {
		t.Fatal(err)
	}
	n, err = st.Read(b)
	if n != 5 || err != nil {
		t.Fatalf("server stream read %v %v", n, err)
	}
	if string(b[:n]) != "hello" {
		t.Fatalf("server received %v", b[:n])
	}
	n, err = st.Read(b)
	if n != 0 || err != io.EOF {
		t.Fatalf("server stream read %v %v, expect %v", n, err, io.EOF)
	}
}

func TestSendMaxData(t *testing.T) {
	config := newTestConfig()
	config.Params.InitialMaxData = 200
	config.Params.InitialMaxStreamDataBidiRemote = 150
	s, err := Accept([]byte("server-cid"), nil, config)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 201)
	stream := &streamFrame{
		streamID: 4,
		offset:   0,
		data:     b,
	}
	_, err = s.recvFrameStream(encodeFrame(stream))
	if err != errFlowControl {
		t.Fatalf("expect error %v, actual %v", errFlowControl, err)
	}
	stream.data = b[:100]
	_, err = s.recvFrameStream(encodeFrame(stream))
	if err != nil {
		t.Fatal(err)
	}
	maxData := s.sendFrameMaxData()
	if maxData != nil {
		t.Fatalf("expect no max data frame, actual %v", maxData)
	}
	// max 1024, read 1000
	st, _ := s.Stream(4)
	st.Read(b)
	t.Logf("flow: %+v", s.flow)
	maxData = s.sendFrameMaxData()
	if maxData == nil || maxData.maximumData != 300 {
		t.Fatalf("expect max data frame, actual %v", maxData)
	}
	t.Logf("stream flow: %+v", st.flow)
	maxStreamData := s.sendFrameMaxStreamData(4, st)
	if maxStreamData == nil || maxStreamData.streamID != 4 || maxStreamData.maximumData != 250 {
		t.Fatalf("expect max stream data frame, actual %v", maxStreamData)
	}
}

func TestInvalidConn(t *testing.T) {
	invalidCID := make([]byte, MaxCIDLength+1)
	validCID := invalidCID[:MaxCIDLength]
	config := NewConfig()

	_, err := Connect(validCID, nil)
	if err == nil || err.Error() != "INTERNAL_ERROR config required" {
		t.Errorf("expect error, actual %+v", err)
	}
	_, err = Accept(invalidCID, nil, config)
	if err == nil || err.Error() != "PROTOCOL_VIOLATION cid too long" {
		t.Errorf("expect error, actual %+v", err)
	}
	_, err = Accept(validCID, invalidCID, config)
	if err == nil || err.Error() != "PROTOCOL_VIOLATION cid too long" {
		t.Errorf("expect error, actual %+v", err)
	}
}

func newTestConn() (client, server *Conn, err error) {
	clientCID := []byte("client-cid")
	clientConfig := newTestConfig()
	clientConfig.TLS.ServerName = "localhost"
	clientConfig.TLS.RootCAs = testCA

	client, err = Connect(clientCID, clientConfig)
	if err != nil {
		return nil, nil, err
	}

	serverConfig := newTestConfig()
	serverConfig.TLS.Certificates = testCerts

	serverCID := []byte("server-cid")
	server, err = Accept(serverCID, nil, serverConfig)
	if err != nil {
		return nil, nil, err
	}
	err = handshake(client, server)
	if err != nil {
		return nil, nil, err
	}
	return client, server, nil
}

func negotiateClient(client *Conn) error {
	b := make([]byte, 1400)
	n, err := client.Read(b)
	if err != nil {
		return err
	}
	h := Header{}
	_, err = h.Decode(b[:n], 0)
	if err != nil {
		return err
	}
	b = make([]byte, 200)
	n, err = NegotiateVersion(b, h.SCID, h.DCID)
	if err != nil {
		return err
	}
	_, err = client.Write(b[:n])
	if err != nil {
		return err
	}
	return nil
}

func retryClient(client *Conn) error {
	b := make([]byte, 1400)
	n, err := client.Read(b)
	if err != nil {
		return err
	}
	h := Header{}
	_, err = h.Decode(b[:n], 0)
	if err != nil {
		return err
	}
	b = make([]byte, 200)
	n, err = Retry(b, h.SCID, []byte("server-cid"), h.DCID, []byte("retry-token"))
	if err != nil {
		return err
	}
	_, err = client.Write(b[:n])
	if err != nil {
		return err
	}
	return nil
}

func handshake(client, server *Conn) error {
	b := make([]byte, 1400)
	start := time.Now()
	for !client.IsEstablished() || !server.IsEstablished() {
		n, err := client.Read(b)
		if err != nil {
			return err
		}
		if n > 0 {
			_, err = server.Write(b[:n])
			if err != nil {
				return err
			}
		}
		n, err = server.Read(b)
		if err != nil {
			return err
		}
		if n > 0 {
			_, err = client.Write(b[:n])
			if err != nil {
				return err
			}
		}
		elapsed := time.Since(start)
		if elapsed > 2*time.Second {
			return fmt.Errorf("handshake too slow: %v", elapsed)
		}
	}
	return nil
}

func BenchmarkCreateConn(b *testing.B) {
	config := newTestConfig()
	cid := make([]byte, MaxCIDLength)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = Accept(cid, cid, config)
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

type noRand struct{}

func (noRand) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = 0
	}
	return len(b), nil
}

var testRand = noRand{}

func testTime() time.Time {
	return time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)
}

func newTestConfig() *Config {
	c := NewConfig()
	c.TLS = &tls.Config{
		Rand: testRand,
		Time: testTime,
	}
	return c
}

// Expires on 31/12/2029
var testCertPEM = []byte(`-----BEGIN CERTIFICATE-----
MIIBczCCARmgAwIBAgIQMNC5PtdQfGBPkDp0QP5NxTAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTIwMDEwMTAwMDAwMFoXDTI5MTIzMTAwMDAwMFow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABL5e
HJzyLez8nzGod2UBWT5QFCv60ijOHUzTs/SIFKWJAcvwBcBL8IaTMA931hSNosjR
wtsVfGFltwfcEFPPPaujUTBPMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggr
BgEFBQcDATAMBgNVHRMBAf8EAjAAMBoGA1UdEQQTMBGCCWxvY2FsaG9zdIcEfwAA
ATAKBggqhkjOPQQDAgNIADBFAiEA0PgEOZ3gMrtAcBxlghkF0FBzHin1NsofjG1j
bjbX9NwCIFgj1xCCL0av3v4e2L+G+Hvn7ZNSKSsfTufJTJ7ZlKPN
-----END CERTIFICATE-----
`)

var testKeyPEM = []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgyNU/Dij7KDbwo7kd
UB61crAf8xE6gfK0Od6BE1GQQ0ShRANCAAS+Xhyc8i3s/J8xqHdlAVk+UBQr+tIo
zh1M07P0iBSliQHL8AXAS/CGkzAPd9YUjaLI0cLbFXxhZbcH3BBTzz2r
-----END PRIVATE KEY-----`)

var testCerts = newTestCerts()
var testCA = newTestCA()

func newTestCerts() []tls.Certificate {
	cert, err := tls.X509KeyPair(testCertPEM, testKeyPEM)
	if err != nil {
		panic(err)
	}
	return []tls.Certificate{cert}
}

func newTestCA() *x509.CertPool {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(testCertPEM) {
		panic("cannot add test server certificate")
	}
	return pool
}

func encodeFrame(f frame) []byte {
	n := f.encodedLen()
	b := make([]byte, n)
	_, err := f.encode(b)
	if err != nil {
		panic(err)
	}
	return b
}
