package transport

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/goburrow/quic/tls13"
)

func TestClientConnInitialState(t *testing.T) {
	config := NewConfig()
	config.Params.OriginalDestinationCID = []byte("01234")
	config.Params.InitialSourceCID = []byte("56789")
	config.Params.RetrySourceCID = []byte("abcdef")
	config.Params.StatelessResetToken = []byte("xyz")
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
	config.Params.OriginalDestinationCID = []byte("01234")
	config.Params.InitialSourceCID = []byte("56789")
	config.Params.RetrySourceCID = []byte("abcdef")
	config.Params.StatelessResetToken = []byte("1234567890123456")
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
	clientConfig.TLS = &tls.Config{
		InsecureSkipVerify: true,
	}
	client, err := Connect([]byte("client"), clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := NewConfig()
	serverConfig.TLS = &tls.Config{
		Certificates: testCerts,
	}
	server, err := Accept([]byte("server"), nil, serverConfig)
	p := &testEndpoint{client: client, server: server}
	_, err = p.handshake()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("server handshaked scid=%x dcid=%x odcid=%x", server.scid, server.dcid, server.odcid)
}

func TestHandshakeWithRetry(t *testing.T) {
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
	p := &testEndpoint{client: client}
	err = p.negotiateVersion()
	if err != nil {
		t.Fatal(err)
	}
	if client.version != ProtocolVersion {
		t.Fatalf("expect negotiated version %v, actual %v", ProtocolVersion, client.version)
	}
	err = p.retry()
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
	p.server = server
	_, err = p.handshake()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("server handshaked scid=%x dcid=%x odcid=%x", server.scid, server.dcid, server.odcid)
}

func TestConnStream(t *testing.T) {
	p, err := newTestConn()
	if err != nil {
		t.Fatal(err)
	}
	ct, err := p.client.Stream(4)
	if err != nil {
		t.Fatal(err)
	}
	n, err := ct.WriteString("hello")
	if n != 5 || err != nil {
		t.Fatalf("stream write: %v %v", n, err)
	}
	err = ct.Close()
	if err != nil {
		t.Fatal(err)
	}
	n, err = p.sendToServer()
	if err != nil {
		t.Fatal(err)
	}
	events := p.server.Events(nil)
	if len(events) != 2 || events[0].Type != EventStreamReadable || events[0].ID != 4 ||
		events[1].Type != EventStreamWritable || events[1].ID != 4 {
		t.Fatalf("events %+v", events)
	}
	st, err := p.server.Stream(events[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	n, err = st.Read(p.buf[:])
	if n != 5 || err != nil {
		t.Fatalf("server stream read %v %v", n, err)
	}
	if string(p.buf[:n]) != "hello" {
		t.Fatalf("server received %v", p.buf[:n])
	}
	n, err = st.Read(p.buf[:])
	if n != 0 || err != io.EOF {
		t.Fatalf("server stream read %v %v, expect %v", n, err, io.EOF)
	}
	n, err = st.WriteString("hi!")
	if err != nil {
		t.Fatal(err)
	}
	err = st.Close()
	if err != nil {
		t.Fatal(err)
	}
	n, err = p.sendToClient()
	if err != nil {
		t.Fatal(err)
	}
	events = p.client.Events(nil)
	if len(events) != 2 || events[0].Type != EventStreamReadable || events[0].ID != 4 ||
		events[1].Type != EventStreamComplete || events[1].ID != 4 {
		t.Fatalf("events %+v", events)
	}
	n, err = ct.Read(p.buf[:])
	if n != 3 || err != nil {
		t.Fatalf("client stream read %v %v", n, err)
	}
	if string(p.buf[:n]) != "hi!" {
		t.Fatalf("client received %v", p.buf[:n])
	}
	n, err = st.Read(p.buf[:])
	if n != 0 || err != io.EOF {
		t.Fatalf("client stream read %v %v, expect %v", n, err, io.EOF)
	}
}

func TestConnSendMaxData(t *testing.T) {
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
	_, err = s.recvFrameStream(encodeFrame(stream), testTime())
	if err == nil || err.Error() != "flow_control_error stream: connection data exceeded 200" {
		t.Fatalf("expect error %v, actual %v", errorCodeString(FlowControlError), err)
	}
	stream.data = b[:100]
	_, err = s.recvFrameStream(encodeFrame(stream), testTime())
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
	if err == nil || err.Error() != "internal_error config required" {
		t.Errorf("expect error, actual %+v", err)
	}
	_, err = Accept(invalidCID, nil, config)
	if err == nil || err.Error() != "protocol_violation cid too long" {
		t.Errorf("expect error, actual %+v", err)
	}
	_, err = Accept(validCID, invalidCID, config)
	if err == nil || err.Error() != "protocol_violation cid too long" {
		t.Errorf("expect error, actual %+v", err)
	}
}

func TestConnRecvResetStream(t *testing.T) {
	config := NewConfig()
	config.Params.InitialMaxData = 1000
	config.Params.InitialMaxStreamDataBidiRemote = 300
	config.Params.InitialMaxStreamDataBidiLocal = 200
	config.Params.InitialMaxStreamDataUni = 100
	config.Params.InitialMaxStreamsBidi = 2
	conn, err := Connect([]byte("client"), config)
	if err != nil {
		t.Fatal(err)
	}
	// Our local stream
	f := resetStreamFrame{
		streamID: 2,
	}
	_, err = conn.recvFrameResetStream(encodeFrame(&f), testTime())
	if err == nil || err.Error() != "stream_state_error reset_stream: invalid id 2" {
		t.Fatalf("expect error %v, actual %v", errorText[StreamStateError], err)
	}
	// Too much connection data
	f = resetStreamFrame{
		streamID:  3,
		finalSize: config.Params.InitialMaxData + 1,
	}
	_, err = conn.recvFrameResetStream(encodeFrame(&f), testTime())
	if err == nil || err.Error() != "flow_control_error reset_stream: connection data exceeded 1000" {
		t.Fatalf("expect error %v, actual %v", errorCodeString(FlowControlError), err)
	}
	// Reset different size
	st := conn.streams.get(3)
	st.pushRecv(make([]byte, 10), 0, true)
	f = resetStreamFrame{
		streamID:  3,
		finalSize: 11,
	}
	_, err = conn.recvFrameResetStream(encodeFrame(&f), testTime())
	if err != errFinalSize {
		t.Fatalf("expect error %v, actual %v", errFinalSize, err)
	}
	// Succeed
	f = resetStreamFrame{
		streamID:  5,
		errorCode: 5,
		finalSize: 10,
	}
	_, err = conn.recvFrameResetStream(encodeFrame(&f), testTime())
	if err != nil {
		t.Fatal(err)
	}
	if conn.flow.totalRecv != f.finalSize {
		t.Fatalf("expect flow recv %v, actual %+v", 10, conn.flow)
	}
	events := conn.Events(nil)
	if len(events) != 1 || events[0].Type != EventStreamReset || events[0].ID != 5 || events[0].Data != 5 {
		t.Fatalf("event %+v", events)
	}
}

func TestConnRecvStopSending(t *testing.T) {
	conn, err := Accept([]byte("server"), nil, NewConfig())
	if err != nil {
		t.Fatal(err)
	}
	conn.peerParams.InitialMaxStreamDataUni = 10
	conn.streams.maxStreams.peerUni = 1
	// Our local stream
	f := stopSendingFrame{
		streamID: 1,
	}
	_, err = conn.recvFrameStopSending(encodeFrame(&f), testTime())
	if err == nil || err.Error() != "stream_state_error stop_sending: stream not existed 1" {
		t.Fatalf("expect error %v, actual %v", errorText[StreamStateError], err)
	}
	f.streamID = 2
	_, err = conn.recvFrameStopSending(encodeFrame(&f), testTime())
	if err == nil || err.Error() != "stream_state_error stop_sending: stream readonly 2" {
		t.Fatalf("expect error %v, actual %v", errorText[StreamStateError], err)
	}
	st, err := conn.Stream(3)
	if err != nil {
		t.Fatal(err)
	}
	n, err := st.WriteString("data")
	if n != 4 || err != nil {
		t.Fatalf("expect write %v %v, actual: %v %v", 4, nil, n, err)
	}
	// Peer wants us to stop sending
	f = stopSendingFrame{
		streamID:  3,
		errorCode: 9,
	}
	_, err = conn.recvFrameStopSending(encodeFrame(&f), testTime())
	if err != nil {
		t.Fatal(err)
	}
	events := conn.Events(nil)
	if len(events) != 1 || events[0].Type != EventStreamStop || events[0].ID != f.streamID || events[0].Data != 9 {
		t.Fatalf("event %+v", events)
	}
	resetFrame := conn.sendFrameResetStream(f.streamID, st)
	if resetFrame == nil || resetFrame.streamID != f.streamID || resetFrame.errorCode != 9 || resetFrame.finalSize != 4 {
		t.Fatalf("expect reset frame %v %v %v, actual %+v", f.streamID, 9, 4, resetFrame)
	}
}

func TestConnRecvPathChallenge(t *testing.T) {
	conn, err := Accept([]byte("server"), nil, NewConfig())
	if err != nil {
		t.Fatal(err)
	}
	f := pathChallengeFrame{
		data: []byte("12345678"),
	}
	_, err = conn.recvFramePathChallenge(encodeFrame(&f), testTime())
	if err != nil {
		t.Fatal(err)
	}
	rf := conn.sendFramePathResponse()
	if rf == nil {
		t.Fatalf("expect path response frame, actual %v", rf)
	}
	if string(rf.data) != "12345678" {
		t.Fatalf("expect response with same challenge, actual %v", rf)
	}
}

func TestConnClose(t *testing.T) {
	conn, err := Accept([]byte("server"), nil, NewConfig())
	if err != nil {
		t.Fatal(err)
	}
	conn.deriveInitialKeyMaterial([]byte("client"))
	conn.Close(false, 1, "failure")
	if conn.ConnectionState() != StateAttempted {
		t.Fatalf("expect connection state not changed, got %v", conn.ConnectionState())
	}
	b := make([]byte, 100)
	n, err := conn.Read(b)
	if err != nil || n == 0 {
		t.Fatalf("expect read has data, got %v %v", n, err)
	}
	if conn.ConnectionState() != StateClosed {
		t.Fatalf("expect connection state %v, got %v", StateClosed, conn.ConnectionState())
	}
}

func TestConnResumption(t *testing.T) {
	clientConfig := newTestConfig()
	clientConfig.TLS.ServerName = "localhost"
	clientConfig.TLS.RootCAs = testCA
	clientConfig.TLS.ClientSessionCache = tls13.NewLRUClientSessionCache(10)
	client, err := Connect([]byte("client"), clientConfig)
	if err != nil {
		t.Fatal(err)
	}

	serverConfig := newTestConfig()
	serverConfig.TLS.Certificates = testCerts
	server, err := Accept([]byte("server"), nil, serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	p := &testEndpoint{
		client: client,
		server: server,
	}
	hs1, err := p.handshake()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("first handshake: %d bytes", hs1)

	p.client.Close(true, 0, "")
	_, err = p.sendToServer()
	if err != nil {
		t.Fatal(err)
	}

	p.client, _ = Connect([]byte("new-client"), clientConfig)
	p.server, _ = Accept([]byte("new-server"), nil, serverConfig)
	hs2, err := p.handshake()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("resume handshake: %d bytes", hs2)
	if hs1 <= hs2 {
		// TODO: 0-RTT
		t.Fatalf("expect less roundtrip than %d, actual %d", hs1, hs2)
	}
}

func newTestConn() (*testEndpoint, error) {
	clientConfig := newTestConfig()
	clientConfig.TLS.ServerName = "localhost"
	clientConfig.TLS.RootCAs = testCA
	clientCID := []byte("client-cid")
	client, err := Connect(clientCID, clientConfig)
	if err != nil {
		return nil, err
	}
	serverConfig := newTestConfig()
	serverConfig.TLS.Certificates = testCerts
	serverCID := []byte("server-cid")
	server, err := Accept(serverCID, nil, serverConfig)
	if err != nil {
		return nil, err
	}
	p := &testEndpoint{
		client: client,
		server: server,
	}
	_, err = p.handshake()
	if err != nil {
		return nil, err
	}
	return p, nil
}

type testEndpoint struct {
	client *Conn
	server *Conn
	buf    [1400]byte
}

func (t *testEndpoint) sendToServer() (int, error) {
	return t.send(t.server, t.client)
}

func (t *testEndpoint) sendToClient() (int, error) {
	return t.send(t.client, t.server)
}

func (t *testEndpoint) send(to *Conn, from *Conn) (int, error) {
	n, err := from.Read(t.buf[:])
	if err != nil {
		return 0, err
	}
	if n > 0 {
		m, err := to.Write(t.buf[:n])
		if err != nil {
			return 0, err
		}
		if n != m {
			return 0, fmt.Errorf("expect write %v, actual %v", n, m)
		}
	}
	return n, nil
}

func (t *testEndpoint) negotiateVersion() error {
	n, err := t.client.Read(t.buf[:])
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("client first packet is empty")
	}
	h := Header{}
	_, err = h.Decode(t.buf[:n], 0)
	if err != nil {
		return fmt.Errorf("header decode: %v %v", n, err)
	}
	b := make([]byte, 256)
	n, err = NegotiateVersion(b, h.SCID, h.DCID)
	if err != nil {
		return err
	}
	_, err = t.client.Write(b[:n])
	return err
}

func (t *testEndpoint) retry() error {
	n, err := t.client.Read(t.buf[:])
	if err != nil {
		return err
	}
	h := Header{}
	_, err = h.Decode(t.buf[:n], 0)
	if err != nil {
		return err
	}
	b := make([]byte, 256)
	n, err = Retry(b, h.SCID, []byte("server-cid"), h.DCID, []byte("retry-token"))
	if err != nil {
		return err
	}
	_, err = t.client.Write(b[:n])
	return err
}

func (t *testEndpoint) handshake() (int, error) {
	start := time.Now()
	count := 0
	for t.client.ConnectionState() != StateActive || t.server.ConnectionState() != StateActive {
		n, err := t.client.Read(t.buf[:])
		if err != nil {
			return count, err
		}
		if n > 0 {
			count += n
			_, err = t.server.Write(t.buf[:n])
			if err != nil {
				return count, err
			}
		}
		n, err = t.server.Read(t.buf[:])
		if err != nil {
			return count, err
		}
		if n > 0 {
			count += n
			_, err = t.client.Write(t.buf[:n])
			if err != nil {
				return count, err
			}
		}
		elapsed := time.Since(start)
		if elapsed > 2*time.Second {
			return count, fmt.Errorf("handshake too slow: %v", elapsed)
		}
	}
	return count, nil
}

func BenchmarkCreateConn(b *testing.B) {
	config := newTestConfig()
	cid := make([]byte, MaxCIDLength)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = Accept(cid, cid, config)
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
