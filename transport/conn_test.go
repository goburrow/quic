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
	if err != nil {
		t.Fatal(err)
	}
	p := newTestEndpoint(t, client, server)
	p.assertHandshake()
	t.Logf("server handshaked scid=%x dcid=%x odcid=%x clientTx=%d serverTx=%d",
		server.scid, server.dcid, server.odcid, p.clientTx, p.serverTx)
}

func TestHandshakeWithRetry(t *testing.T) {
	// Not use stub random and time
	clientConfig := NewConfig()
	clientConfig.Version = 0xffffffff
	clientConfig.TLS = &tls.Config{
		InsecureSkipVerify: true,
	}
	p := newTestEndpoint(t, newTestClient(clientConfig), nil)
	p.assertNegotiateVersion()
	if p.client.version != ProtocolVersion {
		t.Fatalf("expect negotiated version %v, actual %v", ProtocolVersion, p.client.version)
	}
	p.assertRetry()
	t.Logf("client retried scid=%x dcid=%x odcid=%x", p.client.scid, p.client.dcid, p.client.odcid)
	serverConfig := NewConfig()
	serverConfig.TLS = &tls.Config{
		Certificates: testCerts,
	}
	server, err := Accept([]byte("server-cid"), p.client.odcid, serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	p.server = server
	p.assertHandshake()
	t.Logf("server handshaked scid=%x dcid=%x odcid=%x clientTx=%d serverTx=%d",
		server.scid, server.dcid, server.odcid, p.clientTx, p.serverTx)
}

func TestConnStream(t *testing.T) {
	p := newTestConn(t)
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
	p.assertClientSend()
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
	p.assertServerSend()
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

func TestConnHandshakeLoss(t *testing.T) {
	now := testTime()
	config := newTestConfig()
	config.TLS.ServerName = "localhost"
	config.TLS.RootCAs = testCA
	config.TLS.Certificates = testCerts
	config.TLS.Time = func() time.Time {
		return now
	}
	p := newTestEndpoint(t, newTestClient(config), newTestServer(config))
	p.assertClientSend() // CI0: crypto
	p.serverSendLoss()   // SI0+SH0 (L): crypto

	now = now.Add(1 * time.Second) // 1s
	p.assertClientLossTimer(now)
	p.assertServerLossTimer(now)
	p.client.Write(nil) // timed out
	p.clientSendLoss()  // CI1 (L): resend crypto
	p.server.Write(nil)
	p.serverSendLoss() // SI1 (L): resend crypto

	now = now.Add(1 * time.Second) // 2s
	p.assertServerLossTimer(now)
	p.server.Write(nil)
	err := p.serverSend() // SH1 (L): resend Handshake
	if err == nil || err.Error() != "packet_dropped: key_unavailable" {
		t.Fatalf("expect error %v, actual %v", "key_unavailable", err)
	}
	err = p.serverSend() // SH2 (L): ping
	if err == nil || err.Error() != "packet_dropped: key_unavailable" {
		t.Fatalf("expect error %v, actual %v", "key_unavailable", err)
	}

	now = now.Add(1 * time.Second) // 3s
	p.assertClientLossTimer(now)
	p.client.Write(nil)
	p.assertClientSend() // CI2: resend crypto
	p.assertServerSend() // SI2: resend ack

	now = now.Add(2 * time.Second) // 5s
	p.assertServerLossTimer(now)
	p.server.Write(nil)
	p.assertServerSend() // SI3: ack 0,2, crypto
	p.clientSendLoss()   // CI3 (L): ack 2,3
	p.serverSendLoss()   // SI4 (L): ping

	p.client.Write(nil)
	p.assertClientSend() // CI4: ack, ping
	p.assertServerSend() // SH3: crypto
	p.clientSendLoss()   // CH0 (L): crypto

	now = now.Add(1 * time.Second) // 6s
	p.client.Write(nil)
	p.assertClientSend() // CH1: crypto
	p.assertServerSend() // SH4: ack + SA0: done

	if p.client.ConnectionState() != StateActive {
		t.Fatal("client has not handshaked")
	}
	if p.server.ConnectionState() != StateActive {
		t.Fatal("server has not handshaked")
	}
	t.Logf("server tx: %d, client tx: %d", p.serverTx, p.clientTx)
}

func TestConnHandshakeTimeout(t *testing.T) {
	now := testTime()
	config := newTestConfig()
	config.Params.MaxIdleTimeout = 10 * time.Second
	config.TLS.ServerName = "localhost"
	config.TLS.RootCAs = testCA
	config.TLS.Certificates = testCerts
	config.TLS.Time = func() time.Time {
		return now
	}
	p := newTestEndpoint(t, newTestClient(config), newTestServer(config))
	p.assertClientSend() // CI0: crypto
	p.serverSendLoss()   // SI0+SH0: crypto

	now = now.Add(1 * time.Second) // 1
	p.server.Write(nil)
	p.serverSendLoss() // SI1: crypto

	now = now.Add(1 * time.Second) // 2
	p.server.Write(nil)
	p.serverSendLoss() // SH1: crypto
	p.serverSendLoss() // SH2: ping

	now = now.Add(3 * time.Second) // 5
	p.server.Write(nil)
	p.serverSendLoss() // SI2: crypto
	p.serverSendLoss() // SI3: ping
	p.client.Write(nil)
	p.assertClientSend()
	p.serverSendLoss() // SI4: ack

	now = now.Add(5 * time.Second) // 10
	p.server.Write(nil)
	p.serverSendLoss() // SI3: ping
	p.serverSendLoss() // SH4: ping

	now = now.Add(10 * time.Second)
	p.server.Write(nil)
	if p.server.ConnectionState() != StateClosed {
		t.Fatal("server has not closed")
	}
}

func TestConnResumption(t *testing.T) {
	clientConfig := newTestConfig()
	clientConfig.TLS.ServerName = "localhost"
	clientConfig.TLS.RootCAs = testCA
	clientConfig.TLS.ClientSessionCache = tls13.NewLRUClientSessionCache(10)

	serverConfig := newTestConfig()
	serverConfig.TLS.Certificates = testCerts

	p := newTestEndpoint(t, newTestClient(clientConfig), newTestServer(serverConfig))
	p.assertHandshake()
	tx1 := p.clientTx + p.serverTx
	t.Logf("first handshake: %d bytes", tx1)

	p.client.Close(true, 0, "")
	p.assertClientSend()

	client, _ := Connect([]byte("new-client"), clientConfig)
	server, _ := Accept([]byte("new-server"), nil, serverConfig)
	p = newTestEndpoint(t, client, server)
	p.assertHandshake()
	tx2 := p.clientTx + p.serverTx
	t.Logf("resume handshake: %d bytes", tx2)
	if tx1 <= tx2 {
		t.Fatalf("expect less roundtrip than %d, actual %d", tx1, tx2)
	}
}

func newTestClient(config *Config) *Conn {
	if config == nil {
		config = newTestConfig()
		config.TLS.ServerName = "localhost"
		config.TLS.RootCAs = testCA
	}
	cid := []byte("client-cid")
	conn, err := Connect(cid, config)
	if err != nil {
		panic(err)
	}
	return conn
}

func newTestServer(config *Config) *Conn {
	if config == nil {
		config = newTestConfig()
		config.TLS.Certificates = testCerts
	}
	cid := []byte("server-cid")
	conn, err := Accept(cid, nil, config)
	if err != nil {
		panic(err)
	}
	return conn
}

func newTestConn(t *testing.T) *testEndpoint {
	p := newTestEndpoint(t, newTestClient(nil), newTestServer(nil))
	p.assertHandshake()
	return p
}

type testEndpoint struct {
	t *testing.T

	client   *Conn
	clientTx int
	server   *Conn
	serverTx int

	buf [1400]byte
}

func newTestEndpoint(t *testing.T, client, server *Conn) *testEndpoint {
	return &testEndpoint{
		t:      t,
		client: client,
		server: server,
	}
}

func (t *testEndpoint) assertClientSend() {
	err := t.clientSend()
	if err != nil {
		t.t.Helper()
		t.t.Fatal(err)
	}
}

func (t *testEndpoint) clientSend() error {
	n, err := t.client.Read(t.buf[:])
	if err != nil {
		return err
	}
	if n > 0 {
		t.clientTx += n
		m, err := t.server.Write(t.buf[:n])
		if err != nil {
			return err
		}
		if n != m {
			return fmt.Errorf("expect write to server %v, actual %v", n, m)
		}
	}
	return nil
}

func (t *testEndpoint) assertServerSend() {
	err := t.serverSend()
	if err != nil {
		t.t.Helper()
		t.t.Fatal(err)
	}
}

func (t *testEndpoint) serverSend() error {
	n, err := t.server.Read(t.buf[:])
	if err != nil {
		return err
	}
	if n > 0 {
		t.serverTx += n
		m, err := t.client.Write(t.buf[:n])
		if err != nil {
			return err
		}
		if n != m {
			return fmt.Errorf("expect write to client %v, actual %v", n, m)
		}
	}
	return nil
}

func (t *testEndpoint) clientSendLoss() {
	n, _ := t.client.Read(t.buf[:])
	if n <= 0 {
		t.t.Helper()
		t.t.Fatalf("expect client read, actual %v", n)
	}
	t.clientTx += n
}

func (t *testEndpoint) serverSendLoss() {
	n, _ := t.server.Read(t.buf[:])
	if n <= 0 {
		t.t.Helper()
		t.t.Fatalf("expect server read, actual %v", n)
	}
	t.serverTx += n
}

func (t *testEndpoint) assertNegotiateVersion() {
	err := t.negotiateVersion()
	if err != nil {
		t.t.Helper()
		t.t.Fatalf("negotiate version: %v", err)
	}
}

func (t *testEndpoint) negotiateVersion() error {
	n, err := t.client.Read(t.buf[:])
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("client first packet is empty")
	}
	t.clientTx += n
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
	t.serverTx += n
	n, err = t.client.Write(b[:n])
	if err != nil {
		return err
	}
	return nil
}

func (t *testEndpoint) assertRetry() {
	err := t.retry()
	if err != nil {
		t.t.Helper()
		t.t.Fatalf("retry: %v", err)
	}
}

func (t *testEndpoint) retry() error {
	n, err := t.client.Read(t.buf[:])
	if err != nil {
		return err
	}
	t.clientTx += n
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
	t.serverTx += n
	n, err = t.client.Write(b[:n])
	if err != nil {
		return err
	}
	return nil
}

func (t *testEndpoint) assertHandshake() {
	err := t.handshake()
	if err != nil {
		t.t.Helper()
		t.t.Fatalf("handshake: %v", err)
	}
}

func (t *testEndpoint) handshake() error {
	i := 0
	for t.client.ConnectionState() != StateActive || t.server.ConnectionState() != StateActive {
		n, err := t.client.Read(t.buf[:])
		if err != nil {
			return err
		}
		if n > 0 {
			t.clientTx += n
			n, err = t.server.Write(t.buf[:n])
			if err != nil {
				return err
			}
		}
		n, err = t.server.Read(t.buf[:])
		if err != nil {
			return err
		}
		if n > 0 {
			t.serverTx += n
			n, err = t.client.Write(t.buf[:n])
			if err != nil {
				return err
			}
		}
		i++
		if i > 10 {
			return fmt.Errorf("no progress")
		}
	}
	return nil
}

func (t *testEndpoint) assertClientLossTimer(now time.Time) {
	if now.Before(t.client.recovery.lossDetectionTimer) {
		t.t.Helper()
		t.t.Fatalf("expect client loss timer before %v, actual %v", now, t.client.recovery.lossDetectionTimer)
	}
}

func (t *testEndpoint) assertServerLossTimer(now time.Time) {
	if now.Before(t.server.recovery.lossDetectionTimer) {
		t.t.Helper()
		t.t.Fatalf("expect server loss timer before %v, actual %v", now, t.server.recovery.lossDetectionTimer)
	}
}

func (t *testEndpoint) logState() {
	t.t.Logf("client:\n%v", connState(t.client))
	t.t.Logf("server:\n%v", connState(t.server))
}

func connState(conn *Conn) string {
	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, "state: %v\n", conn.state)
	re := conn.recovery
	fmt.Fprintf(buf, "recovery:\n")
	fmt.Fprintf(buf, "  timer: %v %v\n", re.lossDetectionTimer, re.lossTime)
	fmt.Fprintf(buf, "  pto: %v %v %v\n", re.probeTimeout(), re.ptoCount, re.lossProbes)
	fmt.Fprintf(buf, "  sent:\n")
	for i := range re.sent {
		for _, p := range re.sent[i] {
			fmt.Fprintf(buf, "    [%v] %v: %v\n", packetSpace(i), p.packetNumber, p.frames)
		}
	}
	fmt.Fprintf(buf, "  lost:\n")
	for i := range re.lost {
		for _, p := range re.lost[i] {
			fmt.Fprintf(buf, "    [%v] %v: %v\n", packetSpace(i), p.packetNumber, p.frames)
		}
	}
	fmt.Fprintf(buf, "idle: %v\n", conn.idleTimer)
	return buf.String()
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
