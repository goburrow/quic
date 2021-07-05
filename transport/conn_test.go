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
	dcid := []byte{3, 2, 1}

	c, err := Connect(scid, dcid, config)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(scid, c.scid) {
		t.Fatalf("expect scid %x, actual %x", scid, c.scid)
	}
	if !bytes.Equal(scid, c.localParams.InitialSourceCID) {
		t.Fatalf("expect initial source cid %x, actual %#v", scid, c.localParams)
	}
	if !bytes.Equal(dcid, c.dcid) {
		t.Fatalf("expect dcid %x, actual %x", dcid, c.dcid)
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
	client, err := Connect([]byte("client"), []byte("peer"), clientConfig)
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
	if p.client.version != supportedVersions[0] {
		t.Fatalf("expect negotiated version %v, actual %v", supportedVersions[0], p.client.version)
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
	if len(events) != 5 ||
		events[0].Type != EventConnOpen ||
		events[1].Type != EventStreamOpen || events[1].Data != 4 ||
		events[2].Type != EventStreamReadable || events[2].Data != 4 ||
		events[3].Type != EventStreamWritable || events[3].Data != 4 ||
		events[4].Type != EventStreamCreatable || events[4].Data != 3 {
		t.Fatalf("events %+v", events)
	}
	streamID := events[1].Data
	st, err := p.server.Stream(streamID)
	if err != nil {
		t.Fatal(err)
	}
	n, err = st.Read(p.buf[:])
	if n != 5 || err != io.EOF {
		t.Fatalf("server stream read %v %v", n, err)
	}
	if string(p.buf[:n]) != "hello" {
		t.Fatalf("server received %v", p.buf[:n])
	}
	n, err = st.Read(p.buf[:])
	if n != 0 || err != io.EOF {
		t.Fatalf("server stream read %v %v, expect %v", n, err, io.EOF)
	}
	_, err = st.WriteString("hi!")
	if err != nil {
		t.Fatal(err)
	}
	err = st.Close()
	if err != nil {
		t.Fatal(err)
	}
	p.assertServerSend()
	events = p.client.Events(nil)
	if len(events) != 4 ||
		events[0].Type != EventConnOpen ||
		events[1].Type != EventStreamComplete || events[1].Data != 4 ||
		events[2].Type != EventStreamReadable || events[2].Data != 4 ||
		events[3].Type != EventStreamCreatable || events[3].Data != 2 {
		t.Fatalf("events %+v", events)
	}
	n, err = ct.Read(p.buf[:])
	if n != 3 || err != io.EOF {
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
	if err == nil || err.Error() != "error_code=flow_control_error reason=stream: connection data exceeded limit 200" {
		t.Fatalf("expect error %v, actual %v", "flow_control_error", err)
	}
	stream.data = b[:140]
	_, err = s.recvFrameStream(encodeFrame(stream), testTime())
	if err != nil {
		t.Fatal(err)
	}
	maxData := s.sendFrameMaxData()
	if maxData != nil {
		t.Fatalf("expect no max data frame, actual %v", maxData)
	}
	// max 200, read 100, next 300
	st, _ := s.Stream(4)
	st.Read(b)
	t.Logf("flow: %+v", s.flow)
	maxData = s.sendFrameMaxData()
	if maxData == nil || maxData.maximumData != 340 {
		t.Fatalf("expect max data frame, actual %v", maxData)
	}
	t.Logf("stream flow: %+v", st.flow)
	maxStreamData := s.sendFrameMaxStreamData(4, st)
	if maxStreamData == nil || maxStreamData.streamID != 4 || maxStreamData.maximumData != 290 {
		t.Fatalf("expect max stream data frame, actual %v", maxStreamData)
	}
}

func TestInvalidConn(t *testing.T) {
	invalidCID := make([]byte, MaxCIDLength+1)
	validCID := invalidCID[:MaxCIDLength]
	config := NewConfig()

	_, err := Connect(validCID, nil, nil)
	if err == nil || err.Error() != "error_code=internal_error reason=config required" {
		t.Errorf("expect error, actual %+v", err)
	}
	_, err = Connect(validCID, invalidCID, config)
	if err == nil || err.Error() != "error_code=protocol_violation reason=cid length exceeded 20" {
		t.Errorf("expect error, actual %+v", err)
	}
	_, err = Accept(invalidCID, nil, config)
	if err == nil || err.Error() != "error_code=protocol_violation reason=cid length exceeded 20" {
		t.Errorf("expect error, actual %+v", err)
	}
	_, err = Accept(validCID, invalidCID, config)
	if err == nil || err.Error() != "error_code=protocol_violation reason=cid length exceeded 20" {
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
	conn, err := Connect([]byte("client"), []byte("server"), config)
	if err != nil {
		t.Fatal(err)
	}
	// Our local stream
	f := resetStreamFrame{
		streamID: 2,
	}
	_, err = conn.recvFrameResetStream(encodeFrame(&f), testTime())
	if err == nil || err.Error() != "error_code=stream_state_error reason=reset_stream: stream send-only 2" {
		t.Fatalf("expect error %v, actual %v", "stream_state_error", err)
	}
	// Too much connection data
	f = resetStreamFrame{
		streamID:  3,
		finalSize: config.Params.InitialMaxData + 1,
	}
	_, err = conn.recvFrameResetStream(encodeFrame(&f), testTime())
	if err == nil || err.Error() != "error_code=flow_control_error reason=reset_stream: connection data exceeded limit 1000" {
		t.Fatalf("expect error %v, actual %v", "flow_control_error", err)
	}
	// Reset different size
	st, err := conn.Stream(3)
	if err != nil {
		t.Fatal(err)
	}
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
		errorCode: 7,
		finalSize: 10,
	}
	_, err = conn.recvFrameResetStream(encodeFrame(&f), testTime())
	if err != nil {
		t.Fatal(err)
	}
	if conn.flow.recvTotal != f.finalSize {
		t.Fatalf("expect flow recv %v, actual %+v", 10, conn.flow)
	}
	st, err = conn.Stream(5)
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.Read(nil)
	if err == nil || err.Error() != "error_code=7 reason=reset_stream" {
		t.Fatalf("expect read error: %v, actual: %v", "reset_stream", err)
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
	if err == nil || err.Error() != "error_code=stream_state_error reason=stop_sending: stream not existed 1" {
		t.Fatalf("expect error %v, actual %v", "stream_state_error", err)
	}
	f.streamID = 2
	_, err = conn.recvFrameStopSending(encodeFrame(&f), testTime())
	if err == nil || err.Error() != "error_code=stream_state_error reason=stop_sending: stream receive-only 2" {
		t.Fatalf("expect error %v, actual %v", "stream_state_error", err)
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
	// Respond RESET_STREAM
	resetFrame := conn.sendFrameResetStream(f.streamID, st)
	if resetFrame == nil || resetFrame.streamID != f.streamID || resetFrame.errorCode != 9 || resetFrame.finalSize != 4 {
		t.Fatalf("expect reset frame %v %v %v, actual %+v", f.streamID, 9, 4, resetFrame)
	}
	st, err = conn.Stream(3)
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.Write(nil)
	if err == nil || err.Error() != "error_code=9 reason=stop_sending" {
		t.Fatalf("expect error: %v, actual: %v", "stop_sending", err)
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
	err = conn.Close(1, "failure", false)
	if err != nil {
		t.Fatal(err)
	}
	if conn.state != stateAttempted {
		t.Fatalf("expect connection state not changed, got %v", conn.state)
	}
	b := make([]byte, 100)
	n, err := conn.Read(b)
	if err != nil || n == 0 {
		t.Fatalf("expect read has data, got %v %v", n, err)
	}
	if conn.state != stateClosed {
		t.Fatalf("expect connection state %v, got %v", stateClosed, conn.state)
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

	if p.client.state != stateActive {
		t.Fatal("client has not handshaked")
	}
	if p.server.state != stateActive {
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
	if p.server.state != stateClosed {
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

	err := p.client.Close(0, "", true)
	if err != nil {
		t.Fatal(err)
	}
	p.assertClientSend()

	client, _ := Connect([]byte("new-client"), []byte("server"), clientConfig)
	server, _ := Accept([]byte("new-server"), nil, serverConfig)
	p = newTestEndpoint(t, client, server)
	p.assertHandshake()
	tx2 := p.clientTx + p.serverTx
	t.Logf("resume handshake: %d bytes", tx2)
	if tx1 <= tx2 {
		t.Fatalf("expect less roundtrip than %d, actual %d", tx1, tx2)
	}
}

func TestConnDataBlocked(t *testing.T) {
	conn, err := Accept([]byte("server"), nil, NewConfig())
	if err != nil {
		t.Fatal(err)
	}
	conn.flow.setSendMax(100)
	conn.flow.setSendBlocked(true)
	dataBlocked := conn.sendFrameDataBlocked()
	if dataBlocked == nil || dataBlocked.dataLimit != 100 {
		t.Fatalf("expect data blocked frame, actual: %+v", dataBlocked)
	}
}

func TestConnAmplificationLimit(t *testing.T) {
	client := newTestClient(nil)
	server := newTestServer(nil)
	b := make([]byte, MinInitialPacketSize)
	n, _ := client.Read(b)
	if n != MinInitialPacketSize || client.sentBytes != uint64(n) {
		t.Fatalf("expect sent: %v, actual: %v", MinInitialPacketSize, client.sentBytes)
	}
	n, _ = server.Write(b[:n])
	if server.recvBytes != uint64(n) {
		t.Fatalf("expect recv: %v, actual: %v", n, server.recvBytes)
	}
	server.sentBytes = 3000
	n = server.maxPacketSize()
	if n != 600 {
		t.Fatalf("expect max packet size: %v, actual: %v", 600, n)
	}
	n, _ = server.Read(b)
	if n > 600 {
		t.Fatalf("expect sent: %v, actual: %v", 600, n)
	}
	n, _ = server.Read(b)
	if n != 0 {
		t.Fatalf("expect sent: %v, actual: %v", 0, n)
	}
}

func newTestClient(config *Config) *Conn {
	if config == nil {
		config = newTestConfig()
		config.TLS.ServerName = "localhost"
		config.TLS.RootCAs = testCA
	}
	scid := []byte("client")
	dcid := []byte("server")
	conn, err := Connect(scid, dcid, config)
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
	cid := []byte("server")
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
		return fmt.Errorf("client read: %v %v", n, err)
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
	if n == 0 || err != nil {
		return fmt.Errorf("server read: %v %v", n, err)
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
	_, err = t.client.Write(b[:n])
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
	_, err = t.client.Write(b[:n])
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
	for !t.client.HandshakeComplete() || !t.server.HandshakeComplete() {
		n, err := t.client.Read(t.buf[:])
		if err != nil {
			return err
		}
		if n > 0 {
			t.clientTx += n
			_, err = t.server.Write(t.buf[:n])
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
			_, err = t.client.Write(t.buf[:n])
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
	d := now.Sub(t.client.recovery.lossDetectionTimer)
	if d < 0 || d > time.Second {
		t.t.Helper()
		t.t.Fatalf("expect client loss timer before %v, actual %v", now, t.client.recovery.lossDetectionTimer)
	}
}

func (t *testEndpoint) assertServerLossTimer(now time.Time) {
	d := now.Sub(t.server.recovery.lossDetectionTimer)
	if d < 0 || d > time.Second {
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
