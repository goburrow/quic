package transport

import (
	"io"
	"testing"
)

func TestStreamRecv(t *testing.T) {
	s := Stream{}
	s.init(false, true)
	s.flow.init(10, 0)
	// Receive data
	b := []byte("recvstream")
	err := s.pushRecv(b, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if !s.isReadable() {
		t.Fatalf("expect readable: %v", &s)
	}
	// Consume
	b = make([]byte, 10)
	n, err := s.Read(b[:4])
	if err != nil || n != 4 || string(b[:n]) != "recv" {
		t.Fatalf("expect read %v %v %s, actual %v %v %s", 4, nil, "recv", n, err, b[:n])
	}
	if !s.isReadable() {
		t.Fatalf("expect readable: %v", &s)
	}
	// Continue consume
	n, err = s.Read(b)
	if err != io.EOF || n != 6 || string(b[:n]) != "stream" {
		t.Fatalf("expect read %v %v %s, actual %v %v %s", 6, io.EOF, "stream", n, err, b[:n])
	}
	// End
	if s.isReadable() {
		t.Fatalf("expect not readable: %v", &s)
	}
	n, err = s.Read(b)
	if n != 0 || err != io.EOF {
		t.Fatalf("expect error %v, actual %v", io.EOF, err)
	}
	if s.isReadable() {
		t.Fatalf("expect not readable: %v", &s)
	}
	// Receive wrong offset
	s.flow.recvMax++
	err = s.pushRecv(b[:1], 10, true)
	if err != errFinalSize {
		t.Fatalf("expect error %v, actual %v", errFinalSize, err)
	}
}

func TestStreamRecvRetry(t *testing.T) {
	s := Stream{}
	s.init(false, true)
	s.flow.init(100, 0)

	data := []byte("recvstream")
	s.pushRecv(data, 0, false)
	s.pushRecv(data, 20, true)
	b := make([]byte, 100)
	n, err := s.Read(b)
	if err != nil || n != 10 || string(b[:n]) != "recvstream" {
		t.Fatalf("expect read %v %v %s, actual %v %v %s", 10, nil, "recvstream", n, err, b[:n])
	}
	n, err = s.Read(b)
	if err != nil || n != 0 {
		t.Fatalf("expect read %v %v, actual %v %v", 0, nil, n, err)
	}
	s.pushRecv(data, 0, false)
	n, err = s.Read(b)
	if err != nil || n != 0 {
		t.Fatalf("expect read %v %v, actual %v %v", 0, nil, n, err)
	}
	s.pushRecv(data, 6, false)
	n, err = s.Read(b)
	if err != nil || n != 6 || string(b[:n]) != "stream" {
		t.Fatalf("expect read %v %v %s, actual %v %v %s", 6, nil, "stream", n, err, b[:n])
	}
	s.pushRecv(data, 10, false)
	n, err = s.Read(b)
	if err != io.EOF || n != 14 || string(b[:n]) != "reamrecvstream" {
		t.Fatalf("expect read %v %v %s, actual %v %v %s", 14, io.EOF, "reamrecvstream", n, err, b[:n])
	}
	n, err = s.Read(b)
	if err != io.EOF || n != 0 {
		t.Fatalf("expect read %v %v, actual %v %v", 0, io.EOF, n, err)
	}
}

func TestStreamSend(t *testing.T) {
	s := Stream{}
	s.init(false, true)
	s.flow.init(0, 10)
	// Send
	b := []byte("sendstream")
	n, err := s.Write(b[:4])
	if err != nil || n != 4 {
		t.Fatalf("expect write %v %v, actual %v %v", 4, nil, n, err)
	}
	if !s.isWritable() {
		t.Fatalf("expect writeable: %v", &s)
	}
	n, err = s.Write(b[4:])
	if err != nil || n != 6 {
		t.Fatalf("expect write %v %v, actual %v %v", 6, nil, n, err)
	}
	if s.isWritable() {
		t.Fatalf("expect not writeable: %v", &s)
	}
	// Done sending
	err = s.Close()
	if err != nil {
		t.Fatal(err)
	}
	if s.isWritable() {
		t.Fatalf("expect not writeable: %v", &s)
	}
	// Consume
	b, off, fin := s.popSend(4)
	if string(b) != "send" || off != 0 || fin != false {
		t.Fatalf("expect pop %q %v %v, actual %s %v %v", "send", 0, false, b, off, fin)
	}
	// Continue consume
	b, off, fin = s.popSend(20)
	if string(b) != "stream" || off != 4 || fin != true {
		t.Fatalf("expect pop %q %v %v, actual %s %v %v", "stream", 4, true, b, off, fin)
	}
	// Stream is empty now
	if s.isFlushable() {
		t.Fatalf("expect flushable %v, actual %v", false, s.isFlushable())
	}
	// Cannot send more data
	s.flow.sendMax++
	n, err = s.Write(b[:1])
	if n != 0 || err != errFinalSize {
		t.Fatalf("expect write %v %v, actual %v %v", 0, errFinalSize, n, err)
	}
}

func TestStreamRecvEOF(t *testing.T) {
	s := Stream{}
	s.init(true, true)
	s.flow.init(10, 10)

	s.pushRecv(nil, 10, true)
	b := make([]byte, 100)
	n, err := s.Read(b)
	if err != nil || n != 0 {
		t.Fatalf("expect read %v %v, actual %v %v", 0, nil, n, err)
	}
	s.pushRecv(b[:10], 0, false)
	n, err = s.Read(b)
	if err != io.EOF || n != 10 {
		t.Fatalf("expect read %v %v, actual %v %v", 0, io.EOF, n, err)
	}
	n, err = s.Read(b)
	if err != io.EOF || n != 0 {
		t.Fatalf("expect read %v %v, actual %v %v", 0, nil, n, err)
	}
}

func TestStreamCloseWriteBidi(t *testing.T) {
	s := Stream{}
	s.init(true, true)
	s.flow.init(10, 10)

	_, err := s.WriteString("stream")
	if err != nil {
		t.Fatal(err)
	}
	if !s.isFlushable() {
		t.Fatalf("expect flushable %v, actual %v", true, s.isFlushable())
	}
	err = s.CloseWrite(100)
	if err != nil {
		t.Fatal(err)
	}
	code, ok := s.updateResetStream()
	if ok || code != 0 {
		t.Fatalf("expect send error code %v(%v), actual %v(%v)", 0, false, code, ok)
	}
	if !s.isFlushable() {
		t.Fatalf("expect flushable %v, actual %v", true, s.isFlushable())
	}
	if s.isWritable() {
		t.Fatalf("expect writable %v, actual %v", false, s.isWritable())
	}
	n, err := s.WriteString("more")
	if n != 0 || err == nil || err.Error() != "stream_state_error sending terminated: 100" {
		t.Fatalf("expect write %v %v, actual %v %v", 0, errorCodeString(StreamStateError), n, err)
	}
	// Sending
	b, off, fin := s.popSend(10)
	if string(b) != "stream" || off != 0 || fin != true {
		t.Fatalf("expect pop %q %v %v, actual %q %v %v", "stream", 0, true, b, off, fin)
	}
	code, ok = s.updateResetStream()
	if !ok || code != 100 {
		t.Fatalf("expect send error code %v(%v), actual %v(%v)", 100, true, code, ok)
	}
	s.setResetStream(deliverySending)
	code, ok = s.updateResetStream()
	if ok || code != 0 {
		t.Fatalf("expect send error code %v(%v), actual %v(%v)", 0, true, code, ok)
	}
}

func TestStreamCloseWriteUni(t *testing.T) {
	s := Stream{}
	s.init(false, false)

	err := s.CloseWrite(100)
	if err == nil || err.Error() != "stream_state_error cannot close sending remote unidirectional stream" {
		t.Fatalf("expect error %v, actual %v", errorCodeString(StreamStateError), err)
	}
}

func TestStreamCloseReadBidi(t *testing.T) {
	s := Stream{}
	s.init(false, true)
	s.flow.init(10, 10)

	err := s.CloseRead(100)
	if err != nil {
		t.Fatal(err)
	}
	code, ok := s.updateStopSending()
	if !ok || code != 100 {
		t.Fatalf("expect recv error code %v(%v), actual %v(%v)", 100, true, code, ok)
	}
	err = s.pushRecv([]byte("stream"), 0, false)
	if err != nil {
		t.Fatal(err)
	}
	s.setStopSending(deliverySending)
	code, ok = s.updateStopSending()
	if ok || code != 0 {
		t.Fatalf("expect recv error code %v(%v), actual %v(%v)", 0, false, code, ok)
	}
}

func TestStreamCloseReadUni(t *testing.T) {
	s := Stream{}
	s.init(true, false)

	err := s.CloseRead(100)
	if err == nil || err.Error() != "stream_state_error cannot close receiving local unidirectional stream" {
		t.Fatalf("expect error %v, actual %v", errorCodeString(StreamStateError), err)
	}
}

func TestStreamClose(t *testing.T) {
	s := Stream{}
	s.init(false, true)
	s.flow.init(0, 10)

	_, err := s.WriteString("stream")
	if err != nil {
		t.Fatal(err)
	}
	// Read all data before close
	b, off, fin := s.popSend(20)
	if string(b) != "stream" || off != 0 || fin != false {
		t.Fatalf("expect pop %q %v %v, actual %s %v %v", "stream", 0, false, b, off, fin)
	}
	err = s.Close()
	if err != nil {
		t.Fatalf("close stream: %v", err)
	}
	if s.send.isClosed() {
		t.Fatalf("expect not closed: %+v", &s)
	}
	if !s.isFlushable() {
		t.Fatalf("expect flushable: %+v", &s)
	}
	b, off, fin = s.popSend(20)
	if len(b) != 0 || off != 6 || fin != true {
		t.Fatalf("expect pop %q %v %v, actual %s %v %v", "", 6, true, b, off, fin)
	}
	s.ackSend(0, 6)
	if !s.send.isClosed() {
		t.Fatalf("expect send closed: %+v", &s)
	}
}

func TestStreamType(t *testing.T) {
	data := []struct {
		id     uint64
		client bool
		local  bool
	}{
		{4, true, true},
		{3, true, false},
		{4, false, false},
		{3, false, true},
	}
	for _, d := range data {
		local := isStreamLocal(d.id, d.client)
		if local != d.local {
			t.Fatalf("expect %+v", d)
		}
	}
}

func TestStreamLocalBidi(t *testing.T) {
	s := Stream{}
	s.init(true, true)
	s.flow.init(10, 10)

	b := make([]byte, 10)
	// Send data
	n, err := s.Write(b)
	if err != nil || n != 10 {
		t.Fatalf("expect write %v %v, actual %v %v", 10, nil, n, err)
	}
	if s.flow.sendTotal != 10 {
		t.Fatalf("expect flow send %v, actual %v", 10, s.flow.sendTotal)
	}
	// Send too much data
	n, err = s.Write(b[:1])
	if err != nil || n != 0 {
		t.Fatalf("expect nothing written, actual %v %v", n, err)
	}
	if s.flow.sendTotal != 10 {
		t.Fatalf("expect flow send %v, actual %v", 10, s.flow.sendTotal)
	}
	// Receive data
	err = s.pushRecv(b[:4], 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if s.flow.recvTotal != 4 {
		t.Fatalf("expect flow recv %d, actual %v", 4, s.flow.recvTotal)
	}
	n, err = s.Read(b)
	if n != 4 || err != nil {
		t.Fatalf("expect read %v %v, actual %v %v", 4, nil, n, err)
	}
	if s.flow.recvMaxNext != 14 {
		t.Fatalf("expect flow recv next %v, actual %v", 14, s.flow.recvMaxNext)
	}
}

func TestStreamRemoteBidi(t *testing.T) {
	s := Stream{}
	s.init(false, true)
	s.flow.init(20, 20)

	b := make([]byte, 10)
	// Send data
	n, err := s.Write(b)
	if err != nil || n != 10 {
		t.Fatalf("expect write %v %v, actual %v %v", 10, nil, n, err)
	}
	s.send.pop(5)
	// Resend data
	err = s.send.push(b[:1], 2, false)
	if err != nil {
		t.Fatal(err)
	}
	if !s.isFlushable() {
		t.Fatalf("expect flushable %v, actual %v", true, s.isFlushable())
	}
	b, off, fin := s.send.pop(5)
	if len(b) != 1 || off != 2 || fin {
		t.Fatalf("expect pop %v %v %v, actual %v %v %v", 1, 2, false, len(b), off, fin)
	}
}

func TestStreamRemoteUni(t *testing.T) {
	s := Stream{}
	s.init(false, false)
	s.flow.init(20, 20)
	b := make([]byte, 10)
	// Not allow writing to remote unidirectional stream
	_, err := s.Write(b[:1])
	if err, ok := err.(*Error); !ok || err.Code != StreamStateError {
		t.Fatalf("expect error %+v, actual %+v", errorText[StreamStateError], err)
	}
	// Close should have no effect.
	err = s.Close()
	if err != nil {
		t.Fatal(err)
	}
	// Receive data out of order
	err = s.pushRecv(b, 5, false)
	if err != nil {
		t.Fatal(err)
	}
	if s.flow.recvTotal != 15 {
		t.Fatalf("expect flow recv %v, actual %v", 15, s.flow.recvTotal)
	}
	err = s.pushRecv(b, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if s.flow.recvTotal != 15 {
		t.Fatalf("expect flow recv %v, actual %v", 15, s.flow.recvTotal)
	}
	// Exceeds limits
	err = s.pushRecv(b, 11, false)
	if err == nil || err.Error() != "flow_control_error stream: data exceeded 20" {
		t.Fatalf("expect error %v, actual %v", errorCodeString(FlowControlError), err)
	}
}

func TestStreamUpdateMaxStreamsBidi(t *testing.T) {
	sm := streamMap{}
	sm.init(3, 0)

	for i := 0; i < 3; i++ {
		st, err := sm.create(uint64(i*4), false)
		if err != nil {
			t.Fatal(err)
		}
		st.flow.init(1, 2)
	}
	_, err := sm.create(12, false)
	if err == nil || err.Error() != "stream_limit_error remote bidi streams exceeded 3" {
		t.Fatalf("expect error %v, actual %v", errorCodeString(StreamLimitError), err)
	}
	var b [8]byte
	st := sm.get(0)
	st.pushRecv(b[:1], 0, true)
	n, err := st.Read(b[:0])
	if n != 0 || err != nil {
		t.Fatalf("expect read: %v %v, actual: %v %v", 0, nil, n, err)
	}
	if st.recv.isClosed() {
		t.Fatalf("expect recv stream not closed, actual %v", st.recv.isClosed())
	}
	n, err = st.Read(b[:])
	if n != 1 || err != io.EOF {
		t.Fatalf("expect read: %v %v, actual: %v %v", 1, io.EOF, n, err)
	}
	if !st.recv.isClosed() {
		t.Fatalf("expect recv stream closed, actual %v", st.recv.isClosed())
	}
	st.Write(b[:2])
	st.Close()
	st.popSend(2)
	if st.send.isClosed() {
		t.Fatalf("expect send stream not closed, actual %v", st.send.isClosed())
	}
	st.ackSend(0, 2)
	if !st.send.isClosed() {
		t.Fatalf("expect send stream closed, actual %v", st.send.isClosed())
	}
	sm.checkClosed(func(uint64) {})
	_, existed := sm.closedStreams[0]
	if len(sm.closedStreams) != 1 || !existed {
		t.Fatalf("expect stream moved to closed list, actual %v", sm.closedStreams)
	}
	if sm.maxStreamsNext.localBidi != 4 {
		t.Fatalf("expect localBidi %v, actual %v", 4, sm.maxStreamsNext.localBidi)
	}
	if !sm.updateMaxStreamsBidi {
		t.Fatalf("expect updateMaxStreamsBidi %v, actual %v", true, sm.updateMaxStreamsBidi)
	}
}

func TestStreamUpdateMaxStreamsUni(t *testing.T) {
	sm := streamMap{}
	sm.init(0, 2)

	for i := 0; i < 2; i++ {
		st, err := sm.create(uint64(i*4)+3, true)
		if err != nil {
			t.Fatal(err)
		}
		st.flow.init(0, 1)
	}
	_, err := sm.create(11, true)
	if err == nil || err.Error() != "stream_limit_error remote uni streams exceeded 2" {
		t.Fatalf("expect error %v, actual %v", errorCodeString(StreamLimitError), err)
	}
	st := sm.get(7)
	if st.recv.isClosed() {
		t.Fatalf("expect recv stream not closed, actual %v", st.recv.isClosed())
	}
	st.stopSend(0)
	if !st.send.isClosed() {
		t.Fatalf("expect send stream closed, actual %v", st.send.isClosed())
	}
	sm.checkClosed(func(uint64) {})
	_, existed := sm.closedStreams[7]
	if len(sm.closedStreams) != 1 || !existed {
		t.Fatalf("expect stream moved to closed list, actual %v", sm.closedStreams)
	}
	if sm.maxStreamsNext.localUni != 3 {
		t.Fatalf("expect localUni %v, actual %v", 3, sm.maxStreamsNext.localUni)
	}
	if !sm.updateMaxStreamsUni {
		t.Fatalf("expect updateMaxStreamsBidi %v, actual %v", true, sm.updateMaxStreamsUni)
	}
}
