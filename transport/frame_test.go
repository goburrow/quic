package transport

import (
	"crypto/rand"
	"fmt"
	mrand "math/rand"
	"reflect"
	"testing"

	"github.com/goburrow/quic/testdata"
)

func TestDecodeCryptoFrame(t *testing.T) {
	data := `
060040c4010000c003036660261ff947 cea49cce6cfad687f457cf1b14531ba1
4131a0e8f309a1d0b9c4000006130113 031302010000910000000b0009000006
736572766572ff01000100000a001400 12001d00170018001901000101010201
03010400230000003300260024001d00 204cfdfcd178b784bf328cae793b136f
2aedce005ff183d7bb14952072366470 37002b0003020304000d0020001e0403
05030603020308040805080604010501 060102010402050206020202002d0002
0101001c00024001`
	b := testdata.DecodeHex(data)
	var frameType uint64
	n := getVarint(b, &frameType)
	if n != 1 || frameType != frameTypeCrypto {
		t.Fatalf("unexpected frame: n=%d type=%d", n, frameType)
	}
	frame := cryptoFrame{}
	n, err := frame.decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if n != 200 {
		t.Fatalf("unexpected read: n=%d", n)
	}
}

func TestFrameCrypto(t *testing.T) {
	f := &cryptoFrame{
		offset: 1,
		data:   []byte{1, 2, 3},
	}
	testFrame(t, f, "060103010203")
}

func TestFramePadding(t *testing.T) {
	f := newPaddingFrame(1)
	testFrame(t, f, "00")
	f = newPaddingFrame(5)
	testFrame(t, f, "0000000000")

	n, err := f.decode(nil)
	if n != 1 || err != nil {
		t.Fatalf("expect decode: %v %v, actual: %v %v", 1, nil, n, err)
	}
	n, err = f.decode([]byte{0x80, 0, 0, 0})
	if n != 4 || err != nil {
		t.Fatalf("expect decode: %v %v, actual: %v %v", 4, nil, n, err)
	}
	n, err = f.decode([]byte{0x40, 0, 0})
	if n != 3 || err != nil {
		t.Fatalf("expect decode: %v %v, actual: %v %v", 3, nil, n, err)
	}
	if f.length != 3 {
		t.Fatalf("expect padding length: %v, actual: %v", 3, f)
	}
}

func TestFramePing(t *testing.T) {
	f := &pingFrame{}
	testFrame(t, f, "01")

	n, err := f.decode(nil)
	if n != 1 || err != nil {
		t.Fatalf("expect decode: %v %v, actual: %v %v", 1, nil, n, err)
	}
	n, err = f.decode([]byte{0x40, 1})
	if n != 2 || err != nil {
		t.Fatalf("expect decode: %v %v, actual: %v %v", 2, nil, n, err)
	}
}

func TestFrameAck(t *testing.T) {
	f := &ackFrame{
		largestAck:    0x1234,
		ackDelay:      0x3456,
		firstAckRange: 0x78,
		ackRanges: []ackRange{
			{
				gap:      1,
				ackRange: 2,
			},
			{
				gap:      3,
				ackRange: 4,
			},
		},
	}
	testFrame(t, f, "025234745602407801020304")
	ranges := f.toRangeSet(nil)
	if ranges.String() != "ranges=3 [4526,4530] [4535,4537] [4540,4660]" {
		t.Fatalf("range set: actual=%s", ranges)
	}
	rf := &ackFrame{
		ackDelay: f.ackDelay,
	}
	rf.fromRangeSet(ranges)
	if !reflect.DeepEqual(f, rf) {
		t.Fatalf("ack frame:\nactual=%+v\n  want=%+v", rf, f)
	}
}

func TestFrameAckRangeSet(t *testing.T) {
	var f ackFrame
	var ranges rangeSet
	f.fromRangeSet(ranges)

	for i := 0; i < 100; i++ {
		n := uint64(mrand.Intn(100))
		ranges.push(n, n)
		f.fromRangeSet(ranges)
		if f.largestAck != ranges.largest() {
			t.Fatalf("largest ack: actual=%d, want=%d\n%s\n%s",
				f.largestAck, ranges.largest(), ranges, &f)
		}
		if len(f.ackRanges) != len(ranges)-1 {
			t.Fatalf("ranges size: actual=%d, want=%d\n%s\n%s",
				len(f.ackRanges), len(ranges), ranges, &f)
		}
		//t.Logf("ranges\n%s\nframe %s", ranges, &f)
	}
}

func TestFrameAckContinuous(t *testing.T) {
	var f ackFrame
	var ranges rangeSet
	for i := 0; i < 1000; i++ {
		n := uint64(i)
		ranges.push(n, n)
		f.fromRangeSet(ranges)
		actual := f.toRangeSet(nil)
		if len(actual) != 1 || actual[0].start != 0 || actual[0].end != n {
			t.Fatalf("expect range %v, actual %v", ranges, actual)
		}
	}
}

func TestFrameAckECN(t *testing.T) {
	f := &ackFrame{
		largestAck:    0x1234,
		ackDelay:      0x3456,
		firstAckRange: 0x78,
		ackRanges: []ackRange{
			{
				gap:      1,
				ackRange: 2,
			},
			{
				gap:      3,
				ackRange: 4,
			},
		},
		ecnCounts: &ecnCounts{
			ect0Count: 1,
			ect1Count: 2,
			ceCount:   3,
		},
	}
	testFrame(t, f, "035234745602407801020304010203")
}

func TestFrameConnectionClose(t *testing.T) {
	f := &connectionCloseFrame{
		errorCode:    0x5678,
		frameType:    0x1234,
		reasonPhrase: []byte{1, 2, 3},
	}
	testFrame(t, f, "1c80005678523403010203")
	f = &connectionCloseFrame{
		errorCode:    0x5678,
		reasonPhrase: []byte{1, 2, 3},
		application:  true,
	}
	testFrame(t, f, "1d8000567803010203")
}

func TestFrameResetStream(t *testing.T) {
	f := &resetStreamFrame{
		streamID:  0x1234,
		errorCode: 0x77,
		finalSize: 0x3456,
	}
	testFrame(t, f, "04523440777456")
}

func TestFrameStopSending(t *testing.T) {
	f := &stopSendingFrame{
		streamID:  0x3f,
		errorCode: 0x77,
	}
	testFrame(t, f, "053f4077")
}

func TestFrameNewToken(t *testing.T) {
	f := &newTokenFrame{
		token: []byte{0x12, 0x34, 0x56},
	}
	testFrame(t, f, "0703123456")
}

func TestFrameStream(t *testing.T) {
	f := &streamFrame{
		streamID: 5,
		offset:   0,
		data:     []byte{1, 2, 3},
		fin:      false,
	}
	testFrame(t, f, "0a0503010203")
	f = &streamFrame{
		streamID: 5,
		offset:   1,
		data:     []byte{1, 2, 3},
		fin:      true,
	}
	testFrame(t, f, "0f050103010203")
}

func TestFrameMaxData(t *testing.T) {
	f := &maxDataFrame{
		maximumData: 0x1234,
	}
	testFrame(t, f, "105234")
}

func TestFrameMaxStreamData(t *testing.T) {
	f := &maxStreamDataFrame{
		streamID:    0x5,
		maximumData: 0x1234,
	}
	testFrame(t, f, "11055234")
}

func TestFrameMaxStreams(t *testing.T) {
	f := &maxStreamsFrame{
		maximumStreams: 0x1234,
		bidi:           false,
	}
	testFrame(t, f, "135234")

	f = &maxStreamsFrame{
		maximumStreams: 0x1234,
		bidi:           true,
	}
	testFrame(t, f, "125234")
}

func TestFrameDataBlocked(t *testing.T) {
	f := &dataBlockedFrame{
		dataLimit: 0x1234,
	}
	testFrame(t, f, "145234")
}

func TestFrameStreamDataBlocked(t *testing.T) {
	f := &streamDataBlockedFrame{
		streamID:  0x5,
		dataLimit: 0x1234,
	}
	testFrame(t, f, "15055234")
}

func TestFrameStreamsBlocked(t *testing.T) {
	f := &streamsBlockedFrame{
		streamLimit: 0x1234,
		bidi:        false,
	}
	testFrame(t, f, "175234")

	f = &streamsBlockedFrame{
		streamLimit: 0x1234,
		bidi:        true,
	}
	testFrame(t, f, "165234")
}

func TestFrameNewConnectionID(t *testing.T) {
	f := &newConnectionIDFrame{
		sequenceNumber:      0x1234,
		retirePriorTo:       0,
		connectionID:        []byte{1, 2},
		statelessResetToken: []byte("1234567890123456"),
	}
	testFrame(t, f, "1852340002010231323334353637383930313233343536")

	b := make([]byte, 100)
	f.connectionID = b[:MaxCIDLength+1]
	n, err := f.encode(b)
	if err == nil || err.Error() != "error_code=frame_encoding_error reason=new_connection_id" {
		t.Fatalf("expect error %v, actual %v %v", "frame_encoding_error", n, err)
	}
	f.connectionID = b[:1]
	f.statelessResetToken = b[:15]
	n, err = f.encode(b)
	if err == nil || err.Error() != "error_code=frame_encoding_error reason=new_connection_id" {
		t.Fatalf("expect error %v, actual %v %v", "frame_encoding_error", n, err)
	}
}

func TestFrameRetireConnectionID(t *testing.T) {
	f := &retireConnectionIDFrame{
		sequenceNumber: 0x1234,
	}
	testFrame(t, f, "195234")
}

func TestFramePathChallenge(t *testing.T) {
	f := &pathChallengeFrame{
		data: []byte("12345678"),
	}
	testFrame(t, f, "1a3132333435363738")
	b := make([]byte, 100)
	f.data = b[:7]
	n, err := f.encode(b)
	if err == nil || err.Error() != "error_code=frame_encoding_error reason=path_challenge" {
		t.Fatalf("expect error %v, actual %v %v", "frame_encoding_error", n, err)
	}
}

func TestFramePathResponse(t *testing.T) {
	f := &pathResponseFrame{
		data: []byte("12345678"),
	}
	testFrame(t, f, "1b3132333435363738")
	b := make([]byte, 100)
	f.data = b[:9]
	n, err := f.encode(b)
	if err == nil || err.Error() != "error_code=frame_encoding_error reason=path_response" {
		t.Fatalf("expect error %v, actual %v %v", "frame_encoding_error", n, err)
	}
}

func TestFrameHandshakeDone(t *testing.T) {
	f := &handshakeDoneFrame{}
	testFrame(t, f, "1e")

	n, err := f.decode(nil)
	if n != 1 || err != nil {
		t.Fatalf("expect decode: %v %v, actual: %v %v", 1, nil, n, err)
	}
	n, err = f.decode([]byte{0xc0, 0, 0, 0, 0, 0, 0, 0x1e})
	if n != 8 || err != nil {
		t.Fatalf("expect decode: %v %v, actual: %v %v", 2, nil, n, err)
	}
}

func TestFrameDatagram(t *testing.T) {
	f := &datagramFrame{
		data: []byte("12345"),
	}
	testFrame(t, f, "31053132333435")
	// Decode without length
	n, err := f.decode([]byte{0x30, 0x31, 0x32, 0x33})
	if err != nil || n != 4 {
		t.Fatalf("decode %v %v", n, err)
	}
	if string(f.data) != "123" {
		t.Fatalf("expect data %s, actual %s", "123", f.data)
	}
}

func TestFuzzFrame(t *testing.T) {
	b := make([]byte, 1024)
	out := make([]byte, len(b))
	var f frame
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("panic decoding frame: %T\n%x", f, b)
		}
	}()
	frames := []frame{
		newPaddingFrame(1),
		&pingFrame{},
		&ackFrame{},
		&resetStreamFrame{},
		&stopSendingFrame{},
		&cryptoFrame{},
		&newTokenFrame{},
		&streamFrame{},
		&maxDataFrame{},
		&maxStreamDataFrame{},
		&maxStreamsFrame{},
		&dataBlockedFrame{},
		&streamDataBlockedFrame{},
		&streamsBlockedFrame{},
		&newConnectionIDFrame{},
		&retireConnectionIDFrame{},
		&pathChallengeFrame{},
		&pathResponseFrame{},
		&connectionCloseFrame{},
		&handshakeDoneFrame{},
	}
	for i := 0; i < 10000; i++ {
		_, err := rand.Read(b)
		if err != nil {
			t.Fatal(err)
		}
		for _, f = range frames {
			n, err := f.decode(b)
			if err == nil {
				_, err = f.encode(out[:n])
				if err != nil {
					if _, ok := f.(*streamFrame); ok && err == errShortBuffer {
						// Stream frame always include length, so encoded length may be greater than decoded length.
						continue
					}
					t.Fatalf("could not encode decoded frame: %#v: %v\n%x", f, err, b)
				}
			}
		}
	}
}

func testFrame(t *testing.T, f frame, expected string) {
	length := len(expected) / 2
	n := f.encodedLen()
	if n != length {
		t.Fatalf("calculate encoded length: actual=%d want=%d", n, length)
	}
	b := make([]byte, length)
	n, err := f.encode(b)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if n != length {
		t.Fatalf("encode length: actual=%d want=%d", n, length)
	}
	encoded := fmt.Sprintf("%x", b)
	if encoded != expected {
		t.Fatalf("encode: actual=%s want=%s", encoded, expected)
	}
	decoded := reflect.New(reflect.ValueOf(f).Elem().Type()).Interface().(frame)
	n, err = decoded.decode(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if n != length {
		t.Fatalf("decode length: actual=%d want=%d", n, length)
	}
	if !reflect.DeepEqual(f, decoded) {
		t.Fatalf("decoded frame:\nactual=%#v\n  want=%#v", decoded, f)
	}
}
