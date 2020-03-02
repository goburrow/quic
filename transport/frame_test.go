package transport

import (
	"crypto/rand"
	"fmt"
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
	ranges := f.toRangeSet()
	if ranges.String() != "size=3 0:[4660,4540] 1:[4537,4535] 2:[4530,4526]" {
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
	t.Logf("ranges %s frame %s", ranges, &f)
	ranges.push(0)
	f.fromRangeSet(ranges)
	t.Logf("ranges %s frame %s", ranges, &f)
	ranges.push(1)
	f.fromRangeSet(ranges)
	t.Logf("ranges %s frame %s", ranges, &f)
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

func TestFrameHandshakeDone(t *testing.T) {
	f := &handshakeDoneFrame{}
	testFrame(t, f, "1e")
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
		newPaddingFrame(0),
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
				n, err = f.encode(out[:n])
				if err != nil {
					if _, ok := f.(*streamFrame); ok && err == errShortBuffer {
						// Stream frame always include length, so encoded length may be greater than decoded length.
						continue
					}
					t.Fatalf("could not encode decoded frame: %v: %v\n%x", f, err, b)
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
