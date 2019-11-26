package transport

import (
	"bytes"
	"reflect"
	"testing"
	"time"

	"github.com/goburrow/quic/testdata"
)

func TestTransportParams(t *testing.T) {
	tp := Parameters{
		IdleTimeout:         30 * time.Millisecond,
		StatelessResetToken: []byte{0x44, 0x9a, 0xee, 0xf4, 0x72, 0x62, 0x6f, 0x18, 0xa5, 0xbb, 0xa2, 0xd5, 0x1a, 0xe4, 0x73, 0xbe},
		MaxPacketSize:       1200,

		InitialMaxData:                 1440000,
		InitialMaxStreamDataBidiLocal:  90000,
		InitialMaxStreamDataBidiRemote: 90000,
		InitialMaxStreamDataUni:        262144,
		InitialMaxStreamsBidi:          8,
		InitialMaxStreamsUni:           8,
	}
	b := testdata.DecodeHex(`0049000100011e00020010449aeef472626f18a5bba2d51ae473be0003000244
		b0000400048015f9000005000480015f900006000480015f9000070004800400
		0000080001080009000108`)
	encoded := tp.marshal()
	if !bytes.Equal(b, encoded) {
		t.Fatalf("encode: actual=%x\nwant=%x", encoded, b)
	}
	tp2 := Parameters{}
	if !tp2.unmarshal(b) {
		t.Fatal("could not unmarshal")
	}
	if !reflect.DeepEqual(&tp, &tp2) {
		t.Fatalf("unmarshal:\nactual=%#v\n  want=%#v", &tp, &tp2)
	}
}
