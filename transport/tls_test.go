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
		OriginalCID:         []byte{0x01, 0x02, 0x03, 0x04, 0x05},
		MaxIdleTimeout:      30 * time.Millisecond,
		StatelessResetToken: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a},
		MaxUDPPayloadSize:   1200,

		InitialMaxData:                 1440000,
		InitialMaxStreamDataBidiLocal:  90000,
		InitialMaxStreamDataBidiRemote: 90000,
		InitialMaxStreamDataUni:        262144,
		InitialMaxStreamsBidi:          8,
		InitialMaxStreamsUni:           8,
	}
	b := testdata.DecodeHex(`
0005010203040501011e020a0102030405060708090a030244b004048015f900
050480015f90060480015f90070480040000080108090108`)
	encoded := tp.marshal()
	if !bytes.Equal(b, encoded) {
		t.Fatalf("marshal transport parameters\nexpect=%x\nactual=%x", b, encoded)
	}
	tp2 := Parameters{}
	if !tp2.unmarshal(b) {
		t.Fatal("could not unmarshal")
	}
	if !reflect.DeepEqual(&tp, &tp2) {
		t.Fatalf("unmarshal transport parameters:\nexpect=%#v\nactual=%#v", &tp, &tp2)
	}
}
