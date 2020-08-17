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
		OriginalDestinationCID: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
		InitialSourceCID:       []byte{0x02, 0x04},
		RetrySourceCID:         []byte{0x03, 0x05, 0x07},
		StatelessResetToken:    []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a},

		MaxIdleTimeout:    30 * time.Millisecond,
		MaxUDPPayloadSize: 1200,

		InitialMaxData:                 1440000,
		InitialMaxStreamDataBidiLocal:  90000,
		InitialMaxStreamDataBidiRemote: 90000,
		InitialMaxStreamDataUni:        262144,
		InitialMaxStreamsBidi:          8,
		InitialMaxStreamsUni:           8,

		ActiveConnectionIDLimit: 2,
		DisableActiveMigration:  true,
	}
	b := testdata.DecodeHex(`
	00050102030405
	01011e
	020a0102030405060708090a
	030244b0
	04048015f900
	050480015f90
	060480015f90
	070480040000
	080108
	090108
	0c
	0e0102
	0f020204
	1003030507`)
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
