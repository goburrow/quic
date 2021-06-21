package transport

import (
	"bytes"
	"crypto/tls"
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
	0c00
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

func TestTransportParamsGreased(t *testing.T) {
	b := testdata.DecodeHex(`
	40d50ebbb51565a7ddd499cf76072a3cd2
	0504800800000604800800000704800800000404800c00000802406409024064010480007530030245ac0b011a0c000e01040f00`)
	tp := Parameters{}
	if !tp.unmarshal(b) {
		t.Fatal("could not unmarshal")
	}
}

func TestTLSHandshakeInitial(t *testing.T) {
	var pnSpaces [packetSpaceCount]*packetNumberSpace
	for i := range pnSpaces {
		pnSpaces[i] = newPacketNumberSpace()
	}
	tlsConfig := &tls.Config{
		ServerName: "localhost",
	}
	handshake := tlsHandshake{}
	handshake.init(tlsConfig, &pnSpaces, true)

	err := handshake.doHandshake()
	if err != nil {
		t.Fatal(err)
	}
	stream := &pnSpaces[packetSpaceInitial].cryptoStream
	if !stream.isFlushable() {
		t.Fatalf("expect crypto stream data, got %v", &stream.send)
	}
}
