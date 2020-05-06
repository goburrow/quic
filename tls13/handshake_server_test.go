package tls13

import (
	"bytes"
	"crypto/tls"
	"io"
	"testing"

	"github.com/goburrow/quic/testdata"
)

type testRecordLayer struct {
	read  [EncryptionLevelApplication + 1]bytes.Buffer
	write [EncryptionLevelApplication + 1]bytes.Buffer
}

func (t *testRecordLayer) ReadRecord(level EncryptionLevel, b []byte) (int, error) {
	n, err := t.read[level].Read(b)
	if err == io.EOF {
		return n, nil
	}
	return n, err
}

func (t *testRecordLayer) WriteRecord(level EncryptionLevel, b []byte) (int, error) {
	n, err := t.write[level].Write(b)
	if err == io.EOF {
		return n, nil
	}
	return n, err
}

func (t *testRecordLayer) SetReadSecret(level EncryptionLevel, readSecret []byte) error {
	return nil
}

func (t *testRecordLayer) SetWriteSecret(level EncryptionLevel, writeSecret []byte) error {
	return nil
}

func TestReadClientHello(t *testing.T) {
	cert, err := tls.LoadX509KeyPair("../testdata/cert.pem", "../testdata/key.pem")
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := tls.Config{Certificates: []tls.Certificate{cert}}

	clientHello := `010001fc030384fcb5280f8be857dc04374f7f1e3f3f5c3081795fe11ecd115e12823d36f4f3204854affeb32f98
	284f0d1de964124caa2e2b1edfac4e959ff62f83d06f1e62260006130113021303010001ad000a00080006001d0017001800
	100011000f0568712d323208687474702f302e39000d00140012040308040401050308050501080606010201003300260024
	001d00206edb3d4512304fd5eaad0aa345815f77cace91b2ac1fe2abdc882eb74ef3a664002d00020101002b0003020304ff
	a50040003e000100025388000300024546000400048098968000050004800f424000060004800f4240000800024064000900
	024064000a000103000b000119000c0000001500f50000000000000000000000000000000000000000000000000000000000
	0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
	0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
	0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
	0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
	00000000000000000000000000000000`
	data := testdata.DecodeHex(clientHello)
	records := testRecordLayer{}
	records.read[EncryptionLevelInitial].Write(data)

	conn := NewConn(&records, &tlsConfig, false)
	err = conn.Handshake()
	if err != ErrWantRead {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn.serverHs.state != serverStateReadClientFinished {
		t.Fatalf("unexpected state: %v", conn.serverHs.state)
	}

	t.Logf("\nhandshake output buffer: %d\n", records.write[EncryptionLevelHandshake].Len())
}
