package transport

import (
	"bytes"
	"math/rand"
	"testing"
)

func TestPacketInitial(t *testing.T) {
	b := make([]byte, 512)
	dcid := randomBytes(MaxCIDLength)
	scid := randomBytes(MaxCIDLength)
	token := randomBytes(32)
	p := packet{
		typ: packetTypeInitial,
		header: packetHeader{
			version: supportedVersions[0],
			dcid:    dcid,
			scid:    scid,
		},
		token:      token,
		payloadLen: minPacketPayloadLength,
	}
	n, err := p.encode(b)
	if err != nil {
		t.Fatal(err)
	}
	// Still need to append encrypted data for a complete packet
	b = b[:n]

	h := Header{}
	n, err = h.Decode(b, 0)
	if err != nil {
		t.Fatal(err)
	}
	if h.Type != "initial" {
		t.Errorf("expect type %s, actual %s", packetTypeInitial, h.Type)
	}
	if !bytes.Equal(dcid, h.DCID) {
		t.Errorf("expect dcid %x, actual %x", dcid, h.DCID)
	}
	if !bytes.Equal(scid, h.SCID) {
		t.Errorf("expect scid %x, actual %x", scid, h.SCID)
	}
	if !bytes.Equal(token, h.Token) {
		t.Errorf("expect token %x, actual %x", token, h.Token)
	}
}

func TestPacketVersionNegotiation(t *testing.T) {
	b := make([]byte, 128)
	dcid := randomBytes(MaxCIDLength)
	scid := randomBytes(MaxCIDLength)

	n, err := NegotiateVersion(b, dcid, scid)
	if err != nil {
		t.Fatal(err)
	}
	b = b[:n]
	p := packet{}
	n, err = decodeUnencryptedPacket(b, &p)
	if err != nil {
		t.Fatal(err)
	}
	if p.typ != packetTypeVersionNegotiation {
		t.Errorf("expect type: %d, actual: %d", packetTypeVersionNegotiation, p.typ)
	}
	if p.header.version != 0 {
		t.Errorf("expect version: %d, actual: %d", 0, p.header.version)
	}
	if !bytes.Equal(dcid, p.header.dcid) {
		t.Errorf("expect dcid %x, actual %x", dcid, p.header.dcid)
	}
	if !bytes.Equal(scid, p.header.scid) {
		t.Errorf("expect scid %x, actual %x", scid, p.header.scid)
	}
	if len(p.supportedVersions) != len(supportedVersions) || p.supportedVersions[0] != supportedVersions[0] {
		t.Errorf("expect supported versions: [%d], actual: %v", supportedVersions[0], p.supportedVersions)
	}

	h := Header{}
	n, err = h.Decode(b, 0)
	if err != nil {
		t.Fatal(err)
	}
	if h.Type != "version_negotiation" {
		t.Errorf("expect type %s, actual %s", packetTypeVersionNegotiation, h.Type)
	}
	if h.Flags != 0xc0 {
		t.Errorf("expect flags 0x%x, actual 0x%x", 0xc0, h.Flags)
	}
	if !bytes.Equal(dcid, h.DCID) {
		t.Errorf("expect dcid %x, actual %x", dcid, h.DCID)
	}
	if !bytes.Equal(scid, h.SCID) {
		t.Errorf("expect scid %x, actual %x", scid, h.SCID)
	}
	if h.Token != nil {
		t.Errorf("expect token nil, actual %x", h.Token)
	}
}

func TestPacketRetry(t *testing.T) {
	b := make([]byte, 512)
	dcid := randomBytes(MaxCIDLength)
	scid := randomBytes(MaxCIDLength)
	odcid := randomBytes(MaxCIDLength)
	token := randomBytes(100)

	n, err := Retry(b, dcid, scid, odcid, token)
	if err != nil {
		t.Fatal(err)
	}
	b = b[:n]
	p := packet{}
	m, err := decodeUnencryptedPacket(b, &p)
	if err != nil {
		t.Fatal(err)
	}
	if n != m+retryIntegrityTagLen {
		t.Errorf("expect length %d, actual %d", n, m+retryIntegrityTagLen)
	}
	if p.typ != packetTypeRetry {
		t.Errorf("expect type %d, actual %d", packetTypeRetry, p.typ)
	}
	if !bytes.Equal(dcid, p.header.dcid) {
		t.Errorf("expect dcid %x, actual %x", dcid, p.header.dcid)
	}
	if !bytes.Equal(scid, p.header.scid) {
		t.Errorf("expect scid %x, actual %x", scid, p.header.scid)
	}
	if !bytes.Equal(token, p.token) {
		t.Errorf("expect dcid %x, actual %x", token, p.token)
	}

	h := Header{}
	n, err = h.Decode(b, 0)
	if err != nil {
		t.Fatal(err)
	}
	if h.Type != "retry" {
		t.Errorf("expect type %s, actual %s", packetTypeRetry, h.Type)
	}
	if h.Flags != 0xf0 {
		t.Errorf("expect flags 0x%x, actual 0x%x", 0xf0, h.Flags)
	}
	if h.Version != supportedVersions[0] {
		t.Errorf("expect version %d, actual %d", supportedVersions[0], h.Version)
	}
	if !bytes.Equal(dcid, h.DCID) {
		t.Errorf("expect dcid %x, actual %x", dcid, h.DCID)
	}
	if !bytes.Equal(scid, h.SCID) {
		t.Errorf("expect scid %x, actual %x", scid, h.SCID)
	}
	if !bytes.Equal(token, h.Token) {
		t.Errorf("expect token %x, actual %x", token, h.Token)
	}
}

func randomBytes(maxLength int) []byte {
	n := rand.Intn(maxLength + 1)
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}

func decodeUnencryptedPacket(b []byte, p *packet) (int, error) {
	hLen, err := p.decodeHeader(b)
	if err != nil {
		return 0, err
	}
	bLen, err := p.decodeBody(b)
	if err != nil {
		return 0, err
	}
	return hLen + bLen, nil
}

func TestPacketNumberWindow(t *testing.T) {
	x := packetNumberWindowTest{t: t}
	x.assertNotContains(0)
	x.w.push(0)
	x.assertContains(0)

	x.w.push(1)
	x.assertContains(1, 0)
	x.assertNotContains(3)

	x.w.push(3)
	x.assertContains(3, 1, 0)
	x.assertNotContains(2)

	x.w.push(63)
	x.assertContains(63, 3, 1, 0)
	x.assertNotContains(64, 2)

	x.w.push(66)
	x.assertContains(66, 63, 3, 2, 1, 0)
	x.assertNotContains(65, 64)
}

func TestPacketNumberWindowUnique(t *testing.T) {
	x := packetNumberWindowTest{t: t}
	n := rand.Intn(1000)
	for i := 0; i < n; i++ {
		v := uint64(i)
		x.w.push(v)
		x.assertContains(v)
		x.assertNotContains(v + 1)
		if i > 0 {
			x.assertContains(v - 1)
		}
	}

	x = packetNumberWindowTest{t: t}
	s := make([]uint64, n)
	rand.Shuffle(len(s), func(i, j int) { s[i], s[j] = s[j], s[i] })
	for _, i := range s {
		v := uint64(i)
		x.w.push(v)
		x.assertContains(v)
	}
}

func TestPacketNumberWindowRandom(t *testing.T) {
	x := packetNumberWindowTest{t: t}
	n := rand.Intn(1000)
	for i := 0; i < n; i++ {
		v := (uint64(rand.Intn(100)))
		x.w.push(v)
		x.assertContains(v)
	}
}

type packetNumberWindowTest struct {
	t *testing.T
	w packetNumberWindow
}

func (t *packetNumberWindowTest) assertContains(n ...uint64) {
	for _, i := range n {
		if !t.w.contains(i) {
			t.t.Fatalf("expect contain %v: %s", i, &t.w)
		}
	}
}

func (t *packetNumberWindowTest) assertNotContains(n ...uint64) {
	for _, i := range n {
		if t.w.contains(i) {
			t.t.Fatalf("expect does not contain %v: %s", 0, &t.w)
		}
	}
}
