package transport

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/goburrow/quic/testdata"
)

// https://quicwg.org/base-drafts/draft-ietf-quic-tls.html#name-retry
func TestPacketRetryDecode(t *testing.T) {
	b := testdata.DecodeHex(`
ffff00001b0008f067a5502a4262b574 6f6b656ea523cb5ba524695f6569f293
a1359d8e`)
	dcid := testdata.DecodeHex(`8394c8f03e515708`)
	testPacketRetryDecode(t, b, dcid)

	b = testdata.DecodeHex(`
f0ff0000191480d0ee4a5b5c1304ef66b296a396b80588c88bce1462d7046715
45f5640bbfdbaf4b53aec8ec968e667175696368657f0000015754d2fb3c3815
fc19245b182a20db2f1dc243825f3db6b00a0c5557f288344fe7a27505`)
	dcid = testdata.DecodeHex(`5754d2fb3c3815fc19245b182a20db2f1dc24382`)
	testPacketRetryDecode(t, b, dcid)
}

func testPacketRetryDecode(t *testing.T, b, dcid []byte) {
	p := packet{}
	n, err := decodeUnencryptedPacket(b, &p)
	if err != nil {
		t.Fatal(err)
	}
	if p.typ != packetTypeRetry {
		t.Fatalf("expect type retry, actual %d", p.typ)
	}
	if n != len(b)-retryIntegrityTagLen {
		t.Fatalf("expect decoded length %d, actual %d", len(b)-retryIntegrityTagLen, n)
	}
	t.Logf("%s", &p)
	if !verifyRetryIntegrity(b, dcid) {
		t.Fatalf("verify retry integrity failed\n%x", b)
	}
}

func TestPacketRetryEncode(t *testing.T) {
	b := make([]byte, 128)
	scid := testdata.DecodeHex(`f067a5502a4262b5`)
	odcid := testdata.DecodeHex(`8394c8f03e515708`)
	token := testdata.DecodeHex(`746f6b656e`)
	n, err := Retry(b, nil, scid, odcid, token)
	if err != nil {
		t.Fatal(err)
	}
	// XXX: To test with the example in spec, the header flags must be 0xff
	expected := testdata.DecodeHex(`
f0ff00001b0008f067a5502a4262b574 6f6b656e825b2c42a3bfbe8d0c441edd
376f531b`)
	if !bytes.Equal(expected, b[:n]) {
		t.Fatalf("expect: %x\nactual: %x", expected, b[:n])
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
	p := packet{}
	m, err := decodeUnencryptedPacket(b[:n], &p)
	if err != nil {
		t.Fatal(err)
	}
	if n != m+retryIntegrityTagLen {
		t.Fatalf("expect length %d, actual %d", n, m+retryIntegrityTagLen)
	}
	if p.typ != packetTypeRetry {
		t.Fatalf("expect type retry, actual %d", p.typ)
	}
	if !bytes.Equal(dcid, p.header.dcid) {
		t.Fatalf("expect dcid %x, actual %x", dcid, p.header.dcid)
	}
	if !bytes.Equal(scid, p.header.scid) {
		t.Fatalf("expect scid %x, actual %x", scid, p.header.scid)
	}
	if !bytes.Equal(token, p.token) {
		t.Fatalf("expect dcid %x, actual %x", token, p.token)
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
	bLen, err := p.decodeBody(b[hLen:])
	if err != nil {
		return 0, err
	}
	return hLen + bLen, nil
}

func TestDecodePacketNumber(t *testing.T) {
	data := []struct {
		pn        uint64
		largest   uint64
		truncated uint64
		len       int
	}{
		{0xa82f9b32, 0xa82f30ea, 0x9b32, 2},
		{2, 0, 2, 4},
	}
	for _, d := range data {
		pn := decodePacketNumber(d.largest, d.truncated, d.len)
		if pn != d.pn {
			t.Fatalf("expect packet number 0x%x actual 0x%x", d.pn, pn)
		}
	}
}

func TestDecryptPacket(t *testing.T) {
	const clientInitial = `
c0ff000017088394c8f03e5157080000 449e3b343aa8535064a4268a0d9d7b1c
9d250ae355162276e9b1e3011ef6bbc0 ab48ad5bcc2681e953857ca62becd752
4daac473e68d7405fbba4e9ee616c870 38bdbe908c06d9605d9ac49030359eec
b1d05a14e117db8cede2bb09d0dbbfee 271cb374d8f10abec82d0f59a1dee29f
e95638ed8dd41da07487468791b719c5 5c46968eb3b54680037102a28e53dc1d
12903db0af5821794b41c4a93357fa59 ce69cfe7f6bdfa629eef78616447e1d6
11c4baf71bf33febcb03137c2c75d253 17d3e13b684370f668411c0f00304b50
1c8fd422bd9b9ad81d643b20da89ca05 25d24d2b142041cae0af205092e43008
0cd8559ea4c5c6e4fa3f66082b7d303e 52ce0162baa958532b0bbc2bc785681f
cf37485dff6595e01e739c8ac9efba31 b985d5f656cc092432d781db95221724
87641c4d3ab8ece01e39bc85b1543661 4775a98ba8fa12d46f9b35e2a55eb72d
7f85181a366663387ddc20551807e007 673bd7e26bf9b29b5ab10a1ca87cbb7a
d97e99eb66959c2a9bc3cbde4707ff77 20b110fa95354674e395812e47a0ae53
b464dcb2d1f345df360dc227270c7506 76f6724eb479f0d2fbb6124429990457
ac6c9167f40aab739998f38b9eccb24f d47c8410131bf65a52af841275d5b3d1
880b197df2b5dea3e6de56ebce3ffb6e 9277a82082f8d9677a6767089b671ebd
244c214f0bde95c2beb02cd1172d58bd f39dce56ff68eb35ab39b49b4eac7c81
5ea60451d6e6ab82119118df02a58684 4a9ffe162ba006d0669ef57668cab38b
62f71a2523a084852cd1d079b3658dc2 f3e87949b550bab3e177cfc49ed190df
f0630e43077c30de8f6ae081537f1e83 da537da980afa668e7b7fb25301cf741
524be3c49884b42821f17552fbd1931a 813017b6b6590a41ea18b6ba49cd48a4
40bd9a3346a7623fb4ba34a3ee571e3c 731f35a7a3cf25b551a680fa68763507
b7fde3aaf023c50b9d22da6876ba337e b5e9dd9ec3daf970242b6c5aab3aa4b2
96ad8b9f6832f686ef70fa938b31b4e5 ddd7364442d3ea72e73d668fb0937796
f462923a81a47e1cee7426ff6d922126 9b5a62ec03d6ec94d12606cb485560ba
b574816009e96504249385bb61a819be 04f62c2066214d8360a2022beb316240
b6c7d78bbe56c13082e0ca272661210a bf020bf3b5783f1426436cf9ff418405
93a5d0638d32fc51c5c65ff291a3a7a5 2fd6775e623a4439cc08dd25582febc9
44ef92d8dbd329c91de3e9c9582e41f1 7f3d186f104ad3f90995116c682a2a14
a3b4b1f547c335f0be710fc9fc03e0e5 87b8cda31ce65b969878a4ad4283e6d5
b0373f43da86e9e0ffe1ae0fddd35162 55bd74566f36a38703d5f34249ded1f6
6b3d9b45b9af2ccfefe984e13376b1b2 c6404aa48c8026132343da3f3a33659e
c1b3e95080540b28b7f3fcd35fa5d843 b579a84c089121a60d8c1754915c344e
eaf45a9bf27dc0c1e784161691220913 13eb0e87555abd706626e557fc36a04f
cd191a58829104d6075c5594f627ca50 6bf181daec940f4a4f3af0074eee89da
acde6758312622d4fa675b39f728e062 d2bee680d8f41a597c262648bb18bcfc
13c8b3d97b1a77b2ac3af745d61a34cc 4709865bac824a94bb19058015e4e42d
c9be6c7803567321829dd85853396269`
	b := testdata.DecodeHex(clientInitial)
	p := packet{}
	_, err := p.decodeHeader(b)
	if err != nil {
		t.Fatal(err)
	}
	pnSpace := packetNumberSpace{}
	pnSpace.init()
	aead := newInitialAEAD(p.header.dcid)
	pnSpace.opener, pnSpace.sealer = aead.client, aead.server
	payload, n, err := pnSpace.decryptPacket(b, &p)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("payload=%d length=%d", len(payload), n)
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
