package transport

import (
	"bytes"
	"testing"
	"time"

	"github.com/goburrow/quic/testdata"
)

// https://quicwg.org/base-drafts/draft-ietf-quic-tls.html#name-client-initial
func TestDecryptClientInitial(t *testing.T) {
	const clientInitial = `
c0ff00001b088394c8f03e5157080000 449e3b343aa8535064a4268a0d9d7b1c
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
38d3b779d72edc00c5cd088eff802b05`
	const clientPayload = `
060040c4010000c003036660261ff947 cea49cce6cfad687f457cf1b14531ba1
4131a0e8f309a1d0b9c4000006130113 031302010000910000000b0009000006
736572766572ff01000100000a001400 12001d00170018001901000101010201
03010400230000003300260024001d00 204cfdfcd178b784bf328cae793b136f
2aedce005ff183d7bb14952072366470 37002b0003020304000d0020001e0403
05030603020308040805080604010501 060102010402050206020202002d0002
0101001c00024001`
	b := testdata.DecodeHex(clientInitial)
	p := packet{}
	headerLen, err := p.decodeHeader(b)
	if err != nil {
		t.Fatal(err)
	}
	pnOffset, err := p.packetNumberOffset(b, headerLen)
	if err != nil {
		t.Fatal(err)
	}
	aead := newInitialAEAD(testdata.DecodeHex("8394c8f03e515708"))
	err = aead.client.decryptHeader(b, pnOffset)
	if err != nil {
		t.Fatal(err)
	}
	p.header.flags = b[0]
	n, err := p.decodeBody(b[headerLen:])
	payload, err := aead.client.decryptPayload(b[:headerLen+n+p.payloadLen], p.packetNumber, p.payloadLen)
	if err != nil {
		t.Fatal(err)
	}
	expect := make([]byte, len(payload)) // for Padding frame
	copy(expect, testdata.DecodeHex(clientPayload))
	if !bytes.Equal(payload, expect) {
		t.Fatalf("client payload\nexpect: %x\nactual: %x", expect, payload)
	}
}

// https://quicwg.org/base-drafts/draft-ietf-quic-tls.html#name-server-initial
func TestDecryptServerInitial(t *testing.T) {
	const serverInitial = `
c9ff00001b0008f067a5502a4262b500 4074168bf22b7002596f99ae67abf65a
5852f54f58c37c808682e2e40492d8a3 899fb04fc0afe9aabc8767b18a0aa493
537426373b48d502214dd856d63b78ce e37bc664b3fe86d487ac7a77c53038a3
cd32f0b5004d9f5754c4f7f2d1f35cf3 f7116351c92bd8c3a9528d2b6aca20f0
8047d9f017f0`
	const serverPayload = `
0d0000000018410a020000560303eefc e7f7b37ba1d1632e96677825ddf73988
cfc79825df566dc5430b9a045a120013 0100002e00330024001d00209d3c940d
89690b84d08a60993c144eca684d1081 287c834d5311bcf32bb9da1a002b0002
0304`
	b := testdata.DecodeHex(serverInitial)
	p := packet{}
	headerLen, err := p.decodeHeader(b)
	if err != nil {
		t.Fatal(err)
	}
	pnOffset, err := p.packetNumberOffset(b, headerLen)
	if err != nil {
		t.Fatal(err)
	}
	aead := newInitialAEAD(testdata.DecodeHex("8394c8f03e515708"))
	err = aead.server.decryptHeader(b, pnOffset)
	if err != nil {
		t.Fatal(err)
	}
	p.header.flags = b[0]
	n, err := p.decodeBody(b[headerLen:])
	payload, err := aead.server.decryptPayload(b[:headerLen+n+p.payloadLen], p.packetNumber, p.payloadLen)
	if err != nil {
		t.Fatal(err)
	}
	expect := testdata.DecodeHex(serverPayload)
	if !bytes.Equal(payload, expect) {
		t.Fatalf("server payload\nexpect: %x\nactual: %x", expect, payload)
	}
}

// https://quicwg.org/base-drafts/draft-ietf-quic-tls.html#name-retry
func TestComputeRetryIntegrity(t *testing.T) {
	odcid := testdata.DecodeHex(`8394c8f03e515708`)
	retry := testdata.DecodeHex(`ffff00001b0008f067a5502a4262b5746f6b656e`)
	b := make([]byte, 0, 128)
	b = append(b, byte(len(odcid)))
	b = append(b, odcid...)
	b = append(b, retry...)

	actual, err := computeRetryIntegrity(b)
	if err != nil {
		t.Fatal(err)
	}
	actual = actual[len(odcid)+1:]
	expect := testdata.DecodeHex(`
ffff00001b0008f067a5502a4262b574 6f6b656ea523cb5ba524695f6569f293
a1359d8e`)
	if !bytes.Equal(expect, actual) {
		t.Fatalf("integrity tag\nexpect: %x\nactual: %x", expect, actual)
	}
	if !verifyRetryIntegrity(expect, odcid) {
		t.Fatalf("verify retry integrity failed: %x", expect)
	}
}

func BenchmarkRetryIntegrity(b *testing.B) {
	odcid := testdata.DecodeHex(`8394c8f03e515708`)
	pseudoPacket := make([]byte, 0, 128)
	pseudoPacket = append(pseudoPacket, testdata.DecodeHex(`00208394c8f03e515708ffff00001b0008f067a5502a4262b5746f6b656e`)...)
	retryPacket := testdata.DecodeHex(`
ffff00001b0008f067a5502a4262b574 6f6b656ea523cb5ba524695f6569f293
a1359d8e`)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := computeRetryIntegrity(pseudoPacket)
		if err != nil {
			b.Fatal(err)
		}
		if !verifyRetryIntegrity(retryPacket, odcid) {
			b.Fatal("verify retry integrity failed")
		}
	}
}

func TestAddressValidator(t *testing.T) {
	addr1 := []byte("1.2.3.4:90")
	addr2 := []byte("5.6.7.8:90")
	odcid := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}
	s, err := NewAddressValidator()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	s.timeFn = func() time.Time {
		return now
	}
	token := s.Generate(addr1, odcid)
	t.Logf("token: %d %x", len(token), token)
	cid := s.Validate(addr1, token)
	if !bytes.Equal(odcid, cid) {
		t.Fatalf("expect cid: %x\nactual: %x", odcid, cid)
	}
	// Still valid
	now = now.Add(10 * time.Second)
	cid = s.Validate(addr1, token)
	if !bytes.Equal(odcid, cid) {
		t.Fatalf("expect cid: %x\nactual: %x", odcid, cid)
	}
	// Wrong address
	cid = s.Validate(addr2, token)
	if cid != nil {
		t.Fatalf("expect cid: <nil>\nactual: %x", cid)
	}
	// Expired
	now = now.Add(1 * time.Second)
	cid = s.Validate(addr2, token)
	if cid != nil {
		t.Fatalf("expect cid: <nil>\nactual: %x", cid)
	}
}

func BenchmarkAddressValidator(b *testing.B) {
	addr := []byte("10.0.0.1:7890")
	odcid := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6}
	s, err := NewAddressValidator()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		token := s.Generate(addr, odcid)
		cid := s.Validate(addr, token)
		if cid == nil {
			b.Fatal("invalid token")
		}
	}
}
