package transport

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"encoding/binary"

	"github.com/goburrow/quic/tls13"
	"golang.org/x/crypto/chacha20"
)

type cryptoLevel int

const (
	cryptoLevelInitial cryptoLevel = iota
	cryptoLevelZeroRTT
	cryptoLevelHandshake
	cryptoLevelOneRTT
)

// version ff00001d
var initialSalt = []byte{
	0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97,
	0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99,
}

type initialAEAD struct {
	client packetProtection
	server packetProtection
}

// https://quicwg.org/base-drafts/draft-ietf-quic-tls.html#initial-secrets
func newInitialAEAD(cid []byte) *initialAEAD {
	suite := tls13.CipherSuiteByID(tls.TLS_AES_128_GCM_SHA256)
	initialSecret := suite.Extract(cid, initialSalt)
	aead := &initialAEAD{}
	// client
	clientSecret := deriveSecret(suite, initialSecret, "client in")
	aead.client.init(suite, clientSecret)

	// server
	serverSecret := deriveSecret(suite, initialSecret, "server in")
	aead.server.init(suite, serverSecret)
	return aead
}

func deriveSecret(suite tls13.CipherSuite, secret []byte, label string) []byte {
	return suite.ExpandLabel(secret, label, suite.Hash().Size())
}

func quicTrafficKey(suite tls13.CipherSuite, secret []byte) (key, iv, hp []byte) {
	const aeadNonceLength = 12
	key = suite.ExpandLabel(secret, "quic key", suite.KeyLen())
	iv = suite.ExpandLabel(secret, "quic iv", aeadNonceLength)
	hp = suite.ExpandLabel(secret, "quic hp", suite.KeyLen())
	return
}

// https://quicwg.org/base-drafts/draft-ietf-quic-tls.html#packet-protection
type packetProtection struct {
	aead  cipher.AEAD
	hp    headerProtection
	nonce [8]byte // packet number
}

func (s *packetProtection) init(suite tls13.CipherSuite, secret []byte) {
	key, iv, hpKey := quicTrafficKey(suite, secret)
	s.aead = suite.AEAD(key, iv)

	if suite.ID() == tls.TLS_CHACHA20_POLY1305_SHA256 {
		s.hp = newChachaHeaderProtection(hpKey)
	} else {
		s.hp = newAESHeaderProtection(hpKey)
	}
}

// https://quicwg.org/base-drafts/draft-ietf-quic-tls.html#aead
// Length of b and payload must include crypto overhead.
func (s *packetProtection) encryptPayload(b []byte, packetNumber uint64, payloadLen int) []byte {
	s.makeNonce(packetNumber)
	offset := len(b) - payloadLen
	header := b[:offset]
	payload := b[offset : len(b)-s.aead.Overhead()]
	payload = s.aead.Seal(payload[:0], s.nonce[:], payload, header)
	return payload
}

// decryptPayload decrypts the payload in packet b given decrypted packetNumber and
// packet.payloadLen resulted from packet.decodeBody().
// Length of b and payload must include crypto overhead.
func (s *packetProtection) decryptPayload(b []byte, packetNumber uint64, payloadLen int) ([]byte, error) {
	s.makeNonce(packetNumber)
	offset := len(b) - payloadLen
	header := b[:offset]
	payload := b[offset:]
	payload, err := s.aead.Open(payload[:0], s.nonce[:], payload, header)
	if err != nil {
		return nil, err
	}
	return payload, nil
}

// The 62 bits of the reconstructed QUIC packet number in network byte order are left-padded
// with zeros to the size of the IV. The exclusive OR of the padded packet number and the IV
// forms the AEAD nonce.
func (s *packetProtection) makeNonce(packetNumber uint64) {
	binary.BigEndian.PutUint64(s.nonce[:], packetNumber)
}

// pnOffset is where Packet Number starts.
// https://quicwg.org/base-drafts/draft-ietf-quic-tls.html#header-protect
//
// Long Header:
// +-+-+-+-+-+-+-+-+
// |1|1|T T|E E E E|
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Version -> Length Fields                 ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Short Header:
// +-+-+-+-+-+-+-+-+
// |0|1|S|E E E E E|
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |               Destination Connection ID (0/32..144)         ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Common Fields:
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |E E E E E E E E E  Packet Number (8/16/24/32) E E E E E E E E...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   [Protected Payload (8/16/24)]             ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |             Sampled part of Protected Payload (128)         ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                 Protected Payload Remainder (*)             ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
func (s *packetProtection) encryptHeader(b []byte, pnOffset int) {
	sampleOffset := pnOffset + maxPacketNumberLength
	mask := s.hp.encryptMask(b[sampleOffset:])
	pnLen := packetNumberLenFromHeader(b[0])
	if len(mask) < 1+pnLen {
		panic("insufficient header protection mask")
	}
	if isLongHeader(b[0]) {
		// Long header: 4 bits masked
		b[0] ^= mask[0] & 0x0f
	} else {
		// Short header: 5 bits masked
		b[0] ^= mask[0] & 0x1f
	}
	for i := 0; i < pnLen; i++ {
		b[pnOffset+i] ^= mask[1+i]
	}
}

func (s *packetProtection) decryptHeader(b []byte, pnOffset int) error {
	sampleOffset := pnOffset + maxPacketNumberLength
	if len(b) < sampleOffset {
		return errInvalidPacket
	}
	mask := s.hp.decryptMask(b[sampleOffset:])
	if len(mask) < 1 {
		return errInvalidPacket
	}
	if isLongHeader(b[0]) {
		b[0] ^= mask[0] & 0x0f
	} else {
		b[0] ^= mask[0] & 0x1f
	}
	pnLen := packetNumberLenFromHeader(b[0])
	if len(mask) < 1+pnLen {
		panic("insufficient header protection mask")
	}
	for i := 0; i < pnLen; i++ {
		b[pnOffset+i] ^= mask[1+i]
	}
	return nil
}

type headerProtection interface {
	encryptMask(sample []byte) []byte
	decryptMask(sample []byte) []byte
}

// https://quicwg.org/base-drafts/draft-ietf-quic-tls.html#name-aes-based-header-protection
// mask = AES-ECB(hp_key, sample)
type aesHeaderProtection struct {
	block cipher.Block
	mask  []byte
}

func newAESHeaderProtection(key []byte) *aesHeaderProtection {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return &aesHeaderProtection{
		block: block,
		mask:  make([]byte, block.BlockSize()),
	}
}

func (s *aesHeaderProtection) encryptMask(sample []byte) []byte {
	sampleLen := s.block.BlockSize()
	if len(sample) < sampleLen {
		return nil
	}
	s.block.Encrypt(s.mask, sample[:sampleLen])
	return s.mask
}

func (s *aesHeaderProtection) decryptMask(sample []byte) []byte {
	sampleLen := s.block.BlockSize()
	if len(sample) < sampleLen {
		return nil
	}
	s.block.Encrypt(s.mask, sample[:sampleLen])
	return s.mask
}

// https://quicwg.org/base-drafts/draft-ietf-quic-tls.html#name-chacha20-based-header-prote
// counter = sample[0..3]
// nonce = sample[4..15]
// mask = ChaCha20(hp_key, counter, nonce, {0,0,0,0,0})
type chachaHeaderProtection struct {
	key  [32]byte
	mask [5]byte
}

func newChachaHeaderProtection(key []byte) *chachaHeaderProtection {
	s := &chachaHeaderProtection{}
	copy(s.key[:], key)
	return s
}

func (s *chachaHeaderProtection) encryptMask(sample []byte) []byte {
	return s.applyMask(sample)
}

func (s *chachaHeaderProtection) decryptMask(sample []byte) []byte {
	return s.applyMask(sample)
}

func (s *chachaHeaderProtection) applyMask(sample []byte) []byte {
	const sampleLen = 16
	if len(sample) < sampleLen {
		return nil
	}
	c, err := chacha20.NewUnauthenticatedCipher(s.key[:], sample[4:sampleLen])
	if err != nil {
		return nil
	}
	c.SetCounter(binary.LittleEndian.Uint32(sample[:4]))
	for i := range s.mask {
		s.mask[i] = 0
	}
	c.XORKeyStream(s.mask[:], s.mask[:])
	return s.mask[:]
}

// Retry Packet Integrity

const retryIntegrityTagLen = 16

var retryIntegrityKey = []byte{
	0xcc, 0xce, 0x18, 0x7e, 0xd0, 0x9a, 0x09, 0xd0,
	0x57, 0x28, 0x15, 0x5a, 0x6c, 0xb9, 0x6b, 0xe1,
}

var retryIntegrityNonce = []byte{
	0xe5, 0x49, 0x30, 0xf9, 0x7f, 0x21, 0x36, 0xf0,
	0x53, 0x0a, 0x8c, 0x1c,
}

var retryIntegrityAEAD cipher.AEAD

func newRetryIntegrityAEAD() cipher.AEAD {
	if retryIntegrityAEAD == nil {
		// XXX: Need sync.Once?
		aes, err := aes.NewCipher(retryIntegrityKey)
		if err != nil {
			panic("retry packet integrity AEAD: " + err.Error())
		}
		gcm, err := cipher.NewGCM(aes)
		if err != nil {
			panic("retry packet integrity AEAD: " + err.Error())
		}
		retryIntegrityAEAD = gcm
	}
	return retryIntegrityAEAD
}

// computeRetryIntegrity append retry integrity tag to given pseudo retry packet.
// https://quicwg.org/base-drafts/draft-ietf-quic-tls.html#name-retry-packet-integrity
func computeRetryIntegrity(pseudo []byte) ([]byte, error) {
	aead := newRetryIntegrityAEAD()
	if cap(pseudo)-len(pseudo) < aead.Overhead() {
		// Avoid allocating
		return nil, errShortBuffer
	}
	b := aead.Seal(pseudo, retryIntegrityNonce, nil, pseudo)
	return b, nil
}

// verifyRetryIntegrity verifies integrity tag in retry packet b given the original destination CID odcid.
func verifyRetryIntegrity(b, odcid []byte) bool {
	if len(b) < retryIntegrityTagLen {
		return false
	}
	pseudo := make([]byte, len(b)+len(odcid)+1)
	pseudo[0] = byte(len(odcid))
	copy(pseudo[1:], odcid)
	copy(pseudo[1+len(odcid):], b[:len(b)-retryIntegrityTagLen])

	out, err := computeRetryIntegrity(pseudo[:len(pseudo)-retryIntegrityTagLen])
	if err != nil || len(out) < retryIntegrityTagLen {
		return false
	}
	inTag := b[len(b)-retryIntegrityTagLen:]
	outTag := out[len(out)-retryIntegrityTagLen:]
	return bytes.Equal(inTag, outTag)
}
