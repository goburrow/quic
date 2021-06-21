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

const (
	labelTrafficKey           = "quic key"
	labelInitializationVector = "quic iv"
	labelHeaderProtection     = "quic hp"
	labelKeyUpdate            = "quic ku"

	// Crypto is not under flow control, but we still enforce a hard limit.
	cryptoMaxData = 1 << 20

	// Maximum number of encrypted packets for each set of keys.
	// AEAD_AES_128_CCM integrity limit is used.
	// https://www.rfc-editor.org/rfc/rfc9001#section-6.6
	maxEncryptedPackets = 1 << 21
	maxInvalidPackets   = 1 << 21
)

// version 1
var initialSalt = [...]byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
}

// https://www.rfc-editor.org/rfc/rfc9001#section-5.2
func newInitialSecrets(cid []byte) (client, server packetProtection) {
	suite := tls13.CipherSuiteByID(tls.TLS_AES_128_GCM_SHA256)
	initialSecret := suite.Extract(cid, initialSalt[:])
	// client
	clientSecret := deriveSecret(suite, initialSecret, "client in")
	client.init(suite, clientSecret)

	// server
	serverSecret := deriveSecret(suite, initialSecret, "server in")
	server.init(suite, serverSecret)
	return
}

func deriveSecret(suite tls13.CipherSuite, secret []byte, label string) []byte {
	return suite.ExpandLabel(secret, label, suite.Hash().Size())
}

func nextTrafficSecret(suite tls13.CipherSuite, secret []byte) []byte {
	return deriveSecret(suite, secret, labelKeyUpdate)
}

func packetProtectionKey(suite tls13.CipherSuite, secret []byte) (key, iv []byte) {
	const aeadNonceLength = 12
	key = suite.ExpandLabel(secret, labelTrafficKey, suite.KeyLen())
	iv = suite.ExpandLabel(secret, labelInitializationVector, aeadNonceLength)
	return
}

func headerProtectionKey(suite tls13.CipherSuite, secret []byte) []byte {
	return suite.ExpandLabel(secret, labelHeaderProtection, suite.KeyLen())
}

// https://www.rfc-editor.org/rfc/rfc9001#section-5
type packetProtection struct {
	secret      []byte
	cipherSuite uint16

	aead  cipher.AEAD
	hp    headerProtection
	nonce [8]byte // packet number
}

func (s *packetProtection) init(suite tls13.CipherSuite, secret []byte) {
	s.secret = secret
	s.cipherSuite = suite.ID()

	key, iv := packetProtectionKey(suite, secret)
	s.aead = suite.AEAD(key, iv)

	hpKey := headerProtectionKey(suite, secret)
	if s.cipherSuite == tls.TLS_CHACHA20_POLY1305_SHA256 {
		s.hp.chaCha20Init(hpKey)
	} else {
		s.hp.aesInit(hpKey)
	}
}

// https://www.rfc-editor.org/rfc/rfc9001#section-5.3
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
// https://www.rfc-editor.org/rfc/rfc9001#section-5.4
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
	if len(b) < sampleOffset+headerSampleLen {
		panic("packet too short for header protection")
	}
	mask := s.hp.applyMask(b[sampleOffset : sampleOffset+headerSampleLen])
	pnLen := packetNumberLenFromHeader(b[0])
	if len(mask) < 1+pnLen {
		panic("invalid mask for header protection")
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
	if len(b) < sampleOffset+headerSampleLen {
		return errInvalidPacket
	}
	mask := s.hp.applyMask(b[sampleOffset : sampleOffset+headerSampleLen])
	if isLongHeader(b[0]) {
		b[0] ^= mask[0] & 0x0f
	} else {
		b[0] ^= mask[0] & 0x1f
	}
	pnLen := packetNumberLenFromHeader(b[0])
	if len(mask) < 1+pnLen {
		panic("invalid mask for header protection")
	}
	for i := 0; i < pnLen; i++ {
		b[pnOffset+i] ^= mask[1+i]
	}
	return nil
}

// updateKey returns a new packetProtection using the new traffic key derived from current secret.
// https://www.rfc-editor.org/rfc/rfc9001.html#section-6
func (s *packetProtection) updateKey() {
	suite := tls13.CipherSuiteByID(s.cipherSuite)
	s.secret = nextTrafficSecret(suite, s.secret)

	// The header protection key is not updated during key update.
	key, iv := packetProtectionKey(suite, s.secret)
	s.aead = suite.AEAD(key, iv)
}

const (
	headerSampleLen = aes.BlockSize
	headerMaskLen   = maxPacketNumberLength + 1
)

// https://www.rfc-editor.org/rfc/rfc9001#section-5.4
type headerProtection struct {
	block cipher.Block // AES Cipher
	key   [32]byte     // ChaCha20 key. For AES it is used as buffer to avoid allocating to heap
}

func (s *headerProtection) applyMask(sample []byte) [headerMaskLen]byte {
	if len(sample) != headerSampleLen {
		panic("invalid sample length for header protection")
	}
	var mask [headerMaskLen]byte
	if s.block == nil {
		s.chacha20Mask(sample, mask[:])
	} else {
		s.aesMask(sample, mask[:])
	}
	return mask
}

func (s *headerProtection) aesInit(key []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	s.block = block
}

// https://www.rfc-editor.org/rfc/rfc9001#section-5.4.3
// mask = AES-ECB(hp_key, sample)
func (s *headerProtection) aesMask(sample, mask []byte) {
	s.block.Encrypt(s.key[:headerSampleLen], sample)
	copy(mask, s.key[:headerSampleLen])
}

func (s *headerProtection) chaCha20Init(key []byte) {
	copy(s.key[:], key)
}

// https://www.rfc-editor.org/rfc/rfc9001#section-5.4.4
// counter = sample[0..3]
// nonce = sample[4..15]
// mask = ChaCha20(hp_key, counter, nonce, {0,0,0,0,0})
func (s *headerProtection) chacha20Mask(sample, mask []byte) {
	c, err := chacha20.NewUnauthenticatedCipher(s.key[:], sample[4:])
	if err != nil {
		panic(err)
	}
	c.SetCounter(binary.LittleEndian.Uint32(sample[:4]))
	c.XORKeyStream(mask, mask)
}

// Retry Packet Integrity

const retryIntegrityTagLen = 16

var retryIntegrityKey = [...]byte{
	0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
	0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
}

var retryIntegrityNonce = [...]byte{
	0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2,
	0x23, 0x98, 0x25, 0xbb,
}

var retryIntegrityAEAD cipher.AEAD

func newRetryIntegrityAEAD() cipher.AEAD {
	if retryIntegrityAEAD == nil {
		// XXX: Need sync.Once?
		aes, err := aes.NewCipher(retryIntegrityKey[:])
		if err != nil {
			panic(err)
		}
		gcm, err := cipher.NewGCM(aes)
		if err != nil {
			panic(err)
		}
		retryIntegrityAEAD = gcm
	}
	return retryIntegrityAEAD
}

// computeRetryIntegrity append retry integrity tag to given pseudo retry packet.
// https://www.rfc-editor.org/rfc/rfc9001#section-5.8
func computeRetryIntegrity(pseudo []byte) ([]byte, error) {
	aead := newRetryIntegrityAEAD()
	if cap(pseudo)-len(pseudo) < aead.Overhead() {
		// Avoid allocating
		return nil, errShortBuffer
	}
	b := aead.Seal(pseudo, retryIntegrityNonce[:], nil, pseudo)
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
