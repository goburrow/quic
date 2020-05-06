package transport

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"time"

	"github.com/goburrow/quic/tls13"
)

type cryptoLevel int

const (
	cryptoLevelInitial cryptoLevel = iota
	cryptoLevelZeroRTT
	cryptoLevelHandshake
	cryptoLevelOneRTT
)

// version ff000017
var initialSalt = []byte{
	0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a, 0x11, 0xa7,
	0xd2, 0x43, 0x2b, 0xb4, 0x63, 0x65, 0xbe, 0xf9, 0xf5, 0x02,
}

type initialAEAD struct {
	client packetProtection
	server packetProtection
}

// https://quicwg.org/base-drafts/draft-ietf-quic-tls.html#initial-secrets
func newInitialAEAD(cid []byte) (*initialAEAD, error) {
	suite := tls13.CipherSuiteByID(tls.TLS_AES_128_GCM_SHA256)
	initialSecret := suite.Extract(cid, initialSalt)
	aead := &initialAEAD{}
	// client
	clientSecret := suite.DeriveSecret(initialSecret, "client in")
	err := aead.client.init(suite, clientSecret)
	if err != nil {
		return nil, err
	}
	// server
	serverSecret := suite.DeriveSecret(initialSecret, "server in")
	err = aead.server.init(suite, serverSecret)
	if err != nil {
		return nil, err
	}
	return aead, nil
}

// https://quicwg.org/base-drafts/draft-ietf-quic-tls.html#packet-protection
type packetProtection struct {
	aead  cipher.AEAD
	hp    cipher.Block
	nonce [8]byte // packet number
}

func (s *packetProtection) init(suite tls13.CipherSuite, secret []byte) error {
	key, iv, hpKey := suite.QUICTrafficKey(secret)
	var err error
	s.aead = suite.AEAD(key, iv)

	// TODO: Support ChaCha
	s.hp, err = aes.NewCipher(hpKey)
	if err != nil {
		return err
	}
	return nil
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
	sampleLen := s.hp.BlockSize()
	sampleOffset := pnOffset + maxPacketNumberLength
	sample := b[sampleOffset : sampleOffset+sampleLen]
	mask := make([]byte, sampleLen)
	s.hp.Encrypt(mask, sample)
	pnLen := packetNumberLenFromHeader(b[0])
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
	sampleLen := s.hp.BlockSize()
	sampleOffset := pnOffset + maxPacketNumberLength
	if len(b) < sampleOffset+sampleLen {
		return errInvalidPacket
	}
	sample := b[sampleOffset : sampleOffset+sampleLen]
	mask := make([]byte, sampleLen)
	s.hp.Encrypt(mask, sample)
	if isLongHeader(b[0]) {
		b[0] ^= mask[0] & 0x0f
	} else {
		b[0] ^= mask[0] & 0x1f
	}
	pnLen := packetNumberLenFromHeader(b[0])
	for i := 0; i < pnLen; i++ {
		b[pnOffset+i] ^= mask[1+i]
	}
	return nil
}

// Retry Packet Integrity

const retryIntegrityTagLen = 16

var retryIntegrityNonce = []byte{
	0x4d, 0x16, 0x11, 0xd0, 0x55, 0x13, 0xa5, 0x52,
	0xc5, 0x87, 0xd5, 0x75,
}

var retryIntegrityAEAD cipher.AEAD

func newRetryIntegrityAEAD() cipher.AEAD {
	if retryIntegrityAEAD == nil {
		var retryIntegrityKey = []byte{
			0x4d, 0x32, 0xec, 0xdb, 0x2a, 0x21, 0x33, 0xc8,
			0x41, 0xe4, 0x04, 0x3d, 0xf2, 0x7d, 0x44, 0x30,
		}
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

// AddressValidator is a simple implementation for client address validation.
// It encrypts client original CID using AES-GSM AEAD with a randomly-generated key.
type AddressValidator struct {
	aead   cipher.AEAD
	timeFn func() time.Time
}

// NewAddressValidator creates a new AddressValidator or returns error when failed to
// generate secret or AEAD.
func NewAddressValidator() (*AddressValidator, error) {
	var key [16]byte
	_, err := rand.Read(key[:])
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	return &AddressValidator{
		aead:   aead,
		timeFn: time.Now,
	}, nil
}

// Generate encrypts odcid using current time as nonce and addr as additional data.
func (s *AddressValidator) Generate(addr, odcid []byte) []byte {
	now := s.timeFn().Unix()
	nonce := make([]byte, s.aead.NonceSize())
	binary.BigEndian.PutUint32(nonce, uint32(now))

	token := make([]byte, 4+len(odcid)+s.aead.Overhead())
	binary.BigEndian.PutUint32(token, uint32(now))
	s.aead.Seal(token[4:4], nonce, odcid, addr)
	return token
}

// Validate decrypts token and returns odcid.
func (s *AddressValidator) Validate(addr, token []byte) []byte {
	if len(token) < 4 {
		return nil
	}
	const validity = 10 // Second
	now := s.timeFn().Unix()
	issued := int64(binary.BigEndian.Uint32(token))
	if issued < now-validity || issued > now {
		// TODO: Fix overflow when time > MAX_U32
		return nil
	}
	nonce := make([]byte, s.aead.NonceSize())
	copy(nonce, token[:4])
	odcid, err := s.aead.Open(nil, nonce, token[4:], addr)
	if err != nil {
		return nil
	}
	return odcid
}
