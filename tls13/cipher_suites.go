// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls13

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	aeadNonceLength = 12
)

// A cipherSuiteTLS13 defines only the pair of the AEAD algorithm and hash
// algorithm to be used with HKDF. See RFC 8446, Appendix B.4.
type cipherSuiteTLS13 struct {
	id     uint16
	keyLen int
	aead   func(key, fixedNonce []byte) (cipher.AEAD, error)
	hash   crypto.Hash
}

var cipherSuitesTLS13 = []*cipherSuiteTLS13{
	{tls.TLS_AES_128_GCM_SHA256, 16, aeadAESGCM, crypto.SHA256},
	{tls.TLS_CHACHA20_POLY1305_SHA256, 32, aeadChaCha20Poly1305, crypto.SHA256},
	{tls.TLS_AES_256_GCM_SHA384, 32, aeadAESGCM, crypto.SHA384},
}

func aeadAESGCM(key, nonce []byte) (cipher.AEAD, error) {
	if len(nonce) != aeadNonceLength {
		return nil, fmt.Errorf("invalid nonce length: %d", len(nonce))
	}
	aes, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, err
	}

	aead := &xorNonceAEAD{aead: gcm}
	copy(aead.nonce[:], nonce)
	return aead, nil
}

func aeadChaCha20Poly1305(key, nonce []byte) (cipher.AEAD, error) {
	if len(nonce) != aeadNonceLength {
		return nil, fmt.Errorf("invalid nonce length: %d", len(nonce))
	}
	cc, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	aead := &xorNonceAEAD{aead: cc}
	copy(aead.nonce[:], nonce)
	return aead, nil
}

type xorNonceAEAD struct {
	nonce [aeadNonceLength]byte
	aead  cipher.AEAD
}

func (s *xorNonceAEAD) NonceSize() int {
	return 8 // 64-bit sequence number
}

func (s *xorNonceAEAD) Overhead() int {
	return s.aead.Overhead()
}

func (s *xorNonceAEAD) Seal(out, nonce, plaintext, additionalData []byte) []byte {
	for i, b := range nonce {
		s.nonce[4+i] ^= b
	}
	ciphertext := s.aead.Seal(out, s.nonce[:], plaintext, additionalData)
	for i, b := range nonce {
		s.nonce[4+i] ^= b
	}
	return ciphertext
}

func (s *xorNonceAEAD) Open(out, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	for i, b := range nonce {
		s.nonce[4+i] ^= b
	}
	plaintext, err := s.aead.Open(out, s.nonce[:], ciphertext, additionalData)
	for i, b := range nonce {
		s.nonce[4+i] ^= b
	}
	return plaintext, err
}

func mutualCipherSuiteTLS13(have []uint16, want uint16) *cipherSuiteTLS13 {
	for _, id := range have {
		if id == want {
			return cipherSuiteTLS13ByID(id)
		}
	}
	return nil
}

func cipherSuiteTLS13ByID(id uint16) *cipherSuiteTLS13 {
	for _, cipherSuite := range cipherSuitesTLS13 {
		if cipherSuite.id == id {
			return cipherSuite
		}
	}
	return nil
}

type CipherSuite interface {
	DeriveSecret(secret []byte, label string) []byte
	Extract(newSecret, currentSecret []byte) []byte
	QUICTrafficKey(trafficSecret []byte) (key, iv, hp []byte)
	AEAD(key, nonce []byte) (cipher.AEAD, error)
}

func CipherSuiteByID(id uint16) CipherSuite {
	return cipherSuiteTLS13ByID(id)
}

func (c *cipherSuiteTLS13) DeriveSecret(secret []byte, label string) []byte {
	return c.expandLabel(secret, label, nil, c.hash.Size())
}

func (c *cipherSuiteTLS13) Extract(newSecret, currentSecret []byte) []byte {
	return c.extract(newSecret, currentSecret)
}

func (c *cipherSuiteTLS13) QUICTrafficKey(trafficSecret []byte) (key, iv, hp []byte) {
	key = c.expandLabel(trafficSecret, "quic key", nil, c.keyLen)
	iv = c.expandLabel(trafficSecret, "quic iv", nil, aeadNonceLength)
	hp = c.expandLabel(trafficSecret, "quic hp", nil, c.keyLen)
	return
}

func (c *cipherSuiteTLS13) AEAD(key, nonce []byte) (cipher.AEAD, error) {
	return c.aead(key, nonce)
}
