// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls13

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"

	"golang.org/x/crypto/chacha20poly1305"
)

// A cipherSuiteTLS13 defines only the pair of the AEAD algorithm and hash
// algorithm to be used with HKDF. See RFC 8446, Appendix B.4.
type cipherSuiteTLS13 struct {
	id     uint16
	keyLen int
	aead   func(key, fixedNonce []byte) aead
	hash   crypto.Hash
}

var cipherSuitesTLS13 = []*cipherSuiteTLS13{ // TODO: replace with a map.
	{tls.TLS_AES_128_GCM_SHA256, 16, aeadAESGCMTLS13, crypto.SHA256},
	{tls.TLS_CHACHA20_POLY1305_SHA256, 32, aeadChaCha20Poly1305, crypto.SHA256},
	{tls.TLS_AES_256_GCM_SHA384, 32, aeadAESGCMTLS13, crypto.SHA384},
}

var (
	defaultCipherSuites = defaultCipherSuitesTLS13
)

// defaultCipherSuitesTLS13 is also the preference order, since there are no
// disabled by default TLS 1.3 cipher suites. The same AES vs ChaCha20 logic as
// cipherSuitesPreferenceOrder applies.
var defaultCipherSuitesTLS13 = []uint16{
	tls.TLS_AES_128_GCM_SHA256,
	tls.TLS_AES_256_GCM_SHA384,
	tls.TLS_CHACHA20_POLY1305_SHA256,
}

var defaultCipherSuitesTLS13NoAES = []uint16{
	tls.TLS_CHACHA20_POLY1305_SHA256,
	tls.TLS_AES_128_GCM_SHA256,
	tls.TLS_AES_256_GCM_SHA384,
}

var (
	// TODO: tls.hasAESGCMHardwareSupport
	hasAESGCMHardwareSupport = true
)

var aesgcmCiphers = map[uint16]bool{
	// TLS 1.3
	tls.TLS_AES_128_GCM_SHA256: true,
	tls.TLS_AES_256_GCM_SHA384: true,
}

// aesgcmPreferred returns whether the first known cipher in the preference list
// is an AES-GCM cipher, implying the peer has hardware support for it.
func aesgcmPreferred(ciphers []uint16) bool {
	for _, cID := range ciphers {
		if c := cipherSuiteTLS13ByID(cID); c != nil {
			return aesgcmCiphers[cID]
		}
	}
	return false
}

type aead interface {
	cipher.AEAD

	// explicitNonceLen returns the number of bytes of explicit nonce
	// included in each record. This is eight for older AEADs and
	// zero for modern ones.
	explicitNonceLen() int
}

const (
	aeadNonceLength   = 12
	noncePrefixLength = 4
)

// xoredNonceAEAD wraps an AEAD by XORing in a fixed pattern to the nonce
// before each call.
type xorNonceAEAD struct {
	nonceMask [aeadNonceLength]byte
	aead      cipher.AEAD
}

func (f *xorNonceAEAD) NonceSize() int        { return 8 } // 64-bit sequence number
func (f *xorNonceAEAD) Overhead() int         { return f.aead.Overhead() }
func (f *xorNonceAEAD) explicitNonceLen() int { return 0 }

func (f *xorNonceAEAD) Seal(out, nonce, plaintext, additionalData []byte) []byte {
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}
	result := f.aead.Seal(out, f.nonceMask[:], plaintext, additionalData)
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}

	return result
}

func (f *xorNonceAEAD) Open(out, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}
	result, err := f.aead.Open(out, f.nonceMask[:], ciphertext, additionalData)
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}

	return result, err
}

func aeadAESGCMTLS13(key, nonceMask []byte) aead {
	if len(nonceMask) != aeadNonceLength {
		panic("tls: internal error: wrong nonce length")
	}
	aes, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(aes)
	if err != nil {
		panic(err)
	}

	ret := &xorNonceAEAD{aead: aead}
	copy(ret.nonceMask[:], nonceMask)
	return ret
}

func aeadChaCha20Poly1305(key, nonceMask []byte) aead {
	if len(nonceMask) != aeadNonceLength {
		panic("tls: internal error: wrong nonce length")
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}

	ret := &xorNonceAEAD{aead: aead}
	copy(ret.nonceMask[:], nonceMask)
	return ret
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

// CipherSuite is the exported cipherSuiteTLS13 for QUIC usage.
type CipherSuite interface {
	ID() uint16
	KeyLen() int
	AEAD(key, nonce []byte) cipher.AEAD
	Hash() crypto.Hash
	ExpandLabel(secret []byte, label string, length int) []byte
	Extract(newSecret, currentSecret []byte) []byte
}

// CipherSuiteByID is the exported cipherSuiteTLS13ByID for QUIC usage.
func CipherSuiteByID(id uint16) CipherSuite {
	return cipherSuiteTLS13ByID(id)
}

func (c *cipherSuiteTLS13) ID() uint16 {
	return c.id
}

func (c *cipherSuiteTLS13) KeyLen() int {
	return c.keyLen
}

func (c *cipherSuiteTLS13) AEAD(key, nonce []byte) cipher.AEAD {
	return c.aead(key, nonce)
}

func (c *cipherSuiteTLS13) Hash() crypto.Hash {
	return c.hash
}

func (c *cipherSuiteTLS13) ExpandLabel(secret []byte, label string, length int) []byte {
	return c.expandLabel(secret, label, nil, length)
}

func (c *cipherSuiteTLS13) Extract(newSecret, currentSecret []byte) []byte {
	return c.extract(newSecret, currentSecret)
}
