// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls13

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"io"
	"sync"

	"golang.org/x/crypto/cryptobyte"
)

// sessionStateTLS13 is the content of a TLS 1.3 session ticket. Its first
// version (revision = 0) doesn't carry any of the information needed for 0-RTT
// validation and the nonce is always empty.
type sessionStateTLS13 struct {
	// uint8 version  = 0x0304;
	// uint8 revision = 0;
	cipherSuite      uint16
	createdAt        uint64
	resumptionSecret []byte          // opaque resumption_master_secret<1..2^8-1>;
	certificate      tls.Certificate // CertificateEntry certificate_list<0..2^24-1>;
}

func (m *sessionStateTLS13) marshal() []byte {
	var b cryptobyte.Builder
	b.AddUint16(tls.VersionTLS13)
	b.AddUint8(0) // revision
	b.AddUint16(m.cipherSuite)
	addUint64(&b, m.createdAt)
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(m.resumptionSecret)
	})
	marshalCertificate(&b, m.certificate)
	return b.BytesOrPanic()
}

func (m *sessionStateTLS13) unmarshal(data []byte) bool {
	*m = sessionStateTLS13{}
	s := cryptobyte.String(data)
	var version uint16
	var revision uint8
	return s.ReadUint16(&version) &&
		version == tls.VersionTLS13 &&
		s.ReadUint8(&revision) &&
		revision == 0 &&
		s.ReadUint16(&m.cipherSuite) &&
		readUint64(&s, &m.createdAt) &&
		readUint8LengthPrefixed(&s, &m.resumptionSecret) &&
		len(m.resumptionSecret) != 0 &&
		unmarshalCertificate(&s, &m.certificate) &&
		s.Empty()
}

func (c *Conn) encryptTicket(state []byte) ([]byte, error) {
	encrypted := make([]byte, ticketKeyNameLen+aes.BlockSize+len(state)+sha256.Size)
	keyName := encrypted[:ticketKeyNameLen]
	iv := encrypted[ticketKeyNameLen : ticketKeyNameLen+aes.BlockSize]
	macBytes := encrypted[len(encrypted)-sha256.Size:]

	if _, err := io.ReadFull(configRand(c.config), iv); err != nil {
		return nil, err
	}
	key := configTicketKeys(c.config)[0]
	copy(keyName, key.keyName[:])
	block, err := aes.NewCipher(key.aesKey[:])
	if err != nil {
		return nil, errors.New("tls: failed to create cipher while encrypting ticket: " + err.Error())
	}
	cipher.NewCTR(block, iv).XORKeyStream(encrypted[ticketKeyNameLen+aes.BlockSize:], state)

	mac := hmac.New(sha256.New, key.hmacKey[:])
	mac.Write(encrypted[:len(encrypted)-sha256.Size])
	mac.Sum(macBytes[:0])

	return encrypted, nil
}

func (c *Conn) decryptTicket(encrypted []byte) (plaintext []byte, usedOldKey bool) {
	if len(encrypted) < ticketKeyNameLen+aes.BlockSize+sha256.Size {
		return nil, false
	}

	keyName := encrypted[:ticketKeyNameLen]
	iv := encrypted[ticketKeyNameLen : ticketKeyNameLen+aes.BlockSize]
	macBytes := encrypted[len(encrypted)-sha256.Size:]
	ciphertext := encrypted[ticketKeyNameLen+aes.BlockSize : len(encrypted)-sha256.Size]

	keys := configTicketKeys(c.config)
	keyIndex := -1
	for i, candidateKey := range keys {
		if bytes.Equal(keyName, candidateKey.keyName[:]) {
			keyIndex = i
			break
		}
	}

	if keyIndex == -1 {
		return nil, false
	}
	key := &keys[keyIndex]

	mac := hmac.New(sha256.New, key.hmacKey[:])
	mac.Write(encrypted[:len(encrypted)-sha256.Size])
	expected := mac.Sum(nil)

	if subtle.ConstantTimeCompare(macBytes, expected) != 1 {
		return nil, false
	}

	block, err := aes.NewCipher(key.aesKey[:])
	if err != nil {
		return nil, false
	}
	plaintext = make([]byte, len(ciphertext))
	cipher.NewCTR(block, iv).XORKeyStream(plaintext, ciphertext)

	return plaintext, keyIndex > 0
}

// globalTicketKeys stores all ticketKeys by config pointer
var globalTicketKeys sync.Map
