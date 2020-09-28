// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls13

// BUG(agl): The crypto/tls package only implements some countermeasures
// against Lucky13 attacks on CBC-mode encryption, and only on SHA1
// variants. See http://www.isg.rhul.ac.uk/tls/TLStiming.pdf and
// https://www.imperialviolet.org/2013/02/04/luckythirteen.html.

import (
	"crypto/tls"
	"errors"
)

// EncryptionLevel is QUIC encryption space.
type EncryptionLevel int

// Encryption levels
const (
	EncryptionLevelInitial EncryptionLevel = iota
	EncryptionLevelHandshake
	EncryptionLevelApplication
)

// ErrWantRead is returned when the connection needs to read a handshake message.
var ErrWantRead = errors.New("tls: want read")

// Transport is the connection callback for reading and writing TLS records.
type Transport interface {
	ReadRecord(EncryptionLevel, []byte) (int, error)
	WriteRecord(EncryptionLevel, []byte) (int, error)
	SetReadSecret(level EncryptionLevel, readSecret []byte) error
	SetWriteSecret(level EncryptionLevel, writeSecret []byte) error
}

// Server returns a new TLS server side connection
// using conn as the underlying transport.
// The configuration config must be non-nil and must include
// at least one certificate or else set GetCertificate.
func Server(conn Transport, config *tls.Config) *Conn {
	c := &Conn{
		conn:   conn,
		config: config,
	}
	c.handshakeFn = c.serverHandshake
	return c
}

// Client returns a new TLS client side connection
// using conn as the underlying transport.
// The config cannot be nil: users must set either ServerName or
// InsecureSkipVerify in the config.
func Client(conn Transport, config *tls.Config) *Conn {
	c := &Conn{
		conn:     conn,
		config:   config,
		isClient: true,
	}
	c.handshakeFn = c.clientHandshake
	return c
}
