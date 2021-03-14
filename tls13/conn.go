// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// TLS low level connection and record layer

package tls13

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

// A Conn represents a secured connection.
// It implements the net.Conn interface.
type Conn struct {
	// constant
	conn        Transport
	isClient    bool
	handshakeFn func() error // (*Conn).clientHandshake or serverHandshake

	// handshakeStatus is 1 if the connection is currently transferring
	// application data (i.e. is not currently processing a handshake).
	// This field is only to be accessed with sync/atomic.
	handshakeStatus uint32
	// constant after handshake; protected by handshakeMutex
	handshakeErr error       // error resulting from handshake
	vers         uint16      // TLS version
	haveVers     bool        // version has been negotiated
	config       *tls.Config // configuration passed to constructor
	// handshakes counts the number of handshakes performed on the
	// connection so far. If renegotiation is disabled then this is either
	// zero or one.
	handshakes       int
	didResume        bool // whether this connection was a session resumption
	cipherSuite      uint16
	ocspResponse     []byte   // stapled OCSP response
	scts             [][]byte // signed certificate timestamps from server
	peerCertificates []*x509.Certificate
	// verifiedChains contains the certificate chains that we built, as
	// opposed to the ones presented by the server.
	verifiedChains [][]*x509.Certificate
	// serverName contains the server name indicated by the client, if any.
	serverName string
	// secureRenegotiation is true if the server echoed the secure
	// renegotiation extension. (This is meaningless as a server because
	// renegotiation is not supported in that case.)
	secureRenegotiation bool
	// ekm is a closure for exporting keying material.
	ekm func(label string, context []byte, length int) ([]byte, error)
	// resumptionSecret is the resumption_master_secret for handling
	// NewSessionTicket messages. nil if config.SessionTicketsDisabled.
	resumptionSecret []byte

	// ticketKeys is the set of active session ticket keys for this
	// connection. The first one is used to encrypt new tickets and
	// all are tried to decrypt tickets.
	ticketKeys []ticketKey

	clientProtocol string

	// input/output
	in, out  halfConn
	rawInput []byte // raw input, starting with a record header

	// retryCount counts the number of consecutive non-advancing records
	// received by Conn.readRecord. That is, records that neither advance the
	// handshake, nor deliver application data. Protected by in.Mutex.
	retryCount int

	clientHs *clientHandshakeStateTLS13
	serverHs *serverHandshakeStateTLS13

	quicTransportParams []byte
	peerTransportParams []byte

	alert alert
}

// A halfConn represents one direction of the record layer
// connection, either sending or receiving.
type halfConn struct {
	encryptionLevel EncryptionLevel

	trafficSecret []byte // current TLS 1.3 traffic secret
}

func (c *Conn) readRecord(level EncryptionLevel, n int) error {
	c.growReadBufCapacity(n)
	for len(c.rawInput) < n {
		i, err := c.conn.ReadRecord(level, c.rawInput[len(c.rawInput):n])
		if err != nil {
			return err
		}
		if i == 0 {
			return ErrWantRead
		}
		c.rawInput = c.rawInput[:len(c.rawInput)+i]
	}
	return nil
}

func (c *Conn) growReadBufCapacity(n int) {
	if cap(c.rawInput) >= n {
		return
	}
	// Round up n to a multiple of 512
	const m = 512
	n = (n + m - 1) & (-m)
	b := make([]byte, len(c.rawInput), n)
	copy(b, c.rawInput)
	c.rawInput = b
}

func (c *Conn) writeRecord(typ recordType, data []byte) (int, error) {
	return c.conn.WriteRecord(c.out.encryptionLevel, data)
}

// sendAlert sends a TLS alert message.
func (c *Conn) sendAlert(a alert) {
	c.alert = a
}

// readHandshake reads the next handshake message from
// the record layer.
func (c *Conn) readHandshake() (interface{}, error) {
	err := c.readRecord(c.in.encryptionLevel, 4)
	if err != nil {
		return nil, err
	}

	data := c.rawInput
	n := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if n > maxHandshake {
		c.sendAlert(alertInternalError)
		return nil, fmt.Errorf("tls: handshake message of length %d bytes exceeds maximum of %d bytes", n, maxHandshake)
	}
	err = c.readRecord(c.in.encryptionLevel, 4+n)
	if err != nil {
		return nil, err
	}
	data = c.rawInput
	var m handshakeMessage
	switch data[0] {
	case typeHelloRequest:
		m = new(helloRequestMsg)
	case typeClientHello:
		m = new(clientHelloMsg)
	case typeServerHello:
		m = new(serverHelloMsg)
	case typeNewSessionTicket:
		m = new(newSessionTicketMsgTLS13)
	case typeCertificate:
		m = new(certificateMsgTLS13)
	case typeCertificateRequest:
		m = new(certificateRequestMsgTLS13)
	case typeCertificateStatus:
		m = new(certificateStatusMsg)
	case typeServerKeyExchange:
		m = new(serverKeyExchangeMsg)
	case typeServerHelloDone:
		m = new(serverHelloDoneMsg)
	case typeClientKeyExchange:
		m = new(clientKeyExchangeMsg)
	case typeCertificateVerify:
		m = &certificateVerifyMsg{
			hasSignatureAlgorithm: c.vers >= tls.VersionTLS12,
		}
	case typeFinished:
		m = new(finishedMsg)
	case typeEncryptedExtensions:
		m = new(encryptedExtensionsMsg)
	case typeEndOfEarlyData:
		m = new(endOfEarlyDataMsg)
	case typeKeyUpdate:
		m = new(keyUpdateMsg)
	default:
		c.sendAlert(alertUnexpectedMessage)
		return nil, fmt.Errorf("tls: unsupported handshake message %d", data[0])
	}

	data = make([]byte, len(c.rawInput))
	copy(data, c.rawInput)
	c.rawInput = c.rawInput[:0]
	if !m.unmarshal(data) {
		c.sendAlert(alertUnexpectedMessage)
		return nil, fmt.Errorf("tls: could not parse message %d", data[0])
	}
	return m, nil
}

// handlePostHandshakeMessage processes a handshake message arrived after the
// handshake is complete. Up to TLS 1.2, it indicates the start of a renegotiation.
func (c *Conn) handlePostHandshakeMessage() error {
	if c.vers != tls.VersionTLS13 {
		return fmt.Errorf("tls: unsupported version %v", c.vers)
	}

	msg, err := c.readHandshake()
	if err != nil {
		if err == ErrWantRead {
			return nil
		}
		return err
	}

	c.retryCount++
	if c.retryCount > maxUselessRecords {
		c.sendAlert(alertUnexpectedMessage)
		return errors.New("tls: too many non-advancing records")
	}

	switch msg := msg.(type) {
	case *newSessionTicketMsgTLS13:
		return c.handleNewSessionTicket(msg)
	case *keyUpdateMsg:
		return c.handleKeyUpdate(msg)
	default:
		c.sendAlert(alertUnexpectedMessage)
		return fmt.Errorf("tls: received unexpected handshake message of type %T", msg)
	}
}

func (c *Conn) handleKeyUpdate(keyUpdate *keyUpdateMsg) error {
	cipherSuite := cipherSuiteTLS13ByID(c.cipherSuite)
	if cipherSuite == nil {
		c.sendAlert(alertInternalError)
		return errors.New("tls: unsupported cipher suite")
	}

	newSecret := cipherSuite.nextTrafficSecret(c.in.trafficSecret)
	c.setInSecret(c.in.encryptionLevel, newSecret)

	if keyUpdate.updateRequested {
		msg := &keyUpdateMsg{}
		_, err := c.writeRecord(recordTypeHandshake, msg.marshal())
		if err != nil {
			// Surface the error at the next write.
			return err
		}

		newSecret := cipherSuite.nextTrafficSecret(c.out.trafficSecret)
		c.setOutSecret(c.out.encryptionLevel, newSecret)
	}

	return nil
}

func (c *Conn) setInSecret(level EncryptionLevel, inSecret []byte) error {
	if err := c.conn.SetReadSecret(level, inSecret); err != nil {
		return err
	}
	c.in.trafficSecret = inSecret
	c.in.encryptionLevel = level
	return nil
}

func (c *Conn) setOutSecret(level EncryptionLevel, outSecret []byte) error {
	if err := c.conn.SetWriteSecret(level, outSecret); err != nil {
		return err
	}
	c.out.trafficSecret = outSecret
	c.out.encryptionLevel = level
	return nil
}

// Handshake runs the client or server handshake
// protocol if it has not yet been run.
func (c *Conn) Handshake() error {
	if err := c.handshakeErr; err != nil {
		return err
	}
	if c.handshakeComplete() {
		return c.handlePostHandshakeMessage()
	}

	err := c.handshakeFn()
	if err == nil {
		c.handshakes++
	} else {
		if err != ErrWantRead {
			// Can only continue when it needs new data
			c.handshakeErr = err
		}
		return err
	}

	if c.handshakeComplete() {
		c.handshakeErr = c.handlePostHandshakeMessage()
	} else {
		c.handshakeErr = errors.New("tls: internal error: handshake should have had a result")
	}

	return c.handshakeErr
}

// ConnectionState returns basic TLS details about the connection.
func (c *Conn) ConnectionState() tls.ConnectionState {
	return c.connectionStateLocked()
}

func (c *Conn) connectionStateLocked() tls.ConnectionState {
	var state tls.ConnectionState
	state.HandshakeComplete = c.handshakeComplete()
	state.Version = c.vers
	state.NegotiatedProtocol = c.clientProtocol
	state.DidResume = c.didResume
	state.NegotiatedProtocolIsMutual = true
	state.ServerName = c.serverName
	state.CipherSuite = c.cipherSuite
	state.PeerCertificates = c.peerCertificates
	state.VerifiedChains = c.verifiedChains
	state.SignedCertificateTimestamps = c.scts
	state.OCSPResponse = c.ocspResponse
	return state
}

func (c *Conn) ReadLevel() EncryptionLevel {
	return c.in.encryptionLevel
}

func (c *Conn) WriteLevel() EncryptionLevel {
	return c.out.encryptionLevel
}

func (c *Conn) Alert() uint8 {
	return uint8(c.alert)
}

func (c *Conn) SetQUICTransportParams(b []byte) {
	c.quicTransportParams = b
}

func (c *Conn) PeerQUICTransportParams() []byte {
	return c.peerTransportParams
}

func (c *Conn) handshakeComplete() bool {
	return c.handshakeStatus == 1
}
