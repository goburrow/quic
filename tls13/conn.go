package tls13

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

// EncryptionLevel is QUIC encryption space.
type EncryptionLevel int

const (
	EncryptionLevelInitial EncryptionLevel = iota
	EncryptionLevelHandshake
	EncryptionLevelApplication
)

var ErrWantRead = errors.New("tls: want read")

type RecordLayer interface {
	ReadRecord(EncryptionLevel, []byte) (int, error)
	WriteRecord(EncryptionLevel, []byte) (int, error)
	SetReadSecret(level EncryptionLevel, readSecret []byte) error
	SetWriteSecret(level EncryptionLevel, writeSecret []byte) error
}

// A Conn represents a secured connection.
// It implements the net.Conn interface.
type Conn struct {
	// constant
	isClient bool

	// handshakeStatus is 1 if the connection is currently transferring
	// application data (i.e. is not currently processing a handshake).
	// This field is only to be accessed with sync/atomic.
	handshakeStatus uint32
	// constant after handshake; protected by handshakeMutex
	handshakeErr error       // error resulting from handshake
	vers         uint16      // TLS version
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

	clientProtocol string

	// input/output
	in, out     halfConn
	rawInput    []byte // raw input, starting with a record header
	recordLayer RecordLayer

	clientHs *clientHandshakeStateTLS13
	serverHs *serverHandshakeStateTLS13

	quicTransportParams []byte
	peerTransportParams []byte

	alert alert
}

func NewConn(recordLayer RecordLayer, config *tls.Config, isClient bool) *Conn {
	if config == nil {
		config = defaultConfig()
	}
	return &Conn{
		isClient:    isClient,
		config:      config,
		vers:        tls.VersionTLS13,
		recordLayer: recordLayer,
	}
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
		i, err := c.recordLayer.ReadRecord(level, c.rawInput[len(c.rawInput):n])
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
	return c.recordLayer.WriteRecord(c.out.encryptionLevel, data)
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

func (c *Conn) setInSecret(level EncryptionLevel, inSecret []byte) error {
	if err := c.recordLayer.SetReadSecret(level, inSecret); err != nil {
		return err
	}
	c.in.trafficSecret = inSecret
	c.in.encryptionLevel = level
	return nil
}

func (c *Conn) setOutSecret(level EncryptionLevel, outSecret []byte) error {
	if err := c.recordLayer.SetWriteSecret(level, outSecret); err != nil {
		return err
	}
	c.out.trafficSecret = outSecret
	c.out.encryptionLevel = level
	return nil
}

// Handshake runs the client or server handshake
// protocol if it has not yet been run.
// Most uses of this package need not call Handshake
// explicitly: the first Read or Write will call it automatically.
func (c *Conn) Handshake() error {
	var err error
	if err = c.handshakeErr; err != nil {
		return err
	}
	if c.handshakeComplete() {
		return nil
	}
	if c.isClient {
		err = c.clientHandshake()
	} else {
		err = c.serverHandshake()
	}
	if err != nil {
		if err != ErrWantRead {
			// Can only continue when it needs new data
			c.handshakeErr = err
		}
		return err
	}
	c.handshakes++
	c.handshakeStatus = 1
	// TODO: Delete handshake state
	return nil
}

// ConnectionState returns basic TLS details about the connection.
func (c *Conn) ConnectionState() tls.ConnectionState {
	var state tls.ConnectionState
	state.HandshakeComplete = c.handshakeComplete()
	state.ServerName = c.serverName
	state.CipherSuite = c.cipherSuite

	if state.HandshakeComplete {
		state.Version = c.vers
		state.NegotiatedProtocol = c.clientProtocol
		state.DidResume = c.didResume
		state.PeerCertificates = c.peerCertificates
		state.VerifiedChains = c.verifiedChains
		state.SignedCertificateTimestamps = c.scts
		state.OCSPResponse = c.ocspResponse
	}
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
