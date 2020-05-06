package transport

import (
	"crypto/tls"
	"fmt"
	"time"

	"github.com/goburrow/quic/tls13"
)

const (
	parameterOriginalCID = iota // 0
	parameterMaxIdleTimeout
	parameterStatelessResetToken
	parameterMaxUDPPayloadSize
	parameterInitialMaxData
	parameterInitialMaxStreamDataBidiLocal // 5
	parameterInitialMaxStreamDataBidiRemote
	parameterInitialMaxStreamDataUni
	parameterInitialMaxStreamsBidi
	parameterInitialMaxStreamsUni
	parameterAckDelayExponent // 10
	parameterMaxAckDelay
)

// Parameters is QUIC transport parameters.
// See https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#transport-parameters
type Parameters struct {
	OriginalCID         []byte // Server only
	MaxIdleTimeout      time.Duration
	StatelessResetToken []byte // Server only
	MaxUDPPayloadSize   uint64

	InitialMaxData                 uint64
	InitialMaxStreamDataBidiLocal  uint64
	InitialMaxStreamDataBidiRemote uint64
	InitialMaxStreamDataUni        uint64
	InitialMaxStreamsBidi          uint64
	InitialMaxStreamsUni           uint64

	AckDelayExponent uint64
	MaxAckDelay      time.Duration
}

// https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#transport-parameter-encoding
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                  Transport Parameter 1 (*)                  ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                  Transport Parameter 2 (*)                  ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//                                ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                  Transport Parameter N (*)                  ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
func (s *Parameters) marshal() []byte {
	b := make(tlsExtension, 0, 128)
	if len(s.OriginalCID) > 0 {
		b.writeVarint(parameterOriginalCID)
		b.writeBytes(s.OriginalCID)
	}
	if s.MaxIdleTimeout > 0 {
		b.writeVarint(parameterMaxIdleTimeout)
		b.writeUint(uint64(s.MaxIdleTimeout / time.Millisecond))
	}
	if len(s.StatelessResetToken) > 0 {
		b.writeVarint(parameterStatelessResetToken)
		b.writeBytes(s.StatelessResetToken)
	}
	if s.MaxUDPPayloadSize > 0 {
		b.writeVarint(parameterMaxUDPPayloadSize)
		b.writeUint(s.MaxUDPPayloadSize)
	}
	if s.InitialMaxData > 0 {
		b.writeVarint(parameterInitialMaxData)
		b.writeUint(s.InitialMaxData)
	}
	if s.InitialMaxStreamDataBidiLocal > 0 {
		b.writeVarint(parameterInitialMaxStreamDataBidiLocal)
		b.writeUint(s.InitialMaxStreamDataBidiLocal)
	}
	if s.InitialMaxStreamDataBidiRemote > 0 {
		b.writeVarint(parameterInitialMaxStreamDataBidiRemote)
		b.writeUint(s.InitialMaxStreamDataBidiRemote)
	}
	if s.InitialMaxStreamDataUni > 0 {
		b.writeVarint(parameterInitialMaxStreamDataUni)
		b.writeUint(s.InitialMaxStreamDataUni)
	}
	if s.InitialMaxStreamsBidi > 0 {
		b.writeVarint(parameterInitialMaxStreamsBidi)
		b.writeUint(s.InitialMaxStreamsBidi)
	}
	if s.InitialMaxStreamsUni > 0 {
		b.writeVarint(parameterInitialMaxStreamsUni)
		b.writeUint(s.InitialMaxStreamsUni)
	}
	if s.AckDelayExponent > 0 {
		b.writeVarint(parameterAckDelayExponent)
		b.writeUint(s.AckDelayExponent)
	}
	if s.MaxAckDelay > 0 {
		b.writeVarint(parameterMaxAckDelay)
		b.writeUint(uint64(s.MaxAckDelay / time.Millisecond))
	}
	return b
}

func (s *Parameters) unmarshal(data []byte) bool {
	b := tlsExtension(data)
	var param uint64
	for !b.empty() {
		if !b.readVarint(&param) {
			return false
		}
		switch param {
		case parameterOriginalCID:
			if !b.readBytes(&s.OriginalCID) {
				return false
			}
		case parameterMaxIdleTimeout:
			var v uint64
			if !b.readUint(&v) {
				return false
			}
			s.MaxIdleTimeout = time.Duration(v) * time.Millisecond
		case parameterStatelessResetToken:
			if !b.readBytes(&s.StatelessResetToken) {
				return false
			}
		case parameterMaxUDPPayloadSize:
			if !b.readUint(&s.MaxUDPPayloadSize) {
				return false
			}
		case parameterInitialMaxData:
			if !b.readUint(&s.InitialMaxData) {
				return false
			}
		case parameterInitialMaxStreamDataBidiLocal:
			if !b.readUint(&s.InitialMaxStreamDataBidiLocal) {
				return false
			}
		case parameterInitialMaxStreamDataBidiRemote:
			if !b.readUint(&s.InitialMaxStreamDataBidiRemote) {
				return false
			}
		case parameterInitialMaxStreamDataUni:
			if !b.readUint(&s.InitialMaxStreamDataUni) {
				return false
			}
		case parameterInitialMaxStreamsBidi:
			if !b.readUint(&s.InitialMaxStreamsBidi) {
				return false
			}
		case parameterInitialMaxStreamsUni:
			if !b.readUint(&s.InitialMaxStreamsUni) {
				return false
			}
		case parameterAckDelayExponent:
			if !b.readUint(&s.AckDelayExponent) {
				return false
			}
		case parameterMaxAckDelay:
			var v uint64
			if !b.readUint(&v) {
				return false
			}
			s.MaxAckDelay = time.Duration(v) * time.Millisecond
		default:
			// Unsupported parameter
			var v uint64
			if !b.readVarint(&v) || !b.skip(int(v)) {
				return false
			}
		}
	}
	return true
}

// Each transport parameter is encoded as an (identifier, length, value) tuple.
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                 Transport Parameter ID (i)                  ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |               Transport Parameter Length (i)                ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                Transport Parameter Value (*)                ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type tlsExtension []byte

// readVarint reads next variable-length integer.
func (s *tlsExtension) readVarint(v *uint64) bool {
	b := *s
	if len(b) == 0 {
		return false
	}
	n := getVarint(b, v)
	if n <= 0 {
		return false
	}
	*s = b[n:]
	return true
}

// readUint reads varint with length prefix.
func (s *tlsExtension) readUint(v *uint64) bool {
	var n uint64
	if !s.readVarint(&n) {
		return false
	}
	if n > 0 {
		b := *s
		m := getVarint(b, v)
		if m <= 0 || uint64(m) != n {
			return false
		}
		*s = b[n:]
	}
	return true
}

// readBytes reads bytes with length prefix.
func (s *tlsExtension) readBytes(v *[]byte) bool {
	var n uint64
	if !s.readVarint(&n) {
		return false
	}
	if n > 0 {
		b := *s
		if len(b) < int(n) {
			return false
		}
		*v = b[:n]
		*s = b[n:]
	}
	return true
}

// writeVarint appends integer.
func (s *tlsExtension) writeVarint(v uint64) {
	n := varintLen(v)
	*s = appendVarint(*s, v, n)
}

// writeVarint appends integer with length prefix.
func (s *tlsExtension) writeUint(v uint64) {
	n := varintLen(v)
	s.writeVarint(uint64(n))
	*s = appendVarint(*s, v, n)
}

// writeBytes appends bytes with length prefix.
func (s *tlsExtension) writeBytes(v []byte) {
	s.writeVarint(uint64(len(v)))
	*s = append(*s, v...)
}

func (s *tlsExtension) skip(n int) bool {
	b := *s
	if len(b) < n {
		return false
	}
	*s = b[n:]
	return true
}

func (s tlsExtension) empty() bool {
	return len(s) == 0
}

type tlsHandshake struct {
	conn      *Conn
	tlsConfig *tls.Config
	tlsConn   *tls13.Conn
}

func (s *tlsHandshake) init(conn *Conn, config *tls.Config) {
	s.conn = conn
	s.tlsConfig = config
	s.tlsConn = tls13.NewConn(s, s.tlsConfig, conn.isClient)
}

func (s *tlsHandshake) doHandshake() error {
	err := s.tlsConn.Handshake()
	if err != nil && err != tls13.ErrWantRead {
		alert := uint64(s.tlsConn.Alert())
		return newError(CryptoError+alert, "%v", err)
	}
	return nil
}

func (s *tlsHandshake) HandshakeComplete() bool {
	return s.tlsConn.ConnectionState().HandshakeComplete
}

func (s *tlsHandshake) writeSpace() packetSpace {
	level := s.tlsConn.WriteLevel()
	switch level {
	case tls13.EncryptionLevelInitial:
		return packetSpaceInitial
	case tls13.EncryptionLevelHandshake:
		return packetSpaceHandshake
	case tls13.EncryptionLevelApplication:
		return packetSpaceApplication
	}
	panic(fmt.Sprintf("unsupported TLS write level: %d", level))
}

func (s *tlsHandshake) reset() {
	s.tlsConn = tls13.NewConn(s, s.tlsConfig, s.conn.isClient)
}

func (s *tlsHandshake) ReadRecord(level tls13.EncryptionLevel, b []byte) (int, error) {
	space := s.packetNumberSpace(level)
	return space.cryptoStream.Read(b)
}

func (s *tlsHandshake) WriteRecord(level tls13.EncryptionLevel, b []byte) (int, error) {
	space := s.packetNumberSpace(level)
	return space.cryptoStream.Write(b)
}

func (s *tlsHandshake) SetReadSecret(level tls13.EncryptionLevel, readSecret []byte) error {
	debug("set read secret level=%d read=%d", level, len(readSecret))
	space := s.packetNumberSpace(level)
	cipher := tls13.CipherSuiteByID(s.tlsConn.ConnectionState().CipherSuite)
	if cipher == nil {
		return fmt.Errorf("connection not yet handshaked")
	}
	return space.opener.init(cipher, readSecret)
}

func (s *tlsHandshake) SetWriteSecret(level tls13.EncryptionLevel, writeSecret []byte) error {
	debug("set write secret level=%d write=%d", level, len(writeSecret))
	space := s.packetNumberSpace(level)
	cipher := tls13.CipherSuiteByID(s.tlsConn.ConnectionState().CipherSuite)
	if cipher == nil {
		return fmt.Errorf("connection not yet handshaked")
	}
	return space.sealer.init(cipher, writeSecret)
}

func (s *tlsHandshake) setTransportParams(params *Parameters) {
	s.tlsConn.SetQUICTransportParams(params.marshal())
}

func (s *tlsHandshake) peerTransportParams() *Parameters {
	b := s.tlsConn.PeerQUICTransportParams()
	if len(b) == 0 {
		return nil
	}
	params := &Parameters{}
	if !params.unmarshal(b) {
		return nil
	}
	return params
}

func (s *tlsHandshake) packetNumberSpace(level tls13.EncryptionLevel) *packetNumberSpace {
	space := packetSpaceFromEncryptionLevel(level)
	return &s.conn.packetNumberSpaces[space]
}

func packetSpaceFromEncryptionLevel(level tls13.EncryptionLevel) packetSpace {
	switch level {
	case tls13.EncryptionLevelInitial:
		return packetSpaceInitial
	case tls13.EncryptionLevelHandshake:
		return packetSpaceHandshake
	case tls13.EncryptionLevelApplication:
		return packetSpaceApplication
	default:
		panic(fmt.Sprintf("unsupported encryption level: %v", level))
	}
}
