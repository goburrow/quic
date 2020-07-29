package transport

import (
	"crypto/tls"
	"fmt"
	"time"

	"github.com/goburrow/quic/tls13"
)

// Transport parameters
const (
	paramOriginalDestinationCID         = 0x00
	paramMaxIdleTimeout                 = 0x01
	paramStatelessResetToken            = 0x02
	paramMaxUDPPayloadSize              = 0x03
	paramInitialMaxData                 = 0x04
	paramInitialMaxStreamDataBidiLocal  = 0x05
	paramInitialMaxStreamDataBidiRemote = 0x06
	paramInitialMaxStreamDataUni        = 0x07
	paramInitialMaxStreamsBidi          = 0x08
	paramInitialMaxStreamsUni           = 0x09
	paramAckDelayExponent               = 0x0a
	paramMaxAckDelay                    = 0x0b
	paramInitialSourceCID               = 0x0f
	paramRetrySourceCID                 = 0x10
)

// Parameters is QUIC transport parameters.
// See https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#transport-parameters
type Parameters struct {
	// OriginalDestinationCID is the DCID from the first Initial packet.
	OriginalDestinationCID []byte // Only sent by server
	// InitialSourceCID is the SCID of the frist Initial packet.
	InitialSourceCID []byte
	// RetrySourceCID is the SCID of Retry packet.
	RetrySourceCID []byte // Only sent by server
	// StatelessResetToken must be 16 bytes
	StatelessResetToken []byte // Only sent by server

	MaxIdleTimeout    time.Duration
	MaxUDPPayloadSize uint64

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
	if len(s.OriginalDestinationCID) > 0 {
		b.writeVarint(paramOriginalDestinationCID)
		b.writeBytes(s.OriginalDestinationCID)
	}
	if s.MaxIdleTimeout > 0 {
		b.writeVarint(paramMaxIdleTimeout)
		b.writeUint(uint64(s.MaxIdleTimeout / time.Millisecond))
	}
	if len(s.StatelessResetToken) > 0 {
		b.writeVarint(paramStatelessResetToken)
		b.writeBytes(s.StatelessResetToken)
	}
	if s.MaxUDPPayloadSize > 0 {
		b.writeVarint(paramMaxUDPPayloadSize)
		b.writeUint(s.MaxUDPPayloadSize)
	}
	if s.InitialMaxData > 0 {
		b.writeVarint(paramInitialMaxData)
		b.writeUint(s.InitialMaxData)
	}
	if s.InitialMaxStreamDataBidiLocal > 0 {
		b.writeVarint(paramInitialMaxStreamDataBidiLocal)
		b.writeUint(s.InitialMaxStreamDataBidiLocal)
	}
	if s.InitialMaxStreamDataBidiRemote > 0 {
		b.writeVarint(paramInitialMaxStreamDataBidiRemote)
		b.writeUint(s.InitialMaxStreamDataBidiRemote)
	}
	if s.InitialMaxStreamDataUni > 0 {
		b.writeVarint(paramInitialMaxStreamDataUni)
		b.writeUint(s.InitialMaxStreamDataUni)
	}
	if s.InitialMaxStreamsBidi > 0 {
		b.writeVarint(paramInitialMaxStreamsBidi)
		b.writeUint(s.InitialMaxStreamsBidi)
	}
	if s.InitialMaxStreamsUni > 0 {
		b.writeVarint(paramInitialMaxStreamsUni)
		b.writeUint(s.InitialMaxStreamsUni)
	}
	if s.AckDelayExponent > 0 {
		b.writeVarint(paramAckDelayExponent)
		b.writeUint(s.AckDelayExponent)
	}
	if s.MaxAckDelay > 0 {
		b.writeVarint(paramMaxAckDelay)
		b.writeUint(uint64(s.MaxAckDelay / time.Millisecond))
	}
	if len(s.InitialSourceCID) > 0 {
		b.writeVarint(paramInitialSourceCID)
		b.writeBytes(s.InitialSourceCID)
	}
	if len(s.RetrySourceCID) > 0 {
		b.writeVarint(paramRetrySourceCID)
		b.writeBytes(s.RetrySourceCID)
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
		case paramOriginalDestinationCID:
			if !b.readBytes(&s.OriginalDestinationCID) {
				return false
			}
		case paramMaxIdleTimeout:
			var v uint64
			if !b.readUint(&v) {
				return false
			}
			s.MaxIdleTimeout = time.Duration(v) * time.Millisecond
		case paramStatelessResetToken:
			if !b.readBytes(&s.StatelessResetToken) {
				return false
			}
		case paramMaxUDPPayloadSize:
			if !b.readUint(&s.MaxUDPPayloadSize) {
				return false
			}
		case paramInitialMaxData:
			if !b.readUint(&s.InitialMaxData) {
				return false
			}
		case paramInitialMaxStreamDataBidiLocal:
			if !b.readUint(&s.InitialMaxStreamDataBidiLocal) {
				return false
			}
		case paramInitialMaxStreamDataBidiRemote:
			if !b.readUint(&s.InitialMaxStreamDataBidiRemote) {
				return false
			}
		case paramInitialMaxStreamDataUni:
			if !b.readUint(&s.InitialMaxStreamDataUni) {
				return false
			}
		case paramInitialMaxStreamsBidi:
			if !b.readUint(&s.InitialMaxStreamsBidi) {
				return false
			}
		case paramInitialMaxStreamsUni:
			if !b.readUint(&s.InitialMaxStreamsUni) {
				return false
			}
		case paramAckDelayExponent:
			if !b.readUint(&s.AckDelayExponent) {
				return false
			}
		case paramMaxAckDelay:
			var v uint64
			if !b.readUint(&v) {
				return false
			}
			s.MaxAckDelay = time.Duration(v) * time.Millisecond
		case paramInitialSourceCID:
			if !b.readBytes(&s.InitialSourceCID) {
				return false
			}
		case paramRetrySourceCID:
			if !b.readBytes(&s.RetrySourceCID) {
				return false
			}
		default:
			// Unsupported parameter
			debug("skip unsupported transport parameter 0x%x", param)
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
		*v = append((*v)[:0], b[:n]...)
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
	tlsConfig *tls.Config
	tlsConn   *tls13.Conn

	packetNumberSpaces *[packetSpaceCount]packetNumberSpace
}

func (s *tlsHandshake) init(config *tls.Config, packetNumberSpaces *[packetSpaceCount]packetNumberSpace, isClient bool) {
	s.tlsConfig = config
	s.tlsConn = tls13.NewConn(s, s.tlsConfig, isClient)
	s.packetNumberSpaces = packetNumberSpaces
}

func (s *tlsHandshake) doHandshake() error {
	err := s.tlsConn.Handshake()
	if err != nil && err != tls13.ErrWantRead {
		alert := uint64(s.tlsConn.Alert())
		return newError(CryptoError+alert, err.Error())
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
	default:
		panic(sprint("unsupported tls encryption level ", level))
	}
}

// XXX: Store isClient in tlsHandshake?
func (s *tlsHandshake) reset(isClient bool) {
	s.tlsConn = tls13.NewConn(s, s.tlsConfig, isClient)
}

func (s *tlsHandshake) ReadRecord(level tls13.EncryptionLevel, b []byte) (int, error) {
	space := packetSpaceFromEncryptionLevel(level)
	return s.packetNumberSpaces[space].cryptoStream.Read(b)
}

func (s *tlsHandshake) WriteRecord(level tls13.EncryptionLevel, b []byte) (int, error) {
	space := packetSpaceFromEncryptionLevel(level)
	return s.packetNumberSpaces[space].cryptoStream.Write(b)
}

func (s *tlsHandshake) SetReadSecret(level tls13.EncryptionLevel, readSecret []byte) error {
	suite := s.tlsConn.ConnectionState().CipherSuite
	debug("set read secret level=%d ciphersuite=0x%x read=%d", level, suite, len(readSecret))
	cipher := tls13.CipherSuiteByID(suite)
	if cipher == nil {
		return fmt.Errorf("connection not yet handshaked")
	}
	space := packetSpaceFromEncryptionLevel(level)
	s.packetNumberSpaces[space].opener.init(cipher, readSecret)
	return nil
}

func (s *tlsHandshake) SetWriteSecret(level tls13.EncryptionLevel, writeSecret []byte) error {
	suite := s.tlsConn.ConnectionState().CipherSuite
	debug("set write secret level=%d ciphersuite=0x%x write=%d", level, suite, len(writeSecret))
	cipher := tls13.CipherSuiteByID(suite)
	if cipher == nil {
		return fmt.Errorf("connection not yet handshaked")
	}
	space := packetSpaceFromEncryptionLevel(level)
	s.packetNumberSpaces[space].sealer.init(cipher, writeSecret)
	return nil
}

func (s *tlsHandshake) setTransportParams(params *Parameters) {
	debug("transport params: %+v", params)
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

func packetSpaceFromEncryptionLevel(level tls13.EncryptionLevel) packetSpace {
	switch level {
	case tls13.EncryptionLevelInitial:
		return packetSpaceInitial
	case tls13.EncryptionLevelHandshake:
		return packetSpaceHandshake
	case tls13.EncryptionLevelApplication:
		return packetSpaceApplication
	default:
		panic(sprint("unsupported tls encryption level ", level))
	}
}
