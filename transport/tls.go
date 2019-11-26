package transport

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/goburrow/quic/tls13"
)

const (
	parameterOriginalCID uint16 = iota // 0
	parameterIdleTimeout
	parameterStatelessResetToken
	parameterMaxPacketSize
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
	OriginalCID         []byte
	IdleTimeout         time.Duration
	StatelessResetToken []byte
	MaxPacketSize       uint64

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
// |      Sequence Length (16)     |
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
	b := make(tlsExtension, 2, 128)
	if len(s.OriginalCID) > 0 {
		b.addUint16(parameterOriginalCID)
		b.addBytes(s.OriginalCID)
	}
	if s.IdleTimeout > 0 {
		b.addUint16(parameterIdleTimeout)
		b.addVarint(uint64(s.IdleTimeout / time.Millisecond))
	}
	if len(s.StatelessResetToken) > 0 {
		b.addUint16(parameterStatelessResetToken)
		b.addBytes(s.StatelessResetToken)
	}
	if s.MaxPacketSize > 0 {
		b.addUint16(parameterMaxPacketSize)
		b.addVarint(s.MaxPacketSize)
	}
	if s.InitialMaxData > 0 {
		b.addUint16(parameterInitialMaxData)
		b.addVarint(s.InitialMaxData)
	}
	if s.InitialMaxStreamDataBidiLocal > 0 {
		b.addUint16(parameterInitialMaxStreamDataBidiLocal)
		b.addVarint(s.InitialMaxStreamDataBidiLocal)
	}
	if s.InitialMaxStreamDataBidiRemote > 0 {
		b.addUint16(parameterInitialMaxStreamDataBidiRemote)
		b.addVarint(s.InitialMaxStreamDataBidiRemote)
	}
	if s.InitialMaxStreamDataUni > 0 {
		b.addUint16(parameterInitialMaxStreamDataUni)
		b.addVarint(s.InitialMaxStreamDataUni)
	}
	if s.InitialMaxStreamsBidi > 0 {
		b.addUint16(parameterInitialMaxStreamsBidi)
		b.addVarint(s.InitialMaxStreamsBidi)
	}
	if s.InitialMaxStreamsUni > 0 {
		b.addUint16(parameterInitialMaxStreamsUni)
		b.addVarint(s.InitialMaxStreamsUni)
	}
	if s.AckDelayExponent > 0 {
		b.addUint16(parameterAckDelayExponent)
		b.addVarint(s.AckDelayExponent)
	}
	if s.MaxAckDelay > 0 {
		b.addUint16(parameterMaxAckDelay)
		b.addVarint(uint64(s.MaxAckDelay / time.Millisecond))
	}
	binary.BigEndian.PutUint16(b, uint16(len(b)-2))
	return b
}

func (s *Parameters) unmarshal(data []byte) bool {
	b := tlsExtension(data)
	var param uint16
	// Check length
	if !b.readUint16(&param) {
		return false
	}
	if len(b) != int(param) {
		return false
	}
	for !b.empty() {
		if !b.readUint16(&param) {
			return false
		}
		switch param {
		case parameterOriginalCID:
			if !b.readBytes(&s.OriginalCID) {
				return false
			}
		case parameterIdleTimeout:
			var v uint64
			if !b.readVarint(&v) {
				return false
			}
			s.IdleTimeout = time.Duration(v) * time.Millisecond
		case parameterStatelessResetToken:
			if !b.readBytes(&s.StatelessResetToken) {
				return false
			}
		case parameterMaxPacketSize:
			if !b.readVarint(&s.MaxPacketSize) {
				return false
			}
		case parameterInitialMaxData:
			if !b.readVarint(&s.InitialMaxData) {
				return false
			}
		case parameterInitialMaxStreamDataBidiLocal:
			if !b.readVarint(&s.InitialMaxStreamDataBidiLocal) {
				return false
			}
		case parameterInitialMaxStreamDataBidiRemote:
			if !b.readVarint(&s.InitialMaxStreamDataBidiRemote) {
				return false
			}
		case parameterInitialMaxStreamDataUni:
			if !b.readVarint(&s.InitialMaxStreamDataUni) {
				return false
			}
		case parameterInitialMaxStreamsBidi:
			if !b.readVarint(&s.InitialMaxStreamsBidi) {
				return false
			}
		case parameterInitialMaxStreamsUni:
			if !b.readVarint(&s.InitialMaxStreamsUni) {
				return false
			}
		case parameterAckDelayExponent:
			if !b.readVarint(&s.AckDelayExponent) {
				return false
			}
		case parameterMaxAckDelay:
			var v uint64
			if !b.readVarint(&v) {
				return false
			}
			s.MaxAckDelay = time.Duration(v) * time.Millisecond
		default:
			// Unsupported parameter
			var v uint16
			if !b.readUint16(&v) || !b.skip(int(v)) {
				return false
			}
		}
	}
	return true
}

type tlsExtension []byte

func (s *tlsExtension) addUint16(v uint16) {
	*s = append(*s, uint8(v>>8), uint8(v))
}

func (s *tlsExtension) readUint16(v *uint16) bool {
	b := *s
	if len(b) < 2 {
		return false
	}
	*v = binary.BigEndian.Uint16(b)
	*s = b[2:]
	return true
}

func (s *tlsExtension) readVarint(v *uint64) bool {
	var n uint16
	if !s.readUint16(&n) {
		return false
	}
	b := *s
	if len(b) < int(n) {
		return false
	}
	if getVarint(b, v) != int(n) {
		return false
	}
	*s = b[n:]
	return true
}

func (s *tlsExtension) readBytes(v *[]byte) bool {
	var n uint16
	if !s.readUint16(&n) {
		return false
	}
	b := *s
	if len(b) < int(n) {
		return false
	}
	*v = b[:n]
	*s = b[n:]
	return true
}

func (s *tlsExtension) addBytes(v []byte) {
	s.addUint16(uint16(len(v)))
	*s = append(*s, v...)
}

func (s *tlsExtension) addVarint(v uint64) {
	n := varintLen(v)
	s.addUint16(uint16(n))
	*s = appendVarint(*s, v, n)
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
	if conn.isClient {
		s.tlsConn = tls13.Client(s, s.tlsConfig)
	} else {
		s.tlsConn = tls13.Server(s, s.tlsConfig)
	}
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
	if s.conn.isClient {
		s.tlsConn = tls13.Client(s, s.tlsConfig)
	} else {
		s.tlsConn = tls13.Server(s, s.tlsConfig)
	}
}

func (s *tlsHandshake) ReadRecord(level tls13.EncryptionLevel, b []byte) (int, error) {
	space := s.packetNumberSpace(level)
	return space.cryptoStream.Read(b)
}

func (s *tlsHandshake) WriteRecord(level tls13.EncryptionLevel, b []byte) (int, error) {
	space := s.packetNumberSpace(level)
	return space.cryptoStream.Write(b)
}

func (s *tlsHandshake) SetSecrets(level tls13.EncryptionLevel, readSecret, writeSecret []byte) error {
	debug("set secret level=%d read=%d write=%d", level, len(readSecret), len(writeSecret))
	space := s.packetNumberSpace(level)
	cipher := tls13.CipherSuiteByID(s.tlsConn.ConnectionState().CipherSuite)
	if cipher == nil {
		return fmt.Errorf("connection not yet handshaked")
	}
	if readSecret != nil {
		if err := space.opener.init(cipher, readSecret); err != nil {
			return err
		}
	}
	if writeSecret != nil {
		if err := space.sealer.init(cipher, writeSecret); err != nil {
			return err
		}
	}
	return nil
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
