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
	paramDisableActiveMigration         = 0x0c
	paramActiveConnectionIDLimit        = 0x0e
	paramInitialSourceCID               = 0x0f
	paramRetrySourceCID                 = 0x10
	// Datagram extension
	paramMaxDatagramPayloadSize = 0x20
)

const (
	// defaultUDPPayloadSize is the maximum permitted UDP payload.
	defaultMaxUDPPayloadSize = 65527
	// defaultAckDelayExponent is used when transport parameter AckDelayExponent does not present.
	defaultAckDelayExponent = 3
	// defaultMaxAckDelay is used when transport parameter MaxAckDelay does not present.
	defaultMaxAckDelay = 25 * time.Millisecond
)

// Parameters is QUIC transport parameters.
// https://www.rfc-editor.org/rfc/rfc9000#section-7.4
type Parameters struct {
	// OriginalDestinationCID is the DCID from the first Initial packet.
	// This parameter is only sent by server.
	OriginalDestinationCID []byte
	// InitialSourceCID is the SCID of the first Initial packet.
	InitialSourceCID []byte
	// RetrySourceCID is the SCID of Retry packet.
	// This parameter is only sent by server.
	RetrySourceCID []byte
	// StatelessResetToken is used in verifying a stateless reset and must be 16 bytes.
	// This parameter is only sent by server.
	StatelessResetToken []byte

	// MaxIdleTimeout is the duration that if the connection remains idle, it will be closed.
	MaxIdleTimeout time.Duration
	// MaxUDPPayloadSize is the maximum size of UDP payloads that the endpoint is willing to receive.
	MaxUDPPayloadSize uint64

	InitialMaxData                 uint64
	InitialMaxStreamDataBidiLocal  uint64
	InitialMaxStreamDataBidiRemote uint64
	InitialMaxStreamDataUni        uint64
	InitialMaxStreamsBidi          uint64
	InitialMaxStreamsUni           uint64

	// AckDelayExponent is the exponent used to decode ACK Delay field.
	// A default value of 3 will be used if this value is zero. Values above 20 are invalid.
	AckDelayExponent uint64
	// MaxAckDelay is the maximum time the endpoint will delay sending acknowledgement.
	MaxAckDelay time.Duration

	// ActiveConnectionIDLimit is the maximum number of connection IDs from the peer that
	// an endpoint is willing to store.
	ActiveConnectionIDLimit uint64
	// MaxDatagramPayloadSize is the maximum size of payload in a DATAGRAM frame the endpoint
	// is willing to receive. DATAGRAM is disabled when the value is zero.
	// See https://quicwg.org/datagram/draft-ietf-quic-datagram.html#section-3
	MaxDatagramPayloadSize uint64
	// DisableActiveMigration indicates the endpoint does not support active connection migration.
	DisableActiveMigration bool
}

// https://www.rfc-editor.org/rfc/rfc9000#section-18
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
	if s.DisableActiveMigration {
		b.writeVarint(paramDisableActiveMigration)
		b.writeVarint(0)
	}
	if s.ActiveConnectionIDLimit > 0 {
		b.writeVarint(paramActiveConnectionIDLimit)
		b.writeUint(s.ActiveConnectionIDLimit)
	}
	if len(s.InitialSourceCID) > 0 {
		b.writeVarint(paramInitialSourceCID)
		b.writeBytes(s.InitialSourceCID)
	}
	if len(s.RetrySourceCID) > 0 {
		b.writeVarint(paramRetrySourceCID)
		b.writeBytes(s.RetrySourceCID)
	}
	if s.MaxDatagramPayloadSize > 0 {
		b.writeVarint(paramMaxDatagramPayloadSize)
		b.writeUint(s.MaxDatagramPayloadSize)
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
			if !b.readUint(&param) {
				return false
			}
			s.MaxIdleTimeout = time.Duration(param) * time.Millisecond
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
			if !b.readUint(&param) {
				return false
			}
			s.MaxAckDelay = time.Duration(param) * time.Millisecond
		case paramDisableActiveMigration:
			if !b.readVarint(&param) || param != 0 {
				return false
			}
			s.DisableActiveMigration = true
		case paramActiveConnectionIDLimit:
			if !b.readUint(&s.ActiveConnectionIDLimit) {
				return false
			}
		case paramInitialSourceCID:
			if !b.readBytes(&s.InitialSourceCID) {
				return false
			}
		case paramRetrySourceCID:
			if !b.readBytes(&s.RetrySourceCID) {
				return false
			}
		case paramMaxDatagramPayloadSize:
			if !b.readUint(&s.MaxDatagramPayloadSize) {
				return false
			}
		default:
			// Unsupported parameter
			debug("skip unsupported transport parameter 0x%x", param)
			if !(b.readVarint(&param) && b.skip(int(param))) {
				return false
			}
		}
	}
	return true
}

func (s *Parameters) validate(isClient bool) error {
	// Original destination CID is only sent by server.
	if len(s.OriginalDestinationCID) != 0 && isClient {
		return newError(TransportParameterError, "original_destination_connection_id")
	}
	// Stateless reset token must not be sent by a client, but may be sent by a server.
	if len(s.StatelessResetToken) != 0 {
		if isClient || len(s.StatelessResetToken) != 16 {
			return newError(TransportParameterError, "stateless_reset_token")
		}
	}
	if s.MaxUDPPayloadSize > 0 && s.MaxUDPPayloadSize < MinInitialPacketSize {
		return newError(TransportParameterError, "max_udp_payload_size")
	}
	if s.AckDelayExponent > 20 {
		return newError(TransportParameterError, "ack_delay_exponent")
	}
	if s.MaxAckDelay < 0 || s.MaxAckDelay >= 1<<14*time.Millisecond {
		return newError(TransportParameterError, "max_ack_delay")
	}
	// If a max_streams transport parameter or MAX_STREAMS frame is received with a value greater than 2^60,
	// the connection MUST be closed immediately with a connection error of type STREAM_LIMIT_ERROR
	if s.InitialMaxStreamsBidi > maxStreams {
		return newError(StreamLimitError, "initial_max_streams_bidi")
	}
	if s.InitialMaxStreamsUni > maxStreams {
		return newError(StreamLimitError, "initial_max_streams_uni")
	}
	return nil
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

// tlsHandshake implements tls13.Transport
type tlsHandshake struct {
	tlsConfig *tls.Config
	tlsConn   *tls13.Conn
	// packetNumberSpaces links to Conn.packetNumberSpaces.
	packetNumberSpaces *[packetSpaceCount]*packetNumberSpace
	// Keep track of current TLS level for sending.
	writeLevel tls13.EncryptionLevel
}

func (s *tlsHandshake) init(config *tls.Config, packetNumberSpaces *[packetSpaceCount]*packetNumberSpace, isClient bool) {
	s.tlsConfig = config
	if isClient {
		s.tlsConn = tls13.Client(s, s.tlsConfig)
	} else {
		s.tlsConn = tls13.Server(s, s.tlsConfig)
	}
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
	switch s.writeLevel {
	case tls13.EncryptionLevelInitial:
		return packetSpaceInitial
	case tls13.EncryptionLevelHandshake:
		return packetSpaceHandshake
	case tls13.EncryptionLevelApplication:
		if !s.HandshakeComplete() {
			// Downgrade to handshake packet space as the handshake is not complete yet
			return packetSpaceHandshake
		}
		return packetSpaceApplication
	default:
		panic(sprint("unsupported tls encryption level ", s.writeLevel))
	}
}

// XXX: Store isClient in tlsHandshake?
func (s *tlsHandshake) reset(isClient bool) {
	if isClient {
		s.tlsConn = tls13.Client(s, s.tlsConfig)
	} else {
		s.tlsConn = tls13.Server(s, s.tlsConfig)
	}
}

func (s *tlsHandshake) ReadRecord(level tls13.EncryptionLevel, b []byte) (int, error) {
	space := packetSpaceFromEncryptionLevel(level)
	pnSpace := s.packetNumberSpaces[space]
	if pnSpace == nil {
		return 0, errInvalidPacket
	}
	return pnSpace.cryptoStream.Read(b)
}

func (s *tlsHandshake) WriteRecord(level tls13.EncryptionLevel, b []byte) (int, error) {
	space := packetSpaceFromEncryptionLevel(level)
	pnSpace := s.packetNumberSpaces[space]
	if pnSpace == nil {
		return 0, errInvalidPacket
	}
	return pnSpace.cryptoStream.Write(b)
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
	s.writeLevel = level
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
