package transport

import (
	"bytes"
	"crypto/tls"
	"time"
)

// connectionState is the state of a QUIC connection.
type connectionState uint8

// Supported connection states
const (
	stateAttempted connectionState = iota
	stateHandshake
	stateActive
	stateDraining
	stateClosed
)

var connectionStateNames = [...]string{
	stateAttempted: "attempted",
	stateHandshake: "handshake",
	stateActive:    "active",
	stateDraining:  "draining",
	stateClosed:    "closed",
}

func (s connectionState) String() string {
	return connectionStateNames[s]
}

// ConnectionState is the state and statistics about the connection.
type ConnectionState struct {
	State string // Internal state

	// Received packets
	RecvPackets uint64
	RecvBytes   uint64
	// Sent packets
	SentPackets uint64
	SentBytes   uint64
	// Lost packets
	LostPackets uint64
	LostBytes   uint64
	// Peer transport parameters.
	PeerParams Parameters
	// TLS handshake state.
	TLS tls.ConnectionState
	// Local and peer error when closing connection.
	LocalError error
	PeerError  error
}

// Conn is a QUIC connection.
type Conn struct {
	scid  []byte // Source CID
	dcid  []byte // Destination CID. DCID can be replaced in recvPacketInitial.
	odcid []byte // Original destination CID. Used to validate transport parameters.
	rscid []byte // Retry source CID. Set in recvPacketRetry.
	token []byte // Stateless retry token

	packetNumberSpaces [packetSpaceCount]*packetNumberSpace
	streams            streamMap
	datagram           Datagram

	localParams Parameters
	peerParams  Parameters

	handshake tlsHandshake
	recovery  lossRecovery
	flow      flowControl

	timeFn func() time.Time // Current time

	idleTimer     time.Time // Idle timeout expiration time.
	drainingTimer time.Time // Draining timeout expiration time.

	pathResponse []byte // Data from path challenge

	localError *Error // Error sending to peer
	peerError  *Error // Error received from peer

	// Events resulting from received frames
	events []Event
	// Application callbacks
	logEventFn func(LogEvent)
	// Metrics
	sentPackets uint64
	sentBytes   uint64
	recvPackets uint64
	recvBytes   uint64

	invalidPackets uint // Number of received packets that fail authentication

	// States
	version               uint32
	state                 connectionState
	isClient              bool
	gotPeerCID            bool
	didRetry              bool
	didVersionNegotiation bool
	peerAddressVerified   bool // Whether the peer's address has been verified.
	ackElicitingSent      bool // Whether an ACK-eliciting packet has been sent since last receiving a packet.
	handshakeConfirmed    bool // On server, it's handshakeDone frame sent. On client, it's the frame received
	derivedInitialSecrets bool
	updateMaxData         bool // Whether a MAX_DATA needs to be sent
}

// Connect creates a client connection.
// scid is the source connection id.
// dcid is the destination connection id.
func Connect(scid, dcid []byte, config *Config) (*Conn, error) {
	return newConn(config, scid, dcid, true)
}

// Accept creates a server connection.
// scid is the source connection id.
// odcid is the optional original destination connection id.
func Accept(scid, odcid []byte, config *Config) (*Conn, error) {
	return newConn(config, scid, odcid, false)
}

func newConn(config *Config, scid, dcid []byte, isClient bool) (*Conn, error) {
	if config == nil {
		return nil, newError(InternalError, "config required")
	}
	if len(scid) > MaxCIDLength || len(dcid) > MaxCIDLength {
		return nil, newError(ProtocolViolation, sprint("cid length exceeded ", MaxCIDLength))
	}
	s := &Conn{
		version:     config.Version,
		isClient:    isClient,
		localParams: config.Params,
		state:       stateAttempted,
	}
	for i := range s.packetNumberSpaces {
		s.packetNumberSpaces[i] = newPacketNumberSpace()
	}
	if config.MaxPacketsPerKey > 0 {
		s.packetNumberSpaces[packetSpaceApplication].maxEncryptedPackets = config.MaxPacketsPerKey
	}
	// Use tls.Config.Time if provided
	if config.TLS != nil && config.TLS.Time != nil {
		s.timeFn = config.TLS.Time
	} else {
		s.timeFn = time.Now
	}
	s.handshake.init(config.TLS, &s.packetNumberSpaces, isClient)
	s.streams.init(s.localParams.InitialMaxStreamsBidi, s.localParams.InitialMaxStreamsUni)
	s.recovery.init()
	s.recovery.enablePacing = enablePacing
	s.recovery.congestion.enableCubic = enableCubic
	s.recovery.congestion.enablePRR = enablePRR
	s.flow.init(s.localParams.InitialMaxData, 0)
	s.scid = scid
	s.localParams.InitialSourceCID = s.scid // SCID is fixed so can use its reference
	// Do not take CIDs from config
	s.localParams.OriginalDestinationCID = nil
	s.localParams.RetrySourceCID = nil
	if isClient {
		// Stateless reset token must not be sent by client
		s.localParams.StatelessResetToken = nil
		// Destination connection id for client is required for initial key.
		if len(dcid) == 0 {
			return nil, newError(InternalError, "destination cid required")
		}
		s.dcid = dcid
		s.deriveInitialKeyMaterial(s.dcid)
	} else {
		if len(dcid) > 0 {
			s.odcid = dcid
			s.localParams.OriginalDestinationCID = s.odcid
			s.localParams.RetrySourceCID = s.scid
			s.didRetry = true // So odcid will not be set again
			s.peerAddressVerified = true
		}
		// Assume clients validate the server's address implicitly.
		s.recovery.setPeerCompletedAddressValidation()
	}
	if err := s.localParams.validate(isClient); err != nil {
		return nil, err
	}
	s.handshake.setTransportParams(&s.localParams)
	s.datagram.setMaxRecv(s.localParams.MaxDatagramFramePayloadSize)
	return s, nil
}

// Write consumes received data.
// NOTE: b will be modified as data is decrypted directly to b.
func (s *Conn) Write(b []byte) (int, error) {
	now := s.timeFn()
	n := 0
	for n < len(b) {
		if s.state >= stateDraining {
			// Closing
			break
		}
		i, err := s.recv(b[n:], now)
		n += i
		// Keep track bytes received from peer to limit bytes sending back
		// until its address is verified.
		s.recvPackets++
		s.recvBytes += uint64(i)
		if err != nil {
			return n, err
		}
	}
	if n == 0 || !s.handshakeConfirmed {
		// Check probe timeout when the connection does not receive anything or
		// during handshake where there are multiple packet number spaces.
		// FIXME: What if peer does not send ACK?
		s.checkTimeout(now)
	}
	return n, nil
}

func (s *Conn) deriveInitialKeyMaterial(cid []byte) {
	client, server := newInitialSecrets(cid)
	pnSpace := s.packetNumberSpaces[packetSpaceInitial]
	if s.isClient {
		pnSpace.opener, pnSpace.sealer = server, client
	} else {
		pnSpace.opener, pnSpace.sealer = client, server
	}
	s.derivedInitialSecrets = true
}

// recv processes single received packet.
func (s *Conn) recv(b []byte, now time.Time) (int, error) {
	p := packet{
		header: packetHeader{
			dcil: uint8(len(s.scid)),
		},
	}
	_, err := p.decodeHeader(b)
	if err != nil {
		s.logPacketDropped(&p, logTriggerHeaderParseError, now)
		return 0, newPacketDroppedError(logTriggerHeaderParseError)
	}
	switch p.typ {
	case packetTypeInitial:
		return s.recvPacketInitial(b, &p, now)
	case packetTypeZeroRTT:
		return 0, newError(InternalError, "zerortt packet not supported")
	case packetTypeHandshake:
		return s.recvPacketHandshake(b, &p, now)
	case packetTypeRetry:
		return s.recvPacketRetry(b, &p, now)
	case packetTypeVersionNegotiation:
		return s.recvPacketVersionNegotiation(b, &p, now)
	case packetTypeOneRTT:
		return s.recvPacketShort(b, &p, now)
	default:
		panic(sprint("unsupported packet type ", p.typ))
	}
}

// https://www.rfc-editor.org/rfc/rfc9000.html#section-6
func (s *Conn) recvPacketVersionNegotiation(b []byte, p *packet, now time.Time) (int, error) {
	// VN packet can only be sent by server
	if !s.isClient || s.didVersionNegotiation || s.state != stateAttempted ||
		s.packetNumberSpaces[packetSpaceInitial] == nil {
		s.logPacketDropped(p, logTriggerUnexpectedPacket, now)
		return 0, newPacketDroppedError(logTriggerUnexpectedPacket)
	}
	if !bytes.Equal(p.header.dcid, s.scid) || !bytes.Equal(p.header.scid, s.dcid) {
		s.logPacketDropped(p, logTriggerUnknownConnectionID, now)
		return 0, newPacketDroppedError(logTriggerUnknownConnectionID)
	}
	n, err := p.decodeBody(b)
	if err != nil {
		s.logPacketDropped(p, logTriggerHeaderParseError, now)
		return 0, newPacketDroppedError(logTriggerHeaderParseError)
	}
	var newVersion uint32
	for _, v := range p.supportedVersions {
		if IsVersionSupported(v) {
			newVersion = v
			break
		}
	}
	if newVersion == 0 {
		return 0, newError(InternalError, sprint("unsupported version ", p.supportedVersions))
	}
	s.version = newVersion
	s.didVersionNegotiation = true
	// Reset connection state to send another initial packet
	s.gotPeerCID = false
	s.recovery.onPacketNumberSpaceDiscarded(packetSpaceInitial, now)
	s.packetNumberSpaces[packetSpaceInitial].reset()
	s.handshake.reset(s.isClient)
	s.handshake.setTransportParams(&s.localParams)
	s.logPacketReceived(p, now)
	return p.headerLen + n, nil
}

// https://www.rfc-editor.org/rfc/rfc9000.html#section-8.1
func (s *Conn) recvPacketRetry(b []byte, p *packet, now time.Time) (int, error) {
	// Retry packet can only be sent by server
	// Packet's SCID must not be equal to the client's DCID.
	if !s.isClient || s.didRetry || s.state != stateAttempted ||
		s.packetNumberSpaces[packetSpaceInitial] == nil {
		s.logPacketDropped(p, logTriggerUnexpectedPacket, now)
		return 0, newPacketDroppedError(logTriggerUnexpectedPacket)
	}
	// scid must be different
	if !bytes.Equal(p.header.dcid, s.scid) || bytes.Equal(p.header.scid, s.dcid) {
		s.logPacketDropped(p, logTriggerUnknownConnectionID, now)
		return 0, newPacketDroppedError(logTriggerUnknownConnectionID)
	}
	_, err := p.decodeBody(b)
	if err != nil {
		s.logPacketDropped(p, logTriggerHeaderParseError, now)
		return 0, newPacketDroppedError(logTriggerHeaderParseError)
	}
	// Verify token and integrity tag
	if len(p.token) == 0 || !verifyRetryIntegrity(b, s.dcid) {
		return 0, newError(InvalidToken, "")
	}
	s.didRetry = true
	s.token = copyBytes(p.token)
	// Update CIDs and crypto: dcid => odcid, header.scid => dcid
	s.odcid = copyBytes(s.dcid)
	s.dcid = copyBytes(p.header.scid)
	s.rscid = copyBytes(p.header.scid)
	s.deriveInitialKeyMaterial(s.dcid)
	// Reset connection state to send another initial packet
	s.gotPeerCID = false
	s.recovery.onPacketNumberSpaceDiscarded(packetSpaceInitial, now)
	s.packetNumberSpaces[packetSpaceInitial].reset()
	s.handshake.reset(s.isClient)
	s.handshake.setTransportParams(&s.localParams)
	s.logPacketReceived(p, now)
	return len(b), nil // p.headerLen + bodyLen + retryIntegrityTagLen
}

func (s *Conn) recvPacketInitial(b []byte, p *packet, now time.Time) (int, error) {
	// packet dcid can be different to connection scid
	if s.gotPeerCID && !bytes.Equal(p.header.scid, s.dcid) {
		s.logPacketDropped(p, logTriggerUnknownConnectionID, now)
		return 0, newPacketDroppedError(logTriggerUnknownConnectionID)
	}
	if s.packetNumberSpaces[packetSpaceInitial] == nil {
		s.logPacketDropped(p, logTriggerUnexpectedPacket, now)
		return 0, newPacketDroppedError(logTriggerUnexpectedPacket)
	}
	if !s.isClient && !s.didVersionNegotiation {
		if !IsVersionSupported(p.header.version) {
			return 0, newPacketDroppedError(logTriggerUnsupportedVersion)
		}
		s.version = p.header.version
		s.didVersionNegotiation = true
	}
	if !s.derivedInitialSecrets { // Server side
		s.deriveInitialKeyMaterial(p.header.dcid)
	}
	if !s.gotPeerCID {
		if s.isClient {
			if len(s.odcid) == 0 {
				s.odcid = copyBytes(s.dcid)
			}
		} else {
			if !s.didRetry {
				s.odcid = copyBytes(p.header.dcid)
				s.localParams.OriginalDestinationCID = s.odcid
				s.handshake.setTransportParams(&s.localParams)
			}
		}
		// Replace the randomly generated destination connection ID with
		// the one supplied by the server.
		s.dcid = copyBytes(p.header.scid)
		s.gotPeerCID = true
	}
	return s.recvPacket(b, p, packetSpaceInitial, now)
}

func (s *Conn) recvPacketHandshake(b []byte, p *packet, now time.Time) (int, error) {
	// packet dcid can be different to connection scid
	if s.gotPeerCID && !bytes.Equal(p.header.scid, s.dcid) {
		s.logPacketDropped(p, logTriggerUnknownConnectionID, now)
		return 0, newPacketDroppedError(logTriggerUnknownConnectionID)
	}
	if s.packetNumberSpaces[packetSpaceHandshake] == nil {
		s.logPacketDropped(p, logTriggerUnexpectedPacket, now)
		return 0, newPacketDroppedError(logTriggerUnexpectedPacket)
	}
	if !s.isClient && !s.didVersionNegotiation {
		if !IsVersionSupported(p.header.version) {
			return 0, newPacketDroppedError(logTriggerUnsupportedVersion)
		}
		s.version = p.header.version
		s.didVersionNegotiation = true
	}
	return s.recvPacket(b, p, packetSpaceHandshake, now)
}

func (s *Conn) recvPacketShort(b []byte, p *packet, now time.Time) (int, error) {
	if !bytes.Equal(p.header.dcid, s.scid) {
		s.logPacketDropped(p, logTriggerUnknownConnectionID, now)
		return 0, newPacketDroppedError(logTriggerUnknownConnectionID)
	}
	return s.recvPacket(b, p, packetSpaceApplication, now)
}

func (s *Conn) recvPacket(b []byte, p *packet, space packetSpace, now time.Time) (int, error) {
	pnSpace := s.packetNumberSpaces[space]
	if !pnSpace.canDecrypt() {
		s.logPacketDropped(p, logTriggerKeyUnavailable, now)
		return 0, newPacketDroppedError(logTriggerKeyUnavailable)
	}
	payload, err := pnSpace.decryptPacket(b, p)
	if err != nil {
		s.logPacketDropped(p, logTriggerPayloadDecryptError, now)
		s.invalidPackets++
		if s.invalidPackets > maxInvalidPackets {
			return 0, newError(AEADLimitReached, logTriggerPayloadDecryptError)
		}
		return 0, newPacketDroppedError(logTriggerPayloadDecryptError)
	}
	if pnSpace.isPacketReceived(p.packetNumber) {
		// Ignore duplicate packet but still continue because packet can be coalesced.
		s.logPacketDropped(p, logTriggerDuplicate, now)
		return p.packetSize, nil // No error for duplicate
	}
	s.logPacketReceived(p, now)
	if err = s.recvFrames(payload, p.typ, space, now); err != nil {
		return 0, err
	}
	// Process acked frames
	s.processAckedPackets(space)

	// https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.2.1
	// A server stops sending and processing Initial packets when it receives its first Handshake packet.
	if space == packetSpaceHandshake {
		if !s.isClient && pnSpace.largestRecvPacketTime.IsZero() {
			s.dropPacketSpace(packetSpaceInitial, now)
		}
		if s.state < stateHandshake {
			s.setState(stateHandshake, now)
		}
		if !s.peerAddressVerified {
			s.peerAddressVerified = true
		}
	}
	// Mark this packet received
	pnSpace.onPacketReceived(p.packetNumber, now)

	s.setIdleTimer(now)
	s.ackElicitingSent = false
	return p.packetSize, nil
}

// https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4
// recvFrames sets ackElicited if a received frame is an ack eliciting.
func (s *Conn) recvFrames(b []byte, pktType packetType, space packetSpace, now time.Time) error {
	// To avoid sending an ACK in response to an ACK-only packet, we need
	// to keep track of whether this packet contains any frame other than
	// ACK, PADDING and CONNECTION_CLOSE.
	var ackElicited = false
	for len(b) > 0 {
		var typ uint64
		n := getVarint(b, &typ)
		if n == 0 {
			return newError(FrameEncodingError, "")
		}
		if !isFrameAllowedInPacket(typ, pktType) {
			return newError(ProtocolViolation, sprint("unexpected frame ", typ))
		}
		var err error
		if typ >= frameTypeStream && typ <= frameTypeStreamEnd {
			n, err = s.recvFrameStream(b, now)
		} else {
			switch typ {
			case frameTypePadding:
				n, err = s.recvFramePadding(b, now)
			case frameTypePing:
				n, err = s.recvFramePing(b, now)
			case frameTypeAck, frameTypeAckECN:
				n, err = s.recvFrameAck(b, space, now)
			case frameTypeResetStream:
				n, err = s.recvFrameResetStream(b, now)
			case frameTypeStopSending:
				n, err = s.recvFrameStopSending(b, now)
			case frameTypeCrypto:
				n, err = s.recvFrameCrypto(b, space, now)
			case frameTypeNewToken:
				n, err = s.recvFrameNewToken(b, now)
			case frameTypeMaxData:
				n, err = s.recvFrameMaxData(b, now)
			case frameTypeMaxStreamData:
				n, err = s.recvFrameMaxStreamData(b, now)
			case frameTypeMaxStreamsBidi, frameTypeMaxStreamsUni:
				n, err = s.recvFrameMaxStreams(b, now)
			case frameTypeDataBlocked:
				n, err = s.recvFrameDataBlocked(b, now)
			case frameTypeStreamDataBlocked:
				n, err = s.recvFrameStreamDataBlocked(b, now)
			case frameTypeStreamsBlockedBidi, frameTypeStreamsBlockedUni:
				n, err = s.recvFrameStreamsBlocked(b, now)
			case frameTypeNewConnectionID:
				n, err = s.recvFrameNewConnectionID(b, now)
			case frameTypeRetireConnectionID:
				n, err = s.recvFrameRetireConnectionID(b, now)
			case frameTypePathChallenge:
				n, err = s.recvFramePathChallenge(b, now)
			case frameTypePathResponse:
				n, err = s.recvFramePathResponse(b, now)
			case frameTypeConnectionClose, frameTypeApplicationClose:
				n, err = s.recvFrameConnectionClose(b, space, now)
			case frameTypeHanshakeDone:
				n, err = s.recvFrameHandshakeDone(b, now)
			case frameTypeDatagram, frameTypeDatagramWithLength:
				n, err = s.recvFrameDatagram(b, now)
			default:
				return newError(FrameEncodingError, sprint("unsupported frame ", typ))
			}
		}
		if err != nil {
			debug("%v error processing frame 0x%x: %v", s.pov(), typ, err)
			return err
		}
		if n <= 0 {
			panic(sprint("no progress processing frame ", typ))
		}
		if !ackElicited {
			ackElicited = isFrameAckEliciting(typ)
		}
		b = b[n:]
	}
	if ackElicited {
		s.packetNumberSpaces[space].ackElicited = true
	}
	return nil
}

func (s *Conn) recvFramePadding(b []byte, now time.Time) (int, error) {
	var f paddingFrame
	n, err := f.decode(b)
	if err == nil {
		s.logFrameProcessed(&f, now)
	}
	return n, err
}

func (s *Conn) recvFramePing(b []byte, now time.Time) (int, error) {
	// Will ack
	var f pingFrame
	n, err := f.decode(b)
	if err == nil {
		debug("%v received frame 0x%x: %v", s.pov(), b[0], &f)
		s.logFrameProcessed(&f, now)
	}
	return n, err
}

func (s *Conn) recvFrameAck(b []byte, space packetSpace, now time.Time) (int, error) {
	var f ackFrame
	n, err := f.decode(b)
	if err != nil {
		return 0, err
	}
	debug("%v received frame 0x%x: %v", s.pov(), b[0], &f)
	s.logFrameProcessed(&f, now)
	ranges := f.toRangeSet(s.packetNumberSpaces[space].recvAckRanges[:0])
	if ranges == nil {
		return 0, newError(FrameEncodingError, sprint("ack: invalid ranges ", f.String()))
	}
	// Cache received ack ranges slice.
	s.packetNumberSpaces[space].recvAckRanges = ranges
	// Servers complete address validation when a protected packet is received.
	if !s.recovery.peerCompletedAddressValidation && space == packetSpaceHandshake {
		s.recovery.setPeerCompletedAddressValidation()
	}
	ackDelayExponent := s.peerParams.AckDelayExponent
	if ackDelayExponent == 0 {
		ackDelayExponent = defaultAckDelayExponent
	}
	ackDelay := time.Duration((1<<ackDelayExponent)*f.ackDelay) * time.Microsecond
	s.recovery.onAckReceived(ranges, ackDelay, space, now)
	return n, nil
}

// An endpoint uses a RESET_STREAM frame to abruptly terminate
// the sending part of a stream.
func (s *Conn) recvFrameResetStream(b []byte, now time.Time) (int, error) {
	var f resetStreamFrame
	n, err := f.decode(b)
	if err != nil {
		return 0, err
	}
	debug("%v received frame 0x%x: %v", s.pov(), b[0], &f)
	s.logFrameProcessed(&f, now)
	// Not for send-only stream
	local := isStreamLocal(f.streamID, s.isClient)
	bidi := isStreamBidi(f.streamID)
	if local && !bidi {
		debug("%v received reset for send-only stream: id=%d local=%v bidi=%v", s.pov(), f.streamID, local, bidi)
		return 0, newError(StreamStateError, sprint("reset_stream: stream send-only ", f.streamID))
	}
	st, err := s.getOrCreateStream(f.streamID, false)
	if err != nil {
		return 0, err
	}
	if !st.isClosed() {
		mayRecv := uint64(0)
		if f.finalSize > st.recv.length {
			mayRecv = f.finalSize - st.recv.length
		}
		if mayRecv > s.flow.availRecv() {
			return 0, newError(FlowControlError, sprint("reset_stream: connection data exceeded limit ", s.flow.recvMax))
		}
		err = st.resetRecv(f.finalSize, f.errorCode)
		if err != nil {
			return 0, err
		}
		s.flow.addRecv(mayRecv)
	}
	return n, nil
}

// An endpoint uses a STOP_SENDING frame to communicate that incoming data
// is being discarded on receipt at application request.
func (s *Conn) recvFrameStopSending(b []byte, now time.Time) (int, error) {
	var f stopSendingFrame
	n, err := f.decode(b)
	if err != nil {
		return 0, err
	}
	debug("%v received frame 0x%x: %v", s.pov(), b[0], &f)
	s.logFrameProcessed(&f, now)
	// Not for a locally-initiated stream that has not yet been created.
	local := isStreamLocal(f.streamID, s.isClient)
	if local && s.streams.get(f.streamID) == nil {
		return 0, newError(StreamStateError, sprint("stop_sending: stream not existed ", f.streamID))
	}
	// Not for a receive-only stream.
	bidi := isStreamBidi(f.streamID)
	if !local && !bidi {
		debug("%v received stop for receive-only stream: id=%d local=%v bidi=%v", s.pov(), f.streamID, local, bidi)
		return 0, newError(StreamStateError, sprint("stop_sending: stream receive-only ", f.streamID))
	}
	st, err := s.getOrCreateStream(f.streamID, false)
	if err != nil {
		return 0, err
	}
	if !st.isClosed() {
		st.stopSend(f.errorCode)
	}
	return n, nil
}

func (s *Conn) recvFrameCrypto(b []byte, space packetSpace, now time.Time) (int, error) {
	var f cryptoFrame
	n, err := f.decode(b)
	if err != nil {
		return 0, err
	}
	debug("%v received frame 0x%x: %v", s.pov(), b[0], &f)
	s.logFrameProcessed(&f, now)
	// Push the data to the stream so it can be re-ordered.
	err = s.packetNumberSpaces[space].cryptoStream.pushRecv(f.data, f.offset, false)
	if err != nil {
		return 0, err
	}
	err = s.doHandshake(now)
	if err != nil {
		return 0, err
	}
	return n, nil
}

func (s *Conn) recvFrameNewToken(b []byte, now time.Time) (int, error) {
	// TODO
	var f newTokenFrame
	n, err := f.decode(b)
	if err != nil {
		return 0, err
	}
	debug("%v received frame 0x%x: %v", s.pov(), b[0], &f)
	s.logFrameProcessed(&f, now)
	return n, nil
}

func (s *Conn) recvFrameStream(b []byte, now time.Time) (int, error) {
	var f streamFrame
	n, err := f.decode(b)
	if err != nil {
		return 0, err
	}
	debug("%v received frame 0x%x: %v", s.pov(), b[0], &f)
	s.logFrameProcessed(&f, now)
	// Peer can't send on our unidirectional streams.
	local := isStreamLocal(f.streamID, s.isClient)
	bidi := isStreamBidi(f.streamID)
	if local && !bidi {
		debug("%v received data sending to its stream: id=%d local=%v bidi=%v", s.pov(), f.streamID, local, bidi)
		return 0, newError(StreamStateError, sprint("stream: stream send-only ", f.streamID))
	}
	if uint64(len(f.data)) > s.flow.availRecv() {
		return 0, newError(FlowControlError, sprint("stream: connection data exceeded limit ", s.flow.recvMax))
	}
	st, err := s.getOrCreateStream(f.streamID, false)
	if err != nil {
		return 0, err
	}
	// Stream can be closed before data is resent by peer, ignore it.
	if !st.isClosed() {
		err = st.pushRecv(f.data, f.offset, f.fin)
		if err != nil {
			return 0, err
		}
		debug("%v stream recv: id=%v %v", s.pov(), f.streamID, &st.recv)
	}
	// A receiver maintains a cumulative sum of bytes received on all streams,
	// which is used to check for flow control violations
	s.flow.addRecv(uint64(len(f.data)))
	return n, nil
}

func (s *Conn) recvFrameMaxData(b []byte, now time.Time) (int, error) {
	var f maxDataFrame
	n, err := f.decode(b)
	if err != nil {
		return 0, err
	}
	debug("%v received frame 0x%x: %v", s.pov(), b[0], &f)
	s.logFrameProcessed(&f, now)
	s.flow.setSendMax(f.maximumData)
	return n, nil
}

func (s *Conn) recvFrameMaxStreamData(b []byte, now time.Time) (int, error) {
	var f maxStreamDataFrame
	n, err := f.decode(b)
	if err != nil {
		return 0, err
	}
	debug("%v received frame 0x%x: %v", s.pov(), b[0], &f)
	s.logFrameProcessed(&f, now)
	st, err := s.getOrCreateStream(f.streamID, false)
	if err != nil {
		return 0, err
	}
	if !st.isClosed() {
		st.flow.setSendMax(f.maximumData)
	}
	return n, nil
}

func (s *Conn) recvFrameMaxStreams(b []byte, now time.Time) (int, error) {
	var f maxStreamsFrame
	n, err := f.decode(b)
	if err != nil {
		return 0, err
	}
	debug("%v received frame 0x%x: %v", s.pov(), b[0], &f)
	s.logFrameProcessed(&f, now)
	if f.maximumStreams > maxStreams {
		return 0, newError(StreamLimitError, sprint("max_streams: streams exceeded limit ", f.maximumStreams))
	}
	if f.bidi {
		s.streams.setPeerMaxStreamsBidi(f.maximumStreams)
	} else {
		s.streams.setPeerMaxStreamsUni(f.maximumStreams)
	}
	return n, nil
}

func (s *Conn) recvFrameDataBlocked(b []byte, now time.Time) (int, error) {
	var f dataBlockedFrame
	n, err := f.decode(b)
	if err != nil {
		return 0, err
	}
	debug("%v received frame 0x%x: %v", s.pov(), b[0], &f)
	s.logFrameProcessed(&f, now)
	// Respond MAX_DATA frame
	if s.flow.recvMaxNext > f.dataLimit {
		s.updateMaxData = true
	}
	return n, nil
}

func (s *Conn) recvFrameStreamDataBlocked(b []byte, now time.Time) (int, error) {
	var f streamDataBlockedFrame
	n, err := f.decode(b)
	if err != nil {
		return 0, err
	}
	debug("%v received frame 0x%x: %v", s.pov(), b[0], &f)
	s.logFrameProcessed(&f, now)
	// Respond MAX_STREAM_DATA frame
	st, err := s.getOrCreateStream(f.streamID, false)
	if err != nil {
		return 0, err
	}
	if !st.isClosed() && st.flow.recvMaxNext > f.dataLimit {
		st.setUpdateMaxData(true)
	}
	return n, nil
}

func (s *Conn) recvFrameStreamsBlocked(b []byte, now time.Time) (int, error) {
	var f streamsBlockedFrame
	n, err := f.decode(b)
	if err != nil {
		return 0, err
	}
	debug("%v received frame 0x%x: %v", s.pov(), b[0], &f)
	s.logFrameProcessed(&f, now)
	// Respond MAX_STREAMS frame
	if f.bidi {
		if s.streams.maxStreamsNext.localBidi > f.streamLimit {
			s.streams.setUpdateMaxStreamsBidi(true)
		}
	} else {
		if s.streams.maxStreamsNext.localUni > f.streamLimit {
			s.streams.setUpdateMaxStreamsUni(true)
		}
	}
	return n, nil
}

// TODO
func (s *Conn) recvFrameNewConnectionID(b []byte, now time.Time) (int, error) {
	var f newConnectionIDFrame
	n, err := f.decode(b)
	if err != nil {
		return 0, err
	}
	debug("%v received frame 0x%x: %v", s.pov(), b[0], &f)
	s.logFrameProcessed(&f, now)
	return n, nil
}

// TODO
func (s *Conn) recvFrameRetireConnectionID(b []byte, now time.Time) (int, error) {
	var f retireConnectionIDFrame
	n, err := f.decode(b)
	if err != nil {
		return 0, err
	}
	debug("%v received frame 0x%x: %v", s.pov(), b[0], &f)
	s.logFrameProcessed(&f, now)
	return n, nil
}

func (s *Conn) recvFramePathChallenge(b []byte, now time.Time) (int, error) {
	var f pathChallengeFrame
	n, err := f.decode(b)
	if err != nil {
		return 0, err
	}
	debug("%v received frame 0x%x: %v", s.pov(), b[0], &f)
	s.logFrameProcessed(&f, now)
	s.pathResponse = copyBytes(f.data)
	return n, nil
}

// TODO
func (s *Conn) recvFramePathResponse(b []byte, now time.Time) (int, error) {
	var f pathResponseFrame
	n, err := f.decode(b)
	if err != nil {
		return 0, err
	}
	debug("%v received frame 0x%x: %v", s.pov(), b[0], &f)
	s.logFrameProcessed(&f, now)
	return n, nil
}

func (s *Conn) recvFrameConnectionClose(b []byte, space packetSpace, now time.Time) (int, error) {
	var f connectionCloseFrame
	n, err := f.decode(b)
	if err != nil {
		return 0, err
	}
	debug("%v received frame 0x%x: %s (%s)", s.pov(), b[0], &f, errorCodeString(f.errorCode))
	s.logFrameProcessed(&f, now)
	// After receiving a CONNECTION_CLOSE frame, endpoints enter the draining state.
	if s.peerError == nil {
		if f.application {
			s.peerError = newAppError(f.errorCode, string(f.reasonPhrase))
		} else {
			s.peerError = newError(f.errorCode, string(f.reasonPhrase))
		}
	}
	if s.state < stateDraining {
		// Persist for at least three times the current Probe Timeout
		s.drainingTimer = now.Add(s.recovery.probeTimeout() * 3)
		debug("%v set draining_timer=%v", s.pov(), s.drainingTimer)
		s.setState(stateDraining, now)
	}
	return n, nil
}

func (s *Conn) recvFrameHandshakeDone(b []byte, now time.Time) (int, error) {
	var f handshakeDoneFrame
	n, err := f.decode(b)
	if err != nil {
		return 0, err
	}
	debug("%v received frame 0x%x: %v", s.pov(), b[0], &f)
	s.logFrameProcessed(&f, now)
	if !s.isClient {
		return 0, newError(ProtocolViolation, "handshake_done: unexpected for server")
	}
	if s.state == stateActive && !s.handshakeConfirmed {
		// Drop client's handshake state when it received done from server
		s.dropPacketSpace(packetSpaceHandshake, now)
		s.setHandshakeConfirmed()
		// Server address is now validated.
		s.recovery.setPeerCompletedAddressValidation()
	}
	return n, nil
}

func (s *Conn) recvFrameDatagram(b []byte, now time.Time) (int, error) {
	var f datagramFrame
	n, err := f.decode(b)
	if err != nil {
		return 0, err
	}
	debug("%v received frame 0x%x: %v", s.pov(), b[0], &f)
	s.logFrameProcessed(&f, now)
	err = s.datagram.pushRecv(f.data)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// processAckedPackets is called when the connection got an ACK frame.
func (s *Conn) processAckedPackets(space packetSpace) {
	s.recovery.drainAcked(space, func(f frame) {
		switch f := f.(type) {
		case *ackFrame:
			// Stop sending ack for packets when receiving is confirmed
			s.packetNumberSpaces[space].recvPacketNeedAck.removeUntil(f.largestAck)
		case *cryptoFrame:
			s.packetNumberSpaces[space].cryptoStream.ackSend(f.offset, uint64(len(f.data)))
			freeDataBuffer(f.data)
		case *streamFrame:
			st := s.streams.getOpen(f.streamID)
			if st != nil {
				complete := st.ackSend(f.offset, uint64(len(f.data)))
				if complete {
					s.addEvent(newEventStreamComplete(f.streamID))
				}
			}
			freeDataBuffer(f.data)
		case *resetStreamFrame:
			st := s.streams.getOpen(f.streamID)
			if st != nil {
				st.setResetStream(deliveryConfirmed)
			}
		case *stopSendingFrame:
			st := s.streams.getOpen(f.streamID)
			if st != nil {
				st.setStopSending(deliveryConfirmed)
			}
		case *datagramFrame:
			freeDataBuffer(f.data)
		}
	})
}

func (s *Conn) doHandshake(now time.Time) error {
	err := s.handshake.doHandshake()
	if err != nil {
		return err
	}
	// Keep track of the handshake keys availability for recovery
	if !s.recovery.hasHandshakeKeys {
		pnSpace := s.packetNumberSpaces[packetSpaceHandshake]
		if pnSpace != nil && pnSpace.canEncrypt() && pnSpace.canDecrypt() {
			s.recovery.setHasHandshakeKeys()
		}
	}
	if s.state < stateActive && s.handshake.connectionState().HandshakeComplete {
		params := s.handshake.peerTransportParams()
		debug("%v peer transport params: %+v", s.pov(), params)
		if err := s.validatePeerTransportParams(params); err != nil {
			return err
		}
		// Update connection state
		s.setPeerParams(params, now)
		s.setState(stateActive, now)
		// TODO: early app frames
	}
	return nil
}

func (s *Conn) setPeerParams(params *Parameters, now time.Time) {
	s.peerParams = *params
	// Update flow and stream states
	s.flow.setSendMax(s.peerParams.InitialMaxData)
	s.streams.setPeerMaxStreamsBidi(s.peerParams.InitialMaxStreamsBidi)
	s.streams.setPeerMaxStreamsUni(s.peerParams.InitialMaxStreamsUni)
	// Update loss recovery state
	s.recovery.setMaxAckDelay(s.peerParams.MaxAckDelay)
	if s.peerParams.MaxUDPPayloadSize > 0 {
		s.recovery.setMaxDatagramSize(uint(s.peerParams.MaxUDPPayloadSize))
	}
	// Datagram
	if s.peerParams.MaxDatagramFramePayloadSize > 0 {
		s.datagram.setMaxSend(s.peerParams.MaxDatagramFramePayloadSize)
		s.addEvent(newEventDatagramOpen(s.peerParams.MaxDatagramFramePayloadSize))
	}
	s.logParametersSet(params, now)
}

// https://www.rfc-editor.org/rfc/rfc9000.html#section-7.3
//
// Client                                                  Server
// Initial: DCID=S1, SCID=C1 ->
//                                     <- Retry: DCID=C1, SCID=S2
// Initial: DCID=S2, SCID=C1 ->
//                                   <- Initial: DCID=C1, SCID=S3
//                              ...
// 1-RTT: DCID=S3 ->
//                                              <- 1-RTT: DCID=C1
// Client:
//   initial_source_connection_id = C1
// Server without Retry:
//   original_destination_connection_id = S1
//   initial_source_connection_id = S3
//   retry_source_connection_id = nil
// Server with Retry:
//   original_destination_connection_id = S1
//   retry_source_connection_id = S2
//   initial_source_connection_id = S3
func (s *Conn) validatePeerTransportParams(p *Parameters) error {
	if p == nil {
		return newError(TransportParameterError, "")
	}
	if err := p.validate(!s.isClient); err != nil {
		return err
	}
	// Initial Source CID must be sent by both endpoints
	if !bytes.Equal(p.InitialSourceCID, s.dcid) {
		return newError(TransportParameterError, "initial_source_connection_id")
	}
	if s.isClient && !bytes.Equal(p.OriginalDestinationCID, s.odcid) {
		return newError(TransportParameterError, "original_destination_connection_id")
	}
	if len(s.rscid) > 0 && !bytes.Equal(p.RetrySourceCID, s.rscid) {
		return newError(TransportParameterError, "retry_source_connection_id")
	}
	return nil
}

// Read produces data for sending to the client.
func (s *Conn) Read(b []byte) (int, error) {
	if s.state >= stateDraining {
		// An endpoint in the draining state MUST NOT send any packets
		return 0, nil
	}
	now := s.timeFn()
	if s.localError == nil {
		// Only check handshake when not in closing state, so it can send connection close
		// frame when handshake failed.
		if s.state < stateActive {
			if err := s.doHandshake(now); err != nil {
				return 0, err
			}
		}
		// Checking streams state before finding write space to check stream updates.
		s.checkStreamsState(now)
	}
	space := s.writeSpace()
	if space == packetSpaceCount {
		return 0, nil
	}
	n, err := s.send(b, space, now)
	if err != nil {
		return 0, err
	}
	// Coalesce packets when possible.
	// https://www.rfc-editor.org/rfc/rfc9000.html#section-12.2
	if space < packetSpaceApplication && s.state < stateDraining {
		avail := minInt(s.maxPacketSize(), len(b))
		if avail-n >= 96 { // Enough for a handshake packet
			nextSpace := s.writeSpace()
			if nextSpace < packetSpaceCount && nextSpace > space {
				debug("%v coalesce packet: space=%v space=%v", s.pov(), space, nextSpace)
				m, err := s.send(b[n:avail], nextSpace, now)
				if err != nil {
					return 0, err
				}
				if m > 0 {
					n += m
					s.sentPackets++
				}
			}
		}
	}
	if n > 0 {
		// Keep track bytes sent to peer.
		s.sentPackets++
		s.sentBytes += uint64(n)
		s.logRecovery(now)
	}
	return n, nil
}

func (s *Conn) send(b []byte, space packetSpace, now time.Time) (int, error) {
	pnSpace := s.packetNumberSpaces[space]
	if !pnSpace.canEncrypt() {
		return 0, newError(InternalError, "cannot encrypt space "+space.String())
	}
	// Check lost packets first to resend.
	s.processLostPackets(space, now)
	avail := minInt(s.maxPacketSize(), len(b))
	p := packet{
		header: packetHeader{
			version: s.version,
			dcid:    s.dcid,
			scid:    s.scid,
		},
		token:      s.token,
		payloadLen: avail, // For calculating packet size
	}
	p.setType(packetTypeFromSpace(space))
	p.setPacketNumber(pnSpace.nextPacketNumber)
	if space == packetSpaceApplication {
		p.setKeyPhase(pnSpace.keyPhase)
	}
	// Calculate what is left for payload
	overhead := pnSpace.sealer.aead.Overhead()
	pktOverhead := p.encodedLen() + overhead - p.payloadLen // Packet length without payload
	left := avail - pktOverhead
	if left <= minPacketPayloadLength {
		// May due to congestion control
		debug("%v short buffer: avail=%d left=%d", s.pov(), avail, left)
		return 0, nil
	}
	// Add frames
	op := newSentPacket(p.packetNumber, now)
	p.payloadLen = s.sendFrames(op, space, left, now)
	if len(op.frames) == 0 {
		return 0, nil
	}
	left -= p.payloadLen
	// Pad client initial packet
	// FIXME: Should pad after packets are coalesced. Currently ack only frame is padded.
	if s.isClient && p.typ == packetTypeInitial {
		n := MinInitialPacketSize - pktOverhead - p.payloadLen
		if n > 0 {
			if n > left {
				return 0, errShortBuffer
			}
			op.addFrame(newPaddingFrame(n))
			p.payloadLen += n
			left -= n
		}
	}
	if p.payloadLen < minPacketPayloadLength {
		n := minPacketPayloadLength - p.payloadLen
		if n > left {
			return 0, errShortBuffer
		}
		op.addFrame(newPaddingFrame(n))
		p.payloadLen += n
		left -= n
	}
	// Include crypto overhead to encode packet header with correct length
	p.payloadLen += overhead
	payloadOffset, err := p.encode(b)
	if err != nil {
		return 0, err
	}
	// Encode frames to sending packet then encrypt it
	p.packetSize, err = encodeFrames(b[payloadOffset:], op.frames)
	if err != nil {
		return 0, err
	}
	p.packetSize += payloadOffset + overhead
	if p.packetSize != payloadOffset+p.payloadLen || p.packetSize > len(b) {
		return 0, newError(InternalError, sprint("encoded payload length ", p.packetSize, " exceeded buffer capacity ", len(b)))
	}
	pnSpace.encryptPacket(b[:p.packetSize], &p)
	op.sentBytes = uint(p.packetSize)
	// Finish preparing sending packet
	debug("%v sending packet %s %s", s.pov(), &p, op)
	s.onPacketSent(op, space)
	// TODO: Log real payload length without crypto overhead
	s.logPacketSent(&p, op.frames, now)
	// https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.2.1
	// A client stops both sending and processing Initial packets when it sends its first Handshake packet.
	if p.packetNumber == 0 {
		if s.isClient {
			if space == packetSpaceHandshake {
				s.dropPacketSpace(packetSpaceInitial, now)
			}
		} else {
			if space == packetSpaceApplication {
				// First Application packet from server is HandshakeDone
				s.dropPacketSpace(packetSpaceHandshake, now)
			}
		}
	}
	return p.packetSize, nil
}

func (s *Conn) writeSpace() packetSpace {
	// On error, send packet in the latest space available.
	if s.localError != nil {
		return s.handshake.writeSpace()
	}
	for i := packetSpaceInitial; i < packetSpaceCount; i++ {
		pnSpace := s.packetNumberSpaces[i]
		if pnSpace == nil || !pnSpace.canEncrypt() {
			continue
		}
		// Only use application packet number space when handshake is complete.
		if i == packetSpaceApplication && s.state < stateActive {
			continue
		}
		// Select the space which
		// - Has data to send e.g. crypto, or
		// - Has Lost frames, or
		// - Needs to send PTO probe.
		if pnSpace.ready() || len(s.recovery.lost[i]) > 0 || s.recovery.lossProbes[i] > 0 {
			return i
		}
	}
	// If there are flushable streams, use Application.
	if s.state == stateActive && ((!s.isClient && !s.handshakeConfirmed) ||
		s.updateMaxData || s.flow.shouldUpdateRecvMax() || s.flow.sendBlocked ||
		s.datagram.isFlushable() || s.streams.hasUpdate()) {
		return packetSpaceApplication
	}
	// Nothing to send
	return packetSpaceCount
}

func (s *Conn) maxPacketSize() int {
	var n uint
	if s.state >= stateActive && s.peerParams.MaxUDPPayloadSize > 0 {
		n = uint(s.peerParams.MaxUDPPayloadSize)
	} else {
		n = MinInitialPacketSize
	}
	cwnd := s.recovery.availSend()
	if n > cwnd {
		n = cwnd
	}
	// Limit data sent by the server before client address is validated.
	if !s.isClient && !s.peerAddressVerified && s.localError == nil {
		maxSend := s.recvBytes * maxAmplificationFactor
		if maxSend > s.sentBytes {
			maxSend -= s.sentBytes
		} else {
			maxSend = 0
		}
		if n > uint(maxSend) {
			n = uint(maxSend)
		}
	}
	return int(n)
}

func (s *Conn) processLostPackets(space packetSpace, now time.Time) {
	s.logPacketsLost(s.recovery.lost[space], space, now)
	s.recovery.drainLost(space, func(f frame) {
		switch f := f.(type) {
		case *ackFrame:
			s.packetNumberSpaces[space].ackElicited = true
		case *cryptoFrame:
			// Push data back to send again
			err := s.packetNumberSpaces[space].cryptoStream.pushSend(f.data, f.offset, false)
			if err != nil {
				debug("%v process lost crypto frame %s: %v", s.pov(), f, err)
			}
			freeDataBuffer(f.data)
		case *resetStreamFrame:
			st := s.streams.getOpen(f.streamID)
			if st != nil {
				st.setResetStream(deliveryReady)
			}
		case *stopSendingFrame:
			st := s.streams.getOpen(f.streamID)
			if st != nil {
				st.setStopSending(deliveryReady)
			}
		case *streamFrame:
			st := s.streams.getOpen(f.streamID)
			if st != nil {
				// Push data back to send again
				err := st.pushSend(f.data, f.offset, f.fin)
				if err != nil {
					debug("%v process lost stream frame %s: %v", s.pov(), f, err)
				}
			}
			freeDataBuffer(f.data)
		case *maxDataFrame:
			s.updateMaxData = true
		case *maxStreamDataFrame:
			st := s.streams.getOpen(f.streamID)
			if st != nil {
				st.setUpdateMaxData(true)
			}
		case *maxStreamsFrame:
			if f.bidi {
				s.streams.setUpdateMaxStreamsBidi(true)
			} else {
				s.streams.setUpdateMaxStreamsUni(true)
			}
		case *dataBlockedFrame:
			s.flow.setSendBlocked(true)
		case *streamDataBlockedFrame:
			st := s.streams.getOpen(f.streamID)
			if st != nil {
				st.flow.setSendBlocked(true)
			}
		case *pathResponseFrame:
			s.pathResponse = f.data
		case *handshakeDoneFrame:
			// Toggle flag to resend HANDSHAKE_DONE frame
			s.handshakeConfirmed = false
		case *datagramFrame:
			freeDataBuffer(f.data)
		}
	})
}

func (s *Conn) sendFrames(op *sentPacket, space packetSpace, left int, now time.Time) int {
	payloadLen := 0
	// ACK
	if f := s.sendFrameAck(space, now); f != nil {
		n := f.encodedLen()
		if left >= n {
			op.addFrame(f)
			payloadLen += n
			left -= n
			s.packetNumberSpaces[space].ackElicited = false
		}
	}
	// CONNECTION_CLOSE
	if f := s.sendFrameConnectionClose(); f != nil {
		n := f.encodedLen()
		if left >= n {
			op.addFrame(f)
			payloadLen += n
			left -= n
			// After sending a CONNECTION_CLOSE frame, an endpoint immediately enters the closing state
			if s.state < stateClosed {
				s.setState(stateClosed, now)
			}
			return payloadLen // do not need to continue
		}
	}
	// CRYPTO
	if f := s.sendFrameCrypto(space, left); f != nil {
		n := f.encodedLen()
		op.addFrame(f)
		payloadLen += n
		left -= n
	}
	if space == packetSpaceApplication {
		// HANDSHAKE_DONE
		if f := s.sendFrameHandshakeDone(); f != nil {
			n := f.encodedLen()
			if left >= n {
				op.addFrame(f)
				payloadLen += n
				left -= n
				s.setHandshakeConfirmed()
			}
		}
		// PATH_RESPONSE
		if f := s.sendFramePathResponse(); f != nil {
			n := f.encodedLen()
			if left >= n {
				op.addFrame(f)
				payloadLen += n
				left -= n
				s.pathResponse = nil
			}
		}
		// MAX_DATA
		if f := s.sendFrameMaxData(); f != nil {
			n := f.encodedLen()
			if left >= n {
				op.addFrame(f)
				payloadLen += n
				left -= n
				s.updateMaxData = false
				s.flow.commitRecvMax()
			}
		}
		// MAX_STREAMS (bidi)
		if f := s.sendFrameMaxStreamsBidi(); f != nil {
			n := f.encodedLen()
			if left >= n {
				op.addFrame(f)
				payloadLen += n
				left -= n
				s.streams.setUpdateMaxStreamsBidi(false)
				s.streams.commitMaxStreamsBidi()
			}
		}
		// MAX_STREAMS (uni)
		if f := s.sendFrameMaxStreamsUni(); f != nil {
			n := f.encodedLen()
			if left >= n {
				op.addFrame(f)
				payloadLen += n
				left -= n
				s.streams.setUpdateMaxStreamsUni(false)
				s.streams.commitMaxStreamsUni()
			}
		}
		// DATA_BLOCKED
		if f := s.sendFrameDataBlocked(); f != nil {
			n := f.encodedLen()
			if left >= n {
				op.addFrame(f)
				payloadLen += n
				left -= n
				s.flow.setSendBlocked(false)
			}
		}
		for id, st := range s.streams.streams {
			// STOP_SENDING
			if f := s.sendFrameStopSending(id, st); f != nil {
				n := f.encodedLen()
				if left >= n {
					op.addFrame(f)
					payloadLen += n
					left -= n
					st.setStopSending(deliverySending)
				}
			}
			// RESET_STREAM
			if f := s.sendFrameResetStream(id, st); f != nil {
				n := f.encodedLen()
				if left >= n {
					op.addFrame(f)
					payloadLen += n
					left -= n
					st.setResetStream(deliverySending)
				}
			}
			// MAX_STREAM_DATA
			if f := s.sendFrameMaxStreamData(id, st); f != nil {
				n := f.encodedLen()
				if left >= n {
					op.addFrame(f)
					payloadLen += n
					left -= n
					st.setUpdateMaxData(false)
					st.flow.commitRecvMax()
				}
			}
			// STREAM_DATA_BLOCKED
			if f := s.sendFrameStreamDataBlocked(id, st); f != nil {
				n := f.encodedLen()
				if left >= n {
					op.addFrame(f)
					payloadLen += n
					left -= n
					st.flow.setSendBlocked(false)
				}
			}
		}
		// DATAGRAM
		for f := s.sendFrameDatagram(left); f != nil; f = s.sendFrameDatagram(left) {
			n := f.encodedLen()
			op.addFrame(f)
			payloadLen += n
			left -= n
		}
		// STREAM
		// TODO: support stream priority
		for id, st := range s.streams.streams {
			if f := s.sendFrameStream(id, st, left); f != nil {
				n := f.encodedLen()
				op.addFrame(f)
				payloadLen += n
				left -= n
				s.flow.addSend(len(f.data))
				if s.flow.availSend() == 0 {
					debug("%v connection blocked: %v", s.pov(), &s.flow)
					s.flow.setSendBlocked(true)
				}
				if left <= maxStreamFrameOverhead {
					break
				}
			}
		}
	}
	// PING
	if s.recovery.lossProbes[space] > 0 {
		if op.ackEliciting {
			// Do not need PING if an ack-eliciting frame is sent
			s.recovery.onProbeSent(space)
		} else if f := s.sendFramePing(left); f != nil {
			n := f.encodedLen()
			op.addFrame(f)
			payloadLen += n
			left -= n
			s.recovery.onProbeSent(space)
		}
	}
	return payloadLen
}

func (s *Conn) onPacketSent(op *sentPacket, space packetSpace) {
	s.recovery.onPacketSent(op, space)
	s.packetNumberSpaces[space].nextPacketNumber++
	// (Re)start the idle timer if we are sending the first ACK-eliciting
	// packet since last receiving a packet.
	if op.ackEliciting && !s.ackElicitingSent {
		s.setIdleTimer(op.timeSent)
		s.ackElicitingSent = true
	}
}

// Timeout returns the amount of time until the next timeout event.
// A negative timeout means that the timer should be disarmed.
func (s *Conn) Timeout() time.Duration {
	if s.state == stateClosed {
		return -1
	}
	now := s.timeFn()
	s.logLossTimer(now)
	var deadline time.Time
	if !s.drainingTimer.IsZero() {
		deadline = s.drainingTimer
	} else if !s.recovery.lossDetectionTimer.IsZero() {
		// Minimum of loss and idle timer
		deadline = s.recovery.lossDetectionTimer
		if !s.idleTimer.IsZero() && deadline.After(s.idleTimer) {
			deadline = s.idleTimer
		}
	} else if !s.idleTimer.IsZero() {
		deadline = s.idleTimer
	} else {
		return -1
	}
	timeout := deadline.Sub(now)
	if timeout < 0 {
		timeout = 0
	}
	return timeout
}

func (s *Conn) checkTimeout(now time.Time) {
	if !s.drainingTimer.IsZero() && !now.Before(s.drainingTimer) {
		debug("%v draining timeout expired: %v", s.pov(), s.drainingTimer)
		if s.state < stateClosed {
			s.setState(stateClosed, now)
		}
		return
	}
	if !s.idleTimer.IsZero() && !now.Before(s.idleTimer) {
		debug("%v idle timeout expired: %v", s.pov(), s.idleTimer)
		if s.state < stateClosed {
			s.setState(stateClosed, now)
		}
		return
	}
	if !s.recovery.lossDetectionTimer.IsZero() && !now.Before(s.recovery.lossDetectionTimer) {
		debug("%v loss timeout expired: %v", s.pov(), s.recovery.lossDetectionTimer)
		s.recovery.onLossDetectionTimeout(now)
	}
}

func (s *Conn) setIdleTimer(now time.Time) {
	if s.localParams.MaxIdleTimeout > 0 {
		// If both are set, use minimum value.
		if s.peerParams.MaxIdleTimeout > 0 && s.peerParams.MaxIdleTimeout < s.localParams.MaxIdleTimeout {
			s.idleTimer = now.Add(s.peerParams.MaxIdleTimeout)
		} else {
			s.idleTimer = now.Add(s.localParams.MaxIdleTimeout)
		}
	} else if s.peerParams.MaxIdleTimeout > 0 {
		// Use peer's setting if presents
		s.idleTimer = now.Add(s.peerParams.MaxIdleTimeout)
	}
}

// Delay returns duration that application should wait to delivery
// the last packet it got from Read.
// A non-positive duration means the packet should be delivered immediately.
func (s *Conn) Delay() time.Duration {
	if s.recovery.lastPacketSchedule.IsZero() {
		return 0
	}
	now := s.timeFn()
	delay := s.recovery.lastPacketSchedule.Sub(now)
	debug("packet delay: %v", delay)
	return delay
}

// Close sets the connection to Closing state if it is not in Draining or Closed state.
// Packet generated from calling Read afterward will include a ConnectionClose frame.
// If the peer already initiated connection closing with an error, this function will
// immediately set connection state to Closed and return that error.
// https://www.rfc-editor.org/rfc/rfc9000.html#section-10.2.2
func (s *Conn) Close(errCode uint64, reason string, app bool) error {
	if s.localError == nil && s.state < stateDraining {
		// Closing or draining or already closed
		debug("%v set closing: code=%d reason=%v", s.pov(), errCode, reason)
		s.localError = &Error{
			Code:   errCode,
			Reason: reason,
			App:    app,
		}
	}
	if s.state == stateDraining {
		s.setState(stateClosed, s.timeFn())
	}
	if !isNoError(s.peerError) {
		return s.peerError
	}
	return nil
}

// IsClosed returns true when the connection state is closed.
func (s *Conn) IsClosed() bool {
	return s.state == stateClosed
}

// ConnectionState returns the current connection state and statistics.
func (s *Conn) ConnectionState() ConnectionState {
	state := ConnectionState{
		State: s.state.String(),

		RecvPackets: s.recvPackets,
		RecvBytes:   s.recvBytes,
		SentPackets: s.sentPackets,
		SentBytes:   s.sentBytes,
		LostPackets: s.recovery.lostPackets,
		LostBytes:   s.recovery.lostBytes,
		PeerParams:  s.peerParams,

		TLS: s.handshake.connectionState(),
	}
	if !isNoError(s.localError) {
		state.LocalError = s.localError
	}
	if !isNoError(s.peerError) {
		state.PeerError = s.peerError
	}
	return state
}

// HandshakeComplete returns true when connection handshake is completed and not closing.
func (s *Conn) HandshakeComplete() bool {
	return s.state == stateActive
}

// Events consumes received connection events as well as stream and datagram events.
// It appends to provided events slice and clears received events.
func (s *Conn) Events(events []Event) []Event {
	if len(s.events) > 0 {
		events = append(events, s.events...)
		s.events = s.events[:0]
	}
	if s.state >= stateActive {
		events = s.addStreamEvents(events)
		events = s.addDatagramEvents(events)
	}
	return events
}

// Stream returns an openned stream or create a local stream if it does not exist.
// Client-initiated streams have even-numbered stream IDs and
// server-initiated streams have odd-numbered stream IDs.
func (s *Conn) Stream(id uint64) (*Stream, error) {
	return s.getOrCreateStream(id, true)
}

// Datagram returns a Datagram associated to this QUIC connection.
func (s *Conn) Datagram() *Datagram {
	return &s.datagram
}

func (s *Conn) sendFrameAck(space packetSpace, now time.Time) *ackFrame {
	pnSpace := s.packetNumberSpaces[space]
	if (pnSpace.ackElicited || s.recovery.lossProbes[space] > 0) && len(pnSpace.recvPacketNeedAck) > 0 {
		ackDelay := uint64(now.Sub(pnSpace.largestRecvPacketTime).Microseconds())
		ackDelay /= 1 << s.peerParams.AckDelayExponent
		return newAckFrame(ackDelay, pnSpace.recvPacketNeedAck)
	}
	return nil
}

func (s *Conn) sendFrameCrypto(space packetSpace, left int) *cryptoFrame {
	left -= maxCryptoFrameOverhead
	if left > 0 {
		pnSpace := s.packetNumberSpaces[space]
		data, offset, _ := pnSpace.cryptoStream.popSend(left)
		if len(data) > 0 {
			return newCryptoFrame(data, offset)
		}
	}
	return nil
}

func (s *Conn) sendFrameStream(id uint64, st *Stream, left int) *streamFrame {
	// Connection level limits
	allowed := int(s.flow.availSend())
	left -= maxStreamFrameOverhead
	if left > allowed {
		left = allowed
	}
	// In PTO mode, stream data can be resend so we need to check stream limits.
	if s.recovery.ptoCount > 0 {
		allowed = int(st.flow.availSend())
		if left > allowed {
			left = allowed
		}
	}
	if left > 0 {
		data, offset, fin := st.popSend(left)
		if len(data) > 0 || fin {
			debug("%v stream send: id=%v %v", s.pov(), id, &st.send)
			return newStreamFrame(id, data, offset, fin)
		}
	}
	return nil
}

func (s *Conn) sendFrameResetStream(id uint64, st *Stream) *resetStreamFrame {
	if code, ok := st.updateResetStream(); ok {
		return newResetStreamFrame(id, code, st.send.length)
	}
	return nil
}

func (s *Conn) sendFrameStopSending(id uint64, st *Stream) *stopSendingFrame {
	if code, ok := st.updateStopSending(); ok {
		return newStopSendingFrame(id, code)
	}
	return nil
}

func (s *Conn) sendFrameMaxData() *maxDataFrame {
	if s.updateMaxData || s.flow.shouldUpdateRecvMax() {
		return newMaxDataFrame(s.flow.recvMaxNext)
	}
	return nil
}

func (s *Conn) sendFrameMaxStreamData(id uint64, st *Stream) *maxStreamDataFrame {
	if st.updateMaxData {
		return newMaxStreamDataFrame(id, st.flow.recvMaxNext)
	}
	return nil
}

func (s *Conn) sendFrameMaxStreamsBidi() *maxStreamsFrame {
	if s.streams.updateMaxStreamsBidi {
		return newMaxStreamsFrame(s.streams.maxStreamsNext.localBidi, true)
	}
	return nil
}

func (s *Conn) sendFrameMaxStreamsUni() *maxStreamsFrame {
	if s.streams.updateMaxStreamsUni {
		return newMaxStreamsFrame(s.streams.maxStreamsNext.localUni, false)
	}
	return nil
}

func (s *Conn) sendFrameDataBlocked() *dataBlockedFrame {
	if s.flow.sendBlocked {
		return newDataBlockedFrame(s.flow.sendMax)
	}
	return nil
}

func (s *Conn) sendFrameStreamDataBlocked(id uint64, st *Stream) *streamDataBlockedFrame {
	if st.flow.sendBlocked {
		return newStreamDataBlockedFrame(id, st.flow.sendMax)
	}
	return nil
}

func (s *Conn) sendFrameHandshakeDone() *handshakeDoneFrame {
	// HandshakeDone is sent only by server.
	if !s.isClient && s.state == stateActive && !s.handshakeConfirmed {
		return &handshakeDoneFrame{}
	}
	return nil
}

func (s *Conn) sendFramePathResponse() *pathResponseFrame {
	if s.pathResponse != nil {
		return newPathResponseFrame(s.pathResponse)
	}
	return nil
}

func (s *Conn) sendFramePing(left int) *pingFrame {
	if left > 0 {
		return &pingFrame{}
	}
	return nil
}

func (s *Conn) sendFrameDatagram(left int) *datagramFrame {
	data := s.datagram.popSend(left - maxDatagramFrameOverhead)
	if len(data) > 0 {
		return newDatagramFrame(data)
	}
	return nil
}

func (s *Conn) sendFrameConnectionClose() *connectionCloseFrame {
	if s.localError != nil {
		return &connectionCloseFrame{
			errorCode:    s.localError.Code,
			reasonPhrase: []byte(s.localError.Reason),
			application:  s.localError.App,
		}
	}
	return nil
}

func (s *Conn) getOrCreateStream(id uint64, local bool) (*Stream, error) {
	st := s.streams.get(id)
	if st != nil {
		return st, nil
	}
	// Initialize new stream
	if local != isStreamLocal(id, s.isClient) {
		return nil, newError(StreamStateError, sprint("invalid type of stream ", id))
	}
	st, err := s.streams.create(id, s.isClient)
	if err != nil {
		return nil, err
	}
	var maxRecv, maxSend uint64
	if st.local {
		if st.bidi {
			maxRecv = s.localParams.InitialMaxStreamDataBidiLocal
			maxSend = s.peerParams.InitialMaxStreamDataBidiRemote
		} else {
			maxRecv = 0
			maxSend = s.peerParams.InitialMaxStreamDataUni
		}
	} else {
		if st.bidi {
			maxRecv = s.localParams.InitialMaxStreamDataBidiRemote
			maxSend = s.peerParams.InitialMaxStreamDataBidiLocal
		} else {
			maxRecv = s.localParams.InitialMaxStreamDataUni
			maxSend = 0
		}
	}
	st.flow.init(maxRecv, maxSend)
	// Manually set connection flow control to get updated read bytes
	st.connFlow = &s.flow
	if !st.local {
		s.addEvent(newEventStreamOpen(id))
	}
	return st, nil
}

// Check closed streams for garbage collection.
func (s *Conn) checkStreamsState(now time.Time) {
	if s.state == stateActive {
		s.streams.checkClosed(func(id uint64) {
			s.addEvent(newEventStreamClosed(id))
			s.logStreamClosed(id, now)
		})
	}
}

func (s *Conn) setState(state connectionState, now time.Time) {
	s.logConnectionState(s.state, state, now)
	s.state = state
	switch state {
	case stateActive:
		s.addEvent(newEventConnectionOpen())
	case stateClosed:
		// When the connection is closed, all streams should be detached from the connection.
		// That will allow all streams to be drained concurrently by the application.
		for _, st := range s.streams.streams {
			st.connFlow = nil
		}
		s.addEvent(newEventConnectionClosed())
	}
	debug("%v set state=%v", s.pov(), state)
}

func (s *Conn) setHandshakeConfirmed() {
	s.handshakeConfirmed = true
	s.recovery.setHandshakeConfirmed()
	// Once the handshake is confirmed, an endpoint may initiate a key update.
	s.packetNumberSpaces[packetSpaceApplication].setKeyUpdatePermitted()
}

func (s *Conn) dropPacketSpace(space packetSpace, now time.Time) {
	s.packetNumberSpaces[space] = nil
	s.recovery.onPacketNumberSpaceDiscarded(space, now)
	debug("%v dropped space=%v", s.pov(), space)
}

func (s *Conn) addStreamEvents(events []Event) []Event {
	for id, st := range s.streams.streams {
		if st.isReadable() {
			events = append(events, newEventStreamReadable(id))
		}
	}
	if s.state == stateActive {
		if s.flow.availSend() > 0 {
			for id, st := range s.streams.streams {
				if st.isWritable() {
					events = append(events, newEventStreamWritable(id))
				}
			}
		}
		bidi := s.streams.creatableLocalStreamBidi()
		uni := s.streams.creatableLocalStreamUni()
		if bidi || uni {
			events = append(events, newEventStreamCreatable(bidi, uni))
		}
	}
	return events
}

func (s *Conn) addDatagramEvents(events []Event) []Event {
	if s.datagram.isWritable() {
		events = append(events, newEventDatagramWritable())
	}
	if s.datagram.isReadable() {
		events = append(events, newEventDatagramReadable())
	}
	return events
}

func (s *Conn) addEvent(e Event) {
	s.events = append(s.events, e)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// SetLogger sets handler for received events.
func (s *Conn) SetLogger(fn func(LogEvent)) {
	s.logEventFn = fn
}

func (s *Conn) logPacketDropped(p *packet, trigger string, now time.Time) {
	debug("%v dropped packet: %v %v", s.pov(), trigger, p)
	if s.logEventFn != nil {
		e := newLogEvent(now, logEventPacketDropped)
		logPacket(&e, p)
		e.addField("trigger", trigger)
		s.logEventFn(e)
		freeLogEvent(e)
	}
}

func (s *Conn) logPacketReceived(p *packet, now time.Time) {
	debug("%v received packet: %v", s.pov(), p)
	if s.logEventFn != nil {
		e := newLogEvent(now, logEventPacketReceived)
		logPacket(&e, p)
		s.logEventFn(e)
		freeLogEvent(e)
	}
}

func (s *Conn) logPacketSent(p *packet, frames []frame, now time.Time) {
	if s.logEventFn != nil {
		e := newLogEvent(now, logEventPacketSent)
		logPacket(&e, p)
		s.logEventFn(e)
		e.Name = logEventFramesProcessed
		for _, f := range frames {
			e.resetData()
			logFrame(&e, f)
			s.logEventFn(e)
		}
		freeLogEvent(e)
	}
}

func (s *Conn) logPacketsLost(packets []*sentPacket, space packetSpace, now time.Time) {
	if s.logEventFn != nil {
		e := newLogEvent(now, logEventPacketLost)
		p := packet{
			typ: packetTypeFromSpace(space),
		}
		for _, sp := range packets {
			p.packetNumber = sp.packetNumber
			e.resetData()
			logPacket(&e, &p)
			s.logEventFn(e)
		}
		freeLogEvent(e)
	}
}

func (s *Conn) logFrameProcessed(f frame, now time.Time) {
	if s.logEventFn != nil {
		e := newLogEvent(now, logEventFramesProcessed)
		logFrame(&e, f)
		s.logEventFn(e)
		freeLogEvent(e)
	}
}

func (s *Conn) logParametersSet(p *Parameters, now time.Time) {
	if s.logEventFn != nil {
		e := newLogEvent(now, logEventParametersSet)
		logParameters(&e, p)
		s.logEventFn(e)
		freeLogEvent(e)
	}
}

func (s *Conn) logRecovery(now time.Time) {
	if s.logEventFn != nil {
		e := newLogEvent(now, logEventMetricsUpdated)
		logRecovery(&e, &s.recovery)
		s.logEventFn(e)
		freeLogEvent(e)
	}
}

func (s *Conn) logLossTimer(now time.Time) {
	if s.logEventFn != nil {
		e := newLogEvent(now, logEventLossTimerUpdated)
		logLossTimer(&e, &s.recovery)
		s.logEventFn(e)
		freeLogEvent(e)
	}
}

func (s *Conn) logStreamClosed(id uint64, now time.Time) {
	if s.logEventFn != nil {
		e := newLogEvent(now, logEventStreamStateUpdated)
		logStreamClosed(&e, id)
		s.logEventFn(e)
		freeLogEvent(e)
	}
}

func (s *Conn) logConnectionState(old, new connectionState, now time.Time) {
	if s.logEventFn != nil {
		e := newLogEvent(now, logEventConnStateUpdated)
		logConnectionState(&e, old, new)
		s.logEventFn(e)
		freeLogEvent(e)
	}
}

// pov returns connection perspective, either client or server.
func (s *Conn) pov() string {
	if s.isClient {
		return "client"
	}
	return "server"
}

func copyBytes(src []byte) []byte {
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}
