package transport

import (
	"bytes"
	"crypto/rand"
	"io"
	"time"
)

type connectionState uint8

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

// Conn is a QUIC connection.
type Conn struct {
	isClient bool
	version  uint32

	scid  []byte // Source CID
	dcid  []byte // Destination CID. DCID can be replaced in recvPacketInitial.
	odcid []byte // Original destination CID. Used to validate transport parameters.
	rscid []byte // Retry source CID. Set in recvPacketRetry.
	token []byte // Stateless retry token

	packetNumberSpaces [packetSpaceCount]packetNumberSpace
	streams            streamMap

	localParams Parameters
	peerParams  Parameters

	handshake tlsHandshake
	recovery  lossRecovery
	flow      flowControl

	state                 connectionState
	gotPeerCID            bool
	didRetry              bool
	didVersionNegotiation bool
	ackElicitingSent      bool // Whether an ACK-eliciting packet has been sent since last receiving a packet.
	handshakeConfirmed    bool // On server, it's handshakeDone frame sent. On client, it's the frame received
	derivedInitialSecrets bool
	updateMaxData         bool // Whether a MAX_DATA needs to be sent

	closeFrame *connectionCloseFrame // Error to be send to peer

	idleTimer     time.Time // Idle timeout expiration time.
	drainingTimer time.Time // Draining timeout expiration time.

	events []Event
	// Application callbacks
	logEventFn func(LogEvent)
}

// Connect creates a client connection.
func Connect(scid []byte, config *Config) (*Conn, error) {
	return newConn(config, scid, nil, true)
}

// Accept creates a server connection.
func Accept(scid, odcid []byte, config *Config) (*Conn, error) {
	return newConn(config, scid, odcid, false)
}

func newConn(config *Config, scid, odcid []byte, isClient bool) (*Conn, error) {
	if config == nil {
		return nil, newError(InternalError, "config required")
	}
	if len(scid) > MaxCIDLength || len(odcid) > MaxCIDLength {
		return nil, newError(ProtocolViolation, "cid too long")
	}
	s := &Conn{
		version:     config.Version,
		isClient:    isClient,
		localParams: config.Params,
		state:       stateAttempted,
	}
	s.handshake.init(config.TLS, &s.packetNumberSpaces, isClient)
	for i := range s.packetNumberSpaces {
		s.packetNumberSpaces[i].init()
	}
	s.streams.init(s.localParams.InitialMaxStreamsBidi, s.localParams.InitialMaxStreamsUni)
	s.recovery.init()
	s.flow.init(s.localParams.InitialMaxData, 0)
	if len(scid) > 0 {
		s.scid = append(s.scid[:0], scid...)
	}
	s.localParams.InitialSourceCID = s.scid // SCID is fixed so can use its reference
	if len(odcid) > 0 {
		s.odcid = append(s.odcid[:0], odcid...)
		s.localParams.OriginalDestinationCID = s.odcid
		s.localParams.RetrySourceCID = s.scid
		s.didRetry = true // So odcid will not be set again
	} else {
		// Do not take CIDs from config
		s.localParams.OriginalDestinationCID = nil
		s.localParams.RetrySourceCID = nil
	}
	if isClient {
		// Stateless reset token must not be sent by client
		s.localParams.StatelessResetToken = nil
		// Random first destination connection id from client
		s.dcid = make([]byte, MaxCIDLength)
		if err := s.rand(s.dcid); err != nil {
			return nil, err
		}
		s.deriveInitialKeyMaterial(s.dcid)
	}
	s.handshake.setTransportParams(&s.localParams)
	return s, nil
}

// Write consumes received data.
func (s *Conn) Write(b []byte) (int, error) {
	now := s.time()
	n := 0
	for n < len(b) {
		if !s.drainingTimer.IsZero() || s.closeFrame != nil {
			// Closing
			break
		}
		i, err := s.recv(b[n:], now)
		if err != nil {
			return n, err
		}
		n += i
	}
	s.checkTimeout(now)
	s.addStreamEvents()
	return n, nil
}

func (s *Conn) deriveInitialKeyMaterial(cid []byte) {
	client, server := newInitialSecrets(cid)
	space := &s.packetNumberSpaces[packetSpaceInitial]
	if s.isClient {
		space.opener, space.sealer = server, client
	} else {
		space.opener, space.sealer = client, server
	}
	s.derivedInitialSecrets = true
}

func (s *Conn) recv(b []byte, now time.Time) (int, error) {
	p := packet{
		header: packetHeader{
			dcil: uint8(len(s.scid)),
		},
	}
	_, err := p.decodeHeader(b)
	if err != nil {
		return 0, err
	}
	switch p.typ {
	case packetTypeVersionNegotiation:
		return s.recvPacketVersionNegotiation(b, &p, now)
	case packetTypeRetry:
		return s.recvPacketRetry(b, &p, now)
	case packetTypeInitial:
		return s.recvPacketInitial(b, &p, now)
	case packetTypeZeroRTT:
		return 0, newError(InternalError, "zerortt packet not supported")
	case packetTypeHandshake:
		return s.recvPacketHandshake(b, &p, now)
	case packetTypeShort:
		return s.recvPacketShort(b, &p, now)
	default:
		panic(sprint("unsupported packet type ", p.typ))
	}
}

// https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#version-negotiation
func (s *Conn) recvPacketVersionNegotiation(b []byte, p *packet, now time.Time) (int, error) {
	// VN packet can only be sent by server
	if !s.isClient || s.didVersionNegotiation || s.state != stateAttempted ||
		!bytes.Equal(p.header.dcid, s.scid) || !bytes.Equal(p.header.scid, s.dcid) {
		debug("dropped packet %v", p)
		s.logPacketDropped(p, now)
		return len(b), nil
	}
	n, err := p.decodeBody(b)
	if err != nil {
		return 0, err
	}
	debug("received packet %v", p)
	var newVersion uint32
	for _, v := range p.supportedVersions {
		if versionSupported(v) {
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
	s.recovery.onPacketNumberSpaceDiscarded(packetSpaceInitial)
	s.packetNumberSpaces[packetSpaceInitial].reset()
	s.handshake.reset(s.isClient)
	s.handshake.setTransportParams(&s.localParams)
	s.logPacketReceived(p, now)
	return p.headerLen + n, nil
}

// https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#validate-handshake
func (s *Conn) recvPacketRetry(b []byte, p *packet, now time.Time) (int, error) {
	// Retry packet can only be sent by server
	// Packet's SCID must not be equal to the client's DCID.
	if !s.isClient || s.didRetry || s.state != stateAttempted ||
		!bytes.Equal(p.header.dcid, s.scid) || bytes.Equal(p.header.scid, s.dcid) {
		debug("dropped packet %v", p)
		s.logPacketDropped(p, now)
		return len(b), nil
	}
	_, err := p.decodeBody(b)
	if err != nil {
		return 0, err
	}
	// Verify token and integrity tag
	if len(p.token) == 0 || !verifyRetryIntegrity(b, s.dcid) {
		return 0, errInvalidToken
	}
	debug("received packet %v", p)
	s.didRetry = true
	s.token = append(s.token[:0], p.token...)
	// Update CIDs and crypto: dcid => odcid, header.scid => dcid
	s.odcid = append(s.odcid[:0], s.dcid...)
	s.dcid = append(s.dcid[:0], p.header.scid...)
	s.rscid = s.dcid // DCID is now fixed
	s.deriveInitialKeyMaterial(s.dcid)
	// Reset connection state to send another initial packet
	s.gotPeerCID = false
	s.recovery.onPacketNumberSpaceDiscarded(packetSpaceInitial)
	s.packetNumberSpaces[packetSpaceInitial].reset()
	s.handshake.reset(s.isClient)
	s.handshake.setTransportParams(&s.localParams)
	s.logPacketReceived(p, now)
	return len(b), nil // p.headerLen + bodyLen + retryIntegrityTagLen
}

func (s *Conn) recvPacketInitial(b []byte, p *packet, now time.Time) (int, error) {
	if s.gotPeerCID && (!bytes.Equal(p.header.dcid, s.scid) || !bytes.Equal(p.header.scid, s.dcid)) {
		debug("dropped packet %v", p)
		s.logPacketDropped(p, now)
		return len(b), nil
	}
	if !s.derivedInitialSecrets { // Server side
		s.deriveInitialKeyMaterial(p.header.dcid)
	}
	if !s.gotPeerCID {
		if s.isClient {
			if len(s.odcid) == 0 {
				s.odcid = append(s.odcid[:0], s.dcid...)
			}
		} else {
			if !s.didRetry {
				s.odcid = append(s.odcid[:0], p.header.dcid...)
				s.localParams.OriginalDestinationCID = s.odcid
				s.handshake.setTransportParams(&s.localParams)
			}
		}
		// Replace the randomly generated destination connection ID with
		// the one supplied by the server.
		s.dcid = append(s.dcid[:0], p.header.scid...)
		s.gotPeerCID = true
	}
	return s.recvPacket(b, p, packetSpaceInitial, now)
}

func (s *Conn) recvPacketHandshake(b []byte, p *packet, now time.Time) (int, error) {
	if !bytes.Equal(p.header.dcid, s.scid) || !bytes.Equal(p.header.scid, s.dcid) {
		debug("dropped packet %v", p)
		s.logPacketDropped(p, now)
		return len(b), nil
	}
	return s.recvPacket(b, p, packetSpaceHandshake, now)
}

func (s *Conn) recvPacketShort(b []byte, p *packet, now time.Time) (int, error) {
	if !bytes.Equal(p.header.dcid, s.scid) {
		debug("dropped packet %v", p)
		s.logPacketDropped(p, now)
		return len(b), nil
	}
	return s.recvPacket(b, p, packetSpaceApplication, now)
}

func (s *Conn) recvPacket(b []byte, p *packet, space packetSpace, now time.Time) (int, error) {
	pnSpace := &s.packetNumberSpaces[space]
	if !pnSpace.canDecrypt() {
		debug("dropped undecryptable packet %v space=%v", p, space)
		s.logPacketDropped(p, now)
		return len(b), nil
	}
	payload, err := pnSpace.decryptPacket(b, p)
	if err != nil {
		return 0, err
	}
	debug("received packet %v payload=%d", p, len(payload))
	if pnSpace.isPacketReceived(p.packetNumber) {
		// Ignore duplicate packet
		s.logPacketDropped(p, now)
		return p.packetSize, nil
	}
	s.logPacketReceived(p, now)
	if err = s.recvFrames(payload, p.typ, space, now); err != nil {
		return 0, err
	}
	// Process acked frames
	s.processAckedPackets(space)

	// https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#name-abandoning-initial-packets
	// A server stops sending and processing Initial packets when it receives its first Handshake packet.
	if space == packetSpaceHandshake {
		if !s.isClient && pnSpace.largestRecvPacketTime.IsZero() {
			s.dropPacketSpace(packetSpaceInitial)
		}
		if s.state < stateHandshake {
			s.setState(stateHandshake, now)
		}
	}
	// Mark this packet received
	pnSpace.onPacketReceived(p.packetNumber, now)

	if s.localParams.MaxIdleTimeout > 0 {
		s.idleTimer = now.Add(s.localParams.MaxIdleTimeout)
	}
	s.ackElicitingSent = false
	return p.packetSize, nil
}

// https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#frames
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
		// TODO: Check allowed frames for current packet type
		switch {
		case typ == frameTypePadding:
			n, err = s.recvFramePadding(b, now)
		case typ == frameTypePing:
			s.recvFramePing(now)
		case typ == frameTypeAck:
			n, err = s.recvFrameAck(b, space, now)
		case typ == frameTypeResetStream:
			n, err = s.recvFrameResetStream(b, now)
		case typ == frameTypeStopSending:
			n, err = s.recvFrameStopSending(b, now)
		case typ == frameTypeCrypto:
			n, err = s.recvFrameCrypto(b, space, now)
		case typ == frameTypeNewToken:
			n, err = s.recvFrameNewToken(b, now)
		case typ >= frameTypeStream && typ <= frameTypeStreamEnd:
			n, err = s.recvFrameStream(b, now)
		case typ == frameTypeMaxData:
			n, err = s.recvFrameMaxData(b, now)
		case typ == frameTypeMaxStreamData:
			n, err = s.recvFrameMaxStreamData(b, now)
		case typ == frameTypeMaxStreamsBidi || typ == frameTypeMaxStreamsUni:
			n, err = s.recvFrameMaxStreams(b, now)
		case typ == frameTypeDataBlocked:
			n, err = s.recvFrameDataBlocked(b, now)
		case typ == frameTypeStreamDataBlocked:
			n, err = s.recvFrameStreamDataBlocked(b, now)
		case typ == frameTypeStreamsBlockedBidi || typ == frameTypeStreamsBlockedUni:
			n, err = s.recvFrameStreamsBlocked(b, now)
		case typ == frameTypeConnectionClose || typ == frameTypeApplicationClose:
			n, err = s.recvFrameConnectionClose(b, space, now)
		case typ == frameTypeHanshakeDone:
			n, err = s.recvFrameHandshakeDone(b, now)
		default:
			return newError(FrameEncodingError, sprint("unsupported frame ", typ))
		}
		if err != nil {
			debug("error processing frame 0x%x: %v", typ, err)
			return err
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
	s.logFrameProcessed(&f, now)
	return n, err
}

func (s *Conn) recvFramePing(now time.Time) {
	// Will ack
	var f pingFrame
	s.logFrameProcessed(&f, now)
}

func (s *Conn) recvFrameAck(b []byte, space packetSpace, now time.Time) (int, error) {
	var f ackFrame
	n, err := f.decode(b)
	if err != nil {
		return 0, err
	}
	debug("received frame 0x%x: %v", b[0], &f)
	ranges := f.toRangeSet()
	if ranges == nil {
		return 0, newError(FrameEncodingError, sprint("invalid ack ranges ", f.String()))
	}
	ackDelay := time.Duration((1<<s.peerParams.AckDelayExponent)*f.ackDelay) * time.Microsecond
	s.recovery.onAckReceived(ranges, ackDelay, space, now)
	s.logFrameProcessed(&f, now)
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
	debug("received frame 0x%x: %v", b[0], &f)
	// Not for send-only stream
	local := isStreamLocal(f.streamID, s.isClient)
	bidi := isStreamBidi(f.streamID)
	if local && !bidi {
		debug("peer attempted to reset our send-only stream: id=%d local=%v bidi=%v", f.streamID, local, bidi)
		return 0, newError(StreamStateError, sprint("reset stream ", f.streamID))
	}
	st, err := s.getOrCreateStream(f.streamID, false)
	if err != nil {
		return 0, err
	}
	mayRecv, err := st.resetRecv(f.finalSize)
	if err != nil {
		return 0, err
	}
	if s.flow.canRecv() < uint64(mayRecv) {
		return 0, errFlowControl
	}
	s.flow.addRecv(mayRecv)
	s.addEvent(newEventStreamReset(f.streamID, f.errorCode))
	s.logFrameProcessed(&f, now)
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
	debug("received frame 0x%x: %v", b[0], &f)
	// Not for a locally-initiated stream that has not yet been created.
	local := isStreamLocal(f.streamID, s.isClient)
	if local && s.streams.get(f.streamID) == nil {
		return 0, newError(StreamStateError, sprint("stop sending stream ", f.streamID))
	}
	// Not for a receive-only stream.
	bidi := isStreamBidi(f.streamID)
	if !bidi {
		debug("peer attempted to stop sending their receive-only stream: id=%d local=%v bidi=%v", f.streamID, local, bidi)
		return 0, newError(StreamStateError, sprint("stop sending stream ", f.streamID))
	}
	// TODO: block writing data to the stream?
	s.addEvent(newEventStreamStop(f.streamID, f.errorCode))
	s.logFrameProcessed(&f, now)
	return n, nil
}

func (s *Conn) recvFrameCrypto(b []byte, space packetSpace, now time.Time) (int, error) {
	var f cryptoFrame
	n, err := f.decode(b)
	if err != nil {
		return 0, err
	}
	debug("received frame 0x%x: %v", b[0], &f)
	// Push the data to the stream so it can be re-ordered.
	err = s.packetNumberSpaces[space].cryptoStream.pushRecv(f.data, f.offset, false)
	if err != nil {
		return 0, err
	}
	err = s.doHandshake(now)
	if err != nil {
		return 0, err
	}
	s.logFrameProcessed(&f, now)
	return n, nil
}

func (s *Conn) recvFrameNewToken(b []byte, now time.Time) (int, error) {
	// TODO
	var f newTokenFrame
	n, err := f.decode(b)
	if err != nil {
		return 0, err
	}
	debug("received frame 0x%x: %v", b[0], &f)
	s.logFrameProcessed(&f, now)
	return n, nil
}

func (s *Conn) recvFrameStream(b []byte, now time.Time) (int, error) {
	var f streamFrame
	n, err := f.decode(b)
	if err != nil {
		return 0, err
	}
	debug("received frame 0x%x: %v", b[0], &f)
	// Peer can't send on our unidirectional streams.
	local := isStreamLocal(f.streamID, s.isClient)
	bidi := isStreamBidi(f.streamID)
	if local && !bidi {
		debug("peer attempted to sent to our stream: id=%d local=%v bidi=%v", f.streamID, local, bidi)
		return 0, newError(StreamStateError, "writing not permitted")
	}
	if s.flow.canRecv() < uint64(len(f.data)) {
		return 0, errFlowControl
	}
	st, err := s.getOrCreateStream(f.streamID, false)
	if err != nil {
		return 0, err
	}
	err = st.pushRecv(f.data, f.offset, f.fin)
	if err != nil {
		return 0, err
	}
	debug("stream %d received %v", f.streamID, &st.recv)
	// A receiver maintains a cumulative sum of bytes received on all streams,
	// which is used to check for flow control violations
	s.flow.addRecv(len(f.data))
	if st.isReadable() {
		s.addEvent(newEventStreamReadable(f.streamID))
	}
	s.logFrameProcessed(&f, now)
	return n, nil
}

func (s *Conn) recvFrameMaxData(b []byte, now time.Time) (int, error) {
	var f maxDataFrame
	n, err := f.decode(b)
	if err != nil {
		return 0, err
	}
	debug("received frame 0x%x: %v", b[0], &f)
	s.flow.setMaxSend(f.maximumData)
	s.logFrameProcessed(&f, now)
	return n, nil
}

func (s *Conn) recvFrameMaxStreamData(b []byte, now time.Time) (int, error) {
	var f maxStreamDataFrame
	n, err := f.decode(b)
	if err != nil {
		return 0, err
	}
	debug("received frame 0x%x: %v", b[0], &f)
	st, err := s.getOrCreateStream(f.streamID, false)
	if err != nil {
		return 0, err
	}
	st.flow.setMaxSend(f.maximumData)
	s.logFrameProcessed(&f, now)
	return n, nil
}

func (s *Conn) recvFrameMaxStreams(b []byte, now time.Time) (int, error) {
	var f maxStreamsFrame
	n, err := f.decode(b)
	if err != nil {
		return 0, err
	}
	if f.bidi {
		s.streams.setPeerMaxStreamsBidi(f.maximumStreams)
	} else {
		s.streams.setPeerMaxStreamsUni(f.maximumStreams)
	}
	s.logFrameProcessed(&f, now)
	return n, nil
}

// TODO
func (s *Conn) recvFrameDataBlocked(b []byte, now time.Time) (int, error) {
	var f dataBlockedFrame
	n, err := f.decode(b)
	if err != nil {
		return 0, err
	}
	s.logFrameProcessed(&f, now)
	return n, nil
}

// TODO
func (s *Conn) recvFrameStreamDataBlocked(b []byte, now time.Time) (int, error) {
	var f streamDataBlockedFrame
	n, err := f.decode(b)
	if err != nil {
		return 0, err
	}
	s.logFrameProcessed(&f, now)
	return n, nil
}

// TODO
func (s *Conn) recvFrameStreamsBlocked(b []byte, now time.Time) (int, error) {
	var f streamsBlockedFrame
	n, err := f.decode(b)
	if err != nil {
		return 0, err
	}
	s.logFrameProcessed(&f, now)
	return n, nil
}

func (s *Conn) recvFrameConnectionClose(b []byte, space packetSpace, now time.Time) (int, error) {
	var f connectionCloseFrame
	n, err := f.decode(b)
	if err != nil {
		return 0, err
	}
	debug("receiving frame 0x%x: %s (%s)", b[0], &f, errorCodeString(f.errorCode))
	s.setState(stateDraining, now)
	s.setDraining(now)
	s.logFrameProcessed(&f, now)
	return n, nil
}

func (s *Conn) recvFrameHandshakeDone(b []byte, now time.Time) (int, error) {
	var f handshakeDoneFrame
	n, err := f.decode(b)
	if err != nil {
		return 0, err
	}
	if !s.isClient {
		return 0, newError(ProtocolViolation, "unexpected handshake done frame")
	}
	debug("received frame 0x%x: %v", b[0], &f)
	if s.state == stateActive && !s.handshakeConfirmed {
		// Drop client's handshake state when it received done from server
		s.dropPacketSpace(packetSpaceHandshake)
		s.handshakeConfirmed = true
	}
	s.logFrameProcessed(&f, now)
	return n, nil
}

// processAckedPackets is called when the connection got an ACK frame.
func (s *Conn) processAckedPackets(space packetSpace) {
	pnSpace := &s.packetNumberSpaces[space]
	s.recovery.drainAcked(space, func(f frame) {
		switch f := f.(type) {
		case *ackFrame:
			// Stop sending ack for packets when receiving is confirmed
			pnSpace.recvPacketNeedAck.removeUntil(f.largestAck)
		case *cryptoFrame:
			pnSpace.cryptoStream.ackSend(f.offset, uint64(len(f.data)))
		case *streamFrame:
			st := s.streams.get(f.streamID)
			if st != nil {
				complete := st.ackSend(f.offset, uint64(len(f.data)))
				if complete {
					s.addEvent(newEventStreamComplete(f.streamID))
					// TODO: Garbage collect the stream
				}
			}
		case *maxDataFrame:
			s.updateMaxData = false
		case *maxStreamDataFrame:
			st := s.streams.get(f.streamID)
			if st != nil {
				st.ackMaxData()
			}
		}
	})
}

func (s *Conn) doHandshake(now time.Time) error {
	if s.state >= stateActive {
		return nil
	}
	err := s.handshake.doHandshake()
	if err != nil {
		return err
	}
	if s.handshake.HandshakeComplete() {
		params := s.handshake.peerTransportParams()
		debug("peer transport params: %+v", params)
		if err := s.validatePeerTransportParams(params); err != nil {
			return err
		}
		// Update connection state
		s.flow.setMaxSend(params.InitialMaxData)
		s.streams.setPeerMaxStreamsBidi(params.InitialMaxStreamsBidi)
		s.streams.setPeerMaxStreamsUni(params.InitialMaxStreamsUni)
		s.setState(stateActive, now)
		// Update loss recovery state
		s.recovery.setMaxAckDelay(params.MaxAckDelay)
		s.peerParams = *params
		// TODO: early app frames
		s.logParametersSet(params, now)
	}
	return nil
}

// https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#name-authenticating-connection-i
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
	// Initial Source CID must be sent by both endpoints
	if len(p.InitialSourceCID) == 0 || !bytes.Equal(p.InitialSourceCID, s.dcid) {
		return newError(TransportParameterError, "initial source cid")
	}
	if s.isClient {
		if !bytes.Equal(p.OriginalDestinationCID, s.odcid) {
			return newError(TransportParameterError, "original destination cid")
		}
	} else {
		// Original CID and Stateless reset token must not be sent by client
		if len(p.OriginalDestinationCID) > 0 {
			return newError(TransportParameterError, "original destination cid")
		}
		// Stateless reset token
		if len(p.StatelessResetToken) > 0 {
			return newError(TransportParameterError, "reset token")
		}
	}
	if len(s.rscid) > 0 && !bytes.Equal(p.RetrySourceCID, s.rscid) {
		return newError(TransportParameterError, "retry source cid")
	}
	return nil
}

// Read produces data for sending to the client.
func (s *Conn) Read(b []byte) (int, error) {
	now := s.time()
	if !s.drainingTimer.IsZero() {
		return 0, nil
	}
	if err := s.doHandshake(now); err != nil {
		return 0, err
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
	// https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#packet-coalesce
	if space < packetSpaceApplication {
		avail := minInt(s.maxPacketSize(), len(b))
		if avail-n >= 96 { // Enough for a handshake packet
			nextSpace := s.writeSpace()
			if nextSpace < packetSpaceCount && nextSpace > space {
				m, err := s.send(b[n:avail], nextSpace, now)
				if err != nil {
					return 0, err
				}
				n += m
			}
		}
	}
	s.logRecovery(now)
	return n, nil
}

func (s *Conn) send(b []byte, space packetSpace, now time.Time) (int, error) {
	pnSpace := &s.packetNumberSpaces[space]
	if !pnSpace.canEncrypt() {
		return 0, newError(InternalError, sprint("cannot encrypt space ", space.String()))
	}
	avail := minInt(s.maxPacketSize(), len(b))
	p := packet{
		typ: packetTypeFromSpace(space),
		header: packetHeader{
			version: s.version,
			dcid:    s.dcid,
			scid:    s.scid,
		},
		token:        s.token,
		packetNumber: pnSpace.nextPacketNumber,
		payloadLen:   avail,
	}
	// Calculate what is left for payload
	overhead := pnSpace.sealer.aead.Overhead()
	pktOverhead := p.encodedLen() + overhead - p.payloadLen // Packet length without payload
	left := avail - pktOverhead
	if left <= minPayloadLength {
		// May due to congestion control
		debug("short buffer: avail=%d left=%d", avail, left)
		return 0, nil
	}
	s.processLostPackets(space, now)
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
	if p.payloadLen < minPayloadLength {
		n := minPayloadLength - p.payloadLen
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
	op.sentBytes = uint64(p.packetSize)
	// Finish preparing sending packet
	debug("sending packet %s %s", &p, op)
	s.onPacketSent(op, space)
	// TODO: Log real payload length without crypto overhead
	s.logPacketSent(&p, op.frames, now)
	// https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#name-abandoning-initial-packets
	// A client stops both sending and processing Initial packets when it sends its first Handshake packet.
	if p.typ == packetTypeHandshake {
		if s.isClient && p.packetNumber == 0 {
			s.dropPacketSpace(packetSpaceInitial)
		}
		if s.state < stateHandshake {
			s.setState(stateHandshake, now)
		}
	}
	if p.packetNumber == 0 && !s.isClient && space == packetSpaceApplication {
		// First Application packet from server is HandshakeDone
		s.dropPacketSpace(packetSpaceHandshake)
	}
	return p.packetSize, nil
}

func (s *Conn) writeSpace() packetSpace {
	// On error, send packet in the latest space available.
	if s.closeFrame != nil {
		space := s.handshake.writeSpace()
		if space == packetSpaceApplication && !s.handshake.HandshakeComplete() {
			// Downgrade to handshake packet space as the handshake is not complete yet
			return packetSpaceHandshake
		}
		return space
	}
	for i := packetSpaceInitial; i < packetSpaceCount; i++ {
		if !s.packetNumberSpaces[i].canEncrypt() {
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
		if s.packetNumberSpaces[i].ready() || len(s.recovery.lost[i]) > 0 || s.recovery.lossProbes[i] > 0 {
			return i
		}
	}
	// If there are flushable streams, use Application.
	if s.state >= stateActive && (s.streams.hasFlushable() || s.flow.shouldUpdateMaxRecv()) {
		return packetSpaceApplication
	}
	// Nothing to send
	return packetSpaceCount
}

func (s *Conn) maxPacketSize() int {
	var n uint64
	if s.state >= stateActive && s.peerParams.MaxUDPPayloadSize > 0 {
		n = s.peerParams.MaxUDPPayloadSize
		if n > MaxPacketSize {
			n = MaxPacketSize
		}
	} else {
		n = MinInitialPacketSize
	}
	cwnd := s.recovery.congestion.canSend()
	if n > cwnd {
		n = cwnd
	}
	return int(n)
}

func (s *Conn) processLostPackets(space packetSpace, now time.Time) {
	s.logPacketsLost(s.recovery.lost[space], space, now)
	pnSpace := &s.packetNumberSpaces[space]
	s.recovery.drainLost(space, func(f frame) {
		debug("lost frame space=%v %v", space, f)
		switch f := f.(type) {
		case *ackFrame:
			pnSpace.ackElicited = true
		case *cryptoFrame:
			// Push data back to send again
			err := pnSpace.cryptoStream.pushSend(f.data, f.offset, false)
			if err != nil {
				debug("process lost crypto frame %s: %v", f, err)
			}
		case *streamFrame:
			st := s.streams.get(f.streamID)
			if st != nil {
				// Push data back to send again
				err := st.pushSend(f.data, f.offset, f.fin)
				if err != nil {
					debug("process lost stream frame %s: %v", f, err)
				}
			}
		case *handshakeDoneFrame:
			s.handshakeConfirmed = false
		}
	})
}

func (s *Conn) sendFrames(op *sentPacket, space packetSpace, left int, now time.Time) int {
	pnSpace := &s.packetNumberSpaces[space]
	payloadLen := 0
	// CONNECTION_CLOSE
	if s.closeFrame != nil {
		n := s.closeFrame.encodedLen()
		if left >= n {
			op.addFrame(s.closeFrame)
			payloadLen += n
			left -= n
			s.setDraining(now)
		}
	}
	if s.state < stateDraining {
		// ACK
		if f := s.sendFrameAck(pnSpace, now); f != nil {
			n := f.encodedLen()
			if left >= n {
				op.addFrame(f)
				payloadLen += n
				left -= n
				pnSpace.ackElicited = false
			}
		}
		// CRYPTO
		if f := s.sendFrameCrypto(pnSpace, left); f != nil {
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
					s.handshakeConfirmed = true
				}
			}
			// MAX_DATA
			if f := s.sendFrameMaxData(); f != nil {
				n := f.encodedLen()
				if left >= n {
					op.addFrame(f)
					payloadLen += n
					left -= n
					s.updateMaxData = true
					s.flow.commitMaxRecv()
				}
			}
			// MAX_STREAM_DATA
			for id, st := range s.streams.streams {
				if f := s.sendFrameMaxStreamData(id, st); f != nil {
					n := f.encodedLen()
					if left >= n {
						op.addFrame(f)
						payloadLen += n
						left -= n
						st.flow.commitMaxRecv()
					}
				}
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
				}
			}
		}
		// PING
		if s.recovery.lossProbes[space] > 0 {
			if op.ackEliciting {
				// Do not need PING if an ack-elicitng frame is sent
				s.recovery.lossProbes[space]--
			} else if f := s.sendFramePing(left); f != nil {
				n := f.encodedLen()
				op.addFrame(f)
				payloadLen += n
				left -= n
				s.recovery.lossProbes[space]--
			}
		}
	}
	return payloadLen
}

func (s *Conn) onPacketSent(op *sentPacket, space packetSpace) {
	s.recovery.onPacketSent(op, space)
	s.packetNumberSpaces[space].nextPacketNumber++
	// (Re)start the idle timer if we are sending the first ACK-eliciting
	// packet since last receiving a packet.
	if op.ackEliciting {
		if !s.ackElicitingSent && s.localParams.MaxIdleTimeout > 0 {
			s.idleTimer = op.timeSent.Add(s.localParams.MaxIdleTimeout)
		}
		s.ackElicitingSent = true
	}
}

// Timeout returns the amount of time until the next timeout event.
// A negative timeout means that the timer should be disarmed.
func (s *Conn) Timeout() time.Duration {
	if s.state == stateClosed {
		return -1
	}
	var deadline time.Time
	if !s.drainingTimer.IsZero() {
		deadline = s.drainingTimer
	} else if !s.recovery.lossDetectionTimer.IsZero() {
		deadline = s.recovery.lossDetectionTimer
	} else if !s.idleTimer.IsZero() {
		deadline = s.idleTimer
	} else {
		return -1
	}
	timeout := deadline.Sub(s.time())
	if timeout < 0 {
		timeout = 0
	}
	return timeout
}

func (s *Conn) checkTimeout(now time.Time) {
	if !s.drainingTimer.IsZero() && !now.Before(s.drainingTimer) {
		debug("draining timeout expired")
		s.setState(stateClosed, now)
		return
	}
	if !s.idleTimer.IsZero() && !now.Before(s.idleTimer) {
		debug("idle timeout expired")
		s.setState(stateClosed, now)
		return
	}
	if !s.recovery.lossDetectionTimer.IsZero() && !now.Before(s.recovery.lossDetectionTimer) {
		s.recovery.onLossDetectionTimeout(now)
	}
}

// Close sets the connection to closing state.
// https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#draining
func (s *Conn) Close(app bool, errCode uint64, reason string) {
	if !s.drainingTimer.IsZero() || s.closeFrame != nil || s.state >= stateDraining {
		return
	}
	debug("set close code=%d", errCode)
	s.closeFrame = &connectionCloseFrame{
		application:  app,
		errorCode:    errCode,
		reasonPhrase: []byte(reason),
	}
	s.setState(stateDraining, s.time())
}

// IsEstablished returns true of handshake is complete and the connection is not closing.
func (s *Conn) IsEstablished() bool {
	return s.state == stateActive
}

// IsClosed returns true when the connection is in Closed state and no longer send or receive packets.
func (s *Conn) IsClosed() bool {
	return s.state == stateClosed
}

// Events consumes received events. It appends to provided events slice
// and clear received events.
func (s *Conn) Events(events []Event) []Event {
	events = append(events, s.events...)
	for i := range s.events {
		s.events[i] = Event{}
	}
	s.events = s.events[:0]
	return events
}

// Stream returns an openned stream or create a local stream if it does not exist.
// Client-initiated streams have even-numbered stream IDs and
// server-initiated streams have odd-numbered stream IDs.
func (s *Conn) Stream(id uint64) (*Stream, error) {
	return s.getOrCreateStream(id, true)
}

func (s *Conn) sendFrameAck(pnSpace *packetNumberSpace, now time.Time) *ackFrame {
	if pnSpace.ackElicited {
		ackDelay := uint64(now.Sub(pnSpace.largestRecvPacketTime).Microseconds())
		ackDelay /= 1 << s.peerParams.AckDelayExponent
		return newAckFrame(ackDelay, pnSpace.recvPacketNeedAck)
	}
	return nil
}

func (s *Conn) sendFrameCrypto(pnSpace *packetNumberSpace, left int) *cryptoFrame {
	left -= maxCryptoFrameOverhead
	if left > 0 {
		data, offset, _ := pnSpace.cryptoStream.popSend(left)
		if len(data) > 0 {
			return newCryptoFrame(data, offset)
		}
	}
	return nil
}

func (s *Conn) sendFrameStream(id uint64, st *Stream, left int) *streamFrame {
	allowed := int(s.flow.canSend())
	left -= maxStreamFrameOverhead
	if left > allowed {
		left = allowed
	}
	if left > 0 {
		data, offset, fin := st.popSend(left)
		if len(data) > 0 || fin {
			return newStreamFrame(id, data, offset, fin)
		}
	}
	return nil
}

func (s *Conn) sendFrameMaxData() *maxDataFrame {
	if s.updateMaxData || s.flow.shouldUpdateMaxRecv() {
		return newMaxDataFrame(s.flow.maxRecvNext)
	}
	return nil
}

func (s *Conn) sendFrameMaxStreamData(id uint64, st *Stream) *maxStreamDataFrame {
	if st.updateMaxData {
		return newMaxStreamDataFrame(id, st.flow.maxRecvNext)
	}
	return nil
}

func (s *Conn) sendFrameHandshakeDone() *handshakeDoneFrame {
	// HandshakeDone is sent only by server.
	if s.isClient || s.state != stateActive || s.handshakeConfirmed {
		return nil
	}
	return &handshakeDoneFrame{}
}

func (s *Conn) sendFramePing(left int) *pingFrame {
	if left < 1 {
		return nil
	}
	return &pingFrame{}
}

func (s *Conn) setDraining(now time.Time) {
	if s.drainingTimer.IsZero() {
		s.drainingTimer = now.Add(s.recovery.probeTimeout() * 3)
	}
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
	bidi := isStreamBidi(id)
	st, err := s.streams.create(id, local, bidi)
	if err != nil {
		return nil, err
	}
	var maxRecv, maxSend uint64
	if local {
		if bidi {
			maxRecv = s.localParams.InitialMaxStreamDataBidiLocal
			maxSend = s.peerParams.InitialMaxStreamDataBidiRemote
		} else {
			maxRecv = 0
			maxSend = s.peerParams.InitialMaxStreamDataUni
		}
	} else {
		if bidi {
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
	return st, nil
}

func (s *Conn) setState(state connectionState, now time.Time) {
	if s.logEventFn != nil {
		s.logEventFn(newLogEventConnectionState(now, s.state, state))
	}
	s.state = state
	debug("set state=%v", state)
}

func (s *Conn) dropPacketSpace(space packetSpace) {
	s.packetNumberSpaces[space].drop()
	s.recovery.onPacketNumberSpaceDiscarded(space)
	debug("dropped space=%v", space)
}

func (s *Conn) addStreamEvents() {
	if s.state != stateActive || s.flow.canSend() == 0 {
		return
	}
	for id, st := range s.streams.streams {
		if st.isWriteable() {
			s.addEvent(newEventStreamWritable(id))
		}
	}
}

func (s *Conn) addEvent(e Event) {
	s.events = append(s.events, e)
}

// rand uses tls.Config.Rand if available.
func (s *Conn) rand(b []byte) error {
	var err error
	if s.handshake.tlsConfig != nil && s.handshake.tlsConfig.Rand != nil {
		_, err = io.ReadFull(s.handshake.tlsConfig.Rand, b)
	} else {
		_, err = rand.Read(b)
	}
	return err
}

// time uses tls.Config.Time if available.
func (s *Conn) time() time.Time {
	if s.handshake.tlsConfig != nil && s.handshake.tlsConfig.Time != nil {
		return s.handshake.tlsConfig.Time()
	}
	return time.Now()
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// OnLogEvent sets handler for received events.
func (s *Conn) OnLogEvent(fn func(LogEvent)) {
	s.logEventFn = fn
}

func (s *Conn) logPacketDropped(p *packet, now time.Time) {
	if s.logEventFn != nil {
		s.logEventFn(newLogEventPacket(now, logEventPacketDropped, p))
	}
}

func (s *Conn) logPacketReceived(p *packet, now time.Time) {
	if s.logEventFn != nil {
		s.logEventFn(newLogEventPacket(now, logEventPacketReceived, p))
	}
}

func (s *Conn) logPacketSent(p *packet, frames []frame, now time.Time) {
	if s.logEventFn != nil {
		s.logEventFn(newLogEventPacket(now, logEventPacketSent, p))
		for _, f := range frames {
			s.logEventFn(newLogEventFrame(now, logEventFramesProcessed, f))
		}
	}
}

func (s *Conn) logPacketsLost(packets []*sentPacket, space packetSpace, now time.Time) {
	if s.logEventFn != nil {
		p := packet{
			typ: packetTypeFromSpace(space),
		}
		for _, sp := range packets {
			p.packetNumber = sp.packetNumber
			s.logEventFn(newLogEventPacket(now, logEventPacketLost, &p))
		}
	}
}

func (s *Conn) logFrameProcessed(f frame, now time.Time) {
	if s.logEventFn != nil {
		s.logEventFn(newLogEventFrame(now, logEventFramesProcessed, f))
	}
}

func (s *Conn) logParametersSet(p *Parameters, now time.Time) {
	if s.logEventFn != nil {
		s.logEventFn(newLogEventParametersSet(now, p))
	}
}

func (s *Conn) logRecovery(now time.Time) {
	if s.logEventFn != nil {
		s.logEventFn(newLogEventRecovery(now, &s.recovery))
	}
}
