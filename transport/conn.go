package transport

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"time"
)

type connectionState int

const (
	stateInitial connectionState = iota
	stateHandshake
	stateEstablished
	stateClosing
	stateClosed
)

// Conn is a QUIC connection.
type Conn struct {
	isClient bool
	version  uint32

	scid  []byte
	dcid  []byte
	odcid []byte
	token []byte

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

	closeFrame *connectionCloseFrame // Error to be send to peer

	idleTimer     time.Time // Idle timeout expiration time.
	drainingTimer time.Time // Draining timeout expiration time.

	events []interface{}
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
	s := &Conn{
		version:     config.Version,
		isClient:    isClient,
		localParams: config.Params,
		state:       stateInitial,
	}
	s.handshake.init(s, config.TLS)
	now := s.time() // Depends on handshake TLS config
	for i := range s.packetNumberSpaces {
		s.packetNumberSpaces[i].init()
	}
	s.streams.init(s.localParams.InitialMaxStreamsBidi, s.localParams.InitialMaxStreamsUni)
	s.recovery.init(now)
	s.flow.init(s.localParams.InitialMaxData)
	if len(scid) > 0 {
		s.scid = append(s.scid[:0], scid...)
	}
	if len(odcid) > 0 {
		s.odcid = append(s.odcid[:0], odcid...)
		s.localParams.OriginalCID = s.odcid
	}
	if isClient {
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
			if e, ok := err.(*Error); ok {
				s.Close(false, e.Code, "")
			}
			return n, err
		}
		n += i
	}
	s.checkTimeout(now)
	return n, nil
}

func (s *Conn) deriveInitialKeyMaterial(cid []byte) {
	aead := newInitialAEAD(cid)
	space := &s.packetNumberSpaces[packetSpaceInitial]
	if s.isClient {
		space.opener, space.sealer = aead.server, aead.client
	} else {
		space.opener, space.sealer = aead.client, aead.server
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
		return s.recvPacketVersionNegotiation(b, &p)
	case packetTypeRetry:
		return s.recvPacketRetry(b, &p)
	case packetTypeInitial:
		return s.recvPacketInitial(b, &p, now)
	case packetTypeHandshake:
		return s.recvPacketHandshake(b, &p, now)
	case packetTypeShort:
		return s.recvPacketShort(b, &p, now)
	default:
		return 0, fmt.Errorf("unsupported packet type: %d", p.typ)
	}
}

// https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#version-negotiation
func (s *Conn) recvPacketVersionNegotiation(b []byte, p *packet) (int, error) {
	// VN packet can only be sent by server
	if !s.isClient || s.didVersionNegotiation || s.state != stateInitial ||
		!bytes.Equal(p.header.dcid, s.scid) || !bytes.Equal(p.header.scid, s.dcid) {
		debug("dropped packet %v", p)
		return len(b), nil
	}
	n, err := p.decodeBody(b[p.headerLen:])
	if err != nil {
		return 0, err
	}
	debug("received packet %v", p)
	var newVersion uint32
	for _, v := range p.supportedVersions {
		if v == ProtocolVersion {
			newVersion = v
			break
		}
	}
	if newVersion == 0 {
		return 0, fmt.Errorf("unsupported version: %v", p.supportedVersions)
	}
	s.version = newVersion
	s.didVersionNegotiation = true
	// Reset connection state to send another initial packet
	s.gotPeerCID = false
	s.recovery.dropUnackedData(packetSpaceInitial)
	s.packetNumberSpaces[packetSpaceInitial].reset()
	s.handshake.reset()
	s.handshake.setTransportParams(&s.localParams)
	return p.headerLen + n, nil
}

// https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#validate-handshake
func (s *Conn) recvPacketRetry(b []byte, p *packet) (int, error) {
	// Retry packet can only be sent by server
	// Packet's SCID must not be equal to the client's DCID.
	if !s.isClient || s.didRetry || s.state != stateInitial ||
		!bytes.Equal(p.header.dcid, s.scid) || bytes.Equal(p.header.scid, s.dcid) {
		debug("dropped packet %v", p)
		return len(b), nil
	}
	_, err := p.decodeBody(b[p.headerLen:])
	if err != nil {
		return 0, err
	}
	// Verify token and integrity tag
	if len(p.token) == 0 || !verifyRetryIntegrity(b, s.dcid) {
		return 0, errInvalidPacket
	}
	debug("received packet %v", p)
	s.token = append(s.token[:0], p.token...)
	s.didRetry = true
	// Update CIDs and crypto: dcid => odcid, header.scid => dcid
	s.odcid = append(s.odcid[:0], s.dcid...)
	s.dcid = append(s.dcid[:0], p.header.scid...)
	s.deriveInitialKeyMaterial(s.dcid)
	// Reset connection state to send another initial packet
	s.gotPeerCID = false
	s.recovery.dropUnackedData(packetSpaceInitial)
	s.packetNumberSpaces[packetSpaceInitial].reset()
	s.handshake.reset()
	s.handshake.setTransportParams(&s.localParams)
	return len(b), nil // p.headerLen + bodyLen + retryIntegrityTagLen
}

func (s *Conn) recvPacketInitial(b []byte, p *packet, now time.Time) (int, error) {
	if s.gotPeerCID && (!bytes.Equal(p.header.dcid, s.scid) || !bytes.Equal(p.header.scid, s.dcid)) {
		debug("dropped packet %v", p)
		return len(b), nil
	}
	if s.isClient && !s.gotPeerCID {
		// Replace the randomly generated destination connection ID with
		// the one supplied by the server.
		s.dcid = append(s.dcid[:0], p.header.scid...)
		s.gotPeerCID = true
	}
	if !s.derivedInitialSecrets { // Server side
		s.deriveInitialKeyMaterial(p.header.dcid)
		s.dcid = append(s.dcid[:0], p.header.scid...)
		s.gotPeerCID = true
	}
	return s.recvPacket(b, p, packetSpaceInitial, now)
}

func (s *Conn) recvPacketHandshake(b []byte, p *packet, now time.Time) (int, error) {
	if !bytes.Equal(p.header.dcid, s.scid) || !bytes.Equal(p.header.scid, s.dcid) {
		debug("dropped packet %v", p)
		return len(b), nil
	}
	return s.recvPacket(b, p, packetSpaceHandshake, now)
}

func (s *Conn) recvPacketShort(b []byte, p *packet, now time.Time) (int, error) {
	if !bytes.Equal(p.header.dcid, s.scid) {
		debug("dropped packet %v", p)
		return len(b), nil
	}
	return s.recvPacket(b, p, packetSpaceApplication, now)
}

func (s *Conn) recvPacket(b []byte, p *packet, space packetSpace, now time.Time) (int, error) {
	pnSpace := &s.packetNumberSpaces[space]
	if !pnSpace.canDecrypt() {
		debug("dropped undecryptable packet %v space=%d", &p.header, space)
		return len(b), nil
	}
	payload, length, err := pnSpace.decryptPacket(b, p)
	if err != nil {
		return 0, err
	}
	debug("decrypted packet %v payload=%d", p, len(payload))
	if pnSpace.isPacketReceived(p.packetNumber) {
		// Ignore duplicate packet
		return length, nil
	}
	if err = s.recvFrames(payload, space, now); err != nil {
		return 0, err
	}

	// Process acked frames
	s.processAckedPackets(space)

	// Mark this packet received
	pnSpace.onPacketReceived(p.packetNumber, now)

	if s.localParams.MaxIdleTimeout > 0 {
		s.idleTimer = now.Add(s.localParams.MaxIdleTimeout)
	}
	// An Handshake packet has been received from the client and has been successfully processed,
	// so we can drop the initial state and consider the client's address to be verified.
	if !s.isClient && space == packetSpaceHandshake && s.state == stateInitial {
		s.state = stateHandshake
		s.dropPacketSpace(packetSpaceInitial)
	}
	s.ackElicitingSent = false
	return length, nil
}

// https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#frames
// recvFrames sets ackElicited if a received frame is an ack eliciting.
func (s *Conn) recvFrames(b []byte, space packetSpace, now time.Time) error {
	// To avoid sending an ACK in response to an ACK-only packet, we need
	// to keep track of whether this packet contains any frame other than
	// ACK, PADDING and CONNECTION_CLOSE.
	var ackElicited = false
	for len(b) > 0 {
		var typ uint64
		n := getVarint(b, &typ)
		if n == 0 {
			return errInvalidFrame
		}
		var err error
		// TODO: Check allowed frames for current packet type
		switch {
		case typ == frameTypePadding:
			var f paddingFrame
			n, err = f.decode(b)
		case typ == frameTypePing:
			// Will ack
		case typ == frameTypeAck:
			n, err = s.recvFrameAck(b, space, now)
		case typ == frameTypeResetStream:
			n, err = s.recvFrameResetStream(b)
		case typ == frameTypeStopSending:
			n, err = s.recvFrameStopSending(b)
		case typ == frameTypeCrypto:
			n, err = s.recvFrameCrypto(b, space)
		case typ == frameTypeNewToken:
			n, err = s.recvFrameNewToken(b)
		case typ >= frameTypeStream && typ <= frameTypeStreamEnd:
			n, err = s.recvFrameStream(b)
		case typ == frameTypeMaxData:
			n, err = s.recvFrameMaxData(b)
		case typ == frameTypeMaxStreamData:
			n, err = s.recvFrameMaxStreamData(b)
		case typ == frameTypeMaxStreamsBidi || typ == frameTypeMaxStreamsUni:
			n, err = s.recvFrameMaxStreams(b)
		case typ == frameTypeDataBlocked:
			n, err = s.recvFrameDataBlocked(b)
		case typ == frameTypeStreamDataBlocked:
			n, err = s.recvFrameStreamDataBlocked(b)
		case typ == frameTypeStreamsBlockedBidi || typ == frameTypeStreamsBlockedUni:
			n, err = s.recvFrameStreamsBlocked(b)
		case typ == frameTypeConnectionClose || typ == frameTypeApplicationClose:
			n, err = s.recvFrameConnClose(b, space, now)
		case typ == frameTypeHanshakeDone:
			n, err = s.recvFrameHandshakeDone(b)
		default:
			return newError(FrameEncodingError, "unsupported frame 0x%x", typ)
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

func (s *Conn) recvFrameAck(b []byte, space packetSpace, now time.Time) (int, error) {
	var f ackFrame
	n, err := f.decode(b)
	if err != nil {
		return 0, err
	}
	debug("received frame 0x%x: %v", b[0], &f)
	ranges := f.toRangeSet()
	if ranges == nil {
		return 0, newError(FrameEncodingError, "invalid ack ranges: %v", f)
	}
	ackDelay := time.Duration((1<<s.peerParams.AckDelayExponent)*f.ackDelay) * time.Microsecond
	s.recovery.onAckReceived(ranges, ackDelay, space, now)

	if !s.packetNumberSpaces[space].firstPacketAcked {
		s.packetNumberSpaces[space].firstPacketAcked = true
		// https://quicwg.org/base-drafts/draft-ietf-quic-tls.html#name-handshake-confirmed
		// When we receive an ACK for a 1-RTT packet after handshake completion,
		// it means the handshake has been confirmed.
		if space == packetSpaceApplication && s.state == stateEstablished {
			s.dropPacketSpace(packetSpaceHandshake)
			if s.isClient && !s.handshakeConfirmed {
				s.handshakeConfirmed = true
			}
		}
	}
	return n, nil
}

func (s *Conn) recvFrameResetStream(b []byte) (int, error) {
	var f resetStreamFrame
	n, err := f.decode(b)
	if err != nil {
		return 0, err
	}
	debug("received frame 0x%x: %v", b[0], &f)
	local := isStreamLocal(f.streamID, s.isClient)
	bidi := isStreamBidi(f.streamID)
	if local && !bidi {
		debug("peer attempted to reset our receive-only stream: id=%d local=%v bidi=%v", f.streamID, local, bidi)
		return 0, newError(StreamStateError, "ResetStreamFrame: invalid stream id: %d", f.streamID)
	}
	st, err := s.getOrCreateStream(f.streamID, false)
	if err != nil {
		return 0, err
	}
	_, err = st.recv.reset(f.finalSize)
	if err != nil {
		return 0, err
	}
	s.addEvent(StreamResetEvent{
		StreamID:  f.streamID,
		ErrorCode: f.errorCode,
	})
	return n, nil
}

func (s *Conn) recvFrameStopSending(b []byte) (int, error) {
	var f stopSendingFrame
	n, err := f.decode(b)
	if err != nil {
		return 0, err
	}
	debug("received frame 0x%x: %v", b[0], &f)
	// STOP_SENDING on a receive-only stream is a fatal error.
	local := isStreamLocal(f.streamID, s.isClient)
	bidi := isStreamBidi(f.streamID)
	if !local && !bidi {
		debug("peer attempted to stop sending their receive-only stream: id=%d local=%v bidi=%v", f.streamID, local, bidi)
		return 0, newError(StreamStateError, "StopSendingFrame: invalid stream id: %d", f.streamID)
	}
	s.addEvent(StreamStopEvent{
		StreamID:  f.streamID,
		ErrorCode: f.errorCode,
	})
	return n, nil
}

func (s *Conn) recvFrameCrypto(b []byte, space packetSpace) (int, error) {
	var f cryptoFrame
	n, err := f.decode(b)
	if err != nil {
		return 0, err
	}
	debug("received frame 0x%x: %v", b[0], &f)
	s.packetNumberSpaces[space].onCryptoReceived(f.data, f.offset)
	err = s.doHandshake()
	if err != nil {
		return 0, err
	}
	return n, nil
}

func (s *Conn) recvFrameNewToken(b []byte) (int, error) {
	// TODO
	var f newTokenFrame
	n, err := f.decode(b)
	if err != nil {
		return 0, err
	}
	debug("received frame 0x%x: %v", b[0], &f)
	return n, nil
}

func (s *Conn) recvFrameStream(b []byte) (int, error) {
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
		return 0, newError(StreamStateError, "StreamFrame: invalid stream id: %d", f.streamID)
	}
	if !s.flow.canRecv(len(f.data)) {
		return 0, errFlowControl
	}
	st, err := s.getOrCreateStream(f.streamID, false)
	if err != nil {
		return 0, err
	}
	st.recv.push(f.data, f.offset, f.fin)
	debug("stream %d received %v", f.streamID, &st.recv)
	s.flow.addRecv(len(f.data))
	s.addEvent(StreamRecvEvent{
		StreamID: f.streamID,
	})
	return n, nil
}

func (s *Conn) recvFrameMaxData(b []byte) (int, error) {
	var f maxDataFrame
	n, err := f.decode(b)
	if err != nil {
		return 0, err
	}
	debug("received frame 0x%x: %v", b[0], &f)
	s.flow.setMaxSend(f.maximumData)
	return n, nil
}

func (s *Conn) recvFrameMaxStreamData(b []byte) (int, error) {
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
	st.send.setMaxData(f.maximumData)
	return n, nil
}

func (s *Conn) recvFrameMaxStreams(b []byte) (int, error) {
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
	return n, nil
}

// TODO
func (s *Conn) recvFrameDataBlocked(b []byte) (int, error) {
	var f dataBlockedFrame
	return f.decode(b)
}

// TODO
func (s *Conn) recvFrameStreamDataBlocked(b []byte) (int, error) {
	var f streamDataBlockedFrame
	return f.decode(b)
}

// TODO
func (s *Conn) recvFrameStreamsBlocked(b []byte) (int, error) {
	var f streamsBlockedFrame
	return f.decode(b)
}

func (s *Conn) recvFrameConnClose(b []byte, space packetSpace, now time.Time) (int, error) {
	var f connectionCloseFrame
	n, err := f.decode(b)
	if err != nil {
		return 0, err
	}
	debug("receiving frame 0x%x: %s", b[0], &f)
	s.state = stateClosing
	s.setDraining(now)
	return n, nil
}

func (s *Conn) recvFrameHandshakeDone(b []byte) (int, error) {
	var f handshakeDoneFrame
	n, err := f.decode(b)
	if err != nil {
		return 0, err
	}
	if !s.isClient {
		return 0, errInvalidPacket
	}
	debug("received frame 0x%x: %v", b[0], &f)
	if s.state == stateEstablished && !s.handshakeConfirmed {
		// Drop client's handshake state when it received done from server
		s.dropPacketSpace(packetSpaceHandshake)
		s.handshakeConfirmed = true
	}
	return n, nil
}

// processAckedPackets is called when the connection got an ACK frame.
func (s *Conn) processAckedPackets(space packetSpace) {
	s.recovery.drainAcked(space, func(f frame) {
		pnSpace := &s.packetNumberSpaces[space]
		switch f := f.(type) {
		case *ackFrame:
			// Stop sending ack for packets when receiving is confirmed
			pnSpace.recvPacketNeedAck.removeUntil(f.largestAck)
		case *streamFrame:
			// TODO: Ack Stream frame and send event Send Stream Complete
		}
	})
}

func (s *Conn) doHandshake() error {
	if s.state >= stateEstablished {
		return nil
	}
	err := s.handshake.doHandshake()
	if err != nil {
		return err
	}
	if s.handshake.HandshakeComplete() {
		params := s.handshake.peerTransportParams()
		debug("handshaked peer transport params: %+v", params)
		if err := s.validatePeerTransportParams(params); err != nil {
			return err
		}
		s.flow.setMaxSend(params.InitialMaxData)
		s.streams.setPeerMaxStreamsBidi(params.InitialMaxStreamsBidi)
		s.streams.setPeerMaxStreamsUni(params.InitialMaxStreamsUni)
		s.recovery.maxAckDelay = params.MaxAckDelay
		s.peerParams = *params
		// TODO: early app frames
		s.state = stateEstablished
	}
	return nil
}

func (s *Conn) validatePeerTransportParams(p *Parameters) error {
	if p == nil {
		return newError(TransportParameterError, "TransportParameter must present")
	}
	if s.isClient {
		if !bytes.Equal(p.OriginalCID, s.odcid) {
			return newError(TransportParameterError, "TransportParameter: original cid mismatched")
		}
	} else {
		// Original CID and Stateless reset token must not be sent by client
		if len(p.OriginalCID) > 0 {
			return newError(TransportParameterError, "TransportParameter: original cid must not present")
		}
		// Stateless reset token
		if len(p.StatelessResetToken) > 0 {
			return newError(TransportParameterError, "TransportParameter: reset token must not present")
		}
	}
	return nil
}

// Read produces data for sending to the client.
func (s *Conn) Read(b []byte) (int, error) {
	now := s.time()
	if !s.drainingTimer.IsZero() {
		return 0, nil
	}
	if err := s.doHandshake(); err != nil {
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
				return n + m, nil
			}
		}
	}
	return n, nil
}

func (s *Conn) send(b []byte, space packetSpace, now time.Time) (int, error) {
	pnSpace := &s.packetNumberSpaces[space]
	if !pnSpace.canEncrypt() {
		return 0, fmt.Errorf("cannot encrypt space=%d", space)
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
		return 0, errShortBuffer
	}
	s.processLostPackets(space)
	// Add frames
	op := outgoingPacket{
		packetNumber: p.packetNumber,
		frames:       make([]frame, 0, 8),
		timeSent:     now,
	}
	p.payloadLen = s.sendFrames(&op, space, left, now)
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
			op.addInFlightFrame(newPaddingFrame(n))
			p.payloadLen += n
			left -= n
		}
	}
	if p.payloadLen < minPayloadLength {
		n := minPayloadLength - p.payloadLen
		if n > left {
			return 0, errShortBuffer
		}
		op.addInFlightFrame(newPaddingFrame(n))
		p.payloadLen += n
		left -= n
	}
	p.payloadLen += overhead
	payloadOffset, err := p.encode(b)
	if err != nil {
		return 0, err
	}
	// Encode frames to sending packet then encrypt it
	n, err := encodeFrames(b[payloadOffset:], op.frames)
	if err != nil {
		return 0, err
	}
	n += payloadOffset + overhead
	if n != payloadOffset+p.payloadLen || n > len(b) {
		return 0, fmt.Errorf("encoded payload length %d exceeded buffer capacity %d", n, len(b))
	}
	pnSpace.encryptPacket(b[:n], &p)
	op.size = uint64(n)
	// Finish preparing sending packet
	debug("sending packet %s %s", &p, &op)
	s.onPacketSent(&op, space)
	// On the client, drop initial state after sending an Handshake packet.
	if s.isClient && p.typ == packetTypeHandshake && s.state == stateInitial {
		s.state = stateHandshake
		s.dropPacketSpace(packetSpaceInitial)
	}
	return n, nil
}

func (s *Conn) writeSpace() packetSpace {
	// On error or probe, send packet in the latest space available.
	if s.closeFrame != nil || s.recovery.probes > 0 {
		return s.handshake.writeSpace()
	}
	for i := packetSpaceInitial; i < packetSpaceCount; i++ {
		// Only use application packet number space when handshake is complete.
		if i == packetSpaceApplication && s.state < stateEstablished {
			continue
		}
		if s.packetNumberSpaces[i].ready() {
			return i
		}
		if len(s.recovery.lost[i]) > 0 {
			return i
		}
	}
	// If there are flushable streams, use Application.
	if s.state >= stateEstablished && s.streams.hasFlusable() {
		return packetSpaceApplication
	}
	// Nothing to send
	return packetSpaceCount
}

func (s *Conn) maxPacketSize() int {
	if s.state >= stateEstablished && s.peerParams.MaxUDPPayloadSize > 0 {
		n := int(s.peerParams.MaxUDPPayloadSize)
		if n >= MinInitialPacketSize && n <= MaxPacketSize {
			return n
		}
	}
	return MinInitialPacketSize
}

func (s *Conn) processLostPackets(space packetSpace) {
	s.recovery.drainLost(space, func(f frame) {
		debug("lost frame %v", f)
		switch f := f.(type) {
		case *ackFrame:
			s.packetNumberSpaces[space].ackElicited = true
		case *cryptoFrame:
			s.packetNumberSpaces[space].cryptoStream.send.push(f.data, f.offset, false)
		case *streamFrame:
			s.lostFrameStream(f)
		case *handshakeDoneFrame:
			s.handshakeConfirmed = false
		}
	})
}

func (s *Conn) sendFrames(op *outgoingPacket, space packetSpace, left int, now time.Time) int {
	pnSpace := &s.packetNumberSpaces[space]
	payloadLen := 0
	// Close
	if s.closeFrame != nil {
		n := s.closeFrame.encodedLen()
		if left >= n {
			op.addAckElicitingFrame(s.closeFrame)
			payloadLen += n
			left -= n
			s.setDraining(now)
		}
	}
	if s.state < stateClosing {
		// Ack
		if f := s.sendFrameAck(pnSpace, now); f != nil {
			n := f.encodedLen()
			if left >= n {
				op.addFrame(f)
				payloadLen += n
				left -= n
				pnSpace.ackElicited = false
			}
		}
		// Crypto
		if f := s.sendFrameCrypto(pnSpace, left); f != nil {
			n := f.encodedLen()
			op.addAckElicitingFrame(f)
			payloadLen += n
			left -= n
		}
		if space == packetSpaceApplication {
			if f := s.sendFrameHandshakeDone(); f != nil {
				n := f.encodedLen()
				if left >= n {
					op.addFrame(f)
					payloadLen += n
					left -= n
					s.handshakeConfirmed = true
				}
			}
			// MaxData
			if f := s.sendFrameMaxData(); f != nil {
				n := f.encodedLen()
				if left >= n {
					op.addAckElicitingFrame(f)
					payloadLen += n
					left -= n
					s.flow.setMaxRecv(f.maximumData)
				}
			}
			// Stream
			if f := s.sendFrameStream(left); f != nil {
				n := f.encodedLen()
				op.addAckElicitingFrame(f)
				payloadLen += n
				left -= n
			}
		}
		// Ping
		if s.recovery.probes > 0 && left >= 1 {
			f := &pingFrame{}
			n := f.encodedLen()
			op.addAckElicitingFrame(f)
			payloadLen += n
			left -= n
			s.recovery.probes--
		}
	}
	return payloadLen
}

func (s *Conn) onPacketSent(op *outgoingPacket, space packetSpace) {
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
	deadline := s.drainingTimer
	if deadline.IsZero() {
		deadline = s.recovery.lossDetectionTimer
		if deadline.IsZero() {
			deadline = s.idleTimer
			if deadline.IsZero() {
				return -1
			}
		}
	}
	timeout := time.Until(deadline)
	if timeout < 0 {
		timeout = 0
	}
	return timeout
}

func (s *Conn) checkTimeout(now time.Time) {
	if !s.drainingTimer.IsZero() && !now.Before(s.drainingTimer) {
		debug("draining timeout expired")
		s.state = stateClosed
		return
	}
	if !s.idleTimer.IsZero() && !now.Before(s.idleTimer) {
		debug("idle timeout expired")
		s.state = stateClosed
		return
	}
	s.recovery.onLossDetectionTimeout(now)
}

// Close sets the connection to closing state.
// https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#draining
func (s *Conn) Close(app bool, errCode uint64, reason string) {
	if !s.drainingTimer.IsZero() || s.closeFrame != nil {
		return
	}
	debug("set close code=%d", errCode)
	s.closeFrame = &connectionCloseFrame{
		application:  app,
		errorCode:    errCode,
		reasonPhrase: []byte(reason),
	}
	s.state = stateClosing
}

// IsEstablished returns true of handshake is complete and the connection is not closing.
func (s *Conn) IsEstablished() bool {
	return s.state == stateEstablished
}

// IsClosed returns true when the connection is in Closed state and no longer send or receive packets.
func (s *Conn) IsClosed() bool {
	return s.state == stateClosed
}

// Events consumes received events. It appends to provided events slice
// and clear received events.
func (s *Conn) Events(events []interface{}) []interface{} {
	events = append(events, s.events...)
	for i := range s.events {
		s.events[i] = nil
	}
	s.events = s.events[:0]
	return events
}

// Stream returned opened stream or nil if it cannot be created.
// Client-initiated streams have even-numbered stream IDs and
// server-initiated streams have odd-numbered stream IDs.
func (s *Conn) Stream(id uint64) *Stream {
	st, err := s.getOrCreateStream(id, s.isClient)
	if err != nil {
		debug("get stream error: %v", err)
		return nil
	}
	return st
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
	if left > 0 && pnSpace.cryptoStream.send.ready() {
		data, offset, _ := pnSpace.cryptoStream.send.pop(left)
		if len(data) > 0 {
			return newCryptoFrame(data, offset)
		}
	}
	return nil
}

func (s *Conn) sendFrameStream(left int) *streamFrame {
	allowed := s.flow.canSend()
	left -= maxStreamFrameOverhead
	if left > allowed {
		left = allowed
	}
	if left > 0 {
		for id, st := range s.streams.streams {
			debug("stream: %v", st)
			if !st.send.ready() {
				continue
			}
			data, offset, fin := st.send.pop(left)
			if len(data) > 0 {
				s.flow.addSend(len(data))
				return &streamFrame{
					streamID: id,
					data:     data,
					offset:   offset,
					fin:      fin,
				}
			}
		}
	}
	return nil
}

func (s *Conn) sendFrameMaxData() *maxDataFrame {
	if max := s.flow.shouldUpdateMaxRecv(); max > 0 {
		return &maxDataFrame{
			maximumData: max,
		}
	}
	return nil
}

func (s *Conn) sendFrameHandshakeDone() *handshakeDoneFrame {
	// HandshakeDone is sent only by server.
	if s.isClient || s.state != stateEstablished || s.handshakeConfirmed {
		return nil
	}
	return &handshakeDoneFrame{}
}

func (s *Conn) lostFrameStream(f *streamFrame) {
	st := s.streams.get(f.streamID)
	if st == nil {
		return
	}
	// Push data back to send again
	err := st.send.push(f.data, f.offset, f.fin)
	if err != nil {
		debug("process lost stream frame %s: %v", f, err)
		// FIXME
		panic(err)
	}
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
		return nil, newError(StreamStateError, "invalid type of stream id: %d", id)
	}
	bidi := isStreamBidi(id)
	st = s.streams.create(id, local, bidi)
	if st == nil {
		return nil, errStreamLimit
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
	st.init(maxRecv, maxSend)
	return st, nil
}

func (s *Conn) dropPacketSpace(space packetSpace) {
	s.packetNumberSpaces[space].drop()
	s.recovery.dropUnackedData(space)
	debug("dropped space=%d", space)
}

func (s *Conn) addEvent(e interface{}) {
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
