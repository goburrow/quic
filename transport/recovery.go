package transport

import (
	"bytes"
	"fmt"
	"sync"
	"time"
)

const (
	// Maximum reordering in packets before packet threshold loss detection considers a packet lost.
	// https://www.rfc-editor.org/rfc/rfc9002.html#section-6.1.1
	packetThreshold = 3

	// Maximum reordering in time before time threshold loss detection considers a packet lost.
	// Specified as an RTT multiplier.
	// https://www.rfc-editor.org/rfc/rfc9002.html#section-6.1.2
	// NOTE: The value in spec is 9/8, but used as "x + x/8" here to avoid casting to float.
	timeThreshold = 8

	// Timer granularity.
	// https://www.rfc-editor.org/rfc/rfc9002.html#section-6.1.2
	granularity = 1 * time.Millisecond

	// When no previous RTT is available, the initial RTT should be set to 333ms,
	// resulting in a 1 second initial timeout
	// https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.2
	initialRTT = 333 * time.Millisecond

	// The period of time for persistent congestion to be established,
	// specified as a PTO multiplier. The recommended value is 3, which is approximately
	// equivalent to two TLPs before an RTO in TCP.
	// https://www.rfc-editor.org/rfc/rfc9002.html#section-7.6
	persistentCongestionThreshold = 3

	maxProbes = 2
	// Prior to validating the client address, servers MUST NOT send more than three times
	// as many bytes as the number of bytes they have received.
	// https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.2.1
	maxAmplificationFactor = 3

	// maxUint64 indicates infinity
	maxUint64 = ^uint64(0)
	maxUint   = ^uint(0)
)

// https://www.rfc-editor.org/rfc/rfc9002.html#name-sent-packet-fields
type sentPacket struct {
	packetNumber uint64    // The packet number of the sent packet.
	frames       []frame   // The Frames included in the packet.
	timeSent     time.Time // The time the packet was sent.
	timeLost     time.Time // The time the packet declared lost.
	sentBytes    uint      // The number of bytes sent in the packet, including header and encryption overhead

	// ackEliciting indicates whether a packet is ack-eliciting. If true, it is expected that
	// an acknowledgement will be received, though the peer could delay sending the ACK frame
	// containing it by up to the MaxAckDelay.
	ackEliciting bool
	// inFlight indicates whether the packet counts towards bytes in flight.
	// Packets containing frames besides ACK or CONNECTION_CLOSE frames are considered to be in flight.
	inFlight bool
}

func newSentPacket(pn uint64, tm time.Time) *sentPacket {
	s := sentPacketPool.Get().(*sentPacket)
	s.packetNumber = pn
	s.timeSent = tm
	return s
}

// All frames other than ACK, PADDING, and CONNECTION_CLOSE are considered ack-eliciting.
// Packets are considered in-flight when they are ack-eliciting or contain a PADDING frame.
func (s *sentPacket) addFrame(f frame) {
	s.frames = append(s.frames, f)
	if !s.ackEliciting {
		switch f.(type) {
		case *ackFrame, *connectionCloseFrame:
		case *paddingFrame:
			s.inFlight = true
		default:
			s.inFlight = true
			s.ackEliciting = true
		}
	}
}

// markLost marks this packet lost. It moves frames from the current sentPacket
// to a clone that is returned.
func (s *sentPacket) markLost(now time.Time) *sentPacket {
	s.timeLost = now
	sp := newSentPacket(s.packetNumber, s.timeSent)
	sp.inFlight = s.inFlight
	sp.ackEliciting = s.ackEliciting
	sp.sentBytes = s.sentBytes
	sp.timeLost = s.timeLost
	sp.frames, s.frames = s.frames, sp.frames
	return sp
}

func (s *sentPacket) String() string {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "packet_number=%d sent_bytes=%d ack_eliciting=%v in_flight=%v",
		s.packetNumber, s.sentBytes, s.ackEliciting, s.inFlight)
	if !s.timeLost.IsZero() {
		fmt.Fprintf(&buf, " lost_time=%v", s.timeLost)
	}
	for _, f := range s.frames {
		fmt.Fprintf(&buf, " %s", f)
	}
	return buf.String()
}

func freeSentPacket(s *sentPacket) {
	// Reset everything but frames slice.
	frames := s.frames
	for i, f := range frames {
		freeFrame(f)
		frames[i] = nil
	}
	*s = sentPacket{}
	s.frames = frames[:0]
	sentPacketPool.Put(s)
}

var sentPacketPool = sync.Pool{
	New: func() interface{} {
		return &sentPacket{}
	},
}

// https://www.rfc-editor.org/rfc/rfc9002.html
type lossRecovery struct {
	latestRTT   time.Duration // The most recent RTT measurement made when receiving an ack for a previously unacked packet.
	smoothedRTT time.Duration // The exponentially-weighted moving average RTT of the connection.
	rttVariance time.Duration // The mean deviation in the observed RTT samples.
	minRTT      time.Duration // The minimum RTT seen in the connection, ignoring ack delay.
	// maxAckDelay is the maximum amount of time by which the receiver intends
	// to delay acknowledgments for packets in the ApplicationData packet number space.
	// The actual ack_delay in a received ACK frame may be larger due to late timers,
	// reordering, or lost ACK frames.
	maxAckDelay time.Duration

	// Multi-modal timer used for loss detection.
	lossDetectionTimer time.Time
	// The number of times a PTO has been sent without receiving an ack.
	ptoCount uint8
	// The time the most recent ack-eliciting packet was sent.
	timeOfLastAckElicitingPacket [packetSpaceCount]time.Time
	// The largest packet number acknowledged in the packet number space so far.
	largestAckedPacket [packetSpaceCount]uint64
	// The largest packet number the connection has sent.
	largestSentPacket [packetSpaceCount]uint64
	// lossTime is the time at which the next packet in that packet number space
	// will be considered lost based on exceeding the reordering window in time.
	lossTime   [packetSpaceCount]time.Time
	lossProbes [packetSpaceCount]uint8

	// sent is an association of packet numbers in a packet number space to information about them.
	sent  [packetSpaceCount][]*sentPacket
	lost  [packetSpaceCount][]*sentPacket
	acked [packetSpaceCount][]*sentPacket

	// Last packet schedule time
	lastPacketSchedule time.Time

	// Metrics
	lostPackets uint64
	lostBytes   uint64

	// Control PTO calculation.
	hasHandshakeKeys               bool
	peerCompletedAddressValidation bool
	handshakeConfirmed             bool
	enablePacing                   bool

	congestion congestionControl
}

// https://www.rfc-editor.org/rfc/rfc9002.html#section-a.4
func (s *lossRecovery) init() {
	for i := packetSpaceInitial; i < packetSpaceCount; i++ {
		s.largestAckedPacket[i] = maxUint64
	}
	// Use zero value for smoothedRTT to detect whether RTT sample was received
	s.rttVariance = initialRTT / 2
	s.congestion.init()
}

// After a packet is sent, information about the packet is stored.
// https://www.rfc-editor.org/rfc/rfc9002.html#section-a.5
func (s *lossRecovery) onPacketSent(p *sentPacket, space packetSpace) {
	s.setPacketSchedule(p, space)
	s.sent[space] = append(s.sent[space], p)
	if p.packetNumber > s.largestSentPacket[space] {
		s.largestSentPacket[space] = p.packetNumber
	}
	if p.inFlight {
		if p.ackEliciting {
			s.timeOfLastAckElicitingPacket[space] = p.timeSent
		}
		s.congestion.onPacketSent(p.sentBytes, p.timeSent)
		s.setLossDetectionTimer(p.timeSent)
	}
}

// When an ACK frame is received, it may newly acknowledge any number of packets.
// https://www.rfc-editor.org/rfc/rfc9002.html#section-a.7
func (s *lossRecovery) onAckReceived(ranges rangeSet, ackDelay time.Duration, space packetSpace, now time.Time) {
	largestAcked := ranges.largest()
	if largestAcked > s.largestSentPacket[space] {
		debug("invalid largest acknowledged packet number: largestAcked=%v largestSent=%v %v",
			largestAcked, s.largestSentPacket[space], ranges)
		return
	}
	if s.largestAckedPacket[space] == maxUint64 || s.largestAckedPacket[space] < largestAcked {
		s.largestAckedPacket[space] = largestAcked
	}
	// Finds packets that are newly acknowledged and removes them from sent packets.
	ackedLen := len(s.acked[space])
	hasAckEliciting := false
	hasSpurious := false
	s.filterSent(space, func(p *sentPacket) bool {
		if ranges.contains(p.packetNumber) {
			if p.ackEliciting {
				hasAckEliciting = true
			}
			if p.inFlight && !p.timeLost.IsZero() {
				// The packet is already declared lost but it is spurious,
				// so congestion changes need to be reverted.
				hasSpurious = true
				debug("spurious lost packet: %v", p)
			}
			// Move to the acked list.
			s.acked[space] = append(s.acked[space], p)
			return true
		}
		return false
	})
	ackedPackets := s.acked[space][ackedLen:]
	if len(ackedPackets) == 0 {
		// Nothing to do if there are no newly acked packets.
		return
	}
	if hasSpurious {
		s.congestion.rollback()
	}
	if hasAckEliciting {
		largestPacket := ackedPackets[len(ackedPackets)-1]
		// If the largest acknowledged is newly acked and
		// at least one ack-eliciting was newly acked, update the RTT.
		if largestPacket.packetNumber == largestAcked {
			latestRTT := now.Sub(largestPacket.timeSent)
			if space != packetSpaceApplication {
				ackDelay = 0
			}
			s.updateRTT(latestRTT, ackDelay)
		}
	}

	// TODO: Process ECN information if present.

	s.onPacketsAcked(ackedPackets, space, now)
	s.detectLostPackets(space, now)
	// Reset pto_count unless the client is unsure if
	// the server has validated the client's address.
	if s.ptoCount > 0 && s.peerCompletedAddressValidation {
		s.ptoCount = 0
		s.lossProbes[space] = 0
	}
	s.setLossDetectionTimer(now)
}

// https://www.rfc-editor.org/rfc/rfc9002.html#section-5.3
func (s *lossRecovery) updateRTT(latestRTT time.Duration, ackDelay time.Duration) {
	s.latestRTT = latestRTT
	if s.smoothedRTT == 0 {
		// First RTT sample in a connection
		s.minRTT = latestRTT
		s.smoothedRTT = latestRTT
		s.rttVariance = latestRTT / 2
		return
	}
	// min_rtt ignores acknowledgment delay.
	if s.minRTT > latestRTT {
		s.minRTT = latestRTT
	}
	// Limit ack_delay by max_ack_delay after handshake confirmation.
	// Note that ack_delay is 0 for acknowledgements of Initial and Handshake packets.
	if s.handshakeConfirmed && ackDelay > s.maxAckDelay {
		// Limit ack_delay by max_ack_delay
		ackDelay = s.maxAckDelay
	}
	// Adjust for ack delay if plausible.
	adjustedRTT := latestRTT
	if adjustedRTT >= s.minRTT+ackDelay {
		adjustedRTT -= ackDelay
	}
	// rttvar = 3/4 * rttvar + 1/4 * abs(smoothed_rtt - adjusted_rtt)
	// smoothed_rtt = 7/8 * smoothed_rtt + 1/8 * adjusted_rtt
	deltaRTT := s.smoothedRTT - adjustedRTT
	if deltaRTT < 0 {
		deltaRTT = -deltaRTT
	}
	s.rttVariance = s.rttVariance*3/4 + deltaRTT*1/4
	s.smoothedRTT = s.smoothedRTT*7/8 + adjustedRTT*1/8
}

func (s *lossRecovery) onPacketsAcked(packets []*sentPacket, space packetSpace, now time.Time) {
	rtt := s.roundTripTime()
	for _, p := range packets {
		if p.inFlight {
			s.congestion.onPacketAcked(p.sentBytes, p.timeSent, rtt, now)
		}
	}
}

// https://www.rfc-editor.org/rfc/rfc9002.html#section-a.8
func (s *lossRecovery) setLossDetectionTimer(now time.Time) {
	lossTime, _ := s.earliestLossTime()
	if !lossTime.IsZero() {
		// Time threshold loss detection.
		s.lossDetectionTimer = lossTime
		return
	}
	if s.congestion.state.bytesInFlight == 0 && s.peerCompletedAddressValidation {
		// There is nothing to detect lost, so no timer is set.
		// However, the client needs to arm the timer if the
		// server might be blocked by the anti-amplification limit.
		s.lossDetectionTimer = time.Time{}
		return
	}
	// Determine which PN space to arm PTO for.
	timeout, _ := s.earliestProbeTime(now)
	s.lossDetectionTimer = timeout
	debug("set loss_timer=%v", timeout)
}

// onLossDetectionTimeout checks lossDetectionTimer to detect whether a packet was lost.
// https://www.rfc-editor.org/rfc/rfc9002.html#section-a.9
func (s *lossRecovery) onLossDetectionTimeout(now time.Time) {
	lossTime, space := s.earliestLossTime()
	if !lossTime.IsZero() {
		s.detectLostPackets(space, now)
		s.setLossDetectionTimer(now)
		return
	}
	// TODO:
	// if (has Handshake keys):
	//   SendOneAckElicitingHandshakePacket()
	// else:
	//   SendOneAckElicitingPaddedInitialPacket()

	// PTO. Send new data if available, else retransmit old data.
	// If neither is available, send a single PING frame.
	s.ptoCount++
	probes := int(s.ptoCount)
	if probes > maxProbes {
		probes = maxProbes
	}
	_, space = s.earliestProbeTime(now)
	s.lossProbes[space] = uint8(probes)
	// PTO. Send new data if available, else retransmit old data.
	// If neither is available, send a single PING frame.
	// TODO: When there are no ack eliciting packets, the connection might send 2 ping packets in a row.
	// Maybe it should resend a packet from the next space instead.
	s.markResendAckElicitingPackets(space, probes, now)
	s.setLossDetectionTimer(now)
}

// detectLostPackets is called every time an ACK is received or the time threshold loss detection timer expires.
// https://www.rfc-editor.org/rfc/rfc9002.html#section-a.10
func (s *lossRecovery) detectLostPackets(space packetSpace, now time.Time) {
	// loss_delay = max(kTimeThreshold * max(latest_rtt, smoothed_rtt), kGranularity)
	lossDelay := s.roundTripTime()
	if lossDelay < s.latestRTT {
		lossDelay = s.latestRTT
	}
	lossDelay += lossDelay / timeThreshold
	// Minimum time of kGranularity before packets are deemed lost.
	if lossDelay < granularity {
		lossDelay = granularity
	}
	// Packets sent before this time are deemed lost.
	lostSendTime := now.Add(-lossDelay)
	largestAcked := s.largestAckedPacket[space]
	lossTime := time.Time{}

	lostLen := len(s.lost[space])
	s.filterSent(space, func(p *sentPacket) bool {
		if p.packetNumber > largestAcked {
			return false
		}
		if !p.timeLost.IsZero() {
			// The packet can be removed to the sent list if it has been marked lost for a RTT.
			if p.timeLost.Before(lostSendTime) {
				freeSentPacket(p)
				return true
			}
			return false
		}
		if !p.timeSent.After(lostSendTime) || largestAcked >= p.packetNumber+packetThreshold {
			sp := p.markLost(now)
			s.lost[space] = append(s.lost[space], sp)
			// Declare the packet lost but not remove from the sent list yet for spurious check.
			return false
		}
		if p.ackEliciting {
			tm := p.timeSent.Add(lossDelay)
			if lossTime.IsZero() || lossTime.After(tm) {
				lossTime = tm
			}
		}
		return false
	})
	s.lossTime[space] = lossTime
	lostPackets := s.lost[space][lostLen:]
	if len(lostPackets) > 0 {
		s.onPacketsLost(lostPackets, space, now)
	}
}

func (s *lossRecovery) markResendAckElicitingPackets(space packetSpace, probes int, now time.Time) {
	// Retransmit the frames from the oldest sent packets on PTO.
	// Calculate starting point first to keep lost packets in order.
	sent := s.sent[space]
	for _, p := range sent {
		if p.ackEliciting && len(p.frames) > 0 {
			debug("mark packet lost for resending: %v", p)
			sp := p.markLost(now)
			s.lost[space] = append(s.lost[space], sp)
			probes--
			if probes == 0 {
				break
			}
		}
		// The packet may not really lost, so do not change congestion control.
		// It is kept in the sent list so we can actually declare it lost or acked later.
	}
}

// When Initial or Handshake keys are discarded, packets from the space are discarded
// and loss detection state is updated.
// https://www.rfc-editor.org/rfc/rfc9002.html#section-a.11
func (s *lossRecovery) onPacketNumberSpaceDiscarded(space packetSpace, now time.Time) {
	// Remove any unacknowledged packets from flight.
	var unackedBytes uint
	for _, p := range s.sent[space] {
		if p.inFlight {
			unackedBytes += p.sentBytes
		}
	}
	s.congestion.onPacketDiscarded(unackedBytes)
	s.sent[space] = nil
	s.lost[space] = nil
	s.acked[space] = nil
	// Reset the loss detection and PTO timer
	s.timeOfLastAckElicitingPacket[space] = time.Time{}
	s.lossTime[space] = time.Time{}
	s.lossProbes[space] = 0
	s.ptoCount = 0
	s.setLossDetectionTimer(now)
}

// roundTripTime retruns smoothed RTT when available.
func (s *lossRecovery) roundTripTime() time.Duration {
	if s.smoothedRTT > 0 {
		return s.smoothedRTT
	}
	return initialRTT
}

// probeTimeout is the amount of time that a sender ought to wait for an acknowledgement
// of a sent packet.
// When an ack-eliciting packet is transmitted, the sender schedules a timer
// for the PTO period as follows:
//
//   PTO = smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay
//
// https://www.rfc-editor.org/rfc/rfc9002.html#section-6.2.1
func (s *lossRecovery) probeTimeout() time.Duration {
	pto := s.roundTripTime() + s.maxAckDelay
	if s.rttVariance*4 > granularity {
		pto += s.rttVariance * 4
	} else {
		pto += granularity
	}
	return pto
}

// earliestLossTime returns the earliest loss time.
// https://www.rfc-editor.org/rfc/rfc9002.html#section-a.8
func (s *lossRecovery) earliestLossTime() (time.Time, packetSpace) {
	space := packetSpaceInitial
	lossTime := s.lossTime[space]
	for i := space + 1; i < packetSpaceCount; i++ {
		tm := s.lossTime[i]
		if !tm.IsZero() && (lossTime.IsZero() || lossTime.After(tm)) {
			lossTime = tm
			space = i
		}
	}
	return lossTime, space
}

// earliestProbeTime returns the earliest PTO timeout.
// https://www.rfc-editor.org/rfc/rfc9002.html#section-a.8
func (s *lossRecovery) earliestProbeTime(now time.Time) (time.Time, packetSpace) {
	// duration = (smoothed_rtt + max(4 * rttvar, kGranularity)) * (2 ^ pto_count)
	duration := s.probeTimeout() * (1 << s.ptoCount)
	// Arm PTO from now when there are no inflight packets.
	if s.congestion.state.bytesInFlight == 0 {
		if s.hasHandshakeKeys {
			return now.Add(duration), packetSpaceHandshake
		}
		return now.Add(duration), packetSpaceInitial
	}
	space := packetSpaceInitial
	timeout := time.Time{}
	for i := space; i < packetSpaceCount; i++ {
		// Check no in-flight packets in space.
		// XXX: To avoid a loop, it only checks if there is any sending packets.
		if len(s.sent[i]) == 0 {
			continue
		}
		if space == packetSpaceApplication && !s.handshakeConfirmed {
			// Skip Application Data until handshake complete.
			continue
		}
		tm := s.timeOfLastAckElicitingPacket[i]
		if !tm.IsZero() {
			tm = tm.Add(duration)
			if timeout.IsZero() || timeout.After(tm) {
				timeout = tm
				space = i
			}
		}
	}
	return timeout, space
}

func (s *lossRecovery) inPersistentCongestion(lostPackets []*sentPacket) bool {
	// TODO
	//pto = smoothed_rtt + max(4 * rttvar, kGranularity) + max_ack_delay
	//congestion_period = pto * kPersistentCongestionThreshold
	// Determine if all packets in the time period before the
	// largest newly lost packet, including the edges, are
	// marked lost
	//return AreAllPacketsLost(lost_packets, congestion_period)
	return false
}

// onPacketsLost is invoked when detectAndRemoveLostPackets deems packets lost.
// https://www.rfc-editor.org/rfc/rfc9002.html#section-b.8
func (s *lossRecovery) onPacketsLost(packets []*sentPacket, space packetSpace, now time.Time) {
	s.lostPackets += uint64(len(packets))
	sentTimeOfLastLoss := time.Time{}
	for _, p := range packets {
		debug("lost packet: %v", p)
		if p.inFlight {
			s.congestion.onPacketDiscarded(p.sentBytes)
			s.lostBytes += uint64(p.sentBytes)
			if sentTimeOfLastLoss.IsZero() || p.timeSent.After(sentTimeOfLastLoss) {
				sentTimeOfLastLoss = p.timeSent
			}
		}
	}
	if len(packets) > 1 && !sentTimeOfLastLoss.IsZero() {
		// Only consider new congestion event when there are multiple packets lost.
		s.congestion.onCongestionEvent(sentTimeOfLastLoss, now)
	}
	// Reset the congestion window if the loss of these
	// packets indicates persistent congestion.
	// Only consider packets sent after getting an RTT sample.
	if s.smoothedRTT == 0 {
		return
	}
	if s.inPersistentCongestion(packets) {
		s.congestion.collapseWindow()
	}
}

// filterSent removes packet from sent[space] when the filter function returns true.
func (s *lossRecovery) filterSent(space packetSpace, filter func(*sentPacket) bool) {
	sent := s.sent[space]
	if len(sent) > 0 {
		n := 0
		for _, p := range sent {
			if !filter(p) {
				sent[n] = p
				n++
			}
		}
		for i := n; i < len(sent); i++ {
			sent[i] = nil
		}
		s.sent[space] = sent[:n]
	}
}

func (s *lossRecovery) drainLost(space packetSpace, fn func(frame)) {
	packets := s.lost[space]
	for i, p := range packets {
		for _, f := range p.frames {
			fn(f)
		}
		freeSentPacket(p)
		packets[i] = nil
	}
	s.lost[space] = packets[:0]
}

func (s *lossRecovery) drainAcked(space packetSpace, fn func(frame)) {
	packets := s.acked[space]
	for i, p := range packets {
		for _, f := range p.frames {
			fn(f)
		}
		freeSentPacket(p)
		packets[i] = nil
	}
	s.acked[space] = packets[:0]
}

func (s *lossRecovery) setMaxAckDelay(maxAckDelay time.Duration) {
	if s.maxAckDelay > 0 {
		s.maxAckDelay = maxAckDelay
	} else {
		s.maxAckDelay = defaultMaxAckDelay
	}
}

func (s *lossRecovery) setHasHandshakeKeys() {
	s.hasHandshakeKeys = true
}

func (s *lossRecovery) setPeerCompletedAddressValidation() {
	s.peerCompletedAddressValidation = true
}

func (s *lossRecovery) setHandshakeConfirmed() {
	s.handshakeConfirmed = true
}

func (s *lossRecovery) setMaxDatagramSize(n uint) {
	if n > initialMaxDatagramSize {
		n = initialMaxDatagramSize
	} else if n < MinInitialPacketSize {
		n = MinInitialPacketSize
	}
	s.congestion.setMaxDatagramSize(n)
}

// availSend returns number of bytes that are allowed to send.
func (s *lossRecovery) availSend() uint {
	for _, p := range s.lossProbes {
		// https://www.rfc-editor.org/rfc/rfc9002.html#section-7.5
		// Ignore congestion window if packet is sent on PTO timer expiration.
		if p > 0 {
			return initialWindowPackets * initialMaxDatagramSize
		}
	}
	return s.congestion.available()
}

// Check packet pacing.
// https://www.rfc-editor.org/rfc/rfc9002.html#section-7.7
func (s *lossRecovery) setPacketSchedule(p *sentPacket, space packetSpace) {
	// Do not pace packet when:
	// - At start of the connection.
	// - Not application space.
	// - Not an in-flight packet.
	if !s.enablePacing || s.smoothedRTT == 0 || space != packetSpaceApplication || !p.inFlight {
		return
	}
	if !s.lastPacketSchedule.IsZero() {
		// interval = ( smoothed_rtt * packet_size / congestion_window ) / N
		cwnd := s.congestion.window()
		interval := s.smoothedRTT * time.Duration(p.sentBytes) / time.Duration(cwnd) / 3 * 2
		if interval > 0 {
			timeSent := s.lastPacketSchedule.Add(interval)
			// Adjust packet sending time.
			if timeSent.After(p.timeSent) {
				debug("change packet schedule: packet_number=%v sent_bytes=%v delay=%v",
					p.packetNumber, p.sentBytes, timeSent.Sub(p.timeSent))
				// Should change p.timeSent?
				s.lastPacketSchedule = timeSent
				return
			}
		}
	}
	s.lastPacketSchedule = p.timeSent
}

// onProbeSent must only be called when lossProbes[space] > 0
func (s *lossRecovery) onProbeSent(space packetSpace) {
	s.lossProbes[space]--
}

func (s *lossRecovery) log(b []byte) []byte {
	// Loss detection
	b = appendField(b, "min_rtt", s.minRTT)
	b = appendField(b, "smoothed_rtt", s.roundTripTime())
	b = appendField(b, "latest_rtt", s.latestRTT)
	b = appendField(b, "rtt_variance", s.rttVariance)
	b = appendField(b, "pto_count", s.ptoCount)
	// Congestion control
	b = s.congestion.log(b)
	return b
}

func (s *lossRecovery) logLossTimer(b []byte, now time.Time) []byte {
	if s.lossDetectionTimer.IsZero() {
		b = appendField(b, "event_type", "cancelled")
	} else if s.lossDetectionTimer.Before(now) {
		b = appendField(b, "event_type", "set")
		b = appendField(b, "delta", "0")
	} else {
		b = appendField(b, "event_type", "set")
		b = appendField(b, "delta", s.lossDetectionTimer.Sub(now))
	}
	return b
}
