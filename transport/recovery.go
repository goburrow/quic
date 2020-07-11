package transport

import (
	"bytes"
	"fmt"
	"time"
)

const (
	packetThreshold = 3
	granularity     = 1 * time.Millisecond
	initialRTT      = 500 * time.Millisecond

	initialWindowPackets = 10
	maxDatagramSize      = 1452

	initialWindow = initialWindowPackets * maxDatagramSize
	minimumWindow = 2 * maxDatagramSize

	persistentCongestionThreshold = 3

	maxUint64 = ^uint64(0)
)

type outgoingPacket struct {
	packetNumber uint64
	frames       []frame
	timeSent     time.Time
	size         uint64 // size is final packet size including header and encryption overhead

	ackEliciting bool
	inFlight     bool
}

// All frames other than ACK, PADDING, and CONNECTION_CLOSE are considered ack-eliciting.
// Packets are considered in-flight when they are ack-eliciting or contain a PADDING frame.
func (s *outgoingPacket) addFrame(f frame) {
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

func (s *outgoingPacket) String() string {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "length=%d", s.size)
	for _, f := range s.frames {
		fmt.Fprintf(&buf, " %s", f)
	}
	return buf.String()
}

// https://quicwg.org/base-drafts/draft-ietf-quic-recovery.html
type lossRecovery struct {
	lossDetectionTimer time.Time // Multi-modal timer used for loss detection.

	timeLastSentAckElicitingPacket time.Time // The time the most recent ack-eliciting packet was sent.

	largestAckedPacket [packetSpaceCount]uint64 // The largest packet number acknowledged in the packet number space so far.

	latestRTT   time.Duration // The most recent RTT measurement made when receiving an ack for a previously unacked packet.
	smoothedRTT time.Duration // The smoothed RTT of the connection.
	rttVariance time.Duration // The RTT variance.
	minRTT      time.Duration // The minimum RTT seen in the connection, ignoring ack delay.
	// maxAckDelay is The maximum amount of time by which the receiver intends
	// to delay acknowledgments for packets in the ApplicationData packet number space.
	// The actual ack_delay in a received ACK frame may be larger due to late timers,
	// reordering, or lost ACK frames.
	maxAckDelay time.Duration

	// lossTime is the time at which the next packet in that packet number space
	// will be considered lost based on exceeding the reordering window in time.
	lossTime [packetSpaceCount]time.Time
	// sent is an association of packet numbers in a packet number space to information about them.
	sent  [packetSpaceCount]map[uint64]*outgoingPacket
	lost  [packetSpaceCount][]frame
	acked [packetSpaceCount][]frame

	lostCount          uint64
	bytesInFlight      uint64
	congestionWindow   uint64
	recoveryStartTime  time.Time
	slowStartThreshold uint64

	ptoCount uint // The number of times a PTO has been sent without receiving an ack.
	probes   int
}

func (s *lossRecovery) init(now time.Time) {
	s.timeLastSentAckElicitingPacket = now
	for i := packetSpaceInitial; i < packetSpaceCount; i++ {
		s.largestAckedPacket[i] = maxUint64
		s.sent[i] = make(map[uint64]*outgoingPacket)
	}
	s.maxAckDelay = 25 * time.Millisecond
	s.congestionWindow = initialWindow
	s.slowStartThreshold = maxUint64
}

// After a packet is sent, information about the packet is stored.
// https://quicwg.org/base-drafts/draft-ietf-quic-recovery.html#name-on-sending-a-packet
func (s *lossRecovery) onPacketSent(p *outgoingPacket, space packetSpace) {
	s.sent[space][p.packetNumber] = p
	if p.inFlight {
		if p.ackEliciting {
			s.timeLastSentAckElicitingPacket = p.timeSent
		}
		s.bytesInFlight += p.size
		s.setLossDetectionTimer()
	}
}

// When an ACK frame is received, it may newly acknowledge any number of packets.
// https://quicwg.org/base-drafts/draft-ietf-quic-recovery.html#name-on-receiving-an-acknowledgm
func (s *lossRecovery) onAckReceived(ranges rangeSet, ackDelay time.Duration, space packetSpace, now time.Time) {
	largestAcked := ranges.largest()
	if s.largestAckedPacket[space] == maxUint64 || s.largestAckedPacket[space] < largestAcked {
		s.largestAckedPacket[space] = largestAcked
	} else {
		largestAcked = s.largestAckedPacket[space]
	}
	if p, ok := s.sent[space][largestAcked]; ok {
		if p.ackEliciting {
			latestRTT := now.Sub(p.timeSent)
			if space != packetSpaceApplication {
				ackDelay = 0
			}
			s.updateRTT(latestRTT, ackDelay)
		}
	}
	hasNewlyAcked := false
	for _, r := range ranges {
		for pn := r.start; pn <= r.end; pn++ {
			if s.onPacketAcked(pn, space) {
				hasNewlyAcked = true
			}
		}
	}
	if hasNewlyAcked {
		s.detectLostPackets(space, now)
		s.ptoCount = 0
		s.setLossDetectionTimer()
	}
}

// https://quicwg.org/base-drafts/draft-ietf-quic-recovery.html#name-estimating-smoothed_rtt-and
func (s *lossRecovery) updateRTT(latestRTT time.Duration, ackDelay time.Duration) {
	s.latestRTT = latestRTT
	if s.smoothedRTT == 0 {
		// First RTT sample in a connection
		s.minRTT = latestRTT
		s.smoothedRTT = latestRTT
		s.rttVariance = latestRTT / 2
		return
	}
	// Subsequent RTT samples
	if latestRTT < s.minRTT {
		// min_rtt ignores ack delay.
		s.minRTT = latestRTT
	}
	if ackDelay < s.maxAckDelay {
		// Limit ack_delay by max_ack_delay
		s.maxAckDelay = ackDelay
	}
	// Adjust for ack delay if plausible.
	adjustedRTT := latestRTT
	if latestRTT > s.minRTT+ackDelay {
		adjustedRTT -= ackDelay
	}
	var deltaRTT time.Duration // abs(smoothed_rtt - adjusted_rtt)
	if s.smoothedRTT > adjustedRTT {
		deltaRTT = s.smoothedRTT - adjustedRTT
	} else {
		deltaRTT = adjustedRTT - s.smoothedRTT
	}
	s.rttVariance = s.rttVariance*3/4 + deltaRTT*1/4
	s.smoothedRTT = s.smoothedRTT*7/8 + adjustedRTT*1/8
}

// When a packet is acknowledged for the first time, the following OnPacketAcked function is called.
// Note that a single ACK frame may newly acknowledge several packets.
// OnPacketAcked must be called once for each of these newly acknowledged packets.
// https://quicwg.org/base-drafts/draft-ietf-quic-recovery.html#name-on-packet-acknowledgment
//
// onPacketAcked removes frames from s.sent.
func (s *lossRecovery) onPacketAcked(packetNumber uint64, space packetSpace) bool {
	p, ok := s.sent[space][packetNumber]
	if !ok {
		return false
	}
	delete(s.sent[space], packetNumber)
	s.acked[space] = append(s.acked[space], p.frames...)
	if p.inFlight {
		s.bytesInFlight -= p.size
		if s.inRecovery(p.timeSent) {
			return true
		}
		if s.congestionWindow < s.slowStartThreshold {
			// Slow start.
			s.congestionWindow += p.size
		} else {
			// Congestion avoidance.
			s.congestionWindow += (maxDatagramSize * p.size) / s.congestionWindow
		}
	}
	return true
}

// https://quicwg.org/base-drafts/draft-ietf-quic-recovery.html#name-setting-the-loss-detection-
func (s *lossRecovery) setLossDetectionTimer() {
	lossTime, _ := s.earliestLossTime()
	if !lossTime.IsZero() {
		// Time threshold loss detection.
		s.lossDetectionTimer = lossTime
		return
	}
	if s.bytesInFlight == 0 {
		s.lossDetectionTimer = time.Time{}
		return
	}
	// PTO timer
	var timeout time.Duration
	if s.smoothedRTT > 0 {
		// When a PTO timer expires, the PTO period MUST be set to twice its current value.
		timeout = s.probeTimeout() * (1 << s.ptoCount)
	} else {
		timeout = initialRTT * 2
	}
	s.lossDetectionTimer = s.timeLastSentAckElicitingPacket.Add(timeout)
}

// onLossDetectionTimeout checks lossDetectionTimer to detect whether a packet was lost.
// https://quicwg.org/base-drafts/draft-ietf-quic-recovery.html#name-on-timeout
func (s *lossRecovery) onLossDetectionTimeout(now time.Time) {
	if s.lossDetectionTimer.IsZero() || now.Before(s.lossDetectionTimer) {
		return
	}
	lossTime, space := s.earliestLossTime()
	if !lossTime.IsZero() {
		s.detectLostPackets(space, now)
		s.setLossDetectionTimer()
		return
	}
	// TODO:
	//   if (endpoint is client without 1-RTT keys):
	//     // Client sends an anti-deadlock packet: Initial is padded
	//     // to earn more anti-amplification credit,
	//     // a Handshake packet proves address ownership.
	//     if (has Handshake keys):
	//       SendOneAckElicitingHandshakePacket()
	//     else:
	//       SendOneAckElicitingPaddedInitialPacket()
	//   else:
	//     // PTO. Send new data if available, else retransmit old data.
	//     // If neither is available, send a single PING frame.
	//     _, pn_space = GetEarliestTimeAndSpace(
	//       time_of_last_sent_ack_eliciting_packet)
	//     SendOneOrTwoAckElicitingPackets(pn_space)

	// probeTimeout triggers sending one or two probe datagrams when ack-eliciting
	// packets are not acknowledged within the expected period of time or the
	// handshake has not been completed.
	s.probes = 2

	s.ptoCount++
	s.setLossDetectionTimer()
}

// detectLostPackets is called every time an ACK is received and operates on the sent_packets for that packet number space.
// https://quicwg.org/base-drafts/draft-ietf-quic-recovery.html#name-detecting-lost-packets
func (s *lossRecovery) detectLostPackets(space packetSpace, now time.Time) {
	// loss_delay = max(kTimeThreshold * max(latest_rtt, smoothed_rtt), kGranularity)
	lossDelay := s.roundTripTime()
	if lossDelay < s.latestRTT {
		lossDelay = s.latestRTT
	}
	lossDelay = lossDelay * 9 / 8
	if lossDelay < granularity {
		lossDelay = granularity
	}
	lostSendTime := now.Add(-lossDelay)
	largestAcked := s.largestAckedPacket[space]
	lossTime := time.Time{}

	var lostPkt []uint64
	for _, unacked := range s.sent[space] {
		if unacked.packetNumber > largestAcked {
			continue
		}
		// Mark packet as lost, or set time when it should be marked.
		if !unacked.timeSent.After(lostSendTime) || largestAcked >= unacked.packetNumber+packetThreshold {
			if unacked.inFlight {
				// TODO: packet lost
			}
			// Keep track of the packet number to remove later
			lostPkt = append(lostPkt, unacked.packetNumber)
		} else {
			tm := unacked.timeSent.Add(lossDelay)
			if lossTime.IsZero() || lossTime.After(tm) {
				lossTime = tm
			}
		}
	}
	s.lossTime[space] = lossTime
	if len(lostPkt) > 0 {
		s.onPacketsLost(lostPkt, space, now)
	}
}

func (s *lossRecovery) dropUnackedData(space packetSpace) {
	var unackedBytes uint64
	for _, p := range s.sent[space] {
		if p.inFlight {
			unackedBytes += p.size
		}
	}
	s.bytesInFlight -= unackedBytes
	// Remove saved frames
	m := s.sent[space]
	for i := range m {
		delete(m, i)
	}
	s.lost[space] = nil
	s.acked[space] = nil
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
// https://quicwg.org/base-drafts/draft-ietf-quic-recovery.html#name-computing-pto
func (s *lossRecovery) probeTimeout() time.Duration {
	pto := s.roundTripTime() + s.maxAckDelay
	if s.rttVariance*4 > granularity {
		pto += s.rttVariance * 4
	} else {
		pto += granularity
	}
	return pto
}

// earliestLossTime returns min(s.lossTime).
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

func (s *lossRecovery) inRecovery(sentTime time.Time) bool {
	if s.recoveryStartTime.IsZero() {
		return false
	}
	return s.recoveryStartTime.After(sentTime)
}

func (s *lossRecovery) inPersistentCongestion(largestLostPkt *outgoingPacket) bool {
	// TODO
	return false
}

// onPacketsLost moves frames from s.sent to s.lost.
// https://quicwg.org/base-drafts/draft-ietf-quic-recovery.html#name-on-packets-lost
func (s *lossRecovery) onPacketsLost(lostPkt []uint64, space packetSpace, now time.Time) {
	var largestLostPkt *outgoingPacket
	for _, lost := range lostPkt {
		p, ok := s.sent[space][lost]
		if !ok {
			continue
		}
		delete(s.sent[space], lost)
		s.lostCount++
		if !p.inFlight {
			continue
		}
		s.bytesInFlight -= p.size
		s.lost[space] = append(s.lost[space], p.frames...)
		largestLostPkt = p // last
	}
	if largestLostPkt != nil {
		// CongestionEvent
		if !s.inRecovery(largestLostPkt.timeSent) {
			s.recoveryStartTime = now
			s.congestionWindow /= 2
			if s.congestionWindow < minimumWindow {
				s.congestionWindow = minimumWindow
			}
			s.slowStartThreshold = s.congestionWindow
		}
		if s.inPersistentCongestion(largestLostPkt) {
			s.congestionWindow = minimumWindow
		}
	}
}

func (s *lossRecovery) drainLost(space packetSpace, fn func(frame)) {
	frames := s.lost[space]
	for i, f := range frames {
		fn(f)
		frames[i] = nil
	}
	s.lost[space] = frames[:0]
}

func (s *lossRecovery) drainAcked(space packetSpace, fn func(frame)) {
	frames := s.acked[space]
	for i, f := range frames {
		fn(f)
		frames[i] = nil
	}
	s.acked[space] = frames[:0]
}

func (s *lossRecovery) String() string {
	return fmt.Sprintf("lossTimer=%v bytes=%d probes=%d", s.lossDetectionTimer, s.bytesInFlight, s.probes)
}
