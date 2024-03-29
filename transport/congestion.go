package transport

import (
	"fmt"
	"math"
	"time"
)

const (
	// Endpoints should use an initial congestion window of 10 times the maximum datagram size,
	// limited to the larger of 14720 or twice the maximum datagram size
	// https://www.rfc-editor.org/rfc/rfc9002.html#section-7.2
	initialMaxDatagramSize = 1472
	initialWindowPackets   = 10
	// The minimum congestion window is the smallest value the congestion window can decrease
	// to as a response to loss. The recommended value is 2 * max_datagram_size.
	minimumWindowPackets = 2

	// Reduction in congestion window when a new loss event is detected.
	// NOTE: The value in spec is 0.5, but used as "x/2" here to avoid casting to float.
	lossReductionFactor = 2
)

// https://www.rfc-editor.org/rfc/rfc9002.html#section-b.2
type congestionControl struct {
	state congestionState
	// CUBIC
	cubic cubic
	// PRR
	prr proportionalRateReduction

	enableCubic bool
	enablePRR   bool
}

// https://www.rfc-editor.org/rfc/rfc9002.html#section-b.3
func (s *congestionControl) init() {
	s.state.init()
}

// https://www.rfc-editor.org/rfc/rfc9002.html#section-b.4
func (s *congestionControl) onPacketSent(sentBytes uint, sentTime time.Time) {
	if s.enableCubic {
		s.cubic.onSent(&s.state, sentBytes, sentTime)
	}
	if s.enablePRR {
		s.prr.onSent(sentBytes)
	}
	s.state.bytesInFlight += sentBytes
	s.state.lastSentTime = sentTime
}

// onPacketsAcked is invoked from loss detection's onAckReceived and
// is supplied with the newly acked_packets from sent_packets.
// https://www.rfc-editor.org/rfc/rfc9002.html#section-b.5
func (s *congestionControl) onPacketAcked(sentBytes uint, sentTime time.Time, rtt time.Duration, now time.Time) {
	appLimited := s.state.isAppLimited()
	// Remove from in flight.
	if s.state.bytesInFlight > sentBytes {
		s.state.bytesInFlight -= sentBytes
	} else {
		s.state.bytesInFlight = 0
	}
	// Do not increase congestion_window if application limited or
	// in recovery period.
	if s.state.inRecovery(sentTime) {
		if s.enablePRR {
			s.prr.onAcked(&s.state, sentBytes)
		}
		return
	}
	if appLimited {
		debug("application limited on packet acked: %v", s)
		return
	}
	if s.enableCubic {
		s.cubic.onAcked(&s.state, sentBytes, rtt, now)
	} else {
		s.renoOnAcked(sentBytes)
	}
	debug("congestion packet acked: %v", s)
}

// https://www.rfc-editor.org/rfc/rfc9002.html#section-b.9
func (s *congestionControl) onPacketDiscarded(sentBytes uint) {
	if s.state.bytesInFlight > sentBytes {
		s.state.bytesInFlight -= sentBytes
	} else {
		s.state.bytesInFlight = 0
	}
}

// onCongestionEvent is invoked from ProcessECN and OnPacketsLost when a new congestion event is detected.
// May start a new recovery period and reduces the congestion window.
// https://www.rfc-editor.org/rfc/rfc9002.html#section-b.6
func (s *congestionControl) onCongestionEvent(sentTime time.Time, now time.Time) {
	// Start a new congestion event if packet was sent after the
	// start of the previous congestion recovery period.
	if s.state.inRecovery(sentTime) {
		return
	}
	s.state.recoveryStartTime = now
	if s.enableCubic {
		s.cubic.onLost(&s.state)
	} else {
		s.renoOnLost()
	}
	if s.enablePRR {
		s.prr.onLost(&s.state)
	}
	debug("congestion event: %v", s)
}

func (s *congestionControl) rollback() {
	if s.enablePRR {
		s.prr.rollback()
	}
	if s.enableCubic {
		s.cubic.rollback(&s.state)
	}
}

func (s *congestionControl) available() uint {
	cwnd := s.window()
	if cwnd > s.state.bytesInFlight {
		return cwnd - s.state.bytesInFlight
	}
	return 0
}

func (s *congestionControl) window() uint {
	if s.enablePRR {
		return s.state.congestionWindow + s.prr.sndCnt
	}
	return s.state.congestionWindow
}

func (s *congestionControl) collapseWindow() {
	s.state.congestionWindow = minimumWindowPackets * s.state.maxDatagramSize
	s.state.recoveryStartTime = time.Time{}
}

func (s *congestionControl) setMaxDatagramSize(maxDatagramSize uint) {
	if s.state.congestionWindow == initialWindowPackets*s.state.maxDatagramSize {
		// Only update congestion window when it has not been updated.
		s.state.congestionWindow = initialWindowPackets * maxDatagramSize
	}
	s.state.maxDatagramSize = maxDatagramSize
}

// Reno (default)

func (s *congestionControl) renoOnLost() {
	s.state.slowStartThreshold = s.state.congestionWindow / lossReductionFactor
	// congestion_window = max(ssthresh, kMinimumWindow)
	minimumWindow := minimumWindowPackets * s.state.maxDatagramSize
	if s.state.slowStartThreshold < minimumWindow {
		s.state.slowStartThreshold = minimumWindow
	}
	s.state.congestionWindow = s.state.slowStartThreshold
}

func (s *congestionControl) renoOnAcked(sentBytes uint) {
	if s.state.isSlowStart() {
		s.state.congestionWindow += sentBytes
	} else {
		// Congestion avoidance.
		s.state.congestionWindow += s.state.maxDatagramSize * sentBytes / s.state.congestionWindow
	}
}

func (s *congestionControl) log(b []byte) []byte {
	b = appendField(b, "congestion_window", s.window())
	b = appendField(b, "bytes_in_flight", s.state.bytesInFlight)
	if s.state.slowStartThreshold != maxUint {
		b = appendField(b, "ssthresh", s.state.slowStartThreshold)
	}
	return b
}

func (s *congestionControl) String() string {
	return fmt.Sprintf("%v %v %v", &s.state, &s.cubic, &s.prr)
}

type congestionState struct {
	// maxDatagramSize is the sender's current maximum payload size.
	maxDatagramSize uint
	// bytesInFlight is the sum of the size in bytes of all sent packets that contain at least
	// one ack-eliciting or PADDING frame, and have not been acked or declared lost.
	bytesInFlight uint
	// congestionWindow is the maximum number of bytes-in-flight that may be sent.
	congestionWindow uint
	// slowStartThreshold is the slow start threshold in bytes.
	// When the congestion window is below slowStartThreshold, the mode is slow start
	// and the window grows by the number of bytes acknowledged.
	slowStartThreshold uint
	// recoveryStartTime is the time when QUIC first detects congestion due to loss or ECN,
	// causing it to enter congestion recovery. When a packet sent after this time is acknowledged,
	// QUIC exits congestion recovery.
	recoveryStartTime time.Time
	lastSentTime      time.Time
}

func (s *congestionState) init() {
	s.maxDatagramSize = initialMaxDatagramSize
	s.congestionWindow = initialWindowPackets * initialMaxDatagramSize
	s.slowStartThreshold = maxUint
}

func (s *congestionState) inRecovery(sentTime time.Time) bool {
	return !s.recoveryStartTime.IsZero() && !sentTime.After(s.recoveryStartTime)
}

func (s *congestionState) isSlowStart() bool {
	return s.congestionWindow < s.slowStartThreshold
}

// isAppLimited indicates application limited or flow control limited.
func (s *congestionState) isAppLimited() bool {
	if s.bytesInFlight >= s.congestionWindow {
		return false
	}
	// Alow a burst of 2 packets
	return s.bytesInFlight+minimumWindowPackets*s.maxDatagramSize < s.congestionWindow
}

func (s *congestionState) String() string {
	return fmt.Sprintf("congestion_window=%v bytes_in_flight=%v max_datagram_size=%v ssthresh=%v recovery_start_time=%v",
		s.congestionWindow, s.bytesInFlight, s.maxDatagramSize, s.slowStartThreshold, s.recoveryStartTime)
}

// CUBIC

const (
	// Multiplicative decrease factor.
	// The value is 0.7 but is multiplied by 10 for integer arithmetic.
	// https://www.rfc-editor.org/rfc/rfc8312.html#section-4.5
	cubicTenTimesBeta = 7
	// Scale constant that determines the aggressiveness of window increase.
	// The value is 0.4 but is multiplied by 10 for integer arithmetic.
	// https://www.rfc-editor.org/rfc/rfc8312.html#section-5.1
	cubicTenTimesC = 4
)

// https://www.rfc-editor.org/rfc/rfc8312.html
type cubic struct {
	// The time period in seconds it takes to increase the congestion
	// window size at the beginning of the current congestion avoidance
	// stage to W_max.
	k time.Duration
	// Window size just before the window is reduced in the last congestion event.
	windowMax     uint
	windowLastMax uint

	priorRecoveryStartTime  time.Time
	priorK                  time.Duration
	priorCongestionWindow   uint
	priorSlowStartThreshold uint
	priorWindowMax          uint
}

func (s *cubic) onLost(state *congestionState) {
	// Save previous state in case the congestion is spurious.
	s.priorWindowMax = s.windowMax
	s.priorK = s.k
	s.priorSlowStartThreshold = state.slowStartThreshold
	s.priorCongestionWindow = state.congestionWindow
	s.priorRecoveryStartTime = state.recoveryStartTime

	// Save window size before reduction
	s.windowMax = state.congestionWindow

	// Fast convergence.
	// https://www.rfc-editor.org/rfc/rfc8312.html#section-4.6
	if s.windowMax < s.windowLastMax { // should we make room for others
		// Further reduce W_max
		s.windowLastMax = s.windowMax
		s.windowMax = s.windowMax * (10 + cubicTenTimesBeta) / 20
	} else {
		// Remember the last W_max
		s.windowLastMax = s.windowMax
	}
	// Multiplicative Decrease.
	// https://www.rfc-editor.org/rfc/rfc8312.html#section-4.5
	state.slowStartThreshold = state.congestionWindow * cubicTenTimesBeta / 10
	minimumWindow := minimumWindowPackets * state.maxDatagramSize
	if state.slowStartThreshold < minimumWindow {
		state.slowStartThreshold = minimumWindow
	}
	state.congestionWindow = state.slowStartThreshold
	s.updateK(state)
}

func (s *cubic) onSent(state *congestionState, sentBytes uint, sentTime time.Time) {
	if state.bytesInFlight == 0 && !state.lastSentTime.IsZero() && !state.recoveryStartTime.IsZero() {
		// First transmit when no packets in flight
		delta := sentTime.Sub(state.lastSentTime)
		if delta > 0 {
			// We were application limited (idle) for a while.
			// Shift epoch start to keep cwnd growth to cubic curve.
			state.recoveryStartTime = state.recoveryStartTime.Add(delta)
		}
	}
}

func (s *cubic) onAcked(state *congestionState, sentBytes uint, rtt time.Duration, now time.Time) {
	if state.isSlowStart() {
		state.congestionWindow += sentBytes
		return
	}
	// Congestion avoidance.
	timeInCA := now.Sub(state.recoveryStartTime)
	// Spec said comparing W_cubic(t) vs W_est(t) instead.
	windowCubic := s.computeWCubic(state, timeInCA+rtt)
	windowEst := s.computeWEst(state, timeInCA, rtt)
	if windowCubic < windowEst {
		// TCP-Friendly region.
		// https://www.rfc-editor.org/rfc/rfc8312.html#section-4.2
		if state.congestionWindow < windowEst {
			state.congestionWindow = windowEst
		}
	} else {
		// Concave and convex region.
		// cwnd MUST be incremented by (W_cubic(t+RTT) - cwnd)/cwnd.
		// https://www.rfc-editor.org/rfc/rfc8312.html#section-4.3
		// windowCubic = s.computeWCubic(state, timeInCA+rtt)
		if state.congestionWindow < windowCubic {
			state.congestionWindow += (windowCubic - state.congestionWindow) * state.maxDatagramSize / state.congestionWindow
		}
	}
}

func (s *cubic) rollback(state *congestionState) {
	if state.congestionWindow < s.priorCongestionWindow {
		s.windowMax = s.priorWindowMax
		s.k = s.priorK
		state.slowStartThreshold = s.priorSlowStartThreshold
		state.congestionWindow = s.priorCongestionWindow
		state.recoveryStartTime = s.priorRecoveryStartTime
	}
}

// K = cubic_root(W_max*(1-beta_cubic)/C)
// https://www.rfc-editor.org/rfc/rfc8312.html#section-4.1
func (s *cubic) updateK(state *congestionState) {
	d := s.windowMax * (10 - cubicTenTimesBeta) / cubicTenTimesC / state.maxDatagramSize
	s.k = time.Duration(math.Cbrt(float64(d)) * float64(time.Second))
}

// W_cubic(t) = C*(t-K)^3 + W_max
func (s *cubic) computeWCubic(state *congestionState, t time.Duration) uint {
	d := float32(t-s.k) / float32(time.Second)
	d = d * d * d / 10 * cubicTenTimesC
	if d < 0 {
		return s.windowMax - uint(-d)*state.maxDatagramSize
	}
	return s.windowMax + uint(d)*state.maxDatagramSize
}

// W_est(t) = W_max*beta_cubic + [3*(1-beta_cubic)/(1+beta_cubic)] * (t/RTT)
func (s *cubic) computeWEst(state *congestionState, t, rtt time.Duration) uint {
	d := t / (10 + cubicTenTimesBeta) * 3 * (10 - cubicTenTimesBeta) / rtt
	return s.windowMax*cubicTenTimesBeta/10 + uint(d)*state.maxDatagramSize
}

func (s *cubic) String() string {
	return fmt.Sprintf("cubic_w_max=%v cubic_w_last_max=%v cubic_k=%v", s.windowMax, s.windowLastMax, s.k)
}

// Proportional Rate Reduction
// https://www.rfc-editor.org/rfc/rfc6937.html
type proportionalRateReduction struct {
	flightSize uint // FlightSize at the start of recovery (RecoverFS).
	delivered  uint // Total bytes delivered during recovery (prr_delivered).
	out        uint // Total bytes sent during recovery (prr_out).
	sndCnt     uint // Bytes should be sent (sndcnt).
}

func (s *proportionalRateReduction) onLost(state *congestionState) {
	s.flightSize = state.bytesInFlight
	s.delivered = 0
	s.out = 0
	s.sndCnt = 0
}

func (s *proportionalRateReduction) onSent(sentBytes uint) {
	s.out += sentBytes
	if s.sndCnt > sentBytes {
		s.sndCnt -= sentBytes
	} else {
		s.sndCnt = 0
	}
}

func (s *proportionalRateReduction) onAcked(state *congestionState, sentBytes uint) {
	if s.flightSize == 0 {
		return
	}
	s.delivered += sentBytes
	pipe := state.bytesInFlight
	ssthresh := state.slowStartThreshold
	if pipe > ssthresh {
		// Proportional Rate Reduction
		// sndcnt = CEIL(prr_delivered * ssthresh / RecoverFS) - prr_out
		limit := (s.delivered*ssthresh + s.flightSize - 1) / s.flightSize
		if limit > s.out {
			s.sndCnt = limit - s.out
		} else {
			s.sndCnt = 0
		}
	} else {
		// Two versions of the Reduction Bound
		// if (conservative) {    // PRR-CRB
		//     limit = prr_delivered - prr_out
		// } else {               // PRR-SSRB
		//     limit = MAX(prr_delivered - prr_out, DeliveredData) + MSS
		// }
		limit := sentBytes
		if s.delivered > s.out && limit < s.delivered-s.out {
			limit = s.delivered - s.out
		}
		limit += state.maxDatagramSize
		// Attempt to catch up, as permitted by limit
		// sndcnt = MIN(ssthresh-pipe, limit)
		if limit > ssthresh-pipe {
			limit = ssthresh - pipe
		}
		s.sndCnt = limit
	}
}

func (s *proportionalRateReduction) rollback() {
	s.flightSize = 0
	s.delivered = 0
	s.out = 0
	s.sndCnt = 0
}

func (s *proportionalRateReduction) String() string {
	return fmt.Sprintf("prr_flight_size=%v prr_delivered=%v prr_out=%v prr_sndcnt=%v",
		s.flightSize, s.delivered, s.out, s.sndCnt)
}
