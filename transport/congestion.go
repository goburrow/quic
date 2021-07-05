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
	s.cubic.init(&s.state)
	s.prr.init(&s.state)
}

// https://www.rfc-editor.org/rfc/rfc9002.html#section-b.4
func (s *congestionControl) onPacketSent(sentBytes uint, sentTime time.Time) {
	if s.enableCubic {
		s.cubic.onPacketSent(sentBytes, sentTime)
	}
	if s.enablePRR {
		s.prr.onPacketSent(sentBytes)
	}
	s.state.bytesInFlight += sentBytes
	s.state.lastSentTime = sentTime
}

// onPacketsAcked is invoked from loss detection's onAckReceived and
// is supplied with the newly acked_packets from sent_packets.
// https://www.rfc-editor.org/rfc/rfc9002.html#section-b.5
func (s *congestionControl) onPacketAcked(sentBytes uint, sentTime time.Time, rtt time.Duration, now time.Time) {
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
			s.prr.onPacketAcked(sentBytes)
		}
		return
	}
	if s.state.isAppLimited() {
		debug("application limited on packet acked: %v", s)
		return
	}
	if s.enableCubic {
		s.cubic.onPacketAcked(sentBytes, rtt, now)
	} else {
		s.renoOnPacketAcked(sentBytes)
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
func (s *congestionControl) onCongestionEvent(sentTime, now time.Time) {
	// Start a new congestion event if packet was sent after the
	// start of the previous congestion recovery period.
	if s.state.inRecovery(sentTime) {
		return
	}
	s.state.recoveryStartTime = now
	if s.enableCubic {
		s.cubic.onCongestionEvent()
	} else {
		s.renoOnCongestionEvent()
	}
	if s.enablePRR {
		s.prr.onCongestionEvent()
	}
	debug("congestion event: %v", s)
}

func (s *congestionControl) onSpuriousCongestionEvent() {
	if s.enableCubic {
		s.cubic.onSpuriousCongestionEvent()
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

func (s *congestionControl) renoOnCongestionEvent() {
	s.state.slowStartThreshold = s.state.congestionWindow / lossReductionFactor
	// congestion_window = max(ssthresh, kMinimumWindow)
	minimumWindow := minimumWindowPackets * s.state.maxDatagramSize
	if s.state.slowStartThreshold < minimumWindow {
		s.state.slowStartThreshold = minimumWindow
	}
	s.state.congestionWindow = s.state.slowStartThreshold
}

func (s *congestionControl) renoOnPacketAcked(sentBytes uint) {
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
	if s.isSlowStart() {
		return s.bytesInFlight < s.congestionWindow/lossReductionFactor
	}
	// Alow a burst of 10 packets
	return s.bytesInFlight+initialWindowPackets*s.maxDatagramSize < s.congestionWindow
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
	state *congestionState

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

func (s *cubic) init(state *congestionState) {
	s.state = state
}

func (s *cubic) onCongestionEvent() {
	// Save previous state in case the congestion is spurious.
	s.priorWindowMax = s.windowMax
	s.priorK = s.k
	s.priorSlowStartThreshold = s.state.slowStartThreshold
	s.priorCongestionWindow = s.state.congestionWindow
	s.priorRecoveryStartTime = s.state.recoveryStartTime

	// Save window size before reduction
	s.windowMax = s.state.congestionWindow

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
	s.state.slowStartThreshold = s.state.congestionWindow * cubicTenTimesBeta / 10
	minimumWindow := minimumWindowPackets * s.state.maxDatagramSize
	if s.state.slowStartThreshold < minimumWindow {
		s.state.slowStartThreshold = minimumWindow
	}
	s.state.congestionWindow = s.state.slowStartThreshold
	s.updateK()
}

func (s *cubic) onSpuriousCongestionEvent() {
	if s.state.congestionWindow < s.priorCongestionWindow {
		s.windowMax = s.priorWindowMax
		s.k = s.priorK
		s.state.slowStartThreshold = s.priorSlowStartThreshold
		s.state.congestionWindow = s.priorCongestionWindow
		s.state.recoveryStartTime = s.priorRecoveryStartTime
	}
}

func (s *cubic) onPacketSent(sentBytes uint, sentTime time.Time) {
	if s.state.bytesInFlight == 0 && !s.state.lastSentTime.IsZero() && !s.state.recoveryStartTime.IsZero() {
		// First transmit when no packets in flight
		delta := sentTime.Sub(s.state.lastSentTime)
		if delta > 0 {
			// We were application limited (idle) for a while.
			// Shift epoch start to keep cwnd growth to cubic curve.
			s.state.recoveryStartTime = s.state.recoveryStartTime.Add(delta)
		}
	}
}

func (s *cubic) onPacketAcked(sentBytes uint, rtt time.Duration, now time.Time) {
	if s.state.isSlowStart() {
		s.state.congestionWindow += sentBytes
		return
	}
	// Congestion avoidance.
	timeInCA := now.Sub(s.state.recoveryStartTime)
	// Spec said comparing W_cubic(t) vs W_est(t) instead.
	windowCubic := s.computeWCubic(timeInCA + rtt)
	windowEst := s.computeWEst(timeInCA, rtt)
	if windowCubic < windowEst {
		// TCP-Friendly region.
		// https://www.rfc-editor.org/rfc/rfc8312.html#section-4.2
		if s.state.congestionWindow < windowEst {
			s.state.congestionWindow = windowEst
		}
	} else {
		// Concave and convex region.
		// cwnd MUST be incremented by (W_cubic(t+RTT) - cwnd)/cwnd.
		// https://www.rfc-editor.org/rfc/rfc8312.html#section-4.3
		// windowTarget := s.computeWCubic(timeInCA + rtt)
		if s.state.congestionWindow < windowCubic {
			s.state.congestionWindow += (windowCubic - s.state.congestionWindow) * s.state.maxDatagramSize / s.state.congestionWindow
		}
	}
}

// K = cubic_root(W_max*(1-beta_cubic)/C)
// https://www.rfc-editor.org/rfc/rfc8312.html#section-4.1
func (s *cubic) updateK() {
	d := float64(s.windowMax/s.state.maxDatagramSize) * (10 - cubicTenTimesBeta) / cubicTenTimesC
	s.k = time.Duration(math.Cbrt(d) * float64(time.Second))
}

// W_cubic(t) = C*(t-K)^3 + W_max
func (s *cubic) computeWCubic(t time.Duration) uint {
	d := float32(t-s.k) / float32(time.Second)
	d = d * d * d / 10 * cubicTenTimesC
	if d < 0 {
		return s.windowMax - uint(-d)*s.state.maxDatagramSize
	}
	return s.windowMax + uint(d)*s.state.maxDatagramSize
}

// W_est(t) = W_max*beta_cubic + [3*(1-beta_cubic)/(1+beta_cubic)] * (t/RTT)
func (s *cubic) computeWEst(t, rtt time.Duration) uint {
	d := t / (10 + cubicTenTimesBeta) * 3 * (10 - cubicTenTimesBeta) / rtt
	return s.windowMax*cubicTenTimesBeta/10 + uint(d)*s.state.maxDatagramSize
}

func (s *cubic) String() string {
	return fmt.Sprintf("cubic_w_max=%v cubic_w_last_max=%v cubic_k=%v", s.windowMax, s.windowLastMax, s.k)
}

// Proportional Rate Reduction
// https://www.rfc-editor.org/rfc/rfc6937.html
type proportionalRateReduction struct {
	state *congestionState

	flightSize uint // FlightSize at the start of recovery (RecoverFS).
	delivered  uint // Total bytes delivered during recovery (prr_delivered).
	out        uint // Total bytes sent during recovery (prr_out).
	sndCnt     uint // Bytes should be sent (sndcnt).
}

func (s *proportionalRateReduction) init(state *congestionState) {
	s.state = state
}

func (s *proportionalRateReduction) onCongestionEvent() {
	s.flightSize = s.state.bytesInFlight
	s.delivered = 0
	s.out = 0
	s.sndCnt = 0
}

func (s *proportionalRateReduction) onPacketSent(sentBytes uint) {
	s.out += sentBytes
	if s.sndCnt > sentBytes {
		s.sndCnt -= sentBytes
	} else {
		s.sndCnt = 0
	}
}

func (s *proportionalRateReduction) onPacketAcked(sentBytes uint) {
	if s.flightSize == 0 {
		return
	}
	s.delivered += sentBytes
	pipe := s.state.bytesInFlight
	ssthresh := s.state.slowStartThreshold
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
		limit += s.state.maxDatagramSize
		// Attempt to catch up, as permitted by limit
		// sndcnt = MIN(ssthresh-pipe, limit)
		if limit > ssthresh-pipe {
			limit = ssthresh - pipe
		}
		s.sndCnt = limit
	}
}

func (s *proportionalRateReduction) String() string {
	return fmt.Sprintf("prr_flight_size=%v prr_delivered=%v prr_out=%v prr_sndcnt=%v",
		s.flightSize, s.delivered, s.out, s.sndCnt)
}
