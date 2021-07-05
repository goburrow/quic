package transport

import (
	"math"
	"testing"
	"time"
)

func TestCongestionControl(t *testing.T) {
	x := newCongestionControlTest(t)
	x.assertCongestionWindow(10 * initialMaxDatagramSize)

	x.c.setMaxDatagramSize(1000)
	x.assertCongestionWindow(10 * 1000)

	now := time.Now()
	x.c.onPacketSent(1000, now)
	x.assertAppLimited(true)
	x.assertWindowAvailable(9000)

	for i := 1; i < initialWindowPackets; i++ {
		x.c.onPacketSent(1000, now)
	}
	x.assertCongestionWindow(10000)
	x.assertAppLimited(false)
	x.c.onPacketAcked(2000, now, 50*time.Millisecond, now)
	x.assertCongestionWindow(12000)

	x.c.onCongestionEvent(now, now)
	x.assertCongestionWindow(6000)
	// In recovery
	x.c.onCongestionEvent(now, now)
	x.assertCongestionWindow(6000)
	x.assertWindowAvailable(0)
}

func TestCongestionCubic(t *testing.T) {
	const mss = initialMaxDatagramSize
	x := newCongestionControlTest(t)
	x.c.enableCubic = true
	x.assertCongestionWindow(14720) // initialWindowPackets*initialMaxDatagramSize

	sentTime := time.Now()
	rtt := 100 * time.Millisecond
	// Slow start
	x.c.onPacketSent(8*mss, sentTime)

	now := sentTime.Add(100 * time.Millisecond)
	x.c.onPacketAcked(1500, sentTime, rtt, now)
	x.assertCongestionWindow(14720 + 1500)
	x.c.onPacketAcked(500, sentTime, rtt, now)
	x.assertCongestionWindow(14720 + 2000)

	x.c.onCongestionEvent(sentTime, now)

	// cwnd reduced by (1 - beta_cubic)
	x.assertCubicWindowMax(16720)
	x.assertCongestionWindow(16720 - 16720*3/10)
	x.assertSlowStartThreshold(11704) // = cwnd

	k := math.Cbrt(16720 / mss * 0.3 / 0.4) // 2.02062
	x.assertCubicK(k)

	// Congestion avoidance
	sentTime = now.Add(1 * time.Millisecond) // No longer in recovery
	// for i := 0; i < 100; i++ {
	// 	now = now.Add(rtt)
	// 	x.c.cubic.onPacketAcked(1000, rtt, now)
	// }
	now = now.Add(rtt)
	x.c.onPacketAcked(1000, sentTime, rtt, now)
	t.Log(&x.c)

	// cwnd increased by (W_cubic(0.1s + rtt) - cwnd) / cwnd)
	wt := 16720 + math.Pow(0.2-k, 3)*0.4*mss
	x.assertCongestionWindowF(11704 + (wt-11704)*mss/11704)

	// tcp-friendly
	now = now.Add(7 * rtt)
	x.c.onPacketAcked(1000, sentTime, rtt, now)
	wt = 16720*0.7 + 3*(1-0.7)/(1+0.7)*500/100*1472
	x.assertCongestionWindowF(wt)
}

func TestCongestionPRR(t *testing.T) {
	x := newCongestionControlTest(t)
	x.c.enablePRR = true
	x.c.setMaxDatagramSize(1000)

	sentTime := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	x.c.onPacketSent(5000, sentTime)
	x.c.onPacketSent(5000, sentTime)
	x.assertInFlight(10000)

	now := sentTime.Add(100 * time.Millisecond)
	x.c.onCongestionEvent(sentTime, now)
	x.assertSlowStartThreshold(5000)

	if x.c.prr.flightSize != 10000 {
		t.Fatalf("expect prr_flight_size: %v, actual: %v", 10000, &x.c)
	}

	x.c.onPacketSent(1000, sentTime)
	if x.c.prr.out != 1000 {
		t.Fatalf("expect prr_out: %v, actual: %v", 1000, &x.c)
	}
	now = now.Add(50 * time.Millisecond)
	x.c.onPacketAcked(5000, sentTime, 50*time.Millisecond, now)
	// pipe > ssthresh
	x.assertInFlight(6000)
	if x.c.prr.delivered != 5000 {
		t.Fatalf("expect prr_delivered: %v, actual: %v", 5000, &x.c)
	}
	if x.c.prr.sndCnt != 1500 { // 5000*5000/10000 - 1000
		t.Fatalf("expect sndcnt: %v, actual: %v", 1500, &x.c)
	}
	x.c.onPacketAcked(1000, sentTime, 50*time.Millisecond, now)
	x.assertInFlight(5000)
	// pipe == ssthresh
	if x.c.prr.sndCnt != 0 {
		t.Fatalf("expect sndcnt: %v, actual: %v", 0, &x.c)
	}
}

func BenchmarkCongestionControl(b *testing.B) {
	c := congestionControl{}
	c.init()
	c.enableCubic = true
	c.enablePRR = true
	now := time.Now()
	c.onCongestionEvent(now, now)
	now = now.Add(1 * time.Second)
	for i := 0; i < b.N; i++ {
		c.onPacketSent(1000, now)
		c.onPacketAcked(1000, now, time.Millisecond, now)
	}
}

type congestionControlTest struct {
	t *testing.T
	c congestionControl
}

func newCongestionControlTest(t *testing.T) *congestionControlTest {
	x := &congestionControlTest{
		t: t,
	}
	x.c.init()
	return x
}

func (x *congestionControlTest) assertInFlight(n uint) {
	if x.c.state.bytesInFlight != n {
		x.t.Helper()
		x.t.Fatalf("expect bytesInFlight: %v, actual: %d", n, x.c.state.bytesInFlight)
	}
}

func (x *congestionControlTest) assertCongestionWindow(cwnd uint) {
	if x.c.state.congestionWindow != cwnd {
		x.t.Helper()
		x.t.Fatalf("expect congestion window: %v, actual: %v", cwnd, x.c.state.congestionWindow)
	}
}

func (x *congestionControlTest) assertCongestionWindowF(cwnd float64) {
	delta := (cwnd - float64(x.c.state.congestionWindow)) / cwnd
	if delta < -0.75 || delta > 0.75 {
		x.t.Helper()
		x.t.Fatalf("expect congestion window: %v, actual: %v (diff: %.2f%%)", cwnd, x.c.state.congestionWindow, delta*100)
	}
}

func (x *congestionControlTest) assertSlowStartThreshold(ssthresh uint) {
	if x.c.state.slowStartThreshold != ssthresh {
		x.t.Helper()
		x.t.Fatalf("expect ssthresh: %v, actual: %v", ssthresh, x.c.state.slowStartThreshold)
	}
}

func (x *congestionControlTest) assertAppLimited(limited bool) {
	appLimited := x.c.state.isAppLimited()
	if appLimited != limited {
		x.t.Helper()
		x.t.Fatalf("expect app limited: %v, actual: %v", limited, appLimited)
	}
}

func (x *congestionControlTest) assertWindowAvailable(n uint) {
	avail := x.c.available()
	if avail != n {
		x.t.Helper()
		x.t.Fatalf("expect window available: %v, actual: %v", n, avail)
	}
}

func (x *congestionControlTest) assertCubicK(v float64) {
	k := float64(x.c.cubic.k) / float64(time.Second)
	delta := (v - k) / v
	if delta < -0.01 || delta > 0.01 {
		x.t.Helper()
		x.t.Fatalf("expect k: %v, actual: %v (diff: %.2f%%)", v, x.c.cubic.k, delta*100)
	}
}

func (x *congestionControlTest) assertCubicWindowMax(v uint) {
	if x.c.cubic.windowMax != v {
		x.t.Helper()
		x.t.Fatalf("expect w_max: %v, actual: %v", v, x.c.cubic.windowMax)
	}
}
