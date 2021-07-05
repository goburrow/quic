package transport

import (
	"testing"
	"time"
)

func TestRecoveryInitialRTT(t *testing.T) {
	x := newLossRecoveryTest(t)
	x.assertRTT(0, initialRTT, initialRTT/2, 0)

	now := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	x.send(packetSpaceInitial, 1, 101, now, &pingFrame{})

	x.assertSent(packetSpaceInitial, 1)
	x.assertInFlight(101)
	x.assertTimer(now.Add(999 * time.Millisecond))

	// Timeout
	now = now.Add(1 * time.Second)
	x.r.onLossDetectionTimeout(now)
	if x.r.lossProbes[packetSpaceInitial] == 0 {
		t.Fatalf("expect probes > 0, actual: %v", x.r.lossProbes[packetSpaceInitial])
	}
	x.assertTimer(now.Add(998 * time.Millisecond))
	x.assertSent(packetSpaceInitial, 1)
	x.assertLost(packetSpaceInitial, 1)
}

func TestRecoverySetTimer(t *testing.T) {
	x := newLossRecoveryTest(t)

	now := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	x.send(packetSpaceHandshake, 1, 1000, now, &pingFrame{})
	x.send(packetSpaceHandshake, 2, 500, now.Add(5*time.Millisecond), &pingFrame{})
	x.send(packetSpaceHandshake, 3, 200, now.Add(10*time.Millisecond), &ackFrame{})

	x.assertSent(packetSpaceHandshake, 1, 2, 3)
	x.assertInFlight(1500)
	x.assertTimer(now.Add((5 + 999) * time.Millisecond))

	rtt := 20 * time.Millisecond
	x.ack(packetSpaceHandshake, 1, 1, 0, now.Add(rtt))

	x.assertRTT(rtt, rtt, rtt/2, rtt)
	x.assertAcked(packetSpaceHandshake, 1)
	x.assertSent(packetSpaceHandshake, 2, 3)
	x.assertLost(packetSpaceHandshake)
	// 20 + 4*10 + 5
	x.assertTimer(now.Add(65 * time.Millisecond))
}

func TestRecoveryLossOnReordering(t *testing.T) {
	x := newLossRecoveryTest(t)
	x.r.setHandshakeConfirmed()

	now := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	x.send(packetSpaceApplication, 0, 100, now, &pingFrame{})
	rtt := 100 * time.Millisecond
	now = now.Add(rtt)
	x.ack(packetSpaceApplication, 0, 0, 0, now)
	x.assertRTT(rtt, rtt, rtt/2, rtt)
	x.assertAcked(packetSpaceApplication, 0)
	x.r.drainAcked(packetSpaceApplication, func(frame) {})

	x.send(packetSpaceApplication, 1, 100, now, &streamFrame{streamID: 1})
	x.send(packetSpaceApplication, 2, 100, now, &streamFrame{streamID: 2})
	x.send(packetSpaceApplication, 3, 100, now, &streamFrame{streamID: 3})
	x.send(packetSpaceApplication, 4, 100, now, &streamFrame{streamID: 4})
	x.assertTimer(now.Add(3 * rtt))

	now = now.Add(rtt)
	x.ack(packetSpaceApplication, 3, 4, 0, now)

	x.assertAcked(packetSpaceApplication, 3, 4)
	x.assertLost(packetSpaceApplication, 1)
	x.assertSent(packetSpaceApplication, 1, 2)
	x.r.drainAcked(packetSpaceApplication, func(frame) {})
	x.r.drainLost(packetSpaceApplication, func(frame) {})
	x.assertAcked(packetSpaceApplication)
	x.assertLost(packetSpaceApplication)
	x.assertInFlight(100)

	now = now.Add(rtt)
	x.ack(packetSpaceApplication, 1, 1, 10, now)
	x.assertAcked(packetSpaceApplication, 1)
	x.assertLost(packetSpaceApplication)
	x.assertSent(packetSpaceApplication, 2)
	x.assertInFlight(0)
	x.r.drainAcked(packetSpaceApplication, func(frame) {
		t.Errorf("acked frames must be empty")
	})

	now = now.Add(rtt)
	x.r.onLossDetectionTimeout(now)
	x.assertAcked(packetSpaceApplication)
	x.assertLost(packetSpaceApplication, 2)
	x.assertSent(packetSpaceApplication, 2)
	x.assertInFlight(0)
	x.r.drainLost(packetSpaceApplication, func(frame) {})

	now = now.Add(3 * rtt)
	x.r.detectLostPackets(packetSpaceApplication, now)
	x.assertAcked(packetSpaceApplication)
	x.assertLost(packetSpaceApplication)
	x.assertSent(packetSpaceApplication)
	x.assertInFlight(0)
}

func TestRecoveryPacing(t *testing.T) {
	x := newLossRecoveryTest(t)
	x.r.enablePacing = true
	now := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

	x.send(packetSpaceApplication, 0, 6500, now, &streamFrame{streamID: 1})
	x.assertInFlight(6500)
	x.assertPacketSchedule(time.Time{})

	rtt := 50 * time.Millisecond
	now = now.Add(rtt)
	x.ack(packetSpaceApplication, 0, 0, rtt, now)
	x.assertInFlight(0)
	x.assertRTT(rtt, rtt, rtt/2, rtt)

	x.send(packetSpaceApplication, 1, 6500, now, &streamFrame{streamID: 1})
	x.assertPacketSchedule(now)

	x.send(packetSpaceApplication, 2, 6500, now, &streamFrame{streamID: 1})
	x.assertInFlight(13000)
	x.assertPacketSchedule(now.Add(6500 * rtt / 14720 / 3 * 2))
}

type lossRecoveryTest struct {
	t *testing.T
	r lossRecovery
}

func newLossRecoveryTest(t *testing.T) *lossRecoveryTest {
	x := &lossRecoveryTest{
		t: t,
	}
	x.r.init()
	x.r.congestion.enableCubic = false
	x.r.congestion.enablePRR = false
	return x
}

func (x *lossRecoveryTest) send(space packetSpace, pn uint64, size uint, tm time.Time, f frame) {
	p := newSentPacket(pn, tm)
	p.addFrame(f)
	p.sentBytes = size
	x.r.onPacketSent(p, space)
}

func (x *lossRecoveryTest) ack(space packetSpace, pnStart, pnEnd uint64, delay time.Duration, tm time.Time) {
	acked := rangeSet{}
	acked.push(pnStart, pnEnd)
	x.r.onAckReceived(acked, delay, space, tm)
}

func (x *lossRecoveryTest) assertSent(space packetSpace, packetNumbers ...uint64) {
	if len(x.r.sent[space]) != len(packetNumbers) {
		x.t.Helper()
		x.t.Fatalf("expect sent has %v packet(s), actual: %v", len(packetNumbers), x.r.sent[space])
	}
	for i, n := range packetNumbers {
		if x.r.sent[space][i].packetNumber != n {
			x.t.Helper()
			x.t.Fatalf("expect sent packet at %v has number: %v, actual: %v", i, n, x.r.sent[space][i])
		}
	}
}

func (x *lossRecoveryTest) assertLost(space packetSpace, packetNumbers ...uint64) {
	if len(x.r.lost[space]) != len(packetNumbers) {
		x.t.Helper()
		x.t.Fatalf("expect lost has %v packet(s), actual: %v", len(packetNumbers), x.r.lost[space])
	}
	for i, n := range packetNumbers {
		if x.r.lost[space][i].packetNumber != n {
			x.t.Helper()
			x.t.Fatalf("expect lost packet at %v has number: %v, actual: %v", i, n, x.r.lost[space][i])
		}
	}
}

func (x *lossRecoveryTest) assertAcked(space packetSpace, packetNumbers ...uint64) {
	if len(x.r.acked[space]) != len(packetNumbers) {
		x.t.Helper()
		x.t.Fatalf("expect acked has %v packet(s), actual: %v", len(packetNumbers), x.r.acked[space])
	}
	for i, n := range packetNumbers {
		if x.r.acked[space][i].packetNumber != n {
			x.t.Helper()
			x.t.Fatalf("expect acked packet at %v has number: %v, actual: %v", i, n, x.r.acked[space][i])
		}
	}
}

func (x *lossRecoveryTest) assertInFlight(n uint) {
	if x.r.congestion.state.bytesInFlight != n {
		x.t.Helper()
		x.t.Fatalf("expect bytesInFlight: %v, actual: %d", n, x.r.congestion.state.bytesInFlight)
	}
}

func (x *lossRecoveryTest) assertSendAvail(n uint) {
	avail := x.r.availSend()
	if avail != n {
		x.t.Helper()
		x.t.Fatalf("expect send available: %v, actual: %v", n, avail)
	}
}

func (x *lossRecoveryTest) assertTimer(n time.Time) {
	if !x.r.lossDetectionTimer.Equal(n) {
		x.t.Helper()
		x.t.Fatalf("expect lossDetectionTimer: %v, actual: %v", n, x.r.lossDetectionTimer)
	}
}

func (x *lossRecoveryTest) assertRTT(latestRTT, smoothedRTT, rttVar, minRTT time.Duration) {
	if x.r.latestRTT != latestRTT {
		x.t.Helper()
		x.t.Fatalf("expect latest rtt: %v, actual: %v", latestRTT, x.r.latestRTT)
	}
	if x.r.roundTripTime() != smoothedRTT {
		x.t.Helper()
		x.t.Fatalf("expect smoothed rtt: %v, actual: %v", smoothedRTT, x.r.roundTripTime())
	}
	if x.r.rttVariance != rttVar {
		x.t.Helper()
		x.t.Fatalf("expect rtt variance: %v, actual: %v", rttVar, x.r.rttVariance)
	}
	if x.r.minRTT != minRTT {
		x.t.Helper()
		x.t.Fatalf("expect min rtt: %v, actual: %v", minRTT, x.r.minRTT)
	}
}

func (x *lossRecoveryTest) assertPacketSchedule(tm time.Time) {
	if !x.r.lastPacketSchedule.Equal(tm) {
		x.t.Helper()
		x.t.Fatalf("expect last packet schedule: %v, actual: %v", x.r.lastPacketSchedule, tm)
	}
}
