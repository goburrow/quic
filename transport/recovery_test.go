package transport

import (
	"testing"
	"time"
)

func TestRecoverySetTimer(t *testing.T) {
	x := lossRecovery{}
	now := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	x.init(now)

	now = time.Date(2000, 1, 1, 0, 0, 1, 0, time.UTC)
	p := &outgoingPacket{
		packetNumber: 0,
		frames:       []frame{&pingFrame{}},
		timeSent:     now,
		size:         1,
		ackEliciting: true,
		inFlight:     true,
	}
	x.onPacketSent(p, packetSpaceHandshake)

	if x.timeLastSentAckElicitingPacket != now {
		t.Fatalf("expect timeLastSentAckElicitingPacket: %v, actual: %v", now, x.timeLastSentAckElicitingPacket)
	}
	if x.bytesInFlight != p.size {
		t.Fatalf("expect bytesInFlight: %v, actual: %v", p.size, x.bytesInFlight)
	}
	if x.lossDetectionTimer != now.Add(initialRTT*2) {
		t.Fatalf("expect lossDetectionTimer: %v, actual: %v", now.Add(initialRTT*2), x.lossDetectionTimer)
	}
	// expire
	now = now.Add(1 * time.Second)
	x.onLossDetectionTimeout(now)
	if x.probes == 0 {
		t.Fatalf("expect probes > 0, actual: %v", x.probes)
	}
}
