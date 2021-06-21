package transport

import (
	"testing"
	"time"
)

func TestLogConnectionState(t *testing.T) {
	e := newTestLogEvent(logEventStateUpdated)
	logConnectionState(&e, stateHandshake, stateActive)
	expect := "2020-01-05T00:00:00Z connection_state_updated old=handshake new=active"
	assertLogEvent(t, e, expect)
}

func TestLogParameters(t *testing.T) {
	p := &Parameters{
		OriginalDestinationCID: []byte{1, 2},
		InitialSourceCID:       []byte{3},
		RetrySourceCID:         []byte{4, 5},
		StatelessResetToken:    []byte{6, 7, 8},

		MaxIdleTimeout:    60 * time.Second,
		MaxUDPPayloadSize: 1500,

		InitialMaxData:                 1000,
		InitialMaxStreamDataBidiLocal:  200,
		InitialMaxStreamDataBidiRemote: 300,
		InitialMaxStreamDataUni:        100,
		InitialMaxStreamsBidi:          10,
		InitialMaxStreamsUni:           5,

		AckDelayExponent: 3,
		MaxAckDelay:      100 * time.Millisecond,

		ActiveConnectionIDLimit: 2,
		DisableActiveMigration:  true,
	}
	e := newTestLogEvent(logEventParametersSet)
	logParameters(&e, p)
	expect := "2020-01-05T00:00:00Z parameters_set owner=remote original_connection_id=0102 " +
		"max_idle_timeout=60000 stateless_reset_token=060708 max_udp_payload_size=1500 " +
		"initial_max_data=1000 initial_max_stream_data_bidi_local=200 initial_max_stream_data_bidi_remote=300 " +
		"initial_max_stream_data_uni=100 initial_max_streams_bidi=10 initial_max_streams_uni=5 " +
		"ack_delay_exponent=3 max_ack_delay=100 disable_active_migration=true active_connection_id_limit=2 " +
		"initial_source_connection_id=03 retry_source_connection_id=0405"
	assertLogEvent(t, e, expect)
}

func TestLogFramePadding(t *testing.T) {
	testLogFrame(t, newPaddingFrame(1), "frame_type=padding")
}

func TestLogFramePing(t *testing.T) {
	f := &pingFrame{}
	testLogFrame(t, f, "frame_type=ping")
}

func TestLogFrameAck(t *testing.T) {
	f := &ackFrame{
		largestAck:    3,
		ackDelay:      2,
		firstAckRange: 1,
		ecnCounts: &ecnCounts{
			ect0Count: 4,
			ect1Count: 5,
			ceCount:   6,
		},
	}
	testLogFrame(t, f, "frame_type=ack ack_delay=2 acked_ranges=[[2,3]] ect0=4 ect1=5 ce=6")
}

func TestLogFrameResetStream(t *testing.T) {
	f := newResetStreamFrame(1, 2, 3)
	testLogFrame(t, f, "frame_type=reset_stream stream_id=1 error_code=2 final_size=3")
}

func TestLogFrameStopSending(t *testing.T) {
	f := newStopSendingFrame(1, 2)
	testLogFrame(t, f, "frame_type=stop_sending stream_id=1 error_code=2")
}

func TestLogFrameCrypto(t *testing.T) {
	f := newCryptoFrame(make([]byte, 5), 1)
	testLogFrame(t, f, "frame_type=crypto offset=1 length=5")
}

func TestLogFrameNewToken(t *testing.T) {
	f := newNewTokenFrame(make([]byte, 4))
	testLogFrame(t, f, "frame_type=new_token token=00000000")
}

func TestLogFrameStream(t *testing.T) {
	f := newStreamFrame(2, make([]byte, 4), 3, true)
	testLogFrame(t, f, "frame_type=stream stream_id=2 offset=3 length=4 fin=true")
}

func TestLogFrameMaxData(t *testing.T) {
	f := newMaxDataFrame(1)
	testLogFrame(t, f, "frame_type=max_data maximum=1")
}

func TestLogFrameMaxStreamData(t *testing.T) {
	f := newMaxStreamDataFrame(1, 2)
	testLogFrame(t, f, "frame_type=max_stream_data stream_id=1 maximum=2")
}

func TestLogFrameMaxStreams(t *testing.T) {
	f := newMaxStreamsFrame(1, false)
	testLogFrame(t, f, "frame_type=max_streams stream_type=unidirectional maximum=1")
	f = newMaxStreamsFrame(2, true)
	testLogFrame(t, f, "frame_type=max_streams stream_type=bidirectional maximum=2")
}

func TestLogFrameDataBlocked(t *testing.T) {
	f := newDataBlockedFrame(1)
	testLogFrame(t, f, "frame_type=data_blocked limit=1")
}

func TestLogFrameStreamDataBlocked(t *testing.T) {
	f := newStreamDataBlockedFrame(1, 2)
	testLogFrame(t, f, "frame_type=stream_data_blocked stream_id=1 limit=2")
}

func TestLogFrameStreamsBlocked(t *testing.T) {
	f := newStreamsBlockedFrame(1, false)
	testLogFrame(t, f, "frame_type=streams_blocked stream_type=unidirectional limit=1")
	f = newStreamsBlockedFrame(2, true)
	testLogFrame(t, f, "frame_type=streams_blocked stream_type=bidirectional limit=2")
}

func TestLogFrameNewConnectionID(t *testing.T) {
	f := &newConnectionIDFrame{
		sequenceNumber:      1,
		retirePriorTo:       2,
		connectionID:        []byte{1},
		statelessResetToken: []byte{2},
	}
	testLogFrame(t, f, "frame_type=new_connection_id sequence_number=1 retire_prior_to=2 connection_id=01 stateless_reset_token=02")
}

func TestLogFrameRetireConnectionID(t *testing.T) {
	f := &retireConnectionIDFrame{
		sequenceNumber: 1,
	}
	testLogFrame(t, f, "frame_type=retire_connection_id sequence_number=1")
}

func TestLogFramePathChallenge(t *testing.T) {
	f := &pathChallengeFrame{
		data: []byte{1, 2, 3},
	}
	testLogFrame(t, f, "frame_type=path_challenge data=010203")
}

func TestLogFramePathResponse(t *testing.T) {
	f := &pathResponseFrame{
		data: []byte{4, 5},
	}
	testLogFrame(t, f, "frame_type=path_response data=0405")
}

func TestLogFrameConnectionClose(t *testing.T) {
	f := newConnectionCloseFrame(0x122, 99, []byte("reason"), false)
	testLogFrame(t, f, "frame_type=connection_close error_space=transport error_code=crypto_error_34 raw_error_code=290 trigger_frame_type=99 reason=reason")
}

func TestLogFrameHandshakeDone(t *testing.T) {
	f := &handshakeDoneFrame{}
	testLogFrame(t, f, "frame_type=handshake_done")
}

func testLogFrame(t *testing.T, f frame, expect string) {
	e := newTestLogEvent(logEventFramesProcessed)
	logFrame(&e, f)
	expect = "2020-01-05T00:00:00Z frames_processed " + expect
	actual := e.String()
	if expect != actual {
		t.Helper()
		t.Fatalf("\nexpect %v\nactual %v", expect, actual)
	}
}

func TestLogPacket(t *testing.T) {
	p := &packet{
		typ: packetTypeHandshake,
		header: packetHeader{
			version: 1,
			dcid:    []byte{1, 2, 3},
			scid:    []byte{4, 5},
		},
		packetNumber: 1,
		payloadLen:   10,
		packetSize:   20,
	}
	e := newTestLogEvent(logEventPacketSent)
	logPacket(&e, p)
	expect := "2020-01-05T00:00:00Z packet_sent packet_type=handshake version=1 dcid=010203 scid=0405 packet_number=1 packet_size=20 payload_length=10"
	assertLogEvent(t, e, expect)
}

func TestLogRecovery(t *testing.T) {
	r := &lossRecovery{}
	e := newTestLogEvent(logEventMetricsUpdated)
	logRecovery(&e, r)
	expect := "2020-01-05T00:00:00Z metrics_updated min_rtt=0 smoothed_rtt=333 latest_rtt=0 rtt_variance=0 " +
		"pto_count=0 congestion_window=0 bytes_in_flight=0"
	assertLogEvent(t, e, expect)
}

func TestLogLossTimer(t *testing.T) {
	r := &lossRecovery{}
	e := newTestLogEvent(logEventLossTimerUpdated)
	logLossTimer(&e, r)
	expect := "2020-01-05T00:00:00Z loss_timer_updated event_type=cancelled"
	assertLogEvent(t, e, expect)

	r.lossDetectionTimer = e.Time.Add(100 * time.Millisecond)
	e.resetFields()
	logLossTimer(&e, r)
	expect = "2020-01-05T00:00:00Z loss_timer_updated event_type=set delta=100"
	assertLogEvent(t, e, expect)
}

func TestLogStreamState(t *testing.T) {
	e := newTestLogEvent(logEventStreamStateUpdated)
	logStreamClosed(&e, 10)
	expect := "2020-01-05T00:00:00Z stream_state_updated stream_id=10 new=closed"
	assertLogEvent(t, e, expect)
}

func newTestLogEvent(typ string) LogEvent {
	tm := time.Date(2020, time.January, 5, 0, 0, 0, 0, time.UTC)
	return newLogEvent(tm, typ)
}

func assertLogEvent(t *testing.T, e LogEvent, expect string) {
	actual := e.String()
	if expect != actual {
		t.Helper()
		t.Fatalf("\nexpect %v\nactual %v", expect, actual)
	}
}
