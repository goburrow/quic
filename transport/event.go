package transport

// StreamRecvEvent is an event where a STREAM frame was received and data is readable.
type StreamRecvEvent struct {
	StreamID uint64
}

// StreamStopEvent is an event where a STOP_SENDING frame was received.
type StreamStopEvent struct {
	StreamID  uint64
	ErrorCode uint64
}

// StreamResetEvent is an event where a RESET_STREAM frame was received.
type StreamResetEvent struct {
	StreamID  uint64
	ErrorCode uint64
}
