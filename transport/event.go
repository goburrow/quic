package transport

// StreamEvent is when receiving a Stream frame.
type StreamEvent struct {
	StreamID uint64
}

type StopSendingEvent struct {
	StreamID  uint64
	ErrorCode uint64
}

type ResetStreamEvent struct {
	StreamID  uint64
	ErrorCode uint64
}
