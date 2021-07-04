package quic

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Stream provides asynchronous APIs to interact which a QUIC stream.
// All Stream functions must be used in a separated goroutine that is
// different to the connection callback.
// For example:
//
// 	func (handler) Serve(conn *quic.Conn, events []transport.Event) {
// 		for _, e := range events {
// 			switch e.Type {
// 			case transport.EventStreamOpen:
// 				st, err := conn.Stream(e.ID)
// 				...
// 				go func(stream *quic.Stream) {
// 					// Working on the stream.
// 				}(st)
// 			}
// 		}
// 	}
//
// Stream implements net.Conn interface.
type Stream struct {
	id   uint64
	conn *Conn

	// Writing
	wrMu   sync.Mutex
	wrData dataBuffer

	// Reading
	rdMu   sync.Mutex
	rdData dataBuffer

	// Closing
	clMu       sync.Mutex
	clResultCh chan error

	closeOnce sync.Once
	closeCh   chan struct{}
	// Due to asynchronous operators, application may not fully read data when the connection is closed.
	// This stream needs to own the QUIC Stream in this case so that the application can continue reading.
	closeErr error
	closeRd  io.Reader
}

var (
	_ net.Conn = (*Stream)(nil)
)

func newStream(conn *Conn, id uint64) *Stream {
	s := &Stream{
		conn: conn,
		id:   id,

		clResultCh: make(chan error),
		closeCh:    make(chan struct{}),
	}
	s.wrData.init()
	s.rdData.init()
	return s
}

// Write writes data to the connection stream.
// The function is blocked until all data are put into stream buffer or timeout.
func (s *Stream) Write(b []byte) (int, error) {
	s.wrMu.Lock()
	defer s.wrMu.Unlock()

	select {
	case <-s.closeCh:
		// This connection or stream is already closed.
		return 0, s.closeErr
	default:
		return s.writeLocked(b)
	}
}

func (s *Stream) writeLocked(b []byte) (int, error) {
	s.wrData.setBuf(b)
	cmd := connCommand{
		cmd: cmdStreamWrite,
		id:  s.id,
	}
	var err error
	select {
	case <-s.closeCh:
		err = s.closeErr
	case <-s.wrData.deadlineCh:
		err = errDeadlineExceeded
	case s.conn.cmdCh <- cmd:
		// Wait for result
		err = <-s.wrData.resultCh
		for err == errWait {
			select {
			case <-s.closeCh:
				err = s.closeErr
			case <-s.wrData.deadlineCh:
				err = errDeadlineExceeded
			case <-s.wrData.waitCh:
				err = <-s.wrData.resultCh
			}
		}
	}
	n := s.wrData.setBuf(nil)
	return n, err
}

// Read reads data from the stream.
// The function is blocked until any stream data is available or timeout.
func (s *Stream) Read(b []byte) (int, error) {
	s.rdMu.Lock()
	defer s.rdMu.Unlock()

	select {
	case <-s.closeCh:
		// This connection or stream is already closed.
		return s.readClosed(b)
	default:
		return s.readLocked(b)
	}
}

func (s *Stream) readLocked(b []byte) (int, error) {
	s.rdData.setBuf(b)
	cmd := connCommand{
		cmd: cmdStreamRead,
		id:  s.id,
	}
	var err error
	select {
	case <-s.closeCh:
		n := s.rdData.setBuf(nil)
		if n > 0 {
			return n, nil
		}
		return s.readClosed(b)
	case <-s.rdData.deadlineCh:
		err = errDeadlineExceeded
	case s.conn.cmdCh <- cmd:
		// Wait for result
		err = <-s.rdData.resultCh
		for err == errWait {
			select {
			case <-s.closeCh:
				n := s.rdData.setBuf(nil)
				if n > 0 {
					return n, nil
				}
				return s.readClosed(b)
			case <-s.rdData.deadlineCh:
				err = errDeadlineExceeded
			case <-s.rdData.waitCh:
				err = <-s.rdData.resultCh
			}
		}
	}
	n := s.rdData.setBuf(nil)
	return n, err
}

func (s *Stream) readClosed(b []byte) (int, error) {
	if s.closeRd == nil {
		return 0, s.closeErr
	}
	n, err := s.closeRd.Read(b)
	if err == nil && n == 0 {
		// Nothing else to read
		err = s.closeErr
	}
	return n, err
}

// Close closes the sending part of the stream.
func (s *Stream) Close() error {
	return s.close(cmdStreamClose, 0)
}

// CloseWrite terminates sending part of the stream.
func (s *Stream) CloseWrite(errorCode uint64) error {
	return s.close(cmdStreamCloseWrite, errorCode)
}

// CloseRead terminates reading part of the stream.
func (s *Stream) CloseRead(errorCode uint64) error {
	return s.close(cmdStreamCloseRead, errorCode)
}

// LocalAddr returns the local network address.
func (s *Stream) LocalAddr() net.Addr {
	return s.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (s *Stream) RemoteAddr() net.Addr {
	return s.conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines associated with the stream.
func (s *Stream) SetDeadline(t time.Time) error {
	s.SetWriteDeadline(t)
	s.SetReadDeadline(t)
	return nil
}

// SetWriteDeadline sets the write deadline associated with the stream.
func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.wrMu.Lock()
	s.wrData.setDeadline(t)
	s.wrMu.Unlock()
	return nil
}

// SetReadDeadline sets the read deadline associated with the stream.
func (s *Stream) SetReadDeadline(t time.Time) error {
	s.rdMu.Lock()
	s.rdData.setDeadline(t)
	s.rdMu.Unlock()
	return nil
}

func (s *Stream) String() string {
	return fmt.Sprintf("stream_id=%v", s.id)
}

func (s *Stream) close(comm command, errorCode uint64) error {
	select {
	case <-s.closeCh:
		// This connection or stream is already closed.
		return s.closeErr
	default:
	}
	s.clMu.Lock()
	defer s.clMu.Unlock()

	cmd := connCommand{
		cmd: comm,
		id:  s.id,
		n:   errorCode,
	}
	select {
	case <-s.closeCh:
		return s.closeErr
	case s.conn.cmdCh <- cmd:
		return <-s.clResultCh
	}
}

// recvWriteData is called from Conn goroutine.
func (s *Stream) recvWriteData(w io.Writer) (bool, error) {
	return s.wrData.writeTo(w)
}

func (s *Stream) isWriting() bool {
	return s.wrData.checkWaiting()
}

// recvReadData is called from Conn goroutine.
func (s *Stream) recvReadData(r io.Reader) (bool, error) {
	return s.rdData.readFrom(r)
}

func (s *Stream) isReading() bool {
	return s.rdData.checkWaiting()
}

// sendWriteResult is called from Conn goroutine.
func (s *Stream) sendWriteResult(err error) {
	s.wrData.sendResult(err)
}

// sendReadResult is called from Conn goroutine.
func (s *Stream) sendReadResult(err error) {
	s.rdData.sendResult(err)
}

// sendCloseResult is called from Conn goroutine.
func (s *Stream) sendCloseResult(err error) {
	s.clResultCh <- err
}

// setClosed is called from Conn goroutine.
func (s *Stream) setClosed(err error, rd io.Reader) {
	s.closeOnce.Do(func() {
		s.closeErr = err
		s.closeRd = rd
		close(s.closeCh)
	})
}

type dataBuffer struct {
	buf []byte
	off int

	resultCh chan error    // blocking channel
	waitCh   chan struct{} // non-blocking channel

	deadlineTm *time.Timer
	deadlineCh chan struct{}
}

func (s *dataBuffer) init() {
	s.resultCh = make(chan error)
	s.waitCh = make(chan struct{})
	s.deadlineCh = make(chan struct{})
}

func (s *dataBuffer) sendResult(err error) {
	s.resultCh <- err
}

func (s *dataBuffer) checkWaiting() bool {
	select {
	case s.waitCh <- struct{}{}:
		return true
	default:
		return false
	}
}

// setBuf sets new new buffer for data and return old read/write offset.
func (s *dataBuffer) setBuf(b []byte) int {
	s.buf = b
	n := s.off
	s.off = 0
	return n
}

func (s *dataBuffer) setDeadline(t time.Time) {
	if s.deadlineTm != nil && !s.deadlineTm.Stop() {
		// Wait for the current timer callback to finish and close channel
		<-s.deadlineCh
	}
	s.deadlineTm = nil
	closed := false
	select {
	case <-s.deadlineCh:
		closed = true
	default:
	}

	// Time is zero, no deadline
	if t.IsZero() {
		if closed {
			s.deadlineCh = make(chan struct{})
		}
		return
	}
	// Time in the future, set up a timer
	if d := time.Until(t); d > 0 {
		if closed {
			s.deadlineCh = make(chan struct{})
		}
		s.deadlineTm = time.AfterFunc(d, func() {
			close(s.deadlineCh)
		})
		return
	}
	// Time in the past, close immediately
	if !closed {
		close(s.deadlineCh)
	}
}

// writeTo returns true when all data in buf has been written.
func (s *dataBuffer) writeTo(w io.Writer) (bool, error) {
	n, err := w.Write(s.buf[s.off:])
	s.off += n
	return s.off >= len(s.buf), err
}

// readFrom returns true when there is any data has been read.
func (s *dataBuffer) readFrom(r io.Reader) (bool, error) {
	n, err := r.Read(s.buf[s.off:])
	s.off += n
	return s.off > 0, err
}
