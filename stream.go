package quic

import (
	"io"
	"net"
	"os"
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
	wrMu sync.Mutex
	wrCh chan io.Writer
	wrDl deadlineTimer

	// Reading
	rdMu sync.Mutex
	rdCh chan io.Reader
	rdDl deadlineTimer

	// Closing
	clMu sync.Mutex
	clCh chan error

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
		conn:    conn,
		id:      id,
		wrCh:    make(chan io.Writer),
		rdCh:    make(chan io.Reader),
		clCh:    make(chan error),
		closeCh: make(chan struct{}),
	}
	s.wrDl.init()
	s.rdDl.init()
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

func (s *Stream) writeLocked(b []byte) (n int, err error) {
	cmd := connCommand{
		cmd: cmdStreamWrite,
		id:  s.id,
	}
	select {
	case <-s.closeCh:
		err = s.closeErr
		return
	case <-s.wrDl.ch:
		err = os.ErrDeadlineExceeded
		return
	case s.conn.cmdCh <- cmd:
		// Waiting for writer
		for {
			select {
			case <-s.closeCh:
				err = s.closeErr
				return
			case <-s.wrDl.ch:
				err = os.ErrDeadlineExceeded
				return
			case w := <-s.wrCh:
				var m int
				m, err = w.Write(b[n:])
				s.wrCh <- nil // Done writing
				n += m
				if err != nil || n >= len(b) {
					return
				}
			}
		}
	}
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

func (s *Stream) readLocked(b []byte) (n int, err error) {
	cmd := connCommand{
		cmd: cmdStreamRead,
		id:  s.id,
	}
	select {
	case <-s.closeCh:
		return s.readClosed(b)
	case <-s.rdDl.ch:
		err = os.ErrDeadlineExceeded
		return
	case s.conn.cmdCh <- cmd:
		// Wait for reader
		for {
			select {
			case <-s.closeCh:
				if n > 0 {
					return n, nil
				}
				return s.readClosed(b)
			case <-s.rdDl.ch:
				err = os.ErrDeadlineExceeded
				return
			case r := <-s.rdCh:
				n, err = r.Read(b)
				s.rdCh <- nil // Done reading
				if err != nil || n > 0 || len(b) == 0 {
					return
				}
			}
		}
	}
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
	s.wrDl.setDeadline(t)
	s.wrMu.Unlock()
	return nil
}

// SetReadDeadline sets the read deadline associated with the stream.
func (s *Stream) SetReadDeadline(t time.Time) error {
	s.rdMu.Lock()
	s.rdDl.setDeadline(t)
	s.rdMu.Unlock()
	return nil
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
		select {
		case <-s.closeCh:
			return s.closeErr
		case err := <-s.clCh:
			return err
		}
	}
}

func (s *Stream) sendWriter(w io.Writer) {
	select {
	case s.wrCh <- w:
		<-s.wrCh // Wait
	default:
	}
}

func (s *Stream) sendReader(w io.Reader) {
	select {
	case s.rdCh <- w:
		<-s.rdCh // Wait
	default:
	}
}

// sendCloseResult is called from Conn goroutine.
func (s *Stream) sendCloseResult(err error) {
	select {
	case <-s.closeCh:
	case s.clCh <- err:
	}
}

// setClosed is called from Conn goroutine.
func (s *Stream) setClosed(err error, rd io.Reader) {
	s.closeOnce.Do(func() {
		s.closeErr = err
		s.closeRd = rd
		close(s.closeCh)
	})
}

type deadlineTimer struct {
	tm *time.Timer
	ch chan struct{}
}

func (s *deadlineTimer) init() {
	s.ch = make(chan struct{})
}

func (s *deadlineTimer) setDeadline(t time.Time) {
	if s.tm != nil && !s.tm.Stop() {
		// Wait for the current timer callback to finish and close channel
		<-s.ch
	}
	s.tm = nil
	closed := false
	select {
	case <-s.ch:
		closed = true
	default:
	}

	// Time is zero, no deadline
	if t.IsZero() {
		if closed {
			s.ch = make(chan struct{})
		}
		return
	}
	// Time in the future, set up a timer
	if d := time.Until(t); d > 0 {
		if closed {
			s.ch = make(chan struct{})
		}
		s.tm = time.AfterFunc(d, func() {
			close(s.ch)
		})
		return
	}
	// Time in the past, close immediately
	if !closed {
		close(s.ch)
	}
}
