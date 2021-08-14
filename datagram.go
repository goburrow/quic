package quic

import (
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// Datagram provides asynchronous APIs to interact which QUIC datagram.
// All Datagram functions must be used in a separated goroutine that is
// different to the connection callback.
// For example:
//
// 	func (handler) Serve(conn *quic.Conn, events []transport.Event) {
// 		for _, e := range events {
// 			switch e.Type {
// 			case transport.EventDatagramWritable:
// 				go func(datagram *quic.Datagram) {
// 					// Working on the datagram.
// 				}(conn.Datagram())
// 			}
// 		}
// 	}
//
// Datagram implements net.Conn.
type Datagram struct {
	conn *Conn

	// Writing
	wrMu sync.Mutex
	wrCh chan io.Writer
	wrDl deadlineTimer

	// Reading
	rdMu sync.Mutex
	rdCh chan io.Reader
	rdDl deadlineTimer

	closeOnce sync.Once
	closeCh   chan struct{}
	// Due to asynchronous operators, application may not fully read data when the connection is closed.
	// This datagram needs to own the QUIC Datagram in this case so that the application can continue reading.
	closeErr error
	closeRd  io.Reader
}

var (
	_ net.Conn = (*Datagram)(nil)
)

func newDatagram(conn *Conn) *Datagram {
	s := &Datagram{
		conn: conn,

		wrCh:    make(chan io.Writer),
		rdCh:    make(chan io.Reader),
		closeCh: make(chan struct{}),
	}
	s.wrDl.init()
	s.rdDl.init()
	return s
}

// Write writes data to the stream.
func (s *Datagram) Write(b []byte) (int, error) {
	s.wrMu.Lock()
	defer s.wrMu.Unlock()

	select {
	case <-s.closeCh:
		return 0, s.closeErr
	default:
		return s.writeLocked(b)
	}
}

func (s *Datagram) writeLocked(b []byte) (n int, err error) {
	cmd := connCommand{
		cmd: cmdDatagramWrite,
	}
	// Datagram should always be written as a whole so len(b) is returned.
	select {
	case <-s.closeCh:
		err = s.closeErr
		return
	case <-s.wrDl.ch:
		err = os.ErrDeadlineExceeded
		return
	case s.conn.cmdCh <- cmd:
		for {
			select {
			case <-s.closeCh:
				err = s.closeErr
				return
			case <-s.wrDl.ch:
				err = os.ErrDeadlineExceeded
				return
			case w := <-s.wrCh:
				n, err = w.Write(b)
				s.wrCh <- nil // Done writing
				if err != nil || n > 0 {
					return
				}
			}
		}
	}
}

// Read reads datagram from the connection.
func (s *Datagram) Read(b []byte) (int, error) {
	s.rdMu.Lock()
	defer s.rdMu.Unlock()

	select {
	case <-s.closeCh:
		return s.readClosed(b)
	default:
		return s.readLocked(b)
	}
}

func (s *Datagram) readLocked(b []byte) (n int, err error) {
	cmd := connCommand{
		cmd: cmdDatagramRead,
	}
	select {
	case <-s.closeCh:
		return s.readClosed(b)
	case <-s.rdDl.ch:
		err = os.ErrDeadlineExceeded
		return
	case s.conn.cmdCh <- cmd:
		for {
			select {
			case <-s.closeCh:
				return s.readClosed(b)
			case <-s.rdDl.ch:
				err = os.ErrDeadlineExceeded
				return
			case r := <-s.rdCh:
				n, err = r.Read(b)
				s.rdCh <- nil
				if err != nil || n > 0 || len(b) == 0 {
					return
				}
			}
		}
	}
}

func (s *Datagram) readClosed(b []byte) (int, error) {
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

// Close on Datagram does not do anything.
func (s *Datagram) Close() error {
	return nil
}

// LocalAddr returns the local network address.
func (s *Datagram) LocalAddr() net.Addr {
	return s.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (s *Datagram) RemoteAddr() net.Addr {
	return s.conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines associated with the stream.
func (s *Datagram) SetDeadline(t time.Time) error {
	s.SetWriteDeadline(t)
	s.SetReadDeadline(t)
	return nil
}

// SetWriteDeadline sets the write deadline associated with the stream.
func (s *Datagram) SetWriteDeadline(t time.Time) error {
	s.wrMu.Lock()
	s.wrDl.setDeadline(t)
	s.wrMu.Unlock()
	return nil
}

// SetReadDeadline sets the read deadline associated with the stream.
func (s *Datagram) SetReadDeadline(t time.Time) error {
	s.rdMu.Lock()
	s.rdDl.setDeadline(t)
	s.rdMu.Unlock()
	return nil
}

func (s *Datagram) sendWriter(w io.Writer) {
	select {
	case s.wrCh <- w:
		<-s.wrCh // Wait
	default:
	}
}

func (s *Datagram) sendReader(w io.Reader) {
	select {
	case s.rdCh <- w:
		<-s.rdCh // Wait
	default:
	}
}

func (s *Datagram) setClosed(err error, rd io.Reader) {
	s.closeOnce.Do(func() {
		s.closeErr = err
		s.closeRd = rd
		close(s.closeCh)
	})
}
