package quic

import (
	"io"
	"net"
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

	wrMu   sync.Mutex
	wrData dataBuffer

	rdMu   sync.Mutex
	rdData dataBuffer

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

		closeCh: make(chan struct{}),
	}
	s.wrData.init()
	s.rdData.init()
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

func (s *Datagram) writeLocked(b []byte) (int, error) {
	s.wrData.setBuf(b)
	cmd := connCommand{
		cmd: cmdDatagramWrite,
	}
	var err error
	// Datagram should always be written as a whole so len(b) is returned.
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

func (s *Datagram) readLocked(b []byte) (int, error) {
	s.rdData.setBuf(b)
	cmd := connCommand{
		cmd: cmdDatagramRead,
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
	s.wrData.setDeadline(t)
	s.wrMu.Unlock()
	return nil
}

// SetReadDeadline sets the read deadline associated with the stream.
func (s *Datagram) SetReadDeadline(t time.Time) error {
	s.rdMu.Lock()
	s.rdData.setDeadline(t)
	s.rdMu.Unlock()
	return nil
}

// recvWriteData is called from Conn goroutine.
func (s *Datagram) recvWriteData(w io.Writer) (bool, error) {
	return s.wrData.writeTo(w)
}

// recvReadData is called from Conn goroutine.
func (s *Datagram) recvReadData(r io.Reader) (bool, error) {
	return s.rdData.readFrom(r)
}

func (s *Datagram) isReading() bool {
	return s.rdData.checkWaiting()
}

func (s *Datagram) sendWriteResult(err error) {
	s.wrData.sendResult(err)
}

func (s *Datagram) sendReadResult(err error) {
	s.rdData.sendResult(err)
}

func (s *Datagram) setClosed(err error, rd io.Reader) {
	s.closeOnce.Do(func() {
		s.closeErr = err
		s.closeRd = rd
		close(s.closeCh)
	})
}
