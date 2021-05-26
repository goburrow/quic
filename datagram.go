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
func (s *Datagram) Write(b []byte) (n int, err error) {
	select {
	case <-s.closeCh:
		// Connection is already closed.
		return 0, errClosed
	default:
	}
	s.wrMu.Lock()
	defer s.wrMu.Unlock()

	s.wrData.setBuf(b)
	defer func() {
		n = s.wrData.setBuf(nil)
	}()
	cmd := connCommand{
		cmd: cmdDatagramWrite,
	}
	// Datagram should always be written as a whole so len(b) is returned.
	select {
	case <-s.closeCh:
		err = errClosed
	case <-s.wrData.deadlineCh:
		err = errDeadlineExceeded
	case s.conn.cmdCh <- cmd:
		// Wait for result
		err = <-s.wrData.resultCh
		if err == errWait {
			select {
			case <-s.closeCh:
				err = errClosed
			case <-s.wrData.deadlineCh:
				err = errDeadlineExceeded
			case err = <-s.wrData.waitCh:
			}
		}
	}
	return
}

// Read reads datagram from the connection.
func (s *Datagram) Read(b []byte) (n int, err error) {
	select {
	case <-s.closeCh:
		return 0, errClosed
	default:
	}
	s.rdMu.Lock()
	defer s.rdMu.Unlock()

	s.rdData.setBuf(b)
	defer func() {
		n = s.rdData.setBuf(nil)
	}()
	cmd := connCommand{
		cmd: cmdDatagramRead,
	}
	select {
	case <-s.closeCh:
		err = errClosed
	case <-s.rdData.deadlineCh:
		err = errDeadlineExceeded
	case s.conn.cmdCh <- cmd:
		// Wait for result
		err = <-s.rdData.resultCh
		if err == errWait {
			select {
			case <-s.closeCh:
				err = errClosed
			case <-s.rdData.deadlineCh:
				err = errDeadlineExceeded
			case err = <-s.rdData.waitCh:
			}
		}
	}
	return
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
	return s.rdData.hasBuf()
}

func (s *Datagram) sendWriteResult(err error) {
	s.wrData.sendResult(err)
}

func (s *Datagram) sendReadResult(err error) {
	s.rdData.sendResult(err)
}

func (s *Datagram) sendReadWait(err error) {
	s.rdData.sendWaitResult(err)
}

func (s *Datagram) setClosed() {
	s.closeOnce.Do(func() { close(s.closeCh) })
}
