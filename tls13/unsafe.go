package tls13

import (
	"crypto/tls"
	"unsafe"
)

// Work around for using tls.ClientSessionState in ClientSessionCache.
// https://github.com/golang/go/issues/25351
func (s *clientSessionState) toTLS() *tls.ClientSessionState {
	ts := &tls.ClientSessionState{}
	sBytes := (*[unsafe.Sizeof(*s)]byte)(unsafe.Pointer(s))[:]
	tsBytes := (*[unsafe.Sizeof(*ts)]byte)(unsafe.Pointer(ts))[:]
	copy(tsBytes, sBytes)
	return ts
}

func (s *clientSessionState) fromTLS(ts *tls.ClientSessionState) {
	sBytes := (*[unsafe.Sizeof(*s)]byte)(unsafe.Pointer(s))[:]
	tsBytes := (*[unsafe.Sizeof(*ts)]byte)(unsafe.Pointer(ts))[:]
	copy(sBytes, tsBytes)
	return
}
