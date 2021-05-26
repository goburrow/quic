// Package transport provides implementation of QUIC transport protocol.
//
// To create a server or client connection:
//
// 	serverConfig := transport.NewConfig() // Server also requires a TLS certificate
// 	server, err := transport.Accept(scid, odcid, serverConfig)
//
// 	clientConfig := transport.NewConfig()
// 	client, err := transport.Connect(scid, config)
//
// To use the connection, feed it with input data and then get output data
// sending to peer:
//
// 	for { // Loop until the connection is closed
// 		timeout := server.Timeout()
// 		// (A negative timeout means that the timer should be disarmed)
// 		select {
// 			case data := <-dataChanel:  // Got data from peer
// 				n, err := conn.Write(data)
// 			case <-time.After(timeout): // Got receiving timeout
// 				n, err := conn.Write(nil)
// 		}
// 		// Get and process connection events
// 		events = conn.Events(events)
// 		for { // Loop until err != nil or n == 0
// 			n, err := conn.Read(buf)
// 			// Send buf[:n] to peer
// 		}
// 	}
package transport

import (
	"crypto/tls"
	"time"
)

const (
	// MaxCIDLength is the maximum length of a Connection ID
	MaxCIDLength = 20

	// https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#name-packet-size

	// MaxIPv6PacketSize is the QUIC maximum packet size for IPv6 when Path MTU Discovery is missing.
	MaxIPv6PacketSize = 1232
	// MaxIPv4PacketSize is the QUIC maximum packet size for IPv4 when Path MTU Discovery is missing.
	MaxIPv4PacketSize = 1252
	// MaxPacketSize is the maximum permitted UDP payload.
	MaxPacketSize = 65527
	// MinInitialPacketSize is the QUIC minimum packet size when it contains Initial packet.
	MinInitialPacketSize = 1200
)

// supportedVersions are the QUIC versions supported by this implementation.
var supportedVersions = [...]uint32{
	0xff000000 + 32,
	0xff000000 + 31,
	0xff000000 + 30,
	0xff000000 + 29,
}

// Config is a QUIC connection configuration.
// This implementaton utilizes tls.Config.Rand and tls.Config.Time if available.
type Config struct {
	Version uint32
	TLS     *tls.Config
	Params  Parameters
}

// NewConfig creates a default configuration.
func NewConfig() *Config {
	return &Config{
		Version: supportedVersions[0],
		Params: Parameters{
			MaxIdleTimeout:    30 * time.Second,
			MaxUDPPayloadSize: MaxPacketSize,

			InitialMaxData:                 16384,
			InitialMaxStreamDataBidiLocal:  8192,
			InitialMaxStreamDataBidiRemote: 8192,
			InitialMaxStreamDataUni:        8192,
			InitialMaxStreamsBidi:          1,
			InitialMaxStreamsUni:           1,

			AckDelayExponent: 3,
			MaxAckDelay:      25 * time.Millisecond,

			ActiveConnectionIDLimit: 2,
		},
	}
}

// VersionSupported returns true when the provided QUIC transport version is supported.
func VersionSupported(version uint32) bool {
	for _, v := range supportedVersions {
		if v == version {
			return true
		}
	}
	return false
}
