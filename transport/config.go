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

	// https://www.rfc-editor.org/rfc/rfc9000.html#section-14

	// MaxIPv6PacketSize is the QUIC maximum packet size for IPv6 when Path MTU Discovery is missing.
	MaxIPv6PacketSize = 1232
	// MaxIPv4PacketSize is the QUIC maximum packet size for IPv4 when Path MTU Discovery is missing.
	MaxIPv4PacketSize = 1252
	// MinInitialPacketSize is the QUIC minimum packet size when it contains Initial packet.
	MinInitialPacketSize = 1200
)

// supportedVersions are the QUIC versions supported by this implementation.
var supportedVersions = [...]uint32{
	1,
}

// Config is a QUIC connection configuration.
// This implementaton utilizes tls.Config.Rand and tls.Config.Time if available.
type Config struct {
	TLS     *tls.Config // TLS configuration, required for server.
	Params  Parameters  // QUIC transport parameters.
	Version uint32      // QUIC version.

	// The following values are for testing only and subjected to be removed.

	MaxPacketsPerKey uint64 // Override default maximum number of encrypted packets for each AEAD key.
}

// NewConfig creates a default configuration.
func NewConfig() *Config {
	return &Config{
		Version: supportedVersions[0],
		Params: Parameters{
			MaxIdleTimeout:    30 * time.Second,
			MaxUDPPayloadSize: defaultMaxUDPPayloadSize,

			InitialMaxData:                 65536,
			InitialMaxStreamDataBidiLocal:  65536,
			InitialMaxStreamDataBidiRemote: 65536,
			InitialMaxStreamDataUni:        65536,
			InitialMaxStreamsBidi:          1,
			InitialMaxStreamsUni:           1,

			AckDelayExponent: defaultAckDelayExponent,
			MaxAckDelay:      defaultMaxAckDelay,

			ActiveConnectionIDLimit: 2,
			DisableActiveMigration:  true,
		},
	}
}

// IsVersionSupported returns true when the provided QUIC transport version is supported.
func IsVersionSupported(version uint32) bool {
	for _, v := range supportedVersions {
		if v == version {
			return true
		}
	}
	return false
}
