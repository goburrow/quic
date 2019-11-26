// Package transport provides implementation of QUIC transport protocol.
package transport

import (
	"crypto/tls"
	"time"
)

const (
	// MaxCIDLength is the maximum length of a Connection ID
	MaxCIDLength = 20
	// ProtocolVersion is the supported QUIC version
	ProtocolVersion = 0xff000018

	// https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#path-maximum-transmission-unit-pmtu

	// MaxIPv6PacketSize is the QUIC maximum packet size for IPv6 when Path MTU Discovery is missing.
	MaxIPv6PacketSize = 1232
	// MaxIPv4PacketSize is the QUIC maximum packet size for IPv4 when Path MTU Discovery is missing.
	MaxIPv4PacketSize = 1252
	// MaxPacketSize is the maximum permitted UDP payload.
	MaxPacketSize = 65527
	// MinInitialPacketSize is the QUIC minimum packet size when it contains Initial packet.
	MinInitialPacketSize = 1200

	minPayloadLength = 4

	defaultStreamMaxData = 1 << 14 // 16k
)

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
		Version: ProtocolVersion,
		Params: Parameters{
			IdleTimeout:      60 * time.Second,
			AckDelayExponent: 3,
			MaxAckDelay:      25 * time.Millisecond,
		},
	}
}

func versionSupported(ver uint32) bool {
	return ver == ProtocolVersion
}
