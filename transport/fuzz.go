// +build quicfuzz

package transport

// BuildPacket builds and encrypts a 1rtt packet that contains the given payload for fuzzing.
// Payload must have at least 4 bytes for header protection, otherwise padding frame will be added.
// If the connection is not ready to send 1rtt packet, this function will return nil.
// This method is only available when compiling with build tag "quicfuzz".
// See https://github.com/goburrow/quic-fuzz
func (s *Conn) BuildPacket(payload []byte) []byte {
	pnSpace := s.packetNumberSpaces[packetSpaceApplication]
	if !pnSpace.canEncrypt() {
		return nil
	}
	for len(payload) < minPacketPayloadLength {
		payload = append(payload, 0)
	}
	overhead := pnSpace.sealer.aead.Overhead()
	p := packet{
		typ: packetTypeOneRTT,
		header: packetHeader{
			version: s.version,
			dcid:    s.dcid,
			scid:    s.scid,
		},
		packetNumber: pnSpace.nextPacketNumber,
		payloadLen:   len(payload) + overhead,
	}

	b := make([]byte, p.encodedLen())
	payloadOffset, err := p.encode(b)
	if err != nil {
		panic(err)
	}
	p.packetSize = payloadOffset + copy(b[payloadOffset:], payload) + overhead
	if p.packetSize > len(b) {
		panic("packet size miscalculated")
	}
	pnSpace.encryptPacket(b[:p.packetSize], &p)
	pnSpace.nextPacketNumber++
	return b[:p.packetSize]
}
