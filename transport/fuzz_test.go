// +build quicfuzz

package transport

import "testing"

func TestFuzzBuildPacket(t *testing.T) {
	p := newTestConn(t)
	b := p.client.BuildPacket(nil)

	b = p.client.BuildPacket([]byte{1, 0, 0})
	if len(b) == 0 {
		t.Fatalf("expect a valid packet: %v", b)
	}
	n, err := p.server.Write(b)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(b) {
		t.Fatalf("expect write: %v, actual: %v", n, len(b))
	}

	b = p.server.BuildPacket([]byte{0, 1, 0, 1})
	if len(b) == 0 {
		t.Fatalf("expect a valid packet: %v", b)
	}
	n, err = p.client.Write(b[:n])
	if err != nil {
		t.Fatal(err)
	}
	if n != len(b) {
		t.Fatalf("expect write: %v, actual: %v", n, len(b))
	}
}
