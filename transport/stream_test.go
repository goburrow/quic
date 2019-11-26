package transport

import "testing"

func TestRecvStream(t *testing.T) {
	s := recvStream{}
	s.setMaxData(1000)

	d := make([]byte, 100)
	err := s.push(d, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	n, err := s.Read(d)
	if err != nil {
		t.Fatal(err)
	}
	if n != 100 {
		t.Fatalf("expect read %d, actual %d", 100, n)
	}
}

func TestStreamType(t *testing.T) {
	data := []struct {
		id     uint64
		client bool
		local  bool
	}{
		{4, true, true},
		{3, true, false},
		{4, false, false},
		{3, false, true},
	}
	for _, d := range data {
		local := isStreamLocal(d.id, d.client)
		if local != d.local {
			t.Fatalf("expect %+v", d)
		}
	}
}
