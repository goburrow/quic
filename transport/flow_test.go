package transport

import "testing"

func TestFlowControlSend(t *testing.T) {
	s := flowControl{}
	v := s.canSend()
	if v != 0 {
		t.Fatalf("expect canSend %v, actual %v", 0, v)
	}
	s.init(0, 10)
	v = s.canSend()
	if v != 10 {
		t.Fatalf("expect canSend %v, actual %v", 20, v)
	}
	s.addSend(6)
	v = s.canSend()
	if v != 4 {
		t.Fatalf("expect canSend %v, actual %v", 4, v)
	}
	s.setSend(11)
	v = s.canSend()
	if v != 0 {
		t.Fatalf("expect canSend %v, actual %v", 0, v)
	}
}

func TestFlowControlRecv(t *testing.T) {
	s := flowControl{}
	v := s.canRecv()
	if v != 0 {
		t.Fatalf("expect canRecv %v, actual %v", 0, v)
	}
	s.init(10, 0)
	v = s.canRecv()
	if v != 10 {
		t.Fatalf("expect canRecv %v, actual %v", 10, v)
	}
	update := s.shouldUpdateMaxRecv()
	if update {
		t.Fatalf("expect updateMaxRecv %v, actual %v", false, update)
	}
	s.addRecv(6)
	v = s.canRecv()
	if v != 4 {
		t.Fatalf("expect canRecv %v, actual %v", 4, v)
	}
	update = s.shouldUpdateMaxRecv()
	if update {
		t.Fatalf("expect updateMaxRecv %v, actual %v", false, update)
	}
	s.addMaxRecvNext(4)
	update = s.shouldUpdateMaxRecv()
	if !update {
		t.Fatalf("expect updateMaxRecv %v, actual %v", true, update)
	}
}
