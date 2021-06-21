package transport

import "testing"

func TestFlowControlSend(t *testing.T) {
	s := flowControl{}
	v := s.availSend()
	if v != 0 {
		t.Fatalf("expect canSend %v, actual %v", 0, v)
	}
	s.init(0, 10)
	v = s.availSend()
	if v != 10 {
		t.Fatalf("expect canSend %v, actual %v", 20, v)
	}
	s.addSend(6)
	v = s.availSend()
	if v != 4 {
		t.Fatalf("expect canSend %v, actual %v", 4, v)
	}
	s.setSend(11)
	v = s.availSend()
	if v != 0 {
		t.Fatalf("expect canSend %v, actual %v", 0, v)
	}
}

func TestFlowControlRecv(t *testing.T) {
	s := flowControl{}
	v := s.availRecv()
	if v != 0 {
		t.Fatalf("expect canRecv %v, actual %v", 0, v)
	}
	s.init(10, 0)
	v = s.availRecv()
	if v != 10 {
		t.Fatalf("expect canRecv %v, actual %v", 10, v)
	}
	update := s.shouldUpdateRecvMax()
	if update {
		t.Fatalf("expect updateRecvMax %v, actual %v", false, update)
	}
	s.addRecv(6)
	v = s.availRecv()
	if v != 4 {
		t.Fatalf("expect canRecv %v, actual %v", 4, v)
	}
	update = s.shouldUpdateRecvMax()
	if update {
		t.Fatalf("expect updateRecvMax %v, actual %v", false, update)
	}
	s.addRecvMaxNext(4)
	update = s.shouldUpdateRecvMax()
	if !update {
		t.Fatalf("expect updateRecvMax %v, actual %v", true, update)
	}
}
