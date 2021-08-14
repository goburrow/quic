package qlog

import (
	"os"
	"testing"
)

func TestDecode(t *testing.T) {
	f, err := os.Open("client.qlog.txt")
	if err != nil {
		t.Skip(err)
	}
	defer f.Close()
	data, err := Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", data)
	if len(data.Traces) == 0 {
		t.Fatalf("expect traces, actual: %v", data.Traces)
	}
}
