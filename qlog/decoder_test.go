package qlog

import (
	"os"
	"testing"
)

func TestDecode(t *testing.T) {
	f, err := os.Open("client.qlog.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	data, err := Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", data)
	if len(data.Traces) != 1 {
		t.Fatalf("expect traces, actual: %v", data.Traces)
	}
	trace := data.Traces[0]
	if trace.CommonFields.CID != "f93fccb848e3d9a8cab8ec99518d477f1d64c119" {
		t.Fatalf("expect cid: %v, actual: %v", "f93fccb848e3d9a8cab8ec99518d477f1d64c119", trace.CommonFields.CID)
	}
	if trace.VantagePoint.Type != vantagePointClient {
		t.Fatalf("expect vantage point: %v, actual: %v", vantagePointClient, trace.VantagePoint.Type)
	}
	if len(trace.Events) < 2 {
		t.Fatalf("expect events, actual: %v", trace.Events)
	}
	event := trace.Events[1]
	if event.Time() != 1624057771228 || event.Category() != "transport" || event.Event() != "loss_timer_updated" {
		t.Fatalf("expect event loss_timer_updated, actual: %+v", event)
	}
}
