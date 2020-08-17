package qlog

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

const logTimeFormat = "2006/01/02 15:04:05.000000 "

// Decode decodes quince log file.
func Decode(r io.Reader) (*LogFile, error) {
	dec := newDecoder(r)
	err := dec.decode()
	if err != nil {
		return nil, err
	}
	return dec.result, nil
}

type decoder struct {
	scanner *bufio.Scanner
	result  *LogFile

	isServer   bool
	lineNumber uint
}

func newDecoder(r io.Reader) *decoder {
	return &decoder{
		scanner: bufio.NewScanner(r),
		result: &LogFile{
			Version: "draft-02-wip",
			Title:   "quince",
		},
	}
}

func (s *decoder) decode() error {
	for s.scanner.Scan() {
		s.lineNumber++
		line := strings.TrimSpace(s.scanner.Text())
		if len(line) > 0 {
			e, err := s.parseLine(line)
			if err != nil {
				return err
			}
			s.addEvent(e)
		}
	}
	return s.scanner.Err()
}

func (s *decoder) parseLine(line string) (*event, error) {
	if len(line) < len(logTimeFormat) {
		return nil, s.newErrorInvalid()
	}
	// Time
	tm, err := time.Parse(logTimeFormat, line[:len(logTimeFormat)])
	if err != nil {
		return nil, s.newError("parse time", err)
	}
	e := &event{}
	e.Time = uint64(tm.UnixNano()) / 1e6 // ms

	line = strings.TrimSpace(line[len(logTimeFormat):])
	// Event name
	idx := strings.Index(line, " ")
	if idx <= 0 {
		e.Event = line
		return e, nil
	}
	e.Event = line[:idx]
	e.Data = parseEventData(line[idx+1:])
	e.Category = "transport"
	// CID is Group ID
	if cid, ok := e.Data["cid"]; ok {
		e.GroupID = cid.(string)
	}
	delete(e.Data, "cid")
	switch e.Event {
	case "packet_received", "packet_sent":
		// Move packet headers to sub property
		header := make(map[string]interface{})
		for k, v := range e.Data {
			if k == "packet_type" {
				continue
			}
			header[k] = v
			delete(e.Data, k)
		}
		e.Data["header"] = header
	case "metrics_updated":
		e.Category = "recovery"
	}
	return e, nil
}

func (s *decoder) addEvent(e *event) {
	f := s.result
	if len(f.Traces) == 0 && e.Event == "server_listening" {
		s.isServer = true
	}
	t := findTrace(f, e.GroupID)
	if t == nil {
		f.Traces = append(f.Traces, Trace{})
		t = &f.Traces[len(f.Traces)-1]
		if s.isServer {
			t.VantagePoint.Type = VantagePointServer
		} else {
			t.VantagePoint.Type = VantagePointClient
		}
		t.Title = e.GroupID
		t.Configuration.TimeUnit = "ms"
		t.CommonFields.CID = e.GroupID
		t.EventFields = defaultEventFields
	}
	if e.Event == "frames_processed" {
		p := findLastTracePacket(t)
		if p != nil {
			var frames []eventData
			if f, ok := p["frames"]; ok {
				frames = f.([]eventData)
			}
			frames = append(frames, e.Data)
			p["frames"] = frames
			return
		}
	}
	event := []interface{}{
		e.Time,
		e.Category,
		e.Event,
		e.Data,
	}
	t.Events = append(t.Events, event)
}

func (s *decoder) newErrorInvalid() error {
	return fmt.Errorf("%d: invalid format", s.lineNumber)
}

func (s *decoder) newError(msg string, err error) error {
	return fmt.Errorf("%d: %s: %v", s.lineNumber, msg, err)
}

func findTrace(f *LogFile, id string) *Trace {
	for i := range f.Traces {
		t := &f.Traces[i]
		if t.CommonFields.CID == id {
			return t
		}
	}
	return nil
}

func findLastTracePacket(t *Trace) eventData {
	for i := len(t.Events) - 1; i >= 0; i-- {
		e := t.Events[i]
		switch e[2].(string) {
		case "packet_sent", "packet_received":
			return e[3].(eventData)
		}
	}
	return nil
}

func addTracePacketFrame(t *Trace, e *event) eventData {
	for i := len(t.Events) - 1; i >= 0; i-- {
		e := t.Events[i]
		switch e[2].(string) {
		case "packet_sent", "packet_received":
			return e[3].(eventData)
		}
	}
	return nil
}

func parseEventData(line string) eventData {
	line = strings.TrimSpace(line)
	data := make(eventData)
	var field string
	for len(line) > 0 {
		idx := strings.Index(line, " ")
		if idx > 0 {
			field = line[:idx]
		} else {
			field = line
		}
		sep := strings.Index(field, "=")
		if sep <= 0 {
			data["message"] = line // Take whole remaining
			break
		}
		key := field[:sep]
		if key == "message" || key == "description" || key == "reason" {
			data[key] = line[sep+1:]
			break
		}
		data[key] = parseEventValue(field[sep+1:])
		if idx > 0 {
			line = line[idx+1:]
		} else {
			break
		}
	}
	return data
}

func parseEventValue(value string) interface{} {
	if value == "false" {
		return false
	}
	if value == "true" {
		return true
	}
	if strings.HasPrefix(value, "[[") && strings.HasSuffix(value, "]]") {
		items := strings.Split(value[2:len(value)-2], "],[")
		v := make([][2]uint64, len(items))
		for i, item := range items {
			sep := strings.Index(item, ",")
			if sep < 0 {
				return value
			}
			v1, err := strconv.ParseUint(item[:sep], 10, 0)
			if err != nil {
				return value
			}
			v2, err := strconv.ParseUint(item[sep+1:], 10, 0)
			if err != nil {
				return value
			}
			v[i][0], v[i][1] = v1, v2
		}
		return v
	}
	if len(value) < 20 { // max uint62
		if v, err := strconv.ParseUint(value, 10, 0); err == nil {
			return v
		}
	}
	return value
}
