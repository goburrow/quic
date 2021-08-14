package qlog

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

const logTimeFormat = "2006/01/02 15:04:05.000000 "

const (
	eventConnStarted = "connectivity:connection_started"
	eventConnClosed  = "connectivity:connection_closed"

	eventPacketSent     = "transport:packet_sent"
	eventPacketReceived = "transport:packet_received"
	eventPacketLost     = "recovery:packet_lost"
	eventPacketDropped  = "transport:packet_dropped"
	eventPacketBuffered = "transport:packet_buffered"
	eventPacketRestored = "transport:packet_restored"

	eventFramesProcessed = "transport:frames_processed"
)

// Decode decodes quiwi logs to a qlog file.
func Decode(r io.Reader) (File, error) {
	dec := newDecoder(r)
	traces, err := dec.decode()
	f := File{
		Version: version,
		Format:  "JSON",
		Title:   "quiwi",
		Traces:  traces,
	}
	if err == io.EOF {
		err = nil
	}
	return f, err
}

// decoder is for decoding quiwi logs to qlog.
type decoder struct {
	reader *bufio.Reader
}

// newDecoder returns a new Decoder that reads data from r.
func newDecoder(r io.Reader) *decoder {
	return &decoder{
		reader: bufio.NewReader(r),
	}
}

// decode parses logs until EOF and sets results to f.
func (s *decoder) decode() ([]Trace, error) {
	var traces []Trace
	for {
		line, err := s.reader.ReadSlice('\n')
		if err != nil {
			return traces, err
		}
		line = bytes.TrimSpace(line)
		if len(line) > 0 {
			event, err := s.parseLine(line)
			if err != nil {
				return traces, err
			}
			traces = s.addEvent(traces, event)
		}
	}
}

func (s *decoder) parseLine(line []byte) (Event, error) {
	if len(line) < len(logTimeFormat) {
		return Event{}, fmt.Errorf("time invalid: %s", line)
	}
	// Time
	tm, err := time.Parse(logTimeFormat, string(line[:len(logTimeFormat)]))
	if err != nil {
		return Event{}, fmt.Errorf("time format: %v %s", err, line)
	}
	e := Event{}
	e.Time = uint64(tm.UnixNano()) / 1e6 // ms

	line = bytes.TrimSpace(line[len(logTimeFormat):])
	// Event name
	idx := bytes.IndexByte(line, ' ')
	if idx <= 0 {
		e.Name = string(line)
		return e, nil
	}
	e.Name = string(line[:idx])
	e.Data = parseEventData(line[idx+1:])
	// CID is Group ID
	if cid, ok := e.Data["cid"]; ok {
		e.GroupID = cid.(string)
	}
	delete(e.Data, "cid")
	if packetEvents[e.Name] {
		// Move packet headers to sub property
		header := make(map[string]interface{})
		raw := make(map[string]interface{})
		for k, v := range e.Data {
			if packetHeaderFields[k] {
				header[k] = v
				delete(e.Data, k)
			} else if t := packetRawFields[k]; t != "" {
				raw[t] = v
				delete(e.Data, k)
			}
		}
		e.Data["header"] = header
		if len(raw) > 0 {
			e.Data["raw"] = raw
		}
	}
	return e, nil
}

func (s *decoder) addEvent(traces []Trace, e Event) []Trace {
	t := s.findTrace(traces, e.GroupID)
	if t == nil {
		if e.Name != eventConnStarted {
			return traces
		}
		traces = append(traces, newTrace(&e))
		t = &traces[len(traces)-1]
	}
	if e.Name == eventFramesProcessed {
		// Append frame event to packet event instead.
		p := findLastPacketEvent(t)
		if p != nil {
			var frames []map[string]interface{}
			if f, ok := p.Data["frames"]; ok {
				frames = f.([]map[string]interface{})
			}
			frames = append(frames, e.Data)
			p.Data["frames"] = frames
			return traces
		}
	}
	t.Events = append(t.Events, e)
	return traces
}

func (s *decoder) findTrace(traces []Trace, id string) *Trace {
	for i := len(traces) - 1; i >= 0; i-- {
		t := &traces[i]
		if t.CommonFields.GroupID == id {
			return t
		}
	}
	return nil
}

func newTrace(e *Event) Trace {
	t := Trace{}
	switch e.Data["vantage_point"] {
	case "server":
		t.VantagePoint.Type = vantagePointServer
	case "client":
		t.VantagePoint.Type = vantagePointClient
	default:
		t.VantagePoint.Type = vantagePointUnknown
	}
	delete(e.Data, "vantage_point")
	t.Title = e.GroupID
	t.CommonFields.GroupID = e.GroupID
	return t
}

func findLastPacketEvent(t *Trace) *Event {
	for i := len(t.Events) - 1; i >= 0; i-- {
		e := &t.Events[i]
		switch e.Name {
		case eventPacketSent, eventPacketReceived:
			return e
		}
	}
	return nil
}

func parseEventData(line []byte) map[string]interface{} {
	line = bytes.TrimSpace(line)
	data := make(map[string]interface{})
	for len(line) > 0 {
		idx := bytes.IndexByte(line, ' ')
		field := line
		if idx > 0 {
			field = line[:idx]
		}
		sep := bytes.IndexByte(field, '=')
		if sep <= 0 {
			data["message"] = string(line) // Take whole remaining
			break
		}
		key := string(field[:sep])
		if key == "message" || key == "description" || key == "reason" {
			data[key] = string(line[sep+1:])
			break
		}
		data[key] = parseEventValue(string(field[sep+1:]))
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

var packetEvents = map[string]bool{
	eventPacketReceived: true,
	eventPacketSent:     true,
	eventPacketLost:     true,
	eventPacketDropped:  true,
	eventPacketBuffered: true,
	eventPacketRestored: true,
}

// https://quicwg.org/qlog/draft-ietf-quic-qlog-quic-events.html#section-a.4
var packetHeaderFields = map[string]bool{
	"packet_type":        true,
	"version":            true,
	"dcid":               true,
	"scid":               true,
	"packet_number":      true,
	"supported_versions": true,
	"token":              true,
}

var packetRawFields = map[string]string{
	"packet_size":    "length",
	"payload_length": "payload_length",
}
