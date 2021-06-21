// Package qlog transforms quiwi logs to qlog
package qlog

var eventFields = []string{
	"time",
	"category",
	"event",
	"data",
}

// LogFile is the qlog file.
// https://quicwg.org/qlog/draft-ietf-quic-qlog-main-schema.html#section-3
type LogFile struct {
	Version string  `json:"qlog_version"`
	Title   string  `json:"title,omitempty"`
	Traces  []Trace `json:"traces"`
}

// Trace is the qlog trace.
// https://quicwg.org/qlog/draft-ietf-quic-qlog-main-schema.html#section-3.2
type Trace struct {
	Title         string        `json:"title,omitempty"`
	Configuration Configuration `json:"configuration,omitempty"`
	CommonFields  CommonFields  `json:"common_fields,omitempty"`
	EventFields   []string      `json:"event_fields,omitempty"`
	VantagePoint  VantagePoint  `json:"vantage_point"`
	Events        []Event       `json:"events"`
}

// Configuration is the trace configuration.
type Configuration struct {
	TimeUnit   string `json:"time_unit,omitempty"`
	TimeOffset uint64 `json:"time_offset,omitempty"`
}

// CommonFields is the trace common fields.
type CommonFields struct {
	CID string `json:"cid,omitempty"`
}

// VantagePoint is the vantage point from which the traces originate.
// https://quicwg.org/qlog/draft-ietf-quic-qlog-main-schema.html#section-3.3.2
type VantagePoint struct {
	Type string `json:"type"`
}

// Predefined vantage points.
const (
	vantagePointServer = "server"
	vantagePointClient = "client"
)

// Event is the trace event including time, category, event name and data.
type Event [4]interface{}

// Time returns event time.
func (s Event) Time() uint64 {
	if s[0] == nil {
		return 0
	}
	return s[0].(uint64)
}

// Category returns event category.
func (s Event) Category() string {
	if s[1] == nil {
		return ""
	}
	return s[1].(string)
}

// Event returns event name.
func (s Event) Event() string {
	if s[2] == nil {
		return ""
	}
	return s[2].(string)
}

// Data returns event data.
func (s Event) Data() map[string]interface{} {
	if s[3] == nil {
		return nil
	}
	return s[3].(map[string]interface{})
}

type eventGroup struct {
	groupID string

	time     uint64
	category string
	event    string
	data     map[string]interface{}
}
