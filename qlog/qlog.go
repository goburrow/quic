// Package qlog transforms quiwi logs to qlog
package qlog

const version = "draft-02"

// File is the qlog file.
// https://quicwg.org/qlog/draft-ietf-quic-qlog-main-schema.html#section-3
type File struct {
	Version string  `json:"qlog_version"`
	Format  string  `json:"qlog_format,omitempty"`
	Title   string  `json:"title,omitempty"`
	Traces  []Trace `json:"traces,omitempty"`
}

// Trace is the qlog trace.
// https://quicwg.org/qlog/draft-ietf-quic-qlog-main-schema.html#section-3.2
type Trace struct {
	Title         string        `json:"title,omitempty"`
	Configuration Configuration `json:"configuration,omitempty"`
	CommonFields  CommonFields  `json:"common_fields,omitempty"`
	VantagePoint  VantagePoint  `json:"vantage_point,omitempty"`
	Events        []Event       `json:"events,omitempty"`
}

// Configuration is the trace configuration.
// https://quicwg.org/qlog/draft-ietf-quic-qlog-main-schema.html#section-3.3.1
type Configuration struct {
	TimeOffset uint64 `json:"time_offset,omitempty"`
}

// CommonFields is the trace common fields.
// https://quicwg.org/qlog/draft-ietf-quic-qlog-main-schema.html#section-3.4.7
type CommonFields struct {
	GroupID string `json:"group_id,omitempty"`
}

// VantagePoint is the vantage point from which the traces originate.
// https://quicwg.org/qlog/draft-ietf-quic-qlog-main-schema.html#section-3.3.2
type VantagePoint struct {
	Type string `json:"type"`
}

// Predefined vantage points.
const (
	vantagePointServer  = "server"
	vantagePointClient  = "client"
	vantagePointUnknown = "unknown"
)

// Event is the trace event including time, event name and data.
// https://quicwg.org/qlog/draft-ietf-quic-qlog-main-schema.html#section-3.4
type Event struct {
	GroupID string `json:"-"`
	Time    uint64 `json:"time"`
	Name    string `json:"name"`

	Data map[string]interface{} `json:"data"`
}
