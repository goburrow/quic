package qlog

var defaultEventFields = []string{
	"time",
	"category",
	"event",
	"data",
}

type LogFile struct {
	Version string  `json:"qlog_version"`
	Title   string  `json:"title,omitempty"`
	Traces  []Trace `json:"traces"`
}

type Trace struct {
	Title         string          `json:"title,omitempty"`
	Configuration Configuration   `json:"configuration,omitempty"`
	CommonFields  CommonFields    `json:"common_fields,omitempty"`
	EventFields   []string        `json:"event_fields,omitempty"`
	VantagePoint  VantagePoint    `json:"vantage_point"`
	Events        [][]interface{} `json:"events"`
}

type Configuration struct {
	TimeUnit   string `json:"time_unit,omitempty"`
	TimeOffset uint64 `json:"time_offset,omitempty"`
}

type CommonFields struct {
	CID string `json:"cid,omitempty"`
}

type VantagePoint struct {
	Type VantagePointType `json:"type"`
}

type VantagePointType string

const (
	VantagePointServer VantagePointType = "server"
	VantagePointClient VantagePointType = "client"
)

type event struct {
	Time     uint64
	GroupID  string
	Category string
	Event    string
	Data     eventData
}

type eventData map[string]interface{}
