package quic

import (
	"fmt"
	"log"
)

// Log levels
const (
	LevelOff = iota
	LevelError
	LevelInfo
	LevelDebug
	LevelTrace
)

// Logger logs QUIC transactions.
type Logger interface {
	Log(level int, format string, values ...interface{})
}

// LeveledLogger creates a logger with specified level.
func LeveledLogger(level int) Logger {
	return leveledLogger(level)
}

type leveledLogger int

func (l leveledLogger) Log(level int, format string, values ...interface{}) {
	if level <= int(l) {
		msg := fmt.Sprintf(format, values...)
		log.Output(2, msg)
	}
}
