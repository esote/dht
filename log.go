package dht

import (
	"fmt"
	"io"
	"os"
	"sync"
)

type LogLevel int

func (l LogLevel) String() string {
	switch l {
	case LogEmerg:
		return "EMERG"
	case LogAlert:
		return "ALERT"
	case LogCrit:
		return "CRIT"
	case LogErr:
		return "ERR"
	case LogWarning:
		return "WARNING"
	case LogNotice:
		return "NOTICE"
	case LogInfo:
		return "INFO"
	case LogDebug:
		return "DEBUG"
	default:
		return "<nil>"
	}
}

// XXX: clean up / narrow down
// Log levels, based on OpenBSD syslog(3)
const (
	LogEmerg LogLevel = iota
	LogAlert
	LogCrit
	LogErr
	LogWarning
	LogNotice
	LogInfo
	LogDebug
)

type Logger interface {
	Log(level LogLevel, a ...interface{})
	Logf(level LogLevel, format string, a ...interface{})
}

type defaultLogger struct {
	mu sync.Mutex
}

var _ Logger = &defaultLogger{}

func (l *defaultLogger) Log(level LogLevel, a ...interface{}) {
	defer recover()
	var out io.Writer
	switch {
	case level >= LogWarning && level <= LogDebug:
		out = os.Stdout
	default:
		out = os.Stderr
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprint(out, level.String()+": ")
	fmt.Fprintln(out, a...)
}

func (l *defaultLogger) Logf(level LogLevel, format string, a ...interface{}) {
	defer recover()
	var out io.Writer
	switch {
	case level >= LogWarning && level <= LogDebug:
		out = os.Stdout
	default:
		out = os.Stderr
	}
	// TODO: safe to add directly to format string? pre-sprintf it?
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprint(out, level.String()+": ")
	fmt.Fprintf(out, format, a...)
}
