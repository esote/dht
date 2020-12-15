package dht

import (
	"fmt"
	"io"
	"os"
	"sync"
)

// LogLevel is the priority of an event
type LogLevel int

func (l LogLevel) String() string {
	switch l {
	//case LogCrit:
	//	return "CRIT"
	case LogErr:
		return "ERR"
	case LogWarning:
		return "WARNING"
	case LogInfo:
		return "INFO"
	case LogDebug:
		return "DEBUG"
	default:
		return "<nil>"
	}
}

// TODO: ensure all logging follows these categories
// Log levels
const (
	//LogCrit    LogLevel = iota // Critical error, requiring DHT to exit
	LogErr     LogLevel = iota // Error with DHT
	LogWarning                 // Error from external request
	LogInfo                    // DHT operation information
	LogDebug                   // Debug details
)

// Logger records events of varying importance.
type Logger interface {
	Log(level LogLevel, a ...interface{})
	Logf(level LogLevel, format string, a ...interface{})
}

type consoleLogger struct {
	minLevel LogLevel
	mu       sync.Mutex
}

// NewConsoleLogger records logs to the console: stdout if level >= LogInfo,
// otherwise stderr.
func NewConsoleLogger(min LogLevel) Logger {
	return &consoleLogger{minLevel: min}
}

var _ Logger = &consoleLogger{}

func (l *consoleLogger) Log(level LogLevel, a ...interface{}) {
	defer func() {
		_ = recover()
	}()
	if level > l.minLevel {
		return
	}
	var out io.Writer
	switch {
	case level >= LogInfo:
		out = os.Stdout
	default:
		out = os.Stderr
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(out, "%s: %s", level, fmt.Sprintln(a...))
}

func (l *consoleLogger) Logf(level LogLevel, format string, a ...interface{}) {
	defer func() {
		_ = recover()
	}()
	if level > l.minLevel {
		return
	}
	var out io.Writer
	switch {
	case level >= LogInfo:
		out = os.Stdout
	default:
		out = os.Stderr
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(out, "%s: %s\n", level, fmt.Sprintf(format, a...))
}
