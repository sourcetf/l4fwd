// Package logx provides a small leveled logger with an in-memory ring buffer
// and live subscribers, so the web dashboard can tail the log.
package logx

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// Level is a log severity.
type Level int

const (
	Debug Level = iota
	Info
	Warn
	Error
)

func (l Level) String() string {
	switch l {
	case Debug:
		return "DEBUG"
	case Info:
		return "INFO"
	case Warn:
		return "WARN"
	case Error:
		return "ERROR"
	}
	return "?"
}

// ParseLevel converts a name to a Level; unknown names yield Info.
func ParseLevel(s string) Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug", "trace":
		return Debug
	case "info", "":
		return Info
	case "warn", "warning":
		return Warn
	case "error", "err":
		return Error
	}
	return Info
}

// Entry is one log record.
type Entry struct {
	Time  time.Time `json:"time"`
	Level string    `json:"level"`
	Scope string    `json:"scope,omitempty"`
	Msg   string    `json:"msg"`
}

// Logger writes entries to stderr, keeps a bounded history and fans out to
// subscribers created with Subscribe.
type Logger struct {
	mu       sync.Mutex
	level    Level
	ring     []Entry
	ringCap  int
	ringNext int
	ringLen  int
	subs     map[int]chan Entry
	nextSub  int
	out      io.Writer
	file     *os.File
}

// New creates a logger keeping the last cap entries in memory.
func New(level Level, ringCap int) *Logger {
	if ringCap <= 0 {
		ringCap = 1000
	}
	return &Logger{
		level:   level,
		ring:    make([]Entry, ringCap),
		ringCap: ringCap,
		subs:    map[int]chan Entry{},
		out:     os.Stderr,
	}
}

// SetOutput redirects human readable output (defaults to stderr).
func (l *Logger) SetOutput(w io.Writer) {
	l.mu.Lock()
	l.out = w
	l.mu.Unlock()
}

// SetFile tees output into a file in addition to stderr.
func (l *Logger) SetFile(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	l.mu.Lock()
	if l.file != nil {
		_ = l.file.Close()
	}
	l.file = f
	l.mu.Unlock()
	return nil
}

// SetLevel changes the minimum level that gets recorded.
func (l *Logger) SetLevel(level Level) {
	l.mu.Lock()
	l.level = level
	l.mu.Unlock()
}

// Level returns the current minimum level.
func (l *Logger) Level() Level {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.level
}

func (l *Logger) log(level Level, scope, format string, args ...any) {
	l.mu.Lock()
	if level < l.level {
		l.mu.Unlock()
		return
	}
	e := Entry{
		Time:  time.Now(),
		Level: level.String(),
		Scope: scope,
		Msg:   fmt.Sprintf(format, args...),
	}
	l.ring[l.ringNext] = e
	l.ringNext = (l.ringNext + 1) % l.ringCap
	if l.ringLen < l.ringCap {
		l.ringLen++
	}
	line := fmt.Sprintf("%s %-5s %s%s\n", e.Time.Format("2006-01-02 15:04:05.000"), e.Level, scopeLabel(scope), e.Msg)
	out := l.out
	file := l.file
	for _, ch := range l.subs {
		select {
		case ch <- e:
		default: // slow subscriber: drop rather than block the relay path
		}
	}
	l.mu.Unlock()

	if out != nil {
		_, _ = io.WriteString(out, line)
	}
	if file != nil {
		_, _ = io.WriteString(file, line)
	}
}

func scopeLabel(scope string) string {
	if scope == "" {
		return ""
	}
	return "[" + scope + "] "
}

// Debugf logs at debug level.
func (l *Logger) Debugf(scope, format string, args ...any) { l.log(Debug, scope, format, args...) }

// Infof logs at info level.
func (l *Logger) Infof(scope, format string, args ...any) { l.log(Info, scope, format, args...) }

// Warnf logs at warn level.
func (l *Logger) Warnf(scope, format string, args ...any) { l.log(Warn, scope, format, args...) }

// Errorf logs at error level.
func (l *Logger) Errorf(scope, format string, args ...any) { l.log(Error, scope, format, args...) }

// History returns up to n most recent entries, oldest first.
func (l *Logger) History(n int) []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n <= 0 || n > l.ringLen {
		n = l.ringLen
	}
	out := make([]Entry, 0, n)
	start := (l.ringNext - n + l.ringCap) % l.ringCap
	for i := 0; i < n; i++ {
		out = append(out, l.ring[(start+i)%l.ringCap])
	}
	return out
}

// Subscribe returns a channel of live entries and an unsubscribe function.
func (l *Logger) Subscribe(buffer int) (<-chan Entry, func()) {
	if buffer <= 0 {
		buffer = 256
	}
	ch := make(chan Entry, buffer)
	l.mu.Lock()
	id := l.nextSub
	l.nextSub++
	l.subs[id] = ch
	l.mu.Unlock()
	return ch, func() {
		l.mu.Lock()
		if c, ok := l.subs[id]; ok {
			delete(l.subs, id)
			close(c)
		}
		l.mu.Unlock()
	}
}

// Close releases the log file if one was configured.
func (l *Logger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		_ = l.file.Close()
		l.file = nil
	}
}
