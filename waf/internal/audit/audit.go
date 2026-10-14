// Package audit records who changed what through the management API.
package audit

import (
	"encoding/json"
	"os"
	"strings"
	"sync"
	"time"
)

// Entry is one administrative action.
type Entry struct {
	Time   time.Time       `json:"time"`
	User   string          `json:"user"`
	IP     string          `json:"ip"`
	Action string          `json:"action"` // e.g. "PUT /api/open/site", "login"
	Status int             `json:"status"`
	Detail json.RawMessage `json:"detail,omitempty"`
}

// Log keeps recent entries in memory and appends all to a file.
type Log struct {
	mu   sync.Mutex
	ring []Entry
	next int
	full bool
	f    *os.File
}

// New opens path for appending (empty path = memory only).
func New(path string, keep int) (*Log, error) {
	if keep <= 0 {
		keep = 2000
	}
	l := &Log{ring: make([]Entry, keep)}
	if path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, err
		}
		l.f = f
	}
	return l, nil
}

// Add records e.
func (l *Log) Add(e Entry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ring[l.next] = e
	l.next = (l.next + 1) % len(l.ring)
	if l.next == 0 {
		l.full = true
	}
	if l.f != nil {
		b, _ := json.Marshal(e)
		_, _ = l.f.Write(append(b, '\n'))
	}
}

// Latest returns up to n entries, newest first.
func (l *Log) Latest(n int) []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	size := l.next
	if l.full {
		size = len(l.ring)
	}
	out := make([]Entry, 0, min(n, size))
	for i := 0; i < size && len(out) < n; i++ {
		out = append(out, l.ring[(l.next-1-i+len(l.ring))%len(l.ring)])
	}
	return out
}

// Close closes the file.
func (l *Log) Close() error {
	if l.f != nil {
		return l.f.Close()
	}
	return nil
}

// secretKeys are replaced by "***" in recorded request bodies.
var secretKeys = map[string]bool{
	"password": true, "password_hash": true, "key": true, "crt": true, "token": true,
	"secret": true, "current": true, "new": true, "code": true, "otp": true,
}

// Redact returns body (JSON) with secrets masked, truncated to a sane size.
// Bodies that are not JSON are dropped.
func Redact(body []byte) json.RawMessage {
	if len(body) == 0 {
		return nil
	}
	var v any
	if json.Unmarshal(body, &v) != nil {
		return nil
	}
	v = redact(v)
	out, _ := json.Marshal(v)
	if len(out) > 4096 {
		out, _ = json.Marshal(map[string]any{"truncated": true, "size": len(out)})
	}
	return out
}

func redact(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			if secretKeys[strings.ToLower(k)] {
				if s, ok := x.(string); ok && s == "" {
					continue
				}
				t[k] = "***"
				continue
			}
			t[k] = redact(x)
		}
		return t
	case []any:
		for i := range t {
			t[i] = redact(t[i])
		}
		return t
	}
	return v
}
