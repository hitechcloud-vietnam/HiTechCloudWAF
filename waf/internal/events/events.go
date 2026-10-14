// Package events records security events (blocked or flagged requests).
package events

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Event is one security decision.
type Event struct {
	ID       string    `json:"id"`
	Time     time.Time `json:"time"`
	SiteID   int       `json:"site_id"`
	Host     string    `json:"host"`
	ClientIP string    `json:"client_ip"`
	Method   string    `json:"method"`
	URI      string    `json:"uri"`
	UA       string    `json:"user_agent"`
	// Kind is waf, rate_limit, ip_deny or ip_allow.
	Kind string `json:"kind"`
	// Action is block or monitor.
	Action string   `json:"action"`
	Status int      `json:"status"`
	Rules  []Rule   `json:"rules,omitempty"`
	Tags   []string `json:"tags,omitempty"`
}

// Rule is a matched WAF rule.
type Rule struct {
	ID       int    `json:"id"`
	Msg      string `json:"msg"`
	Data     string `json:"data,omitempty"`
	Severity string `json:"severity,omitempty"`
}

// NewID returns a short random event ID shown on the block page.
func NewID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Log keeps the latest events in memory and appends all of them to a JSONL
// file when configured.
type Log struct {
	mu   sync.Mutex
	ring []Event
	next int
	full bool
	file *os.File
	enc  *json.Encoder

	counters map[int]*Counters
}

// Counters are per-site totals since start.
type Counters struct {
	Requests  uint64 `json:"requests"`
	Blocked   uint64 `json:"blocked"`
	Monitored uint64 `json:"monitored"`
	RateLimit uint64 `json:"rate_limited"`
	ACL       uint64 `json:"acl_blocked"`
}

// New creates a log holding size events. path may be empty.
func New(size int, path string) (*Log, error) {
	if size <= 0 {
		size = 1000
	}
	l := &Log{ring: make([]Event, size), counters: map[int]*Counters{}}
	if path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, err
		}
		l.file, l.enc = f, json.NewEncoder(f)
	}
	return l, nil
}

func (l *Log) counter(site int) *Counters {
	c, ok := l.counters[site]
	if !ok {
		c = &Counters{}
		l.counters[site] = c
	}
	return c
}

// CountRequest increments the request counter of a site.
func (l *Log) CountRequest(site int) {
	l.mu.Lock()
	l.counter(site).Requests++
	l.mu.Unlock()
}

// Add records e.
func (l *Log) Add(e Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	c := l.counter(e.SiteID)
	switch {
	case e.Kind == "rate_limit":
		c.RateLimit++
	case e.Kind == "ip_deny" || e.Kind == "ip_allow":
		c.ACL++
	case e.Action == "monitor":
		c.Monitored++
	default:
		c.Blocked++
	}
	l.ring[l.next] = e
	l.next = (l.next + 1) % len(l.ring)
	if l.next == 0 {
		l.full = true
	}
	if l.enc != nil {
		_ = l.enc.Encode(e)
	}
}

// Latest returns up to n events, newest first, optionally for one site.
func (l *Log) Latest(n, site int) []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	size := l.next
	if l.full {
		size = len(l.ring)
	}
	out := make([]Event, 0, min(n, size))
	for i := 0; i < size && len(out) < n; i++ {
		e := l.ring[(l.next-1-i+len(l.ring))%len(l.ring)]
		if site == 0 || e.SiteID == site {
			out = append(out, e)
		}
	}
	return out
}

// Stats returns a copy of the counters.
func (l *Log) Stats() map[int]Counters {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make(map[int]Counters, len(l.counters))
	for k, v := range l.counters {
		out[k] = *v
	}
	return out
}

// Close closes the file.
func (l *Log) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}
