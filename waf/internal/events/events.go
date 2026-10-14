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
	Country  string    `json:"country,omitempty"`
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

	// per-minute totals for the last 60 minutes
	series [60]Bucket

	observers []func(Event)
}

// OnAdd registers f to be called (synchronously, outside the lock) for every
// recorded event. f must not block.
func (l *Log) OnAdd(f func(Event)) {
	l.mu.Lock()
	l.observers = append(l.observers, f)
	l.mu.Unlock()
}

// Bucket is one minute of traffic.
type Bucket struct {
	Minute    int64  `json:"minute"` // unix seconds, start of the minute
	Requests  uint64 `json:"requests"`
	Blocked   uint64 `json:"blocked"`
	Monitored uint64 `json:"monitored"`
	RateLimit uint64 `json:"rate_limited"`
	ACL       uint64 `json:"acl_blocked"`
	Bot       uint64 `json:"bot_failed"`
}

// bucket returns the bucket of the current minute, recycling stale ones.
func (l *Log) bucket(now time.Time) *Bucket {
	m := now.Unix() / 60 * 60
	b := &l.series[(m/60)%60]
	if b.Minute != m {
		*b = Bucket{Minute: m}
	}
	return b
}

// Series returns the last 60 minutes, oldest first, with empty minutes
// filled in.
func (l *Log) Series(now time.Time) []Bucket {
	l.mu.Lock()
	defer l.mu.Unlock()
	cur := now.Unix() / 60 * 60
	out := make([]Bucket, 0, 60)
	for i := 59; i >= 0; i-- {
		m := cur - int64(i)*60
		b := l.series[(m/60)%60]
		if b.Minute != m {
			b = Bucket{Minute: m}
		}
		out = append(out, b)
	}
	return out
}

// Counters are per-site totals since start.
type Counters struct {
	Requests  uint64 `json:"requests"`
	Blocked   uint64 `json:"blocked"`
	Monitored uint64 `json:"monitored"`
	RateLimit uint64 `json:"rate_limited"`
	ACL       uint64 `json:"acl_blocked"`
	Bot       uint64 `json:"bot_failed"`
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
	l.bucket(time.Now()).Requests++
	l.mu.Unlock()
}

// Add records e.
func (l *Log) Add(e Event) {
	l.mu.Lock()
	obs := l.observers
	defer func() {
		for _, f := range obs {
			f(e)
		}
	}()
	defer l.mu.Unlock()
	c := l.counter(e.SiteID)
	b := l.bucket(e.Time)
	switch {
	case e.Kind == "rate_limit":
		c.RateLimit++
		b.RateLimit++
	case e.Kind == "ip_deny" || e.Kind == "ip_allow" || e.Kind == "geo" || e.Kind == "rule":
		c.ACL++
		b.ACL++
	case e.Kind == "bot":
		c.Bot++
		b.Bot++
	case e.Action == "monitor":
		c.Monitored++
		b.Monitored++
	default:
		c.Blocked++
		b.Blocked++
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
