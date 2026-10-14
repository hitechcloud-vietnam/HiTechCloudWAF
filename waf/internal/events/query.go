package events

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Filter selects events. The zero value matches every event.
type Filter struct {
	// SiteID keeps the events of one site (0 = every site).
	SiteID int
	// Kinds and Actions keep events whose Kind/Action is one of these
	// (empty = any).
	Kinds   []string
	Actions []string
	// Countries keeps events from one of these ISO country codes.
	Countries []string
	// RuleID keeps events that matched this WAF rule (0 = any).
	RuleID int
	// IP keeps events whose client address is inside this prefix (an exact
	// address is a /32 or /128 prefix). The zero value matches any address.
	IP netip.Prefix
	// Text keeps events whose URI, host, user agent or ID contains it,
	// ignoring case.
	Text string
	// Since and Until bound the event time (inclusive); zero = unbounded.
	Since, Until time.Time
}

// ParseIPFilter parses an exact address ("203.0.113.7", "2001:db8::1") or a
// CIDR prefix ("203.0.113.0/24").
func ParseIPFilter(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Prefix{}, nil
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid IP/CIDR %q", s)
		}
		if p.Addr().Is4In6() {
			if p.Bits() < 96 {
				return netip.Prefix{}, fmt.Errorf("invalid IP/CIDR %q", s)
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid IP/CIDR %q", s)
	}
	a = a.Unmap().WithZone("")
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// ParseTime reads an RFC 3339 timestamp, or a duration back from now such as
// "15m", "24h" or "7d".
func ParseTime(s string, now time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	var d time.Duration
	var err error
	if n, ok := strings.CutSuffix(s, "d"); ok {
		var days int
		days, err = strconv.Atoi(n)
		d = time.Duration(days) * 24 * time.Hour
	} else {
		d, err = time.ParseDuration(s)
	}
	if err != nil || d <= 0 {
		return time.Time{}, fmt.Errorf("invalid time %q (use RFC 3339, e.g. 2026-01-02T15:04:05Z, or a duration such as 15m, 24h, 7d)", s)
	}
	return now.Add(-d), nil
}

// Match reports whether e passes the filter.
func (f *Filter) Match(e *Event) bool {
	if f.SiteID != 0 && e.SiteID != f.SiteID {
		return false
	}
	if len(f.Kinds) > 0 && !slices.Contains(f.Kinds, e.Kind) {
		return false
	}
	if len(f.Actions) > 0 && !slices.Contains(f.Actions, e.Action) {
		return false
	}
	if len(f.Countries) > 0 && !slices.Contains(f.Countries, e.Country) {
		return false
	}
	if f.RuleID != 0 && !slices.ContainsFunc(e.Rules, func(r Rule) bool { return r.ID == f.RuleID }) {
		return false
	}
	if !f.Since.IsZero() && e.Time.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && e.Time.After(f.Until) {
		return false
	}
	if f.IP.IsValid() {
		a, err := netip.ParseAddr(e.ClientIP)
		if err != nil || !f.IP.Contains(a.Unmap().WithZone("")) {
			return false
		}
	}
	if f.Text != "" {
		q := strings.ToLower(f.Text)
		if !strings.Contains(strings.ToLower(e.URI), q) && !strings.Contains(strings.ToLower(e.Host), q) &&
			!strings.Contains(strings.ToLower(e.UA), q) && !strings.Contains(strings.ToLower(e.ID), q) {
			return false
		}
	}
	return true
}

// snapshot copies the retained events, newest recorded first.
func (l *Log) snapshot() []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	size := l.next
	if l.full {
		size = len(l.ring)
	}
	out := make([]Event, size)
	for i := range size {
		out[i] = l.ring[(l.next-1-i+len(l.ring))%len(l.ring)]
	}
	return out
}

// Query returns up to limit matching events (limit <= 0 = all), newest first.
// Events are ordered by time; events with the same time keep the order in
// which they were recorded (latest first), so pages are stable.
func (l *Log) Query(f Filter, limit int) []Event {
	all := l.snapshot()
	out := all[:0]
	for i := range all {
		if f.Match(&all[i]) {
			out = append(out, all[i])
		}
	}
	slices.SortStableFunc(out, func(a, b Event) int { return b.Time.Compare(a.Time) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return slices.Clip(out)
}

// TopEntry is one row of a Top aggregation.
type TopEntry struct {
	Key   string `json:"key"`
	Label string `json:"label,omitempty"` // rule message for by=rule
	Count int    `json:"count"`
}

// TopFields lists the dimensions accepted by Top.
var TopFields = []string{"ip", "uri", "rule", "country", "kind"}

// ErrTopField is returned by Top for an unknown dimension.
var ErrTopField = errors.New("by must be one of ip, uri, rule, country, kind")

// Top counts matching events by one dimension and returns the n largest
// groups, largest first (ties by key), plus the number of events considered.
// For "uri" the query string is ignored; for "rule" an event counts once for
// each matched rule; events without a country or rule are not counted under
// those dimensions.
func (l *Log) Top(f Filter, by string, n int) ([]TopEntry, int, error) {
	if !slices.Contains(TopFields, by) {
		return nil, 0, ErrTopField
	}
	counts := map[string]*TopEntry{}
	add := func(key, label string) {
		if key == "" {
			return
		}
		e, ok := counts[key]
		if !ok {
			e = &TopEntry{Key: key, Label: label}
			counts[key] = e
		}
		e.Count++
	}
	all := l.snapshot()
	matched := 0
	for i := range all {
		e := &all[i]
		if !f.Match(e) {
			continue
		}
		matched++
		switch by {
		case "ip":
			add(e.ClientIP, "")
		case "uri":
			path, _, _ := strings.Cut(e.URI, "?")
			add(path, "")
		case "country":
			add(e.Country, "")
		case "kind":
			add(e.Kind, "")
		case "rule":
			seen := map[int]bool{}
			for _, r := range e.Rules {
				if !seen[r.ID] {
					seen[r.ID] = true
					add(strconv.Itoa(r.ID), r.Msg)
				}
			}
		}
	}
	out := make([]TopEntry, 0, len(counts))
	for _, e := range counts {
		out = append(out, *e)
	}
	slices.SortFunc(out, func(a, b TopEntry) int {
		if c := cmp.Compare(b.Count, a.Count); c != 0 {
			return c
		}
		return cmp.Compare(a.Key, b.Key)
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out, matched, nil
}
