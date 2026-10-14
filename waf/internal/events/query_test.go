package events

import (
	"net/netip"
	"slices"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func seed(t *testing.T) *Log {
	t.Helper()
	l, err := New(100, "")
	if err != nil {
		t.Fatal(err)
	}
	add := func(id string, min int, site int, ip, country, kind, action, uri, host, ua string, rules ...int) {
		e := Event{ID: id, Time: t0.Add(time.Duration(min) * time.Minute), SiteID: site, ClientIP: ip, Country: country,
			Kind: kind, Action: action, URI: uri, Host: host, UA: ua, Method: "GET", Status: 403}
		for _, r := range rules {
			e.Rules = append(e.Rules, Rule{ID: r, Msg: "rule " + string(rune('A'+r%26))})
		}
		l.Add(e)
	}
	add("e1", 0, 1, "203.0.113.7", "VN", "waf", "block", "/login?id=1'%20OR%201=1", "shop.vn", "sqlmap/1.7", 942100, 949110)
	add("e2", 1, 1, "203.0.113.8", "VN", "waf", "monitor", "/search?q=<script>", "shop.vn", "Mozilla/5.0", 941100, 949110)
	add("e3", 2, 2, "198.51.100.1", "US", "rate_limit", "block", "/api/items", "api.vn", "curl/8.0")
	add("e4", 3, 2, "2001:db8::1", "", "bot", "block", "/", "api.vn", "python-requests")
	add("e5", 4, 1, "203.0.113.7", "VN", "waf", "block", "/etc/passwd", "shop.vn", "Nikto", 930120, 949110)
	// Recorded last but happened first: ordering is by time, not arrival.
	add("e0", -5, 1, "::ffff:203.0.113.9", "VN", "ip_deny", "block", "/", "shop.vn", "x")
	return l
}

func ids(ev []Event) []string {
	out := []string{}
	for _, e := range ev {
		out = append(out, e.ID)
	}
	return out
}

func TestQueryFilters(t *testing.T) {
	l := seed(t)
	ipf := func(s string) Filter {
		p, err := ParseIPFilter(s)
		if err != nil {
			t.Fatal(err)
		}
		return Filter{IP: p}
	}
	cases := []struct {
		name string
		f    Filter
		want []string
	}{
		{"all newest first", Filter{}, []string{"e5", "e4", "e3", "e2", "e1", "e0"}},
		{"site", Filter{SiteID: 2}, []string{"e4", "e3"}},
		{"kind", Filter{Kinds: []string{"waf"}}, []string{"e5", "e2", "e1"}},
		{"kinds", Filter{Kinds: []string{"bot", "rate_limit"}}, []string{"e4", "e3"}},
		{"action", Filter{Actions: []string{"monitor"}}, []string{"e2"}},
		{"exact ip", ipf("203.0.113.7"), []string{"e5", "e1"}},
		{"cidr", ipf("203.0.113.0/24"), []string{"e5", "e2", "e1", "e0"}},
		{"ipv6", ipf("2001:db8::/32"), []string{"e4"}},
		{"mapped prefix", ipf("::ffff:203.0.113.8/128"), []string{"e2"}},
		{"text uri", Filter{Text: "PASSWD"}, []string{"e5"}},
		{"text host", Filter{Text: "api.vn"}, []string{"e4", "e3"}},
		{"text ua", Filter{Text: "sqlmap"}, []string{"e1"}},
		{"since", Filter{Since: t0.Add(2 * time.Minute)}, []string{"e5", "e4", "e3"}},
		{"until", Filter{Until: t0}, []string{"e1", "e0"}},
		{"window", Filter{Since: t0.Add(time.Minute), Until: t0.Add(3 * time.Minute)}, []string{"e4", "e3", "e2"}},
		{"combined", Filter{SiteID: 1, Kinds: []string{"waf"}, Actions: []string{"block"}, Text: "/login"}, []string{"e1"}},
		{"country", Filter{Countries: []string{"US", "XX"}}, []string{"e3"}},
		{"rule", Filter{RuleID: 949110}, []string{"e5", "e2", "e1"}},
		{"rule and ip", Filter{RuleID: 949110, IP: netip.MustParsePrefix("203.0.113.7/32")}, []string{"e5", "e1"}},
		{"none", Filter{Kinds: []string{"geo"}}, []string{}},
	}
	for _, c := range cases {
		if got := ids(l.Query(c.f, 0)); !slices.Equal(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
	if got := ids(l.Query(Filter{}, 2)); !slices.Equal(got, []string{"e5", "e4"}) {
		t.Errorf("limit: %v", got)
	}
}

func TestQueryStableOrderForEqualTimes(t *testing.T) {
	l, _ := New(10, "")
	for _, id := range []string{"a", "b", "c"} {
		l.Add(Event{ID: id, Time: t0})
	}
	for range 3 {
		if got := ids(l.Query(Filter{}, 0)); !slices.Equal(got, []string{"c", "b", "a"}) {
			t.Fatalf("got %v", got)
		}
	}
}

func TestQueryAfterWrap(t *testing.T) {
	l, _ := New(3, "")
	for i := range 5 {
		l.Add(Event{ID: string(rune('a' + i)), Time: t0.Add(time.Duration(i) * time.Second)})
	}
	if got := ids(l.Query(Filter{}, 0)); !slices.Equal(got, []string{"e", "d", "c"}) {
		t.Fatalf("got %v", got)
	}
}

func TestParseIPFilter(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.7":         "203.0.113.7/32",
		" 203.0.113.9/24 ":    "203.0.113.0/24",
		"2001:db8::1":         "2001:db8::1/128",
		"::ffff:10.0.0.1":     "10.0.0.1/32",
		"::ffff:10.0.0.0/104": "10.0.0.0/8",
	} {
		p, err := ParseIPFilter(in)
		if err != nil || p.String() != want {
			t.Errorf("%q: %v %v, want %s", in, p, err, want)
		}
	}
	for _, bad := range []string{"10.0.0", "10.0.0.1/33", "example.com", "::ffff:1.2.3.4/64"} {
		if _, err := ParseIPFilter(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if p, err := ParseIPFilter(""); err != nil || p.IsValid() {
		t.Errorf("empty: %v %v", p, err)
	}
}

func TestParseTime(t *testing.T) {
	now := t0
	for in, want := range map[string]time.Time{
		"":                          {},
		"2026-10-01T10:00:00Z":      time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC),
		"2026-10-01T17:00:00+07:00": time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC),
		"15m":                       now.Add(-15 * time.Minute),
		"24h":                       now.Add(-24 * time.Hour),
		"7d":                        now.Add(-7 * 24 * time.Hour),
	} {
		got, err := ParseTime(in, now)
		if err != nil || !got.Equal(want) {
			t.Errorf("%q: %v %v, want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"yesterday", "-1h", "0s", "2026-10-01", "xd"} {
		if _, err := ParseTime(bad, now); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestTop(t *testing.T) {
	l := seed(t)
	type kv struct {
		k string
		n int
	}
	flat := func(es []TopEntry) []kv {
		out := []kv{}
		for _, e := range es {
			out = append(out, kv{e.Key, e.Count})
		}
		return out
	}
	check := func(by string, f Filter, wantTotal int, want []kv) {
		t.Helper()
		got, total, err := l.Top(f, by, 20)
		if err != nil {
			t.Fatal(err)
		}
		if total != wantTotal || !slices.Equal(flat(got), want) {
			t.Errorf("top %s: total %d %v, want %d %v", by, total, flat(got), wantTotal, want)
		}
	}
	check("ip", Filter{}, 6, []kv{{"203.0.113.7", 2}, {"198.51.100.1", 1}, {"2001:db8::1", 1}, {"203.0.113.8", 1}, {"::ffff:203.0.113.9", 1}})
	check("uri", Filter{}, 6, []kv{{"/", 2}, {"/api/items", 1}, {"/etc/passwd", 1}, {"/login", 1}, {"/search", 1}})
	check("country", Filter{}, 6, []kv{{"VN", 4}, {"US", 1}})
	check("kind", Filter{}, 6, []kv{{"waf", 3}, {"bot", 1}, {"ip_deny", 1}, {"rate_limit", 1}})
	check("rule", Filter{}, 6, []kv{{"949110", 3}, {"930120", 1}, {"941100", 1}, {"942100", 1}})
	check("rule", Filter{Since: t0.Add(4 * time.Minute)}, 1, []kv{{"930120", 1}, {"949110", 1}})
	check("ip", Filter{SiteID: 2}, 2, []kv{{"198.51.100.1", 1}, {"2001:db8::1", 1}})

	got, _, _ := l.Top(Filter{}, "rule", 1)
	if len(got) != 1 || got[0].Label == "" {
		t.Errorf("rule label/limit: %+v", got)
	}
	if _, _, err := l.Top(Filter{}, "method", 20); err == nil {
		t.Error("unknown dimension accepted")
	}
	// A rule listed twice in one event counts once.
	l2, _ := New(10, "")
	l2.Add(Event{Time: t0, Rules: []Rule{{ID: 1}, {ID: 1}}})
	if got, _, _ := l2.Top(Filter{}, "rule", 20); len(got) != 1 || got[0].Count != 1 {
		t.Errorf("duplicate rule: %+v", got)
	}
}
