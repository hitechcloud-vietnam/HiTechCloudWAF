package model

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestParseUpstream(t *testing.T) {
	cases := []struct {
		in     string
		url    string
		weight int
		err    string
	}{
		{"http://10.0.0.1:8080", "http://10.0.0.1:8080", 1, ""},
		{"https://app.internal/", "https://app.internal/", 1, ""},
		{"  http://10.0.0.1:8080   weight=3 ", "http://10.0.0.1:8080", 3, ""},
		{"http://10.0.0.1 WEIGHT=100", "http://10.0.0.1", 100, ""},
		{"http://10.0.0.1 weight=0", "", 0, "weight must be"},
		{"http://10.0.0.1 weight=101", "", 0, "weight must be"},
		{"http://10.0.0.1 weight=x", "", 0, "weight must be"},
		{"http://10.0.0.1 backup", "", 0, "unknown option"},
		{"ftp://10.0.0.1", "", 0, "invalid upstream"},
		{"http://10.0.0.1/app", "", 0, "invalid upstream"},
		{"10.0.0.1:80", "", 0, "invalid upstream"},
		{"   ", "", 0, "empty"},
	}
	for _, c := range cases {
		u, w, err := ParseUpstream(c.in)
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%q: err = %v, want %q", c.in, err, c.err)
			}
			continue
		}
		if err != nil || u.String() != c.url || w != c.weight {
			t.Errorf("%q: got %v %d %v", c.in, u, w, err)
		}
	}
}

func baseSite() Site {
	return Site{ServerNames: []string{"a.vn"}, Upstreams: []string{"http://10.0.0.1"}}
}

func TestNormalizeTraffic(t *testing.T) {
	cases := []struct {
		name  string
		edit  func(*Site)
		err   string
		check func(*testing.T, *Site)
	}{
		{"defaults keep round robin", func(s *Site) {}, "", func(t *testing.T, s *Site) {
			if s.LB != LBRoundRobin || s.StickyCookie != DefaultStickyCookie || s.Upstreams[0] != "http://10.0.0.1" {
				t.Fatalf("%+v", s)
			}
		}},
		{"weights imply weighted and are canonical", func(s *Site) {
			s.Upstreams = []string{"http://10.0.0.1  weight=3", "http://10.0.0.2 weight=1"}
		}, "", func(t *testing.T, s *Site) {
			if s.LB != LBWeighted || s.Upstreams[0] != "http://10.0.0.1 weight=3" || s.Upstreams[1] != "http://10.0.0.2" {
				t.Fatalf("%q %q", s.LB, s.Upstreams)
			}
		}},
		{"explicit strategy kept", func(s *Site) { s.LB = " IP_HASH " }, "", func(t *testing.T, s *Site) {
			if s.LB != LBIPHash {
				t.Fatal(s.LB)
			}
		}},
		{"unknown strategy", func(s *Site) { s.LB = "fastest" }, "lb must be", nil},
		{"no upstreams", func(s *Site) { s.Upstreams = nil }, "upstreams is required", nil},
		{"bad weight", func(s *Site) { s.Upstreams = []string{"http://10.0.0.1 weight=-1"} }, "weight must be", nil},
		{"sticky cookie name", func(s *Site) { s.Sticky, s.StickyCookie = true, "bad name" }, "invalid sticky_cookie", nil},
		{"sticky cookie reserved", func(s *Site) { s.StickyCookie = "hcw_bot" }, "reserved", nil},
		{"sticky ttl range", func(s *Site) { s.StickyTTLSec = -1 }, "sticky_ttl_sec", nil},
		{"header rules canonicalised", func(s *Site) {
			s.RequestHeaders = []HeaderRule{{Action: " SET ", Name: "x-env", Value: " prod "}, {Action: "remove", Name: "cookie", Value: "ignored"}}
			s.ResponseHeaders = []HeaderRule{{Action: "add", Name: "content-security-policy", Value: "default-src 'self'"}}
		}, "", func(t *testing.T, s *Site) {
			r := s.RequestHeaders
			if r[0] != (HeaderRule{"set", "X-Env", "prod"}) || r[1] != (HeaderRule{"remove", "Cookie", ""}) || s.ResponseHeaders[0].Name != "Content-Security-Policy" {
				t.Fatalf("%+v %+v", r, s.ResponseHeaders)
			}
		}},
		{"request Host", func(s *Site) { s.RequestHeaders = []HeaderRule{{Action: "set", Name: "Host", Value: "x"}} }, "cannot be rewritten", nil},
		{"request hop-by-hop", func(s *Site) { s.RequestHeaders = []HeaderRule{{Action: "remove", Name: "connection"}} }, "cannot be rewritten", nil},
		{"request X-Forwarded-For", func(s *Site) {
			s.RequestHeaders = []HeaderRule{{Action: "set", Name: "x-forwarded-for", Value: "1.2.3.4"}}
		}, "cannot be rewritten", nil},
		{"request X-Real-IP", func(s *Site) { s.RequestHeaders = []HeaderRule{{Action: "set", Name: "X-Real-IP", Value: "1.2.3.4"}} }, "cannot be rewritten", nil},
		{"response Transfer-Encoding", func(s *Site) {
			s.ResponseHeaders = []HeaderRule{{Action: "set", Name: "Transfer-Encoding", Value: "chunked"}}
		}, "cannot be rewritten", nil},
		{"response Content-Length", func(s *Site) { s.ResponseHeaders = []HeaderRule{{Action: "remove", Name: "Content-Length"}} }, "cannot be rewritten", nil},
		{"response X-Forwarded-For allowed", func(s *Site) { s.ResponseHeaders = []HeaderRule{{Action: "remove", Name: "X-Forwarded-For"}} }, "", nil},
		{"header injection", func(s *Site) {
			s.ResponseHeaders = []HeaderRule{{Action: "set", Name: "X-A", Value: "a\r\nSet-Cookie: x=1"}}
		}, "single-line", nil},
		{"empty value", func(s *Site) { s.ResponseHeaders = []HeaderRule{{Action: "add", Name: "X-A"}} }, "single-line", nil},
		{"bad name", func(s *Site) { s.ResponseHeaders = []HeaderRule{{Action: "set", Name: "X A", Value: "1"}} }, "invalid header name", nil},
		{"bad action", func(s *Site) { s.ResponseHeaders = []HeaderRule{{Action: "append", Name: "X-A", Value: "1"}} }, "action must be", nil},
		{"too many rules", func(s *Site) {
			s.RequestHeaders = make([]HeaderRule, 51)
		}, "at most", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := baseSite()
			c.edit(&s)
			err := s.Normalize()
			if c.err != "" {
				if err == nil || !strings.Contains(err.Error(), c.err) {
					t.Fatalf("err = %v, want %q", err, c.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if c.check != nil {
				c.check(t, &s)
			}
		})
	}
}

// Sites stored before load balancing existed still load unchanged.
func TestLegacySiteJSON(t *testing.T) {
	var s Site
	if err := json.Unmarshal([]byte(`{"server_names":["a.vn"],"upstreams":["http://10.0.0.1:8080","http://10.0.0.2:8080"]}`), &s); err != nil {
		t.Fatal(err)
	}
	if err := s.Normalize(); err != nil {
		t.Fatal(err)
	}
	if s.LB != LBRoundRobin || s.Sticky || len(s.RequestHeaders) != 0 || s.Upstreams[1] != "http://10.0.0.2:8080" {
		t.Fatalf("%+v", s)
	}
}

func TestExampleSite(t *testing.T) {
	b, err := os.ReadFile("../../examples/site.json")
	if err != nil {
		t.Fatal(err)
	}
	var s Site
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if err := s.Normalize(); err != nil {
		t.Fatal(err)
	}
	if s.LB != LBLeastConn || !s.Sticky || len(s.RequestHeaders) == 0 || len(s.ResponseHeaders) == 0 || !s.HideServerHeaders {
		t.Fatalf("example does not show the traffic options: %+v", s)
	}
}
