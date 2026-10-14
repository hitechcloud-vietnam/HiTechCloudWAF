package model

import (
	"errors"
	"fmt"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
)

// Load-balancing strategies of a site (Site.LB).
const (
	LBRoundRobin = "round_robin" // rotate evenly, weights ignored (default)
	LBWeighted   = "weighted"    // smooth weighted round-robin
	LBLeastConn  = "least_conn"  // fewest in-flight requests per weight
	LBIPHash     = "ip_hash"     // consistent hash of the client address
	LBRandom     = "random"      // weighted random
)

// MaxUpstreamWeight bounds the weight of one upstream.
const MaxUpstreamWeight = 100

// DefaultStickyCookie names the session-affinity cookie.
const DefaultStickyCookie = "hcw_srv"

// Header rule actions.
const (
	HeaderSet    = "set"    // replace every value
	HeaderAdd    = "add"    // append a value
	HeaderRemove = "remove" // delete the header
)

// HeaderRule rewrites one header of the requests sent upstream or of the
// responses returned to clients.
type HeaderRule struct {
	Action string `json:"action"`
	Name   string `json:"name"`
	Value  string `json:"value,omitempty"`
}

// ParseUpstream parses an upstream entry: "http(s)://host[:port]" optionally
// followed by options separated by spaces; the only option is "weight=N"
// (1..100, default 1). The plain URL form stays valid.
func ParseUpstream(s string) (*url.URL, int, error) {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return nil, 0, errors.New("empty upstream")
	}
	pu, err := url.Parse(fields[0])
	if err != nil || (pu.Scheme != "http" && pu.Scheme != "https") || pu.Host == "" || (pu.Path != "" && pu.Path != "/") {
		return nil, 0, fmt.Errorf("invalid upstream %q (use http(s)://host[:port] [weight=N])", s)
	}
	weight := 1
	for _, f := range fields[1:] {
		k, v, _ := strings.Cut(f, "=")
		if strings.ToLower(k) != "weight" {
			return nil, 0, fmt.Errorf("upstream %q: unknown option %q (only weight=N)", s, f)
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > MaxUpstreamWeight {
			return nil, 0, fmt.Errorf("upstream %q: weight must be 1..%d", s, MaxUpstreamWeight)
		}
		weight = n
	}
	return pu, weight, nil
}

// normalizeUpstreams validates upstreams, the balancing strategy and sticky
// sessions. Upstreams are rewritten to "URL" or "URL weight=N".
func (s *Site) normalizeUpstreams() error {
	if len(s.Upstreams) == 0 {
		return errors.New("upstreams is required")
	}
	weighted := false
	for i, raw := range s.Upstreams {
		_, w, err := ParseUpstream(raw)
		if err != nil {
			return err
		}
		s.Upstreams[i] = strings.Fields(raw)[0]
		if w != 1 {
			weighted = true
			s.Upstreams[i] += " weight=" + strconv.Itoa(w)
		}
	}
	s.LB = strings.ToLower(strings.TrimSpace(s.LB))
	switch s.LB {
	case "":
		// Plain lists keep the historical round-robin; weights imply weighted.
		s.LB = LBRoundRobin
		if weighted {
			s.LB = LBWeighted
		}
	case LBRoundRobin, LBWeighted, LBLeastConn, LBIPHash, LBRandom:
	default:
		return fmt.Errorf("lb must be %s, %s, %s, %s or %s", LBRoundRobin, LBWeighted, LBLeastConn, LBIPHash, LBRandom)
	}
	if s.StickyCookie == "" {
		s.StickyCookie = DefaultStickyCookie
	}
	if !isToken(s.StickyCookie) || len(s.StickyCookie) > 64 {
		return fmt.Errorf("invalid sticky_cookie %q", s.StickyCookie)
	}
	if c := strings.ToLower(s.StickyCookie); c == "hcw_bot" || c == "hcw_auth" {
		return fmt.Errorf("sticky_cookie %q is reserved", s.StickyCookie)
	}
	if s.StickyTTLSec < 0 || s.StickyTTLSec > 30*86400 {
		return errors.New("sticky_ttl_sec must be 0..2592000 (0 = browser session)")
	}
	return nil
}

// Headers no rule may touch: hop-by-hop headers, message framing, and the
// ones the engine manages itself (Host is set through upstream_host, the
// forwarding headers carry the verified client address).
var (
	forbiddenHeaders = map[string]bool{
		"Connection": true, "Keep-Alive": true, "Proxy-Connection": true, "Proxy-Authenticate": true,
		"Proxy-Authorization": true, "Te": true, "Trailer": true, "Transfer-Encoding": true, "Upgrade": true,
		"Host": true, "Content-Length": true, "Content-Encoding": true,
	}
	forbiddenRequestHeaders = map[string]bool{
		"X-Forwarded-For": true, "X-Forwarded-Proto": true, "X-Forwarded-Host": true, "X-Real-Ip": true,
		"Forwarded": true, "Expect": true,
	}
)

const maxHeaderRules = 50

func normalizeHeaderRules(field string, rules []HeaderRule, request bool) error {
	if len(rules) > maxHeaderRules {
		return fmt.Errorf("at most %d %s", maxHeaderRules, field)
	}
	for i := range rules {
		r := &rules[i]
		r.Action = strings.ToLower(strings.TrimSpace(r.Action))
		r.Name = strings.TrimSpace(r.Name)
		if !isToken(r.Name) || len(r.Name) > 128 {
			return fmt.Errorf("%s: invalid header name %q", field, r.Name)
		}
		r.Name = textproto.CanonicalMIMEHeaderKey(r.Name)
		if forbiddenHeaders[r.Name] || (request && forbiddenRequestHeaders[r.Name]) {
			return fmt.Errorf("%s: header %s cannot be rewritten", field, r.Name)
		}
		switch r.Action {
		case HeaderSet, HeaderAdd:
			r.Value = strings.TrimSpace(r.Value)
			if r.Value == "" || len(r.Value) > 4096 || strings.ContainsAny(r.Value, "\r\n\x00") {
				return fmt.Errorf("%s: %s %s needs a single-line value (max 4096 bytes)", field, r.Action, r.Name)
			}
		case HeaderRemove:
			r.Value = ""
		default:
			return fmt.Errorf("%s: action must be set, add or remove", field)
		}
	}
	return nil
}

func (s *Site) normalizeHeaders() error {
	if err := normalizeHeaderRules("request_headers", s.RequestHeaders, true); err != nil {
		return err
	}
	return normalizeHeaderRules("response_headers", s.ResponseHeaders, false)
}

// isToken reports whether s is an RFC 9110 token (header or cookie name).
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}
