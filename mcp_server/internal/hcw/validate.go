package hcw

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Site modes accepted by the engine.
var Modes = []string{"block", "monitor", "off"}

// Limits of a single write tool call.
const (
	MaxIPsPerCall   = 100
	MaxRulesPerCall = 50

	// CRS rule IDs (the engine refuses anything else in disabled_rules).
	MinCRSRuleID = 900000
	MaxCRSRuleID = 999999

	// The broadest prefixes a tool may deny: anything wider would block a
	// large part of the Internet, which is never what an analyst means.
	MinDenyPrefixV4 = 8
	MinDenyPrefixV6 = 32
)

// ValidateMode returns the canonical mode.
func ValidateMode(mode string) (string, error) {
	m := strings.ToLower(strings.TrimSpace(mode))
	for _, ok := range Modes {
		if m == ok {
			return m, nil
		}
	}
	return "", fmt.Errorf("invalid mode %q: use block, monitor or off", Clean(mode, 20))
}

// ValidateSiteID checks a site ID argument.
func ValidateSiteID(id int) error {
	if id < 1 {
		return errors.New("site_id must be a positive site ID (see list_sites)")
	}
	return nil
}

// NormalizeCIDR returns the engine's canonical form of an IP address or
// CIDR: "1.2.3.4" becomes "1.2.3.4/32", "10.1.2.3/8" becomes "10.0.0.0/8"
// and IPv4-mapped IPv6 addresses become IPv4.
func NormalizeCIDR(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	bad := fmt.Errorf("invalid IP address or CIDR %q", Clean(s, 60))
	if s == "" || len(s) > 64 {
		return netip.Prefix{}, bad
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil || p.Addr().Zone() != "" {
			return netip.Prefix{}, bad
		}
		if p.Addr().Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		return p.Masked(), nil
	}
	ip, err := netip.ParseAddr(s)
	if err != nil || ip.Zone() != "" {
		return netip.Prefix{}, bad
	}
	ip = ip.Unmap()
	return netip.PrefixFrom(ip, ip.BitLen()), nil
}

// ParseDenyList validates the addresses of add_denied_ips/remove_denied_ips.
// broadOK allows prefixes wider than the deny limits (removal only).
func ParseDenyList(in []string, broadOK bool) ([]string, error) {
	if len(in) == 0 {
		return nil, errors.New("ips must list at least one IP address or CIDR")
	}
	if len(in) > MaxIPsPerCall {
		return nil, fmt.Errorf("at most %d IPs per call", MaxIPsPerCall)
	}
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, s := range in {
		p, err := NormalizeCIDR(s)
		if err != nil {
			return nil, err
		}
		if !broadOK {
			if p.Addr().Is4() && p.Bits() < MinDenyPrefixV4 {
				return nil, fmt.Errorf("refusing to deny %s: IPv4 prefixes must be /%d or narrower", p, MinDenyPrefixV4)
			}
			if !p.Addr().Is4() && p.Bits() < MinDenyPrefixV6 {
				return nil, fmt.Errorf("refusing to deny %s: IPv6 prefixes must be /%d or narrower", p, MinDenyPrefixV6)
			}
		}
		if n := p.String(); !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out, nil
}

// CanonicalCIDR normalises a stored entry for comparison; entries that do
// not parse are compared as written.
func CanonicalCIDR(s string) string {
	if p, err := NormalizeCIDR(s); err == nil {
		return p.String()
	}
	return strings.TrimSpace(s)
}

// ParseRuleIDs validates CRS rule IDs and removes duplicates.
func ParseRuleIDs(in []int) ([]int, error) {
	if len(in) == 0 {
		return nil, errors.New("rule_ids must list at least one CRS rule ID")
	}
	if len(in) > MaxRulesPerCall {
		return nil, fmt.Errorf("at most %d rule IDs per call", MaxRulesPerCall)
	}
	out := make([]int, 0, len(in))
	seen := map[int]bool{}
	for _, id := range in {
		if id < MinCRSRuleID || id > MaxCRSRuleID {
			return nil, fmt.Errorf("rule ID %d is not a CRS rule ID (%d-%d)", id, MinCRSRuleID, MaxCRSRuleID)
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out, nil
}

var (
	eventIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	daysRe    = regexp.MustCompile(`^([0-9]{1,4})d$`)
)

// ValidateEventID checks an event ID (16 hex characters on current nodes).
func ValidateEventID(id string) (string, error) {
	id = strings.TrimSpace(id)
	if !eventIDRe.MatchString(id) {
		return "", errors.New("event_id must be the event ID shown on the block page (letters, digits, - and _)")
	}
	return id, nil
}

// ParseSince accepts an RFC 3339 time ("2026-10-14T08:00:00Z") or a
// duration back from now ("90s", "15m", "2h", "7d"). An empty string means
// no lower bound (zero time).
func ParseSince(s string, now time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		if t.After(now.Add(5 * time.Minute)) {
			return time.Time{}, errors.New("since is in the future")
		}
		return t, nil
	}
	if m := daysRe.FindStringSubmatch(s); m != nil {
		n, _ := strconv.Atoi(m[1])
		return now.Add(-time.Duration(n) * 24 * time.Hour), nil
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return now.Add(-d), nil
	}
	return time.Time{}, fmt.Errorf("invalid since %q: use an RFC 3339 time (2026-10-14T08:00:00Z) or a duration such as 15m, 2h or 7d", Clean(s, 40))
}

// ValidatePurgePrefix checks a cache purge prefix ("" = everything).
func ValidatePurgePrefix(prefix string) error {
	if prefix == "" {
		return nil
	}
	if !strings.HasPrefix(prefix, "/") {
		return errors.New("prefix must start with /")
	}
	if len(prefix) > 2048 {
		return errors.New("prefix is longer than 2048 bytes")
	}
	for _, r := range prefix {
		if hidden(r) || r == ' ' {
			return errors.New("prefix must not contain spaces or control characters")
		}
	}
	return nil
}
