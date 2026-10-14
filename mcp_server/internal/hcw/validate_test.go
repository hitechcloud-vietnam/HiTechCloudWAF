package hcw

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestClean(t *testing.T) {
	for in, want := range map[string]string{
		"/plain?a=b":            "/plain?a=b",
		"a\nb\r\tc":             "a%0Ab%0D%09c",
		"\x1b[31mred":           "%1B[31mred",
		"rtl\u202eoverride":     "rtl%E2%80%AEoverride",
		"zero\u200bwidth\ufeff": "zero%E2%80%8Bwidth%EF%BB%BF",
		"tag\U000E0041":         "tag%F3%A0%81%81",
		"line\u2028sep":         "line%E2%80%A8sep",
		"bad\xffutf8":           "bad%FFutf8",
		"Tiếng Việt ✓":          "Tiếng Việt ✓",
		"del\x7f":               "del%7F",
	} {
		if got := Clean(in, 0); got != want {
			t.Errorf("Clean(%q) = %q, want %q", in, got, want)
		}
	}
	long := strings.Repeat("x", 50)
	if got := Clean(long, 10); got != strings.Repeat("x", 10)+"…[truncated, 50 bytes]" {
		t.Errorf("truncation = %q", got)
	}
	if got := CleanList(nil, 5); got == nil || len(got) != 0 {
		t.Errorf("CleanList(nil) = %#v", got)
	}
}

func TestRedactURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://user:pass@feeds.example/list.txt?key=SECRET": "https://feeds.example/list.txt?<redacted>",
		"http://10.0.0.1:8080":                                "http://10.0.0.1:8080",
		"not a url\n":                                         "not a url%0A",
	} {
		if got := RedactURL(in); got != want {
			t.Errorf("RedactURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRedactJSON(t *testing.T) {
	got := RedactJSON(json.RawMessage(`{"user":"a","password":"p1","nested":{"api_token":"t","list":[{"otp":"123456"}]},"crt":"PEM","note":"x\ny"}`), 0)
	for _, leak := range []string{"p1", `"t"`, "123456", "PEM"} {
		if strings.Contains(got, leak) {
			t.Errorf("RedactJSON leaked %s: %s", leak, got)
		}
	}
	if !strings.Contains(got, `"user":"a"`) || !strings.Contains(got, `x\ny`) {
		t.Errorf("RedactJSON = %s", got)
	}
	if RedactJSON(nil, 0) != "" || RedactJSON(json.RawMessage("null"), 0) != "" {
		t.Error("empty detail not empty")
	}
}

func TestNormalizeCIDRAndDenyList(t *testing.T) {
	for in, want := range map[string]string{
		"1.2.3.4":            "1.2.3.4/32",
		" 10.1.2.3/8 ":       "10.0.0.0/8",
		"::ffff:192.0.2.1":   "192.0.2.1/32",
		"2001:DB8::1":        "2001:db8::1/128",
		"2001:db8::1/48":     "2001:db8::/48",
		"::ffff:1.2.3.0/120": "1.2.3.0/24",
	} {
		p, err := NormalizeCIDR(in)
		if err != nil || p.String() != want {
			t.Errorf("NormalizeCIDR(%q) = %v, %v; want %s", in, p, err, want)
		}
	}
	for _, bad := range []string{"", "1.2.3", "1.2.3.4/33", "fe80::1%eth0", "host.example", "1.2.3.4/", strings.Repeat("1", 70)} {
		if _, err := NormalizeCIDR(bad); err == nil {
			t.Errorf("NormalizeCIDR(%q) accepted", bad)
		}
	}
	got, err := ParseDenyList([]string{"1.2.3.4", "1.2.3.4/32", "10.0.0.0/8", "2001:db8::/32"}, false)
	if err != nil || !slices.Equal(got, []string{"1.2.3.4/32", "10.0.0.0/8", "2001:db8::/32"}) {
		t.Fatalf("ParseDenyList = %v, %v", got, err)
	}
	for _, broad := range []string{"0.0.0.0/0", "8.0.0.0/7", "::/0", "2001::/31"} {
		if _, err := ParseDenyList([]string{broad}, false); err == nil || !strings.Contains(err.Error(), "refusing") {
			t.Errorf("broad %s: %v", broad, err)
		}
		if _, err := ParseDenyList([]string{broad}, true); err != nil {
			t.Errorf("broad %s refused for removal: %v", broad, err)
		}
	}
	if _, err := ParseDenyList(nil, false); err == nil {
		t.Error("empty list accepted")
	}
	if CanonicalCIDR("garbage ") != "garbage" || CanonicalCIDR("1.2.3.4") != "1.2.3.4/32" {
		t.Error("CanonicalCIDR")
	}
}

func TestParseRuleIDsModeEventID(t *testing.T) {
	ids, err := ParseRuleIDs([]int{942100, 900000, 942100, 999999})
	if err != nil || !slices.Equal(ids, []int{942100, 900000, 999999}) {
		t.Fatalf("ParseRuleIDs = %v, %v", ids, err)
	}
	for _, bad := range [][]int{nil, {899999}, {1000000}, {0}, {-942100}, make([]int, 51)} {
		if _, err := ParseRuleIDs(bad); err == nil {
			t.Errorf("ParseRuleIDs(%v) accepted", bad)
		}
	}
	for in, want := range map[string]string{"block": "block", " Monitor ": "monitor", "OFF": "off"} {
		if got, err := ValidateMode(in); err != nil || got != want {
			t.Errorf("ValidateMode(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "disable", "block\n"} {
		if _, err := ValidateMode(bad); err == nil && bad != "block\n" {
			t.Errorf("ValidateMode(%q) accepted", bad)
		}
	}
	if _, err := ValidateEventID("3f9a0c1d2b4e5f60"); err != nil {
		t.Error(err)
	}
	for _, bad := range []string{"", "../x", "a b", strings.Repeat("a", 65)} {
		if _, err := ValidateEventID(bad); err == nil {
			t.Errorf("ValidateEventID(%q) accepted", bad)
		}
	}
	if ValidateSiteID(0) == nil || ValidateSiteID(1) != nil {
		t.Error("ValidateSiteID")
	}
}

func TestParseSinceAndPrefix(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	for in, want := range map[string]time.Time{
		"":                          {},
		"15m":                       now.Add(-15 * time.Minute),
		"2h":                        now.Add(-2 * time.Hour),
		"7d":                        now.Add(-7 * 24 * time.Hour),
		"2026-10-14T08:00:00Z":      time.Date(2026, 10, 14, 8, 0, 0, 0, time.UTC),
		"2026-10-14T15:00:00+07:00": time.Date(2026, 10, 14, 8, 0, 0, 0, time.UTC),
	} {
		got, err := ParseSince(in, now)
		if err != nil || !got.Equal(want) {
			t.Errorf("ParseSince(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"yesterday", "-5m", "0s", "2026-12-01T00:00:00Z", "99999d"} {
		if _, err := ParseSince(bad, now); err == nil {
			t.Errorf("ParseSince(%q) accepted", bad)
		}
	}
	for _, ok := range []string{"", "/", "/static/", "/a?b=c"} {
		if err := ValidatePurgePrefix(ok); err != nil {
			t.Errorf("ValidatePurgePrefix(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"static", "/a b", "/a\x00", "/" + strings.Repeat("a", 2048)} {
		if err := ValidatePurgePrefix(bad); err == nil {
			t.Errorf("ValidatePurgePrefix(%q) accepted", bad)
		}
	}
}
