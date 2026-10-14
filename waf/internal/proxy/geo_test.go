package proxy

import (
	"net"
	"testing"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/model"
)

type fakeGeo map[string]string

func (f fakeGeo) Country(ip net.IP) string { return f[ip.String()] }

func TestCountryAllowDeny(t *testing.T) {
	lb, _ := model.ParseCIDR("127.0.0.1")
	geo := fakeGeo{"203.0.113.9": "VN", "198.51.100.7": "RU"}
	h := newHarness(t, []*net.IPNet{lb},
		model.Site{ServerNames: []string{"deny.vn"}, Mode: model.ModeOff, CountryDeny: []string{"ru"}},
		model.Site{ServerNames: []string{"allow.vn"}, Mode: model.ModeOff, CountryAllow: []string{"VN"}},
	)
	h.eng.opt.GeoIP = geo
	from := func(ip string) map[string]string { return map[string]string{"X-Forwarded-For": ip} }
	cases := []struct {
		host, ip string
		want     int
	}{
		{"deny.vn", "198.51.100.7", 403}, {"deny.vn", "203.0.113.9", 200}, {"deny.vn", "192.0.2.1", 200},
		{"allow.vn", "203.0.113.9", 200}, {"allow.vn", "198.51.100.7", 403}, {"allow.vn", "192.0.2.1", 403},
	}
	for _, c := range cases {
		if code, _ := h.get(t, c.host, "/", from(c.ip)); code != c.want {
			t.Errorf("%s from %s: %d, want %d", c.host, c.ip, code, c.want)
		}
	}
	ev := h.ev.Latest(1, 0)[0]
	if ev.Kind != "geo" {
		t.Fatalf("event = %+v", ev)
	}
	if ev2 := h.ev.Latest(10, 1); len(ev2) != 1 || ev2[0].Country != "RU" {
		t.Fatalf("deny event = %+v", ev2)
	}
}

func TestCountryCodeValidation(t *testing.T) {
	s := model.Site{ServerNames: []string{"x.vn"}, Upstreams: []string{"http://1.1.1.1"}, CountryDeny: []string{"Vietnam"}}
	if err := s.Normalize(); err == nil {
		t.Fatal("accepted invalid country code")
	}
}
