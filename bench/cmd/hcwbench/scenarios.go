package main

import (
	"fmt"
	"net/http"
	"strings"
)

// scenario is one measured configuration.
type scenario struct {
	ID     string
	Name   string
	Direct bool // bypass the WAF entirely (baseline)
	// Sites returns the site definitions created through the API.
	Sites func(c *config) []map[string]any
	// Next builds request n; hosts are the server names of the sites.
	Next   func(n uint64, hosts []string) request
	Expect int
	// CheckDynamic verifies that responses are rewritten by dynamic protection.
	CheckDynamic bool
}

// Browser-like headers: CRS inspects every header, so a realistic set matters.
var browserHeader = http.Header{
	"User-Agent":      {"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"},
	"Accept":          {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"},
	"Accept-Language": {"vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7"},
	"Accept-Encoding": {"gzip, deflate, br"},
	"Cookie":          {"session_id=7f3c2a9e1b4d4e0f9a8b6c5d4e3f2a1b; theme=dark; lang=vi"},
	"Referer":         {"http://bench.local/"},
}

// minimalHeader replaces browserHeader with -minimal-headers.
var minimalHeader = http.Header{
	"User-Agent": {"hcwbench/1.0"},
	"Accept":     {"*/*"},
}

const (
	benignQuery = pathSmall + "?category=sach-lap-trinh&page=2&sort=price_asc&q=golang+concurrency&utm_source=newsletter"
	// Classic UNION-based SQL injection; CRS 942xxx rules score it far above
	// the default inbound threshold of 5.
	attackQuery = pathSmall + "?id=1%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--%20-"
)

func jsonHeader() http.Header {
	h := http.Header{}
	for k, v := range browserHeader {
		h[k] = v
	}
	h["Content-Type"] = []string{"application/json"}
	h["Accept"] = []string{"application/json"}
	return h
}

// orderJSON returns a benign JSON document of at least size bytes.
func orderJSON(size int) []byte {
	var b strings.Builder
	b.WriteString(`{"order_id":"ORD-2026-000123","customer":{"name":"Nguyen Van An","email":"an.nguyen@example.com","phone":"0901234567","address":"12 Nguyen Hue, Quan 1, TP HCM"},"items":[`)
	for i := 0; b.Len() < size-80; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"sku":"SKU-%04d","name":"San pham mau so %d","qty":%d,"price":%d}`, 1000+i, i, 1+i%3, 150000+i*1000)
	}
	b.WriteString(`],"note":"Giao hang trong gio hanh chinh","coupon":"TET2026"}`)
	return []byte(b.String())
}

func oneSite(name string, extra map[string]any) func(c *config) []map[string]any {
	return func(c *config) []map[string]any {
		s := map[string]any{
			"server_names": []string{name},
			"ports":        []string{fmt.Sprint(c.sitePort)},
			"upstreams":    []string{"http://" + c.upstreamAddr},
		}
		for k, v := range extra {
			s[k] = v
		}
		return []map[string]any{s}
	}
}

func getReq(path string) func(n uint64, hosts []string) request {
	return func(n uint64, hosts []string) request {
		return request{method: http.MethodGet, path: path, host: hosts[n%uint64(len(hosts))], header: browserHeader}
	}
}

func scenarios() []scenario {
	post := orderJSON(2048)
	jh := jsonHeader()
	return []scenario{
		{ID: "1", Name: "Upstream trực tiếp (không WAF)", Direct: true, Next: getReq(benignQuery), Expect: 200},
		{ID: "2", Name: "mode off (proxy thuần)", Sites: oneSite("bench.local", map[string]any{"mode": "off"}), Next: getReq(benignQuery), Expect: 200},
		{ID: "3", Name: "block PL1, GET có query", Sites: oneSite("bench.local", map[string]any{"mode": "block", "paranoia": 1}), Next: getReq(benignQuery), Expect: 200},
		{ID: "4", Name: "block PL1, POST JSON 2 KB", Sites: oneSite("bench.local", map[string]any{"mode": "block", "paranoia": 1}),
			Next: func(n uint64, hosts []string) request {
				return request{method: http.MethodPost, path: "/api/orders", host: hosts[0], header: jh, body: post}
			}, Expect: 200},
		{ID: "5", Name: "block PL2, GET có query", Sites: oneSite("bench.local", map[string]any{"mode": "block", "paranoia": 2}), Next: getReq(benignQuery), Expect: 200},
		{ID: "6", Name: "block PL1, tấn công SQLi (403)", Sites: oneSite("bench.local", map[string]any{"mode": "block", "paranoia": 1}), Next: getReq(attackQuery), Expect: 403},
		{ID: "7", Name: "block PL1 + dynamic html, trang 50 KB", Sites: oneSite("bench.local", map[string]any{"mode": "block", "paranoia": 1, "dynamic_protection": map[string]any{"html": true}}),
			Next: getReq(pathLarge), Expect: 200, CheckDynamic: true},
		{ID: "7a", Name: "block PL1, trang 50 KB (đối chứng của 7)", Sites: oneSite("bench.local", map[string]any{"mode": "block", "paranoia": 1}), Next: getReq(pathLarge), Expect: 200},
		{ID: "8", Name: "block PL1, N site (định tuyến)", Sites: manySites, Next: getReq(benignQuery), Expect: 200},
	}
}

// manySites defines c.manySites sites on the same port; traffic is spread
// round-robin over all their server names.
func manySites(c *config) []map[string]any {
	out := make([]map[string]any, c.manySites)
	for i := range out {
		out[i] = map[string]any{
			"server_names": []string{fmt.Sprintf("site%03d.bench.local", i)},
			"ports":        []string{fmt.Sprint(c.sitePort)},
			"upstreams":    []string{"http://" + c.upstreamAddr},
			"mode":         "block",
			"paranoia":     1,
		}
	}
	return out
}
