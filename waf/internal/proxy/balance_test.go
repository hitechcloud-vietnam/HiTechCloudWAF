package proxy

import (
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/model"
)

// lbSite builds a site whose upstreams are never contacted: the tests call
// the balancer directly.
func lbSite(t *testing.T, site model.Site) (*harness, *siteRT) {
	t.Helper()
	site.Mode = model.ModeOff
	if len(site.ServerNames) == 0 {
		site.ServerNames = []string{"lb.vn"}
	}
	h := newHarness(t, nil, site)
	return h, h.eng.rt.Load().ports[h.port].exact[site.ServerNames[0]]
}

func pickN(s *siteRT, n int, ip func(i int) net.IP) []int {
	counts := make([]int, len(s.upstreams))
	req := httptest.NewRequest("GET", "/", nil)
	for i := 0; i < n; i++ {
		idx, _ := s.choose(req, ip(i))
		counts[idx]++
	}
	return counts
}

func seqIP(i int) net.IP { return net.IPv4(10, byte(i>>16), byte(i>>8), byte(i)) }

func TestBalanceDistribution(t *testing.T) {
	ups := func(spec ...string) []string {
		out := make([]string, len(spec))
		for i, s := range spec {
			out[i] = fmt.Sprintf("http://10.9.0.%d:80 %s", i+1, s)
		}
		return out
	}
	cases := []struct {
		name      string
		lb        string
		upstreams []string
		unhealthy []int
		n         int
		want      []float64 // expected share of each upstream
		tol       float64   // absolute tolerance on the share
	}{
		{"round_robin even", "", ups("", "", ""), nil, 300, []float64{1.0 / 3, 1.0 / 3, 1.0 / 3}, 0},
		{"round_robin ignores weights", model.LBRoundRobin, ups("weight=5", ""), nil, 100, []float64{.5, .5}, 0},
		{"weights imply weighted", "", ups("weight=3", "weight=1"), nil, 400, []float64{.75, .25}, 0},
		{"weighted 1:2:3", model.LBWeighted, ups("weight=1", "weight=2", "weight=3"), nil, 600, []float64{1.0 / 6, 2.0 / 6, 3.0 / 6}, 0},
		{"weighted skips unhealthy", model.LBWeighted, ups("weight=1", "weight=5", "weight=3"), []int{1}, 400, []float64{.25, 0, .75}, 0},
		{"random weighted 1:3", model.LBRandom, ups("weight=1", "weight=3"), nil, 40000, []float64{.25, .75}, .02},
		{"random skips unhealthy", model.LBRandom, ups("", "", ""), []int{0}, 6000, []float64{0, .5, .5}, .04},
		{"ip_hash spreads clients", model.LBIPHash, ups("", "", ""), nil, 30000, []float64{1.0 / 3, 1.0 / 3, 1.0 / 3}, .06},
		{"ip_hash follows weights", model.LBIPHash, ups("weight=1", "weight=3"), nil, 30000, []float64{.25, .75}, .06},
		{"least_conn idle rotates", model.LBLeastConn, ups("", ""), nil, 100, []float64{.5, .5}, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, s := lbSite(t, model.Site{LB: c.lb, Upstreams: c.upstreams})
			for _, i := range c.unhealthy {
				s.upstreams[i].unhealthy.Store(true)
			}
			counts := pickN(s, c.n, seqIP)
			for i, want := range c.want {
				got := float64(counts[i]) / float64(c.n)
				if math.Abs(got-want) > c.tol+1e-9 {
					t.Fatalf("upstream %d share %.4f, want %.4f±%.2f (counts %v)", i, got, want, c.tol, counts)
				}
			}
		})
	}
}

func TestSmoothWeightedInterleaves(t *testing.T) {
	_, s := lbSite(t, model.Site{LB: model.LBWeighted, Upstreams: []string{"http://10.9.0.1 weight=5", "http://10.9.0.2", "http://10.9.0.3"}})
	var seq []int
	req := httptest.NewRequest("GET", "/", nil)
	for i := 0; i < 7; i++ {
		idx, _ := s.choose(req, nil)
		seq = append(seq, idx)
	}
	// nginx's smooth WRR for {5,1,1}: a a b a c a a
	if fmt.Sprint(seq) != "[0 0 1 0 2 0 0]" {
		t.Fatalf("sequence %v", seq)
	}
}

func TestLeastConnPicksLeastLoaded(t *testing.T) {
	cases := []struct {
		name     string
		weights  []string
		inflight []int64
		down     []int
		want     int
	}{
		{"fewest in flight", []string{"", "", ""}, []int64{5, 0, 2}, nil, 1},
		{"per weight", []string{"weight=4", "", ""}, []int64{4, 2, 3}, nil, 0},
		{"skips unhealthy", []string{"", "", ""}, []int64{5, 0, 2}, []int{1}, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var ups []string
			for i, w := range c.weights {
				ups = append(ups, fmt.Sprintf("http://10.9.0.%d %s", i+1, w))
			}
			_, s := lbSite(t, model.Site{LB: model.LBLeastConn, Upstreams: ups})
			for i, n := range c.inflight {
				s.lb.inflight[i].Store(n)
			}
			for _, i := range c.down {
				s.upstreams[i].unhealthy.Store(true)
			}
			for k := 0; k < 10; k++ {
				if got, _ := s.choose(httptest.NewRequest("GET", "/", nil), nil); got != c.want {
					t.Fatalf("picked %d, want %d", got, c.want)
				}
			}
		})
	}
}

// A slow upstream holding a request must not receive more while another is idle.
func TestLeastConnLive(t *testing.T) {
	release := make(chan struct{})
	slowHit := make(chan struct{}, 100)
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slowHit <- struct{}{}
		<-release
		_, _ = io.WriteString(w, "slow")
	}))
	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "fast") }))
	defer fast.Close()
	defer slow.Close()
	defer close(release)
	h, s := lbSite(t, model.Site{LB: model.LBLeastConn, Upstreams: []string{slow.URL, fast.URL}})

	var wg sync.WaitGroup
	slowCount := 0
	for i := 0; i < 20; i++ {
		done := make(chan struct{})
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer close(done)
			req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/", h.port), nil)
			req.Host = "lb.vn"
			if resp, err := http.DefaultClient.Do(req); err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}()
		select {
		case <-done:
		case <-slowHit:
			slowCount++
		case <-time.After(5 * time.Second):
			t.Fatal("request neither finished nor reached the slow upstream")
		}
	}
	if slowCount != 1 {
		t.Fatalf("slow upstream got %d requests while busy, want 1", slowCount)
	}
	if n := s.lb.inflight[0].Load(); n != 1 {
		t.Fatalf("slow upstream in flight = %d", n)
	}
	release <- struct{}{}
	wg.Wait()
	// The handler returns just after the client has its response.
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		n := s.lb.inflight[0].Load() + s.lb.inflight[1].Load()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("in-flight counters leak: %d", n)
		}
	}
}

func TestIPHashStability(t *testing.T) {
	three := []string{"http://10.9.0.1", "http://10.9.0.2", "http://10.9.0.3"}
	const clients = 3000
	assign := func(s *siteRT) []string {
		out := make([]string, clients)
		req := httptest.NewRequest("GET", "/", nil)
		for i := range out {
			idx, _ := s.choose(req, seqIP(i))
			out[i] = s.upstreams[idx].url.String()
		}
		return out
	}
	cases := []struct {
		name   string
		change func(t *testing.T, h *harness, s *siteRT) *siteRT
		gone   string
	}{
		{"upstream unhealthy", func(t *testing.T, h *harness, s *siteRT) *siteRT {
			s.upstreams[1].unhealthy.Store(true)
			return s
		}, three[1]},
		{"upstream erroring", func(t *testing.T, h *harness, s *siteRT) *siteRT {
			s.upstreams[1].downUntil.Store(time.Now().Add(time.Minute).UnixNano())
			return s
		}, three[1]},
		{"upstream removed from config", func(t *testing.T, h *harness, s *siteRT) *siteRT {
			site := s.site
			site.Upstreams = []string{three[0], three[2]}
			if err := h.eng.Apply([]model.Site{site}, nil); err != nil {
				t.Fatal(err)
			}
			return h.eng.rt.Load().ports[h.port].exact["lb.vn"]
		}, three[1]},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, s := lbSite(t, model.Site{LB: model.LBIPHash, Upstreams: append([]string(nil), three...)})
			before := assign(s)
			if again := assign(s); fmt.Sprint(again) != fmt.Sprint(before) {
				t.Fatal("ip_hash is not deterministic")
			}
			after := assign(c.change(t, h, s))
			moved := 0
			for i := range before {
				if after[i] == c.gone {
					t.Fatalf("client %d still sent to %s", i, c.gone)
				}
				if before[i] != c.gone && after[i] != before[i] {
					t.Fatalf("client %d moved from healthy %s to %s", i, before[i], after[i])
				}
				if before[i] != after[i] {
					moved++
				}
			}
			// Only the removed upstream's share (about a third) moves.
			if moved < clients/5 || moved > clients/2 {
				t.Fatalf("%d of %d clients moved", moved, clients)
			}
		})
	}
}

func TestIPHashIPv6Prefix(t *testing.T) {
	_, s := lbSite(t, model.Site{LB: model.LBIPHash, Upstreams: []string{"http://10.9.0.1", "http://10.9.0.2", "http://10.9.0.3", "http://10.9.0.4"}})
	req := httptest.NewRequest("GET", "/", nil)
	a, _ := s.choose(req, net.ParseIP("2001:db8:1:2::1"))
	for _, ip := range []string{"2001:db8:1:2::abcd", "2001:db8:1:2:ffff::9"} {
		if b, _ := s.choose(req, net.ParseIP(ip)); b != a {
			t.Fatalf("%s in the same /64 went to %d, want %d", ip, b, a)
		}
	}
}

func TestStickySessions(t *testing.T) {
	mk := func(name string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, name) }))
	}
	a, b := mk("A"), mk("B")
	defer a.Close()
	defer b.Close()

	do := func(t *testing.T, h *harness, cookie *http.Cookie) (string, *http.Cookie) {
		t.Helper()
		req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/", h.port), nil)
		req.Host = "lb.vn"
		if cookie != nil {
			req.AddCookie(cookie)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		var set *http.Cookie
		for _, c := range resp.Cookies() {
			set = c
		}
		return string(body), set
	}

	cases := []struct {
		name   string
		site   model.Site
		cookie string
		maxAge int
	}{
		{"round_robin default cookie", model.Site{Sticky: true}, model.DefaultStickyCookie, 0},
		{"least_conn custom cookie", model.Site{Sticky: true, LB: model.LBLeastConn, StickyCookie: "srv_id", StickyTTLSec: 600}, "srv_id", 600},
		{"weighted", model.Site{Sticky: true, LB: model.LBWeighted}, model.DefaultStickyCookie, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.site.Upstreams = []string{a.URL, b.URL}
			h, s := lbSite(t, c.site)
			first, ck := do(t, h, nil)
			if ck == nil || ck.Name != c.cookie || !ck.HttpOnly || ck.SameSite != http.SameSiteLaxMode || ck.MaxAge != c.maxAge || ck.Path != "/" {
				t.Fatalf("sticky cookie = %+v", ck)
			}
			if strings.Contains(ck.Value, "127.0.0.1") || len(ck.Value) != 22 {
				t.Fatalf("cookie value must be an opaque id: %q", ck.Value)
			}
			for i := 0; i < 10; i++ {
				body, again := do(t, h, ck)
				if body != first {
					t.Fatalf("request %d went to %s, pinned to %s", i, body, first)
				}
				if again != nil {
					t.Fatalf("cookie reissued for a valid pin: %+v", again)
				}
			}
			// Forged or foreign value: rebalanced and re-pinned.
			if _, fresh := do(t, h, &http.Cookie{Name: c.cookie, Value: "forged-value-123456789"}); fresh == nil {
				t.Fatal("forged cookie not replaced")
			}
			// The pinned upstream fails its health check: fall back and re-pin.
			pinned := 0
			if first == "B" {
				pinned = 1
			}
			s.upstreams[pinned].unhealthy.Store(true)
			body, moved := do(t, h, ck)
			if body == first || moved == nil || moved.Value == ck.Value {
				t.Fatalf("unhealthy pin: served by %s, new cookie %+v", body, moved)
			}
			// The upstream comes back: the new pin holds.
			s.upstreams[pinned].unhealthy.Store(false)
			for i := 0; i < 5; i++ {
				if b, _ := do(t, h, moved); b != body {
					t.Fatalf("new pin not kept: %s, want %s", b, body)
				}
			}
		})
	}
}

func TestStickyIDsStableAcrossReload(t *testing.T) {
	h, s := lbSite(t, model.Site{Sticky: true, Upstreams: []string{"http://10.9.0.1", "http://10.9.0.2"}})
	id := s.lb.ids[1]
	site := s.site
	site.Upstreams = []string{"http://10.9.0.2", "http://10.9.0.3 weight=2"}
	if err := h.eng.Apply([]model.Site{site}, nil); err != nil {
		t.Fatal(err)
	}
	s2 := h.eng.rt.Load().ports[h.port].exact["lb.vn"]
	if i, ok := s2.lb.byID[id]; !ok || s2.upstreams[i].url.String() != "http://10.9.0.2" {
		t.Fatal("sticky id of a kept upstream changed on reload")
	}
}

func TestHeaderRewriting(t *testing.T) {
	h := newHarness(t, nil, model.Site{ServerNames: []string{"hdr.vn"}, Mode: model.ModeOff, HideServerHeaders: true,
		RequestHeaders: []model.HeaderRule{
			{Action: "set", Name: "x-env", Value: "prod"},
			{Action: "add", Name: "X-Tag", Value: "one"},
			{Action: "add", Name: "X-Tag", Value: "two"},
			{Action: "remove", Name: "X-Debug"},
		},
		ResponseHeaders: []model.HeaderRule{
			{Action: "set", Name: "X-Frame-Options", Value: "SAMEORIGIN"},
			{Action: "add", Name: "Cache-Control", Value: "no-store"},
			{Action: "remove", Name: "X-Internal"},
		}})
	seen := make(chan http.Header, 1)
	h.origin.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
		w.Header().Set("Server", "Apache/2.4.1 (Ubuntu)")
		w.Header().Set("X-Powered-By", "PHP/8.1")
		w.Header().Set("X-AspNet-Version", "4.0")
		w.Header().Set("X-Internal", "secret")
		w.Header().Set("X-Frame-Options", "ALLOW")
		w.Header().Set("Cache-Control", "private")
		_, _ = io.WriteString(w, "ok")
	})
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/", h.port), nil)
	req.Host = "hdr.vn"
	req.Header.Set("X-Env", "dev")
	req.Header.Set("X-Debug", "1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	up := <-seen

	checks := []struct {
		name string
		got  []string
		want string
	}{
		{"request set replaces", up.Values("X-Env"), "[prod]"},
		{"request add appends", up.Values("X-Tag"), "[one two]"},
		{"request remove", up.Values("X-Debug"), "[]"},
		{"forwarding headers intact", up.Values("X-Forwarded-Host"), "[hdr.vn]"},
		{"response Server hidden", resp.Header.Values("Server"), "[]"},
		{"response X-Powered-By hidden", resp.Header.Values("X-Powered-By"), "[]"},
		{"response X-AspNet-Version hidden", resp.Header.Values("X-AspNet-Version"), "[]"},
		{"response set replaces", resp.Header.Values("X-Frame-Options"), "[SAMEORIGIN]"},
		{"response add appends", resp.Header.Values("Cache-Control"), "[private no-store]"},
		{"response remove", resp.Header.Values("X-Internal"), "[]"},
	}
	for _, c := range checks {
		if fmt.Sprint(c.got) != c.want {
			t.Errorf("%s: got %v, want %s", c.name, c.got, c.want)
		}
	}
}

func TestServerHeadersKeptByDefault(t *testing.T) {
	h := newHarness(t, nil, model.Site{ServerNames: []string{"keep.vn"}, Mode: model.ModeOff})
	h.origin.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		_, _ = io.WriteString(w, "ok")
	})
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/", h.port), nil)
	req.Host = "keep.vn"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Header.Get("Server") != "nginx" {
		t.Fatalf("Server header = %q", resp.Header.Get("Server"))
	}
}
