package threatintel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeResolver answers from maps and counts lookups.
type fakeResolver struct {
	ptr     map[string][]string
	fwd     map[string][]string
	fail    error
	delay   time.Duration
	lookups atomic.Int32
}

func (f *fakeResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	f.lookups.Add(1)
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if f.fail != nil {
		return nil, f.fail
	}
	if n, ok := f.ptr[addr]; ok {
		return n, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
}

func (f *fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	f.lookups.Add(1)
	ips, ok := f.fwd[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	var out []net.IPAddr
	for _, s := range ips {
		out = append(out, net.IPAddr{IP: net.ParseIP(s)})
	}
	return out, nil
}

const (
	googleUA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	bingUA   = "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
)

func newFake() *fakeResolver {
	return &fakeResolver{
		ptr: map[string][]string{
			"66.249.66.1":      {"crawl-66-249-66-1.googlebot.com."},
			"2001:4860:4801::": {"crawl-2001-4860-4801.googlebot.com."},
			"157.55.39.1":      {"msnbot-157-55-39-1.search.msn.com."},
			"203.0.113.9":      {"crawl-203-0-113-9.googlebot.com."}, // spoofed PTR
			"198.51.100.4":     {"host.evilgooglebot.com."},          // suffix without dot boundary
			"192.0.2.1":        {"something.googleusercontent.com."}, // cloud customer
		},
		fwd: map[string][]string{
			"crawl-66-249-66-1.googlebot.com":    {"66.249.66.1"},
			"crawl-2001-4860-4801.googlebot.com": {"2001:4860:4801::"},
			"msnbot-157-55-39-1.search.msn.com":  {"157.55.39.1"},
			"crawl-203-0-113-9.googlebot.com":    {"66.249.66.9"},
			"host.evilgooglebot.com":             {"198.51.100.4"},
			"something.googleusercontent.com":    {"192.0.2.1"},
		},
	}
}

func TestVerifyGoodAndFakeBots(t *testing.T) {
	r := newFake()
	v := NewBotVerifier(r)
	ctx := context.Background()
	cases := []struct {
		ip, ua string
		want   bool
	}{
		{"66.249.66.1", googleUA, true},
		{"2001:4860:4801::", googleUA, true},
		{"157.55.39.1", bingUA, true},
		{"157.55.39.1", googleUA, false},  // Bing address claiming Google
		{"203.0.113.9", googleUA, false},  // PTR does not forward-confirm
		{"198.51.100.4", googleUA, false}, // wrong domain
		{"192.0.2.1", googleUA, false},    // googleusercontent is not a crawler
		{"8.8.4.4", googleUA, false},      // no PTR
	}
	for _, c := range cases {
		if _, got := v.Verify(ctx, net.ParseIP(c.ip), c.ua); got != c.want {
			t.Errorf("%s %q: got %v", c.ip, c.ua, got)
		}
	}
	// Not claiming a known crawler: no DNS traffic at all.
	before := r.lookups.Load()
	if name, ok := v.Verify(ctx, net.ParseIP("66.249.66.1"), "Mozilla/5.0 Firefox/130.0"); ok || name != "" {
		t.Fatal("browser treated as crawler")
	}
	if r.lookups.Load() != before {
		t.Fatal("lookups for a non-crawler UA")
	}
	// Verdicts are cached.
	for range 10 {
		v.Verify(ctx, net.ParseIP("66.249.66.1"), googleUA)
		v.Verify(ctx, net.ParseIP("203.0.113.9"), googleUA)
	}
	if r.lookups.Load() != before {
		t.Fatalf("cache not used: %d lookups", r.lookups.Load()-before)
	}
}

func TestVerifyCacheExpiryAndBound(t *testing.T) {
	r := newFake()
	v := &BotVerifier{Resolver: r, TTL: time.Hour, ErrorTTL: time.Minute, MaxEntries: 50}
	v.init()
	now := time.Now()
	v.now = func() time.Time { return now }
	ctx := context.Background()
	v.Verify(ctx, net.ParseIP("66.249.66.1"), googleUA)
	n := r.lookups.Load()
	now = now.Add(2 * time.Hour)
	v.Verify(ctx, net.ParseIP("66.249.66.1"), googleUA)
	if r.lookups.Load() == n {
		t.Fatal("expired verdict reused")
	}
	for i := range 500 {
		v.Verify(ctx, net.ParseIP(fmt.Sprintf("10.0.%d.%d", i/250, i%250)), googleUA)
	}
	v.mu.Lock()
	size := len(v.cache)
	v.mu.Unlock()
	if size > 50 {
		t.Fatalf("cache grew to %d", size)
	}
}

func TestVerifyTransientErrorsAndTimeout(t *testing.T) {
	r := newFake()
	r.fail = errors.New("server misbehaving")
	v := &BotVerifier{Resolver: r, ErrorTTL: time.Minute}
	v.init()
	now := time.Now()
	v.now = func() time.Time { return now }
	ctx := context.Background()
	if _, ok := v.Verify(ctx, net.ParseIP("66.249.66.1"), googleUA); ok {
		t.Fatal("verified despite DNS failure")
	}
	r.fail = nil
	now = now.Add(2 * time.Minute) // only the short error TTL has passed
	if _, ok := v.Verify(ctx, net.ParseIP("66.249.66.1"), googleUA); !ok {
		t.Fatal("transient failure cached too long")
	}

	slow := newFake()
	slow.delay = 5 * time.Second
	v = &BotVerifier{Resolver: slow, Timeout: 200 * time.Millisecond}
	start := time.Now()
	if _, ok := v.Verify(ctx, net.ParseIP("66.249.66.1"), googleUA); ok {
		t.Fatal("verified after timeout")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("timeout not applied")
	}
}

func TestVerifyConcurrentSingleFlight(t *testing.T) {
	r := newFake()
	r.delay = 100 * time.Millisecond
	v := NewBotVerifier(r)
	var wg sync.WaitGroup
	var okCount atomic.Int32
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := v.Verify(context.Background(), net.ParseIP("66.249.66.1"), googleUA); ok {
				okCount.Add(1)
			}
		}()
	}
	wg.Wait()
	if okCount.Load() != 50 {
		t.Fatalf("verified %d/50", okCount.Load())
	}
	if n := r.lookups.Load(); n != 2 {
		t.Fatalf("expected one PTR + one forward lookup, got %d", n)
	}
}
