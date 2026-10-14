package threatintel

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"
)

// GoodBot is a crawler that can be verified by reverse DNS: the PTR name of
// its address ends in one of Domains, and that name resolves back to the
// address (forward-confirmed reverse DNS, as the search engines document).
type GoodBot struct {
	Name string
	// UA holds lower-case substrings of the User-Agent that claim the bot.
	UA []string
	// Domains are the accepted PTR suffixes, without leading dot.
	Domains []string
}

// DefaultGoodBots are the crawlers whose operators publish rDNS
// verification. Google's user-triggered fetchers (googleusercontent.com)
// are left out on purpose: any cloud customer gets such a PTR name.
var DefaultGoodBots = []GoodBot{
	{Name: "Googlebot", UA: []string{"googlebot", "adsbot-google", "mediapartners-google", "google-inspectiontool", "googleother", "storebot-google", "apis-google"},
		Domains: []string{"googlebot.com", "google.com"}},
	{Name: "Bingbot", UA: []string{"bingbot", "msnbot", "bingpreview", "adidxbot"}, Domains: []string{"search.msn.com"}},
	{Name: "Applebot", UA: []string{"applebot"}, Domains: []string{"applebot.apple.com"}},
	{Name: "YandexBot", UA: []string{"yandexbot", "yandeximages", "yandexmobilebot", "yandexvideo"}, Domains: []string{"yandex.ru", "yandex.net", "yandex.com"}},
	{Name: "Baiduspider", UA: []string{"baiduspider"}, Domains: []string{"baidu.com", "baidu.jp"}},
	{Name: "Yahoo Slurp", UA: []string{"yahoo! slurp"}, Domains: []string{"crawl.yahoo.net"}},
	{Name: "coccocbot", UA: []string{"coccocbot"}, Domains: []string{"coccoc.com"}},
}

// Resolver is the subset of *net.Resolver used for verification; tests
// inject a fake.
type Resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// BotVerifier verifies crawler claims and caches the verdicts.
type BotVerifier struct {
	Resolver Resolver
	Bots     []GoodBot
	// Timeout bounds one verification (PTR plus forward lookups).
	Timeout time.Duration
	// TTL of a verdict; ErrorTTL of a verdict caused by a DNS failure other
	// than "not found", so a resolver hiccup is retried soon.
	TTL, ErrorTTL time.Duration
	// MaxEntries bounds the cache; MaxInflight the concurrent verifications
	// (requests beyond it are treated as unverified, not queued).
	MaxEntries, MaxInflight int

	once     sync.Once
	mu       sync.Mutex
	cache    map[string]verdict
	inflight map[string]*call
	sem      chan struct{}
	now      func() time.Time
}

type verdict struct {
	ok  bool
	exp time.Time
}

type call struct {
	done chan struct{}
	ok   bool
}

// NewBotVerifier uses r, or the system resolver when r is nil.
func NewBotVerifier(r Resolver) *BotVerifier {
	if r == nil {
		r = net.DefaultResolver
	}
	return &BotVerifier{Resolver: r}
}

func (v *BotVerifier) init() {
	v.once.Do(func() {
		if v.Bots == nil {
			v.Bots = DefaultGoodBots
		}
		if v.Timeout <= 0 {
			v.Timeout = 2 * time.Second
		}
		if v.TTL <= 0 {
			v.TTL = 6 * time.Hour
		}
		if v.ErrorTTL <= 0 {
			v.ErrorTTL = time.Minute
		}
		if v.MaxEntries <= 0 {
			v.MaxEntries = 20000
		}
		if v.MaxInflight <= 0 {
			v.MaxInflight = 64
		}
		if v.now == nil {
			v.now = time.Now
		}
		v.cache = map[string]verdict{}
		v.inflight = map[string]*call{}
		v.sem = make(chan struct{}, v.MaxInflight)
	})
}

// Claimed returns the bot a User-Agent claims to be.
func (v *BotVerifier) Claimed(ua string) (GoodBot, bool) {
	v.init()
	l := strings.ToLower(ua)
	for _, b := range v.Bots {
		for _, s := range b.UA {
			if strings.Contains(l, s) {
				return b, true
			}
		}
	}
	return GoodBot{}, false
}

// Verify reports whether a request from ip with User-Agent ua comes from
// the crawler it claims to be, and its name. Requests that claim no known
// crawler return false without any DNS lookup.
func (v *BotVerifier) Verify(ctx context.Context, ip net.IP, ua string) (string, bool) {
	bot, claimed := v.Claimed(ua)
	if !claimed || ip == nil {
		return "", false
	}
	key := bot.Name + "|" + ip.String()
	v.mu.Lock()
	if c, ok := v.cache[key]; ok && v.now().Before(c.exp) {
		v.mu.Unlock()
		return bot.Name, c.ok
	}
	if c, ok := v.inflight[key]; ok {
		v.mu.Unlock()
		select {
		case <-c.done:
			return bot.Name, c.ok
		case <-ctx.Done():
			return bot.Name, false
		}
	}
	select {
	case v.sem <- struct{}{}:
	default:
		v.mu.Unlock()
		return bot.Name, false // too many lookups in flight: no free pass
	}
	c := &call{done: make(chan struct{})}
	v.inflight[key] = c
	v.mu.Unlock()

	// Detached from the request so a client hanging up does not poison the
	// cache with a failed verdict; bounded by Timeout instead.
	lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), v.Timeout)
	ok, transient := v.lookup(lctx, bot, ip)
	cancel()
	<-v.sem

	ttl := v.TTL
	if transient {
		ttl = v.ErrorTTL
	}
	v.mu.Lock()
	v.store(key, verdict{ok: ok, exp: v.now().Add(ttl)})
	delete(v.inflight, key)
	c.ok = ok
	close(c.done)
	v.mu.Unlock()
	return bot.Name, ok
}

// store must be called with v.mu held.
func (v *BotVerifier) store(key string, d verdict) {
	if len(v.cache) >= v.MaxEntries {
		now := v.now()
		for k, e := range v.cache {
			if !now.Before(e.exp) {
				delete(v.cache, k)
			}
		}
		// Still full: drop arbitrary entries (map order is random).
		for k := range v.cache {
			if len(v.cache) < v.MaxEntries*9/10 {
				break
			}
			delete(v.cache, k)
		}
	}
	v.cache[key] = d
}

// lookup does forward-confirmed reverse DNS. transient reports a DNS
// failure that should not be cached for long.
func (v *BotVerifier) lookup(ctx context.Context, bot GoodBot, ip net.IP) (ok, transient bool) {
	names, err := v.Resolver.LookupAddr(ctx, ip.String())
	if err != nil {
		return false, !notFound(err)
	}
	for _, n := range names {
		n = strings.ToLower(strings.TrimSuffix(n, "."))
		if !domainMatch(n, bot.Domains) {
			continue
		}
		addrs, err := v.Resolver.LookupIPAddr(ctx, n)
		if err != nil {
			transient = transient || !notFound(err)
			continue
		}
		for _, a := range addrs {
			if a.IP.Equal(ip) {
				return true, false
			}
		}
	}
	return false, transient
}

func domainMatch(name string, domains []string) bool {
	for _, d := range domains {
		if strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

func notFound(err error) bool {
	var de *net.DNSError
	return errors.As(err, &de) && de.IsNotFound
}
