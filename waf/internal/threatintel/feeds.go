package threatintel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"sync/atomic"
	"time"
)

// FeedConfig is one IP list in threat_intel.feeds of waf.yaml.
type FeedConfig struct {
	// Name identifies the feed in events and the console (letters, digits,
	// "-", "_" and ".").
	Name string `yaml:"name"`
	// URL is http(s)://… or file:///path for a list kept up to date by
	// other means.
	URL string `yaml:"url"`
	// Refresh is the download interval (default 1h, minimum 1m).
	Refresh time.Duration `yaml:"refresh"`
}

// Config is the threat_intel section of waf.yaml.
type Config struct {
	Feeds []FeedConfig `yaml:"feeds"`
	// Timeout of one download (default 60s).
	Timeout time.Duration `yaml:"timeout"`
	// MaxSizeMB caps the size of one list (default 32).
	MaxSizeMB int `yaml:"max_size_mb"`
}

var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// Normalize fills defaults and validates c.
func (c *Config) Normalize() error {
	if c.Timeout == 0 {
		c.Timeout = time.Minute
	}
	if c.Timeout < time.Second || c.Timeout > 10*time.Minute {
		return errors.New("threat_intel.timeout must be 1s..10m")
	}
	if c.MaxSizeMB == 0 {
		c.MaxSizeMB = 32
	}
	if c.MaxSizeMB < 1 || c.MaxSizeMB > 512 {
		return errors.New("threat_intel.max_size_mb must be 1..512")
	}
	seen := map[string]bool{}
	for i := range c.Feeds {
		f := &c.Feeds[i]
		if !nameRe.MatchString(f.Name) {
			return fmt.Errorf("threat_intel feed name %q: use letters, digits, '-', '_' or '.'", f.Name)
		}
		if seen[f.Name] {
			return fmt.Errorf("threat_intel feed %q is defined twice", f.Name)
		}
		seen[f.Name] = true
		u, err := url.Parse(f.URL)
		if err != nil || !((u.Scheme == "http" || u.Scheme == "https") && u.Host != "" || u.Scheme == "file" && u.Path != "") {
			return fmt.Errorf("threat_intel feed %s: url must be http(s)://… or file:///path", f.Name)
		}
		if f.Refresh == 0 {
			f.Refresh = time.Hour
		}
		if f.Refresh < time.Minute {
			return fmt.Errorf("threat_intel feed %s: refresh must be at least 1m", f.Name)
		}
	}
	return nil
}

// Status describes one feed for the management API.
type Status struct {
	Name       string `json:"name"`
	URL        string `json:"url"`
	RefreshSec int    `json:"refresh_sec"`
	// Entries and Ranges of the list in use (0 when none loaded yet).
	Entries int `json:"entries"`
	Ranges  int `json:"ranges"`
	Invalid int `json:"invalid_lines"`
	// Source of the list in use: "download", "cache" (loaded from the data
	// directory at start-up) or "" when nothing is loaded.
	Source string `json:"source"`
	// UpdatedAt is when the list in use was downloaded; CheckedAt the last
	// attempt, successful or not (a 304 Not Modified counts as success).
	UpdatedAt *time.Time `json:"updated_at"`
	CheckedAt *time.Time `json:"checked_at"`
	NextAt    *time.Time `json:"next_at"`
	// LastError of the latest attempt ("" when it succeeded). The previous
	// list stays in use after a failure.
	LastError string `json:"last_error"`
}

type feed struct {
	cfg FeedConfig
	set atomic.Pointer[Set]

	mu     sync.Mutex
	status Status
	meta   cacheMeta
}

type cacheMeta struct {
	URL          string    `json:"url"`
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Manager downloads feeds in the background and answers lookups. It is
// safe for concurrent use.
type Manager struct {
	cfg    Config
	dir    string
	log    *slog.Logger
	client *http.Client
	feeds  []*feed
}

// New validates cfg and loads cached copies of the lists from dir (if any),
// so the node protects from the first request even when offline. dir may
// be empty to disable the cache. Call Run to start downloading.
func New(cfg Config, dir string, log *slog.Logger) (*Manager, error) {
	if err := cfg.Normalize(); err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	m := &Manager{cfg: cfg, dir: dir, log: log, client: &http.Client{Timeout: cfg.Timeout}}
	if dir != "" && len(cfg.Feeds) > 0 {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	for _, fc := range cfg.Feeds {
		f := &feed{cfg: fc, status: Status{Name: fc.Name, URL: fc.URL, RefreshSec: int(fc.Refresh / time.Second)}}
		m.loadCache(f)
		m.feeds = append(m.feeds, f)
	}
	return m, nil
}

func (m *Manager) cachePaths(f *feed) (list, meta string) {
	base := filepath.Join(m.dir, f.cfg.Name)
	return base + ".list", base + ".json"
}

func (m *Manager) loadCache(f *feed) {
	if m.dir == "" || isFile(f.cfg.URL) {
		return
	}
	lp, mp := m.cachePaths(f)
	mb, err := os.ReadFile(mp)
	if err != nil {
		return
	}
	var meta cacheMeta
	if json.Unmarshal(mb, &meta) != nil || meta.URL != f.cfg.URL {
		return // another list was configured under this name
	}
	lf, err := os.Open(lp)
	if err != nil {
		return
	}
	defer lf.Close()
	set, err := Parse(io.LimitReader(lf, m.maxBytes()))
	if err != nil {
		m.log.Warn("threat intel cache unreadable", "feed", f.cfg.Name, "err", err)
		return
	}
	f.set.Store(set)
	f.meta = meta
	up := meta.UpdatedAt
	f.status.Entries, f.status.Ranges, f.status.Invalid = set.Entries, set.Ranges(), set.Invalid
	f.status.Source, f.status.UpdatedAt = "cache", &up
	m.log.Info("threat intel feed loaded from cache", "feed", f.cfg.Name, "entries", set.Entries, "updated_at", up)
}

func (m *Manager) maxBytes() int64 { return int64(m.cfg.MaxSizeMB) << 20 }

func isFile(u string) bool { return len(u) >= 7 && u[:7] == "file://" }

// cgnat (RFC 6598) is not "private" for netip but is never a public client.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// Lookup returns the name of the first feed listing ip. Loopback, private,
// link-local and shared (CGNAT) addresses are never reported: lists such as
// FireHOL level1 contain these bogon ranges, and they would otherwise block
// internal clients and load balancers.
func (m *Manager) Lookup(ip net.IP) (string, bool) {
	if m == nil || len(m.feeds) == 0 {
		return "", false
	}
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return "", false
	}
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() || cgnat.Contains(a) {
		return "", false
	}
	for _, f := range m.feeds {
		if f.set.Load().Contains(a) {
			return f.cfg.Name, true
		}
	}
	return "", false
}

// Status returns the state of every feed, in configuration order.
func (m *Manager) Status() []Status {
	out := []Status{}
	if m == nil {
		return out
	}
	for _, f := range m.feeds {
		f.mu.Lock()
		out = append(out, f.status)
		f.mu.Unlock()
	}
	return out
}

// Run refreshes every feed on its interval until ctx is done.
func (m *Manager) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, f := range m.feeds {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.loop(ctx, f)
		}()
	}
	wg.Wait()
}

func (m *Manager) loop(ctx context.Context, f *feed) {
	// A fresh cached copy is used until its interval runs out.
	var wait time.Duration
	f.mu.Lock()
	if f.status.UpdatedAt != nil {
		wait = time.Until(f.status.UpdatedAt.Add(f.cfg.Refresh))
	}
	f.mu.Unlock()
	for {
		if wait > 0 {
			next := time.Now().Add(wait)
			f.mu.Lock()
			f.status.NextAt = &next
			f.mu.Unlock()
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
			}
		}
		if ctx.Err() != nil {
			return
		}
		err := m.Refresh(ctx, f.cfg.Name)
		wait = f.cfg.Refresh
		if err != nil {
			// Retry sooner, keeping the previous list in the meantime.
			wait = min(wait, 5*time.Minute)
		}
		// up to 10% jitter so nodes of a cluster do not all hit the source together
		wait += time.Duration(rand.Int64N(int64(wait/10) + 1))
	}
}

// RefreshAll downloads every feed once and returns the errors.
func (m *Manager) RefreshAll(ctx context.Context) error {
	var errs []error
	for _, f := range m.feeds {
		if err := m.Refresh(ctx, f.cfg.Name); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Refresh downloads one feed now. On failure the previous list stays in use.
func (m *Manager) Refresh(ctx context.Context, name string) error {
	var f *feed
	for _, x := range m.feeds {
		if x.cfg.Name == name {
			f = x
		}
	}
	if f == nil {
		return fmt.Errorf("threat intel feed %q not configured", name)
	}
	err := m.fetch(ctx, f)
	now := time.Now().UTC()
	f.mu.Lock()
	f.status.CheckedAt = &now
	f.status.LastError = ""
	if err != nil {
		f.status.LastError = err.Error()
	}
	f.mu.Unlock()
	if err != nil {
		m.log.Warn("threat intel feed update failed", "feed", name, "err", err)
		return fmt.Errorf("feed %s: %w", name, err)
	}
	return nil
}

func (m *Manager) fetch(ctx context.Context, f *feed) error {
	if isFile(f.cfg.URL) {
		u, _ := url.Parse(f.cfg.URL)
		fh, err := os.Open(u.Path)
		if err != nil {
			return err
		}
		defer fh.Close()
		body, err := readCapped(fh, m.maxBytes())
		if err != nil {
			return err
		}
		return m.install(f, body, cacheMeta{URL: f.cfg.URL, UpdatedAt: time.Now().UTC()}, false)
	}
	ctx, cancel := context.WithTimeout(ctx, m.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.cfg.URL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "hcw-waf threat-intel")
	f.mu.Lock()
	meta := f.meta
	f.mu.Unlock()
	if f.set.Load() != nil {
		// Only ask for "not modified" when there is a list to keep.
		if meta.ETag != "" {
			req.Header.Set("If-None-Match", meta.ETag)
		}
		if meta.LastModified != "" {
			req.Header.Set("If-Modified-Since", meta.LastModified)
		}
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotModified && f.set.Load() != nil:
		return nil
	case resp.StatusCode != http.StatusOK:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > m.maxBytes() {
		return fmt.Errorf("list is larger than %d MB", m.cfg.MaxSizeMB)
	}
	body, err := readCapped(resp.Body, m.maxBytes())
	if err != nil {
		return err
	}
	return m.install(f, body, cacheMeta{URL: f.cfg.URL, ETag: resp.Header.Get("ETag"),
		LastModified: resp.Header.Get("Last-Modified"), UpdatedAt: time.Now().UTC()}, true)
}

func readCapped(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("list is larger than %d MB", max>>20)
	}
	return b, nil
}

// install parses body and swaps it in, then persists it for the next start.
func (m *Manager) install(f *feed, body []byte, meta cacheMeta, persist bool) error {
	set, err := Parse(bytes.NewReader(body))
	if err != nil {
		return err
	}
	f.set.Store(set)
	f.mu.Lock()
	f.meta = meta
	up := meta.UpdatedAt
	f.status.Entries, f.status.Ranges, f.status.Invalid = set.Entries, set.Ranges(), set.Invalid
	f.status.Source, f.status.UpdatedAt = "download", &up
	f.mu.Unlock()
	m.log.Info("threat intel feed updated", "feed", f.cfg.Name, "entries", set.Entries, "ranges", set.Ranges())
	if persist && m.dir != "" {
		if err := m.saveCache(f, body, meta); err != nil {
			// The new list is in use; only the offline copy is stale.
			m.log.Warn("threat intel cache not written", "feed", f.cfg.Name, "err", err)
		}
	}
	return nil
}

func (m *Manager) saveCache(f *feed, body []byte, meta cacheMeta) error {
	lp, mp := m.cachePaths(f)
	mb, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	// list first, then the metadata that vouches for it
	if err := writeAtomic(lp, body); err != nil {
		return err
	}
	return writeAtomic(mp, mb)
}

func writeAtomic(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
