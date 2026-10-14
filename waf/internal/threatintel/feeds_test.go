package threatintel

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// feedServer serves a list with an ETag and records conditional requests.
type feedServer struct {
	mu       sync.Mutex
	body     string
	etag     string
	status   int // forced status (0 = normal)
	requests int
	notMod   int
	*httptest.Server
}

func newFeedServer(t *testing.T, body string) *feedServer {
	fs := &feedServer{body: body, etag: `"v1"`}
	fs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		fs.requests++
		if fs.status != 0 {
			http.Error(w, "upstream trouble", fs.status)
			return
		}
		if r.Header.Get("If-None-Match") == fs.etag {
			fs.notMod++
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", fs.etag)
		w.Header().Set("Last-Modified", "Tue, 14 Oct 2026 10:00:00 GMT")
		_, _ = w.Write([]byte(fs.body))
	}))
	t.Cleanup(fs.Close)
	return fs
}

func (fs *feedServer) set(f func(*feedServer)) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	f(fs)
}

func status(t *testing.T, m *Manager, name string) Status {
	t.Helper()
	for _, s := range m.Status() {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("no status for %s", name)
	return Status{}
}

func TestManagerDownloadConditionalAndKeepLastGood(t *testing.T) {
	fs := newFeedServer(t, fireholSample)
	dir := t.TempDir()
	m, err := New(Config{Feeds: []FeedConfig{{Name: "firehol_level1", URL: fs.URL}}}, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Lookup(net.ParseIP("1.10.16.5")); ok {
		t.Fatal("nothing loaded yet")
	}
	ctx := context.Background()
	if err := m.RefreshAll(ctx); err != nil {
		t.Fatal(err)
	}
	if name, ok := m.Lookup(net.ParseIP("1.10.16.5")); !ok || name != "firehol_level1" {
		t.Fatalf("lookup = %q %v", name, ok)
	}
	st := status(t, m, "firehol_level1")
	if st.Entries != 7 || st.Source != "download" || st.UpdatedAt == nil || st.LastError != "" || st.RefreshSec != 3600 {
		t.Fatalf("status = %+v", st)
	}

	// Unchanged list: conditional request, 304, list kept.
	if err := m.RefreshAll(ctx); err != nil {
		t.Fatal(err)
	}
	var notMod int
	fs.set(func(fs *feedServer) { notMod = fs.notMod })
	if notMod != 1 {
		t.Fatalf("expected a 304, got %d", notMod)
	}

	// Failures keep the last good list and report the error.
	fs.set(func(fs *feedServer) { fs.status = http.StatusBadGateway })
	if err := m.RefreshAll(ctx); err == nil {
		t.Fatal("expected error")
	}
	if _, ok := m.Lookup(net.ParseIP("1.10.16.5")); !ok {
		t.Fatal("last good list lost after a failed download")
	}
	if st := status(t, m, "firehol_level1"); !strings.Contains(st.LastError, "502") || st.Entries != 7 {
		t.Fatalf("status = %+v", st)
	}
	// An HTML page served with 200 is not a list either.
	fs.set(func(fs *feedServer) { fs.status, fs.etag, fs.body = 0, `"v2"`, "<html>maintenance</html>" })
	if err := m.RefreshAll(ctx); err == nil {
		t.Fatal("expected parse error")
	}
	if _, ok := m.Lookup(net.ParseIP("1.10.16.5")); !ok {
		t.Fatal("last good list lost after a bad download")
	}

	// A new version replaces the list and the cache.
	fs.set(func(fs *feedServer) { fs.etag, fs.body = `"v3"`, "198.51.100.0/24\n" })
	if err := m.RefreshAll(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Lookup(net.ParseIP("1.10.16.5")); ok {
		t.Fatal("old entry still listed")
	}
	if _, ok := m.Lookup(net.ParseIP("198.51.100.77")); !ok {
		t.Fatal("new entry not listed")
	}
	if st := status(t, m, "firehol_level1"); st.LastError != "" {
		t.Fatalf("error not cleared: %+v", st)
	}

	// Start-up while the source is unreachable: the cached copy is used.
	fs.Close()
	m2, err := New(Config{Feeds: []FeedConfig{{Name: "firehol_level1", URL: fs.URL}}}, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m2.Lookup(net.ParseIP("198.51.100.77")); !ok {
		t.Fatal("cached list not loaded at start-up")
	}
	if st := status(t, m2, "firehol_level1"); st.Source != "cache" || st.Entries != 1 {
		t.Fatalf("status = %+v", st)
	}
	if err := m2.RefreshAll(ctx); err == nil {
		t.Fatal("expected connection error")
	}
	if _, ok := m2.Lookup(net.ParseIP("198.51.100.77")); !ok {
		t.Fatal("cached list dropped after failed refresh")
	}

	// A cache made for another URL is ignored.
	m3, _ := New(Config{Feeds: []FeedConfig{{Name: "firehol_level1", URL: "https://lists.example.net/other.netset"}}}, dir, nil)
	if _, ok := m3.Lookup(net.ParseIP("198.51.100.77")); ok {
		t.Fatal("cache of another URL used")
	}
}

func TestManagerSizeCapAndTimeout(t *testing.T) {
	big := strings.Repeat("203.0.113.1\n", 200000) // ~2.4 MB
	fs := newFeedServer(t, big)
	m, _ := New(Config{MaxSizeMB: 1, Feeds: []FeedConfig{{Name: "big", URL: fs.URL}}}, "", nil)
	if err := m.RefreshAll(context.Background()); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Fatalf("size cap: %v", err)
	}

	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer slow.Close()
	m, _ = New(Config{Timeout: time.Second, Feeds: []FeedConfig{{Name: "slow", URL: slow.URL}}}, "", nil)
	start := time.Now()
	if err := m.RefreshAll(context.Background()); err == nil {
		t.Fatal("expected timeout")
	}
	if time.Since(start) > 4*time.Second {
		t.Fatal("timeout not applied")
	}
}

func TestLookupIgnoresPrivateAndOrder(t *testing.T) {
	a := newFeedServer(t, "10.0.0.0/8\n127.0.0.0/8\n100.64.0.0/10\nfe80::/10\n198.51.100.0/24\n")
	b := newFeedServer(t, "198.51.100.0/24\n203.0.113.0/24\n")
	m, err := New(Config{Feeds: []FeedConfig{{Name: "a", URL: a.URL}, {Name: "b", URL: b.URL}}}, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.RefreshAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"10.1.2.3", "127.0.0.1", "100.64.1.1", "fe80::1", "::1", "192.168.1.1"} {
		if name, ok := m.Lookup(net.ParseIP(ip)); ok {
			t.Errorf("%s reported by %s", ip, name)
		}
	}
	if name, _ := m.Lookup(net.ParseIP("198.51.100.1")); name != "a" {
		t.Fatalf("first feed should win, got %q", name)
	}
	if name, _ := m.Lookup(net.ParseIP("::ffff:203.0.113.9")); name != "b" {
		t.Fatalf("mapped address: %q", name)
	}
	var nilM *Manager
	if _, ok := nilM.Lookup(net.ParseIP("198.51.100.1")); ok || len(nilM.Status()) != 0 {
		t.Fatal("nil manager")
	}
}

func TestFileFeedAndRun(t *testing.T) {
	p := filepath.Join(t.TempDir(), "local.txt")
	if err := os.WriteFile(p, []byte("203.0.113.0/24 ; local\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := New(Config{Feeds: []FeedConfig{{Name: "local", URL: "file://" + p, Refresh: time.Minute}}}, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, ok := m.Lookup(net.ParseIP("203.0.113.5")); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Run did not load the feed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if st := status(t, m, "local"); st.NextAt == nil && st.CheckedAt == nil {
		t.Fatalf("status = %+v", st)
	}
}

func TestConfigValidation(t *testing.T) {
	bad := []Config{
		{Feeds: []FeedConfig{{Name: "", URL: "https://x.example/l"}}},
		{Feeds: []FeedConfig{{Name: "a/b", URL: "https://x.example/l"}}},
		{Feeds: []FeedConfig{{Name: "a", URL: "ftp://x.example/l"}}},
		{Feeds: []FeedConfig{{Name: "a", URL: "https://x.example/l"}, {Name: "a", URL: "https://y.example/l"}}},
		{Feeds: []FeedConfig{{Name: "a", URL: "https://x.example/l", Refresh: time.Second}}},
		{MaxSizeMB: -1},
	}
	for i, c := range bad {
		if err := c.Normalize(); err == nil {
			t.Errorf("config %d accepted", i)
		}
	}
	c := Config{Feeds: []FeedConfig{{Name: "spamhaus-drop", URL: "https://www.spamhaus.org/drop/drop.txt"}}}
	if err := c.Normalize(); err != nil || c.Feeds[0].Refresh != time.Hour || c.Timeout != time.Minute || c.MaxSizeMB != 32 {
		t.Fatalf("defaults: %v %+v", err, c)
	}
}
