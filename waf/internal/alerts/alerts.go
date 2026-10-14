// Package alerts sends security notifications to Telegram and webhooks.
//
// Events are aggregated per (site, kind): the first event of a quiet key is
// reported on the next flush (every few seconds), later ones are summarised
// at most once per interval, so an attack produces a handful of messages
// rather than one per request.
package alerts

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/events"
)

// Config is the alerts section of the node configuration.
type Config struct {
	// Kinds to report (waf, geo, ip_deny, ip_allow, rate_limit, bot, auth).
	// Empty means waf only.
	Kinds []string `yaml:"kinds"`
	// Interval between two messages for the same site and kind (default 5m).
	Interval time.Duration `yaml:"interval"`
	// IncludeMonitor also reports attacks seen in monitor mode.
	IncludeMonitor bool `yaml:"include_monitor"`

	Telegram struct {
		BotToken     string `yaml:"bot_token"`
		BotTokenFile string `yaml:"bot_token_file"`
		ChatID       string `yaml:"chat_id"`
		// APIBase overrides https://api.telegram.org (tests, proxies).
		APIBase string `yaml:"api_base"`
	} `yaml:"telegram"`

	Webhooks []Webhook `yaml:"webhooks"`
}

// Webhook receives JSON alerts signed with HMAC-SHA256 of the body in
// X-HCW-Signature: sha256=<hex>.
type Webhook struct {
	URL    string `yaml:"url"`
	Secret string `yaml:"secret"`
}

// Enabled reports whether any channel is configured.
func (c *Config) Enabled() bool {
	return (c.Telegram.BotToken != "" && c.Telegram.ChatID != "") || len(c.Webhooks) > 0
}

// Alert is the payload sent to channels.
type Alert struct {
	Node     string        `json:"node"`
	SiteID   int           `json:"site_id"`
	SiteName string        `json:"site"`
	Kind     string        `json:"kind"`
	Count    int           `json:"count"`
	Since    time.Time     `json:"since"`
	TopIPs   []string      `json:"top_ips"`
	Sample   *events.Event `json:"sample,omitempty"`
	Test     bool          `json:"test,omitempty"`
}

type key struct {
	site int
	kind string
}

type bucket struct {
	count    int
	since    time.Time
	ips      map[string]int
	sample   events.Event
	lastSent time.Time
}

// Notifier aggregates events and delivers alerts.
type Notifier struct {
	cfg      Config
	node     string
	log      *slog.Logger
	http     *http.Client
	siteName func(int) string
	kinds    map[string]bool

	mu      sync.Mutex
	pending map[key]*bucket
	now     func() time.Time
}

// New creates a notifier. siteName resolves site IDs for messages.
func New(cfg Config, node string, siteName func(int) string, log *slog.Logger) *Notifier {
	if cfg.Interval <= 0 {
		cfg.Interval = 5 * time.Minute
	}
	if cfg.Telegram.APIBase == "" {
		cfg.Telegram.APIBase = "https://api.telegram.org"
	}
	kinds := map[string]bool{}
	for _, k := range cfg.Kinds {
		kinds[k] = true
	}
	if len(kinds) == 0 {
		kinds["waf"] = true
	}
	return &Notifier{
		cfg: cfg, node: node, log: log, siteName: siteName, kinds: kinds,
		http:    &http.Client{Timeout: 10 * time.Second},
		pending: map[key]*bucket{},
		now:     time.Now,
	}
}

// Observe records an event; it never blocks on the network.
func (n *Notifier) Observe(e events.Event) {
	if !n.kinds[e.Kind] || (e.Action == "monitor" && !n.cfg.IncludeMonitor) {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	k := key{e.SiteID, e.Kind}
	b := n.pending[k]
	if b == nil {
		b = &bucket{ips: map[string]int{}}
		n.pending[k] = b
	}
	if b.count == 0 {
		b.since = e.Time
		b.sample = e
	}
	b.count++
	if len(b.ips) < 1000 {
		b.ips[e.ClientIP]++
	}
}

// due collects alerts ready to send and resets their counters.
func (n *Notifier) due() []Alert {
	n.mu.Lock()
	defer n.mu.Unlock()
	now := n.now()
	var out []Alert
	for k, b := range n.pending {
		if b.count == 0 {
			// Forget keys that have been quiet for a long time.
			if now.Sub(b.lastSent) > 24*time.Hour {
				delete(n.pending, k)
			}
			continue
		}
		if !b.lastSent.IsZero() && now.Sub(b.lastSent) < n.cfg.Interval {
			continue
		}
		sample := b.sample
		out = append(out, Alert{
			Node: n.node, SiteID: k.site, SiteName: n.siteName(k.site), Kind: k.kind,
			Count: b.count, Since: b.since, TopIPs: topIPs(b.ips, 5), Sample: &sample,
		})
		b.count, b.ips, b.lastSent = 0, map[string]int{}, now
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].SiteID < out[j].SiteID || (out[i].SiteID == out[j].SiteID && out[i].Kind < out[j].Kind)
	})
	return out
}

func topIPs(m map[string]int, n int) []string {
	type kv struct {
		ip string
		c  int
	}
	l := make([]kv, 0, len(m))
	for ip, c := range m {
		l = append(l, kv{ip, c})
	}
	sort.Slice(l, func(i, j int) bool { return l[i].c > l[j].c || (l[i].c == l[j].c && l[i].ip < l[j].ip) })
	out := []string{}
	for i := 0; i < len(l) && i < n; i++ {
		out = append(out, fmt.Sprintf("%s (%d)", l[i].ip, l[i].c))
	}
	return out
}

// Run flushes alerts every tick until ctx is done.
func (n *Notifier) Run(ctx context.Context, tick time.Duration) {
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n.Flush(ctx)
		}
	}
}

// Flush sends everything that is due.
func (n *Notifier) Flush(ctx context.Context) {
	for _, a := range n.due() {
		if err := n.Send(ctx, a); err != nil {
			n.log.Warn("alert delivery failed", "site", a.SiteID, "kind", a.Kind, "err", err)
		}
	}
}

// Send delivers one alert to every channel.
func (n *Notifier) Send(ctx context.Context, a Alert) error {
	var errs []string
	if n.cfg.Telegram.BotToken != "" && n.cfg.Telegram.ChatID != "" {
		if err := n.telegram(ctx, a); err != nil {
			errs = append(errs, "telegram: "+err.Error())
		}
	}
	for _, w := range n.cfg.Webhooks {
		if err := n.webhook(ctx, w, a); err != nil {
			errs = append(errs, "webhook "+w.URL+": "+err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

var kindLabel = map[string]string{
	"waf": "Tấn công web", "geo": "Chặn theo quốc gia", "ip_deny": "IP trong denylist",
	"ip_allow": "IP ngoài allowlist", "rate_limit": "Vượt giới hạn tốc độ", "bot": "Bot bị loại", "auth": "Đăng nhập sai",
}

// Text renders the human-readable message (Telegram HTML subset).
func (a Alert) Text() string {
	var b strings.Builder
	label := kindLabel[a.Kind]
	if label == "" {
		label = a.Kind
	}
	if a.Test {
		b.WriteString("✅ <b>HiTechCloud WAF</b>: tin nhắn thử nghiệm từ node <code>" + html.EscapeString(a.Node) + "</code>")
		return b.String()
	}
	fmt.Fprintf(&b, "🛡 <b>%s</b> – %s\n", html.EscapeString(label), html.EscapeString(a.SiteName))
	fmt.Fprintf(&b, "Số sự kiện: <b>%d</b> từ %s\n", a.Count, a.Since.Local().Format("15:04:05 02/01"))
	fmt.Fprintf(&b, "Node: <code>%s</code>\n", html.EscapeString(a.Node))
	if len(a.TopIPs) > 0 {
		fmt.Fprintf(&b, "IP: %s\n", html.EscapeString(strings.Join(a.TopIPs, ", ")))
	}
	if s := a.Sample; s != nil {
		uri := s.URI
		if len(uri) > 200 {
			uri = uri[:200] + "…"
		}
		fmt.Fprintf(&b, "Ví dụ: <code>%s %s</code>", html.EscapeString(s.Method), html.EscapeString(s.Host+uri))
		if s.Country != "" {
			fmt.Fprintf(&b, " (%s)", html.EscapeString(s.Country))
		}
		if len(s.Tags) > 0 {
			fmt.Fprintf(&b, "\nLoại: %s", html.EscapeString(strings.Join(s.Tags, ", ")))
		}
	}
	return b.String()
}

func (n *Notifier) post(ctx context.Context, url string, body []byte, hdr map[string]string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "hitechcloud-waf-alerts/1")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := n.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}

func (n *Notifier) telegram(ctx context.Context, a Alert) error {
	body, _ := json.Marshal(map[string]any{
		"chat_id": n.cfg.Telegram.ChatID, "text": a.Text(), "parse_mode": "HTML", "disable_web_page_preview": true,
	})
	return n.post(ctx, strings.TrimRight(n.cfg.Telegram.APIBase, "/")+"/bot"+n.cfg.Telegram.BotToken+"/sendMessage", body, nil)
}

// Sign returns the X-HCW-Signature value for body.
func Sign(secret string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

func (n *Notifier) webhook(ctx context.Context, w Webhook, a Alert) error {
	body, _ := json.Marshal(a)
	hdr := map[string]string{}
	if w.Secret != "" {
		hdr["X-HCW-Signature"] = Sign(w.Secret, body)
	}
	return n.post(ctx, w.URL, body, hdr)
}

// SendTest sends a test message to every channel.
func (n *Notifier) SendTest(ctx context.Context) error {
	return n.Send(ctx, Alert{Node: n.node, Test: true, Kind: "test", Since: n.now()})
}
