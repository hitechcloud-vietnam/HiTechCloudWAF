// Package mgmt is the management API of a HiTechCloud WAF node. Its
// collections (/api/open/site, /api/open/cert) are what the cluster agent
// replicates between nodes.
package mgmt

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/audit"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/events"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/model"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/proxy"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/store"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/users"
)

// TokenHeader carries the API token (Authorization: Bearer also works).
const TokenHeader = "X-HCW-API-TOKEN"

// Applier loads the stored configuration into the data plane.
type Applier func(sites []model.Site, certs []model.Cert) error

// API serves the management endpoints.
type API struct {
	Token   string
	Brand   any // served publicly to the console (name, colour)
	Version string
	Started time.Time
	// Console serves the web UI at /; nil disables it.
	Console http.Handler
	// Allow restricts the API and console to these networks (empty = any).
	Allow []*net.IPNet
	// Upstreams reports upstream health (optional).
	Upstreams func() any
	// Cache is the engine response cache (optional).
	Cache interface {
		PurgeCache(siteID int, prefix string) int
		CacheStats() (objects int, bytes int64)
	}
	// Audit records administrative actions (optional).
	Audit *audit.Log
	// Users enables console accounts; nil means API token only.
	Users *users.Store
	guard loginGuard
	// Alerts sends notifications; nil when no channel is configured.
	Alerts interface {
		SendTest(context.Context) error
	}
	Store  *store.Store
	Events *events.Log
	Apply  Applier
	Log    *slog.Logger

	mu sync.Mutex // serialises writes so apply order matches store order
}

type envelope struct {
	Data any     `json:"data"`
	Err  *string `json:"err"`
	Msg  string  `json:"msg"`
}

func ok(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(envelope{Data: data})
}

func fail(w http.ResponseWriter, code int, errCode string, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(envelope{Err: &errCode, Msg: err.Error()})
}

type list[T any] struct {
	Data  []T `json:"data"`
	Total int `json:"total"`
}

func (a *API) authorized(r *http.Request) bool {
	got := r.Header.Get(TokenHeader)
	if got == "" {
		if h := r.Header.Get("Authorization"); len(h) > 7 && h[:7] == "Bearer " {
			got = h[7:]
		}
	}
	return a.Token != "" && subtle.ConstantTimeCompare([]byte(a.Token), []byte(got)) == 1
}

// Handler returns the routes.
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/open/health", func(w http.ResponseWriter, _ *http.Request) { ok(w, "ok") })
	mux.HandleFunc("GET /api/open/site", func(w http.ResponseWriter, r *http.Request) {
		s := a.Store.Sites()
		if !callerOf(r).admin() {
			for i := range s {
				if s[i].Auth.PasswordHash != "" {
					s[i].Auth.PasswordHash = redacted
				}
			}
		}
		ok(w, list[model.Site]{Data: s, Total: len(s)})
	})
	mux.HandleFunc("POST /api/open/site", a.write(func(r *http.Request) (any, error) {
		var s model.Site
		if err := decode(r, &s); err != nil {
			return nil, err
		}
		s.ID = 0
		if err := proxy.ValidateRules(s.CustomRules); err != nil {
			return nil, err
		}
		return a.Store.CreateSite(s)
	}))
	mux.HandleFunc("PUT /api/open/site", a.write(func(r *http.Request) (any, error) {
		var s model.Site
		if err := decode(r, &s); err != nil {
			return nil, err
		}
		if err := proxy.ValidateRules(s.CustomRules); err != nil {
			return nil, err
		}
		return a.Store.UpdateSite(s)
	}))
	mux.HandleFunc("DELETE /api/open/site", a.write(func(r *http.Request) (any, error) {
		var b struct {
			IDs []int `json:"ids"`
		}
		if err := decode(r, &b); err != nil {
			return nil, err
		}
		return nil, a.Store.DeleteSites(b.IDs)
	}))
	mux.HandleFunc("GET /api/open/cert", func(w http.ResponseWriter, r *http.Request) {
		c := a.Store.Certs()
		if !callerOf(r).admin() {
			for i := range c {
				c[i].Key = redacted // private keys are for administrators only
			}
		}
		ok(w, list[model.Cert]{Data: c, Total: len(c)})
	})
	mux.HandleFunc("POST /api/open/cert", a.write(func(r *http.Request) (any, error) {
		var c model.Cert
		if err := decode(r, &c); err != nil {
			return nil, err
		}
		c.ID = 0
		return a.Store.CreateCert(c)
	}))
	mux.HandleFunc("PUT /api/open/cert", a.write(func(r *http.Request) (any, error) {
		var c model.Cert
		if err := decode(r, &c); err != nil {
			return nil, err
		}
		return a.Store.UpdateCert(c)
	}))
	mux.HandleFunc("DELETE /api/open/cert", a.write(func(r *http.Request) (any, error) {
		var b struct {
			IDs []int `json:"ids"`
		}
		if err := decode(r, &b); err != nil {
			return nil, err
		}
		return nil, a.Store.DeleteCerts(b.IDs)
	}))
	mux.HandleFunc("GET /api/open/events", func(w http.ResponseWriter, r *http.Request) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 || limit > 1000 {
			limit = 100
		}
		site, _ := strconv.Atoi(r.URL.Query().Get("site_id"))
		ev := a.Events.Latest(limit, site)
		ok(w, list[events.Event]{Data: ev, Total: len(ev)})
	})
	mux.HandleFunc("GET /api/open/stats", func(w http.ResponseWriter, _ *http.Request) { ok(w, a.Events.Stats()) })
	mux.HandleFunc("GET /api/open/timeseries", func(w http.ResponseWriter, _ *http.Request) { ok(w, a.Events.Series(time.Now())) })
	mux.HandleFunc("GET /api/open/metrics", a.metrics)
	mux.HandleFunc("GET /api/open/upstreams", func(w http.ResponseWriter, _ *http.Request) {
		if a.Upstreams == nil {
			ok(w, map[string]any{})
			return
		}
		ok(w, a.Upstreams())
	})
	mux.HandleFunc("GET /api/open/audit", func(w http.ResponseWriter, r *http.Request) {
		if !adminOnly(w, r) {
			return
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 || limit > 2000 {
			limit = 200
		}
		entries := []audit.Entry{}
		if a.Audit != nil {
			entries = a.Audit.Latest(limit)
		}
		ok(w, list[audit.Entry]{Data: entries, Total: len(entries)})
	})
	mux.HandleFunc("GET /api/open/backup", func(w http.ResponseWriter, r *http.Request) {
		if !adminOnly(w, r) {
			return
		}
		if a.Audit != nil {
			a.Audit.Add(audit.Entry{Time: time.Now().UTC(), User: callerOf(r).name, IP: clientHost(r), Action: "GET /api/open/backup", Status: 200})
		}
		w.Header().Set("Content-Disposition", `attachment; filename="hcw-waf-backup-`+time.Now().UTC().Format("20060102-150405")+`.json"`)
		ok(w, a.Store.Export())
	})
	mux.HandleFunc("POST /api/open/restore", a.write(func(r *http.Request) (any, error) {
		if !callerOf(r).admin() {
			return nil, errors.New("administrators only")
		}
		var b store.Backup
		if err := decode(r, &b); err != nil {
			return nil, err
		}
		for _, site := range b.Sites {
			if err := proxy.ValidateRules(site.CustomRules); err != nil {
				return nil, fmt.Errorf("site %d: %w", site.ID, err)
			}
		}
		if err := a.Store.Replace(b); err != nil {
			return nil, err
		}
		return map[string]int{"sites": len(b.Sites), "certs": len(b.Certs)}, nil
	}))
	mux.HandleFunc("POST /api/open/alerts/test", func(w http.ResponseWriter, r *http.Request) {
		if a.Alerts == nil {
			fail(w, http.StatusConflict, "not_configured", errors.New("no alert channel configured (alerts.telegram or alerts.webhooks in waf.yaml)"))
			return
		}
		if err := a.Alerts.SendTest(r.Context()); err != nil {
			a.Log.Warn("test alert failed", "err", err)
			fail(w, http.StatusBadGateway, "delivery_failed", err)
			return
		}
		ok(w, "sent")
	})
	mux.HandleFunc("GET /api/open/cache", func(w http.ResponseWriter, _ *http.Request) {
		objects, size := 0, int64(0)
		if a.Cache != nil {
			objects, size = a.Cache.CacheStats()
		}
		ok(w, map[string]any{"objects": objects, "bytes": size})
	})
	// Purging does not change the configuration, so it is not re-applied.
	mux.HandleFunc("POST /api/open/cache/purge", func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			SiteID int    `json:"site_id"` // 0 = every site
			Prefix string `json:"prefix"`  // request URI prefix, "" = everything
		}
		if err := decode(r, &b); err != nil {
			fail(w, http.StatusBadRequest, "invalid", err)
			return
		}
		if b.Prefix != "" && !strings.HasPrefix(b.Prefix, "/") {
			fail(w, http.StatusBadRequest, "invalid", errors.New("prefix must start with /"))
			return
		}
		n := 0
		if a.Cache != nil {
			n = a.Cache.PurgeCache(b.SiteID, b.Prefix)
		}
		ok(w, map[string]int{"removed": n})
	})
	mux.HandleFunc("GET /api/open/brand", func(w http.ResponseWriter, _ *http.Request) { ok(w, a.Brand) })
	mux.HandleFunc("GET /api/open/info", func(w http.ResponseWriter, _ *http.Request) {
		ok(w, map[string]any{"version": a.Version, "started_at": a.Started, "sites": len(a.Store.Sites()), "certs": len(a.Store.Certs())})
	})
	a.registerAccountRoutes(mux)
	if a.Console != nil {
		mux.Handle("GET /", a.Console)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		if len(a.Allow) > 0 && !a.allowed(r.RemoteAddr) {
			fail(w, http.StatusForbidden, "forbidden", errors.New("management access is not allowed from this address"))
			return
		}
		public := r.URL.Path == "/api/open/health" || r.URL.Path == "/api/open/brand" ||
			(r.URL.Path == "/api/auth/login" && r.Method == http.MethodPost) || !strings.HasPrefix(r.URL.Path, "/api/")
		if public {
			mux.ServeHTTP(w, r)
			return
		}
		p, authed := a.authenticate(r)
		if !authed {
			fail(w, http.StatusUnauthorized, "unauthorized", errors.New("missing or invalid API token or session"))
			return
		}
		if !p.admin() && !viewerAllowed(r) {
			fail(w, http.StatusForbidden, "forbidden", errors.New("your role is read-only"))
			return
		}
		if a.Audit == nil || r.Method == http.MethodGet {
			mux.ServeHTTP(w, withCaller(r, p))
			return
		}
		// Record every change: who, from where, what, and the outcome.
		body, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		r.Body = io.NopCloser(bytes.NewReader(body))
		rec := &codeRecorder{ResponseWriter: w, code: http.StatusOK}
		mux.ServeHTTP(rec, withCaller(r, p))
		a.Audit.Add(audit.Entry{Time: time.Now().UTC(), User: p.name, IP: clientHost(r),
			Action: r.Method + " " + r.URL.Path, Status: rec.code, Detail: audit.Redact(body)})
	})
}

// metrics renders counters in the Prometheus text format. Scrape it with
// authorization: {credentials: <token>} (Bearer).
func (a *API) metrics(w http.ResponseWriter, _ *http.Request) {
	names := map[int]string{}
	for _, s := range a.Store.Sites() {
		names[s.ID] = s.Name
	}
	stats := a.Events.Stats()
	ids := make([]int, 0, len(stats))
	for id := range stats {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	type metric struct {
		name, help string
		get        func(events.Counters) uint64
	}
	ms := []metric{
		{"hcw_requests_total", "Requests received per site.", func(c events.Counters) uint64 { return c.Requests }},
		{"hcw_blocked_total", "Requests blocked by WAF rules.", func(c events.Counters) uint64 { return c.Blocked }},
		{"hcw_monitored_total", "Attacks logged in monitor mode.", func(c events.Counters) uint64 { return c.Monitored }},
		{"hcw_rate_limited_total", "Requests refused by rate limiting.", func(c events.Counters) uint64 { return c.RateLimit }},
		{"hcw_acl_blocked_total", "Requests refused by IP allow/deny lists.", func(c events.Counters) uint64 { return c.ACL }},
		{"hcw_bot_failed_total", "Failed anti-bot challenges.", func(c events.Counters) uint64 { return c.Bot }},
	}
	for _, m := range ms {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", m.name, m.help, m.name)
		for _, id := range ids {
			fmt.Fprintf(w, "%s{site_id=\"%d\",site=%s} %d\n", m.name, id, strconv.Quote(names[id]), m.get(stats[id]))
		}
	}
	fmt.Fprintf(w, "# HELP hcw_sites Configured sites.\n# TYPE hcw_sites gauge\nhcw_sites %d\n", len(names))
	fmt.Fprintf(w, "# HELP hcw_uptime_seconds Seconds since start.\n# TYPE hcw_uptime_seconds gauge\nhcw_uptime_seconds %d\n", int(time.Since(a.Started).Seconds()))
}

type codeRecorder struct {
	http.ResponseWriter
	code int
}

func (c *codeRecorder) WriteHeader(code int) {
	c.code = code
	c.ResponseWriter.WriteHeader(code)
}

// redacted replaces secrets in responses to read-only users.
const redacted = "***"

func adminOnly(w http.ResponseWriter, r *http.Request) bool {
	if !callerOf(r).admin() {
		fail(w, http.StatusForbidden, "forbidden", errors.New("administrators only"))
		return false
	}
	return true
}

func (a *API) allowed(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	ip := net.ParseIP(host)
	for _, n := range a.Allow {
		if ip != nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 4<<20))
	if err := dec.Decode(v); err != nil {
		return badRequest{err}
	}
	return nil
}

type badRequest struct{ error }

// write runs a store mutation, then reloads the data plane.
func (a *API) write(f func(*http.Request) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		res, err := f(r)
		if err != nil {
			switch {
			case errors.Is(err, store.ErrNotFound):
				fail(w, http.StatusNotFound, "not_found", err)
			default:
				fail(w, http.StatusBadRequest, "invalid", err)
			}
			return
		}
		if err := a.Apply(a.Store.Sites(), a.Store.Certs()); err != nil {
			a.Log.Error("apply configuration", "err", err)
			fail(w, http.StatusInternalServerError, "apply_failed", err)
			return
		}
		ok(w, res)
	}
}
