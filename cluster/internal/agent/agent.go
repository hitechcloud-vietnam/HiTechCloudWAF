// Package agent runs on every WAF node: it reports health to the controller
// and applies the replicated configuration to the local engine.
package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/api"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/config"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/engine"
)

// Version is set at build time.
var Version = "dev"

// Agent is one node agent.
type Agent struct {
	cfg    *config.Agent
	log    *slog.Logger
	http   *http.Client
	base   *url.URL
	engine *engine.Client

	appliedRev string
	configErr  string

	// lastEvent is the newest engine event already reported.
	lastEvent   string
	eventsKnown bool
}

const maxEventsPerBeat = 100

// New builds an agent and fills defaults that need the environment.
func New(cfg *config.Agent, log *slog.Logger) (*Agent, error) {
	u, err := url.Parse(strings.TrimRight(cfg.ControllerURL, "/"))
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid controller_url %q", cfg.ControllerURL)
	}
	if u.Scheme != "https" && !loopback(u.Hostname()) {
		return nil, errors.New("controller_url must use https unless it is a loopback address")
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.ControllerCA != "" {
		pem, err := os.ReadFile(cfg.ControllerCA)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s has no PEM certificate", cfg.ControllerCA)
		}
		tlsCfg.RootCAs = pool
	}
	a := &Agent{
		cfg: cfg, log: log, base: u,
		http: &http.Client{
			Timeout:       20 * time.Second,
			Transport:     &http.Transport{TLSClientConfig: tlsCfg, Proxy: http.ProxyFromEnvironment},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	if cfg.ID == "" {
		h, err := os.Hostname()
		if err != nil {
			return nil, err
		}
		cfg.ID = strings.ToLower(h)
	}
	if cfg.Name == "" {
		cfg.Name = cfg.ID
	}
	if cfg.IPv4 == "" {
		ip, err := outboundIPv4(u.Host)
		if err != nil {
			return nil, fmt.Errorf("ipv4 not configured and could not be detected: %w", err)
		}
		cfg.IPv4 = ip
		log.Warn("ipv4 not configured, using detected address; set agent.ipv4 to the public address behind NAT", "ipv4", ip)
	}
	if cfg.Engine.BaseURL != "" {
		if a.engine, err = engine.New(cfg.Engine); err != nil {
			return nil, fmt.Errorf("local engine: %w", err)
		}
	}
	if b, err := os.ReadFile(a.revFile()); err == nil {
		a.appliedRev = strings.TrimSpace(string(b))
	}
	return a, nil
}

func loopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func outboundIPv4(hostport string) (string, error) {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	c, err := net.Dial("udp4", net.JoinHostPort(host, "443"))
	if err != nil {
		return "", err
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP.String(), nil
}

func (a *Agent) revFile() string { return filepath.Join(a.cfg.DataDir, "applied-revision") }

// Run loops until ctx is done.
func (a *Agent) Run(ctx context.Context) error {
	a.log.Info("agent started", "node", a.cfg.ID, "controller", a.base.String(), "apply_config", a.cfg.ApplyConfig)
	t := time.NewTicker(a.cfg.Interval.Duration)
	defer t.Stop()
	for {
		if err := a.Tick(ctx); err != nil {
			a.log.Warn("tick failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// Tick sends one heartbeat and applies configuration when it changed.
func (a *Agent) Tick(ctx context.Context) error {
	hb := api.Heartbeat{
		ID: a.cfg.ID, Name: a.cfg.Name, Region: a.cfg.Region, Pools: a.cfg.Pools,
		IPv4: a.cfg.IPv4, IPv6: a.cfg.IPv6, Weight: a.cfg.Weight, Labels: a.cfg.Labels,
		Version: Version, ProbeURL: a.cfg.ProbeURL,
		EngineHealthy: true, ConfigRevision: a.appliedRev, ConfigError: a.configErr,
		Stats: collectStats(a.cfg.DataDir),
	}
	if a.engine != nil {
		hctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		if err := a.engine.Health(hctx); err != nil {
			hb.EngineHealthy, hb.EngineError = false, err.Error()
		}
		cancel()
	}
	if a.engine != nil && hb.EngineHealthy {
		hb.Traffic, hb.Events = a.collectTraffic(ctx)
	}
	var resp struct {
		ConfigRevision string `json:"config_revision"`
	}
	if err := a.call(ctx, http.MethodPost, "/v1/heartbeat", hb, &resp); err != nil {
		return fmt.Errorf("heartbeat: %w", err)
	}
	if len(hb.Events) > 0 {
		a.lastEvent = hb.Events[0].ID
	}
	if a.cfg.ApplyConfig && resp.ConfigRevision != "" && resp.ConfigRevision != a.appliedRev {
		a.applyConfig(ctx)
	}
	return nil
}

// collectTraffic reads counters and new events from engines that provide
// /api/open/stats and /api/open/events (HiTechCloud WAF engine). Engines
// without them simply report nothing.
func (a *Agent) collectTraffic(ctx context.Context) (*api.Traffic, []api.Event) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var traffic *api.Traffic
	if v, err := a.engine.Do(cctx, http.MethodGet, "/api/open/stats", "", nil); err == nil {
		if m, ok := v.(map[string]any); ok {
			if per, ok := m["data"].(map[string]any); ok {
				traffic = &api.Traffic{}
				for _, c := range per {
					cm, _ := c.(map[string]any)
					traffic.Requests += num(cm["requests"])
					traffic.Blocked += num(cm["blocked"])
					traffic.Monitored += num(cm["monitored"])
					traffic.RateLimited += num(cm["rate_limited"])
					traffic.ACLBlocked += num(cm["acl_blocked"])
					traffic.BotFailed += num(cm["bot_failed"])
				}
			}
		}
	}
	v, err := a.engine.Do(cctx, http.MethodGet, "/api/open/events", "limit="+strconv.Itoa(maxEventsPerBeat), nil)
	if err != nil {
		return traffic, nil
	}
	raw, _ := json.Marshal(v)
	var env struct {
		Data struct {
			Data []api.Event `json:"data"`
		} `json:"data"`
	}
	if json.Unmarshal(raw, &env) != nil {
		return traffic, nil
	}
	list := env.Data.Data // newest first
	if !a.eventsKnown {
		// First contact: report only a few recent events, not the backlog.
		a.eventsKnown = true
		if len(list) > 20 {
			list = list[:20]
		}
		return traffic, list
	}
	var fresh []api.Event
	for _, e := range list {
		if e.ID == a.lastEvent {
			break
		}
		fresh = append(fresh, e)
	}
	return traffic, fresh
}

func num(v any) uint64 {
	switch n := v.(type) {
	case json.Number:
		u, _ := strconv.ParseUint(n.String(), 10, 64)
		return u
	case float64:
		return uint64(n)
	}
	return 0
}

func (a *Agent) applyConfig(ctx context.Context) {
	var sr struct {
		Snapshot  *api.Snapshot     `json:"snapshot"`
		Resources []config.Resource `json:"resources"`
	}
	if err := a.call(ctx, http.MethodGet, "/v1/config/snapshot", nil, &sr); err != nil {
		a.configErr = "fetch snapshot: " + err.Error()
		a.log.Warn("fetch snapshot failed", "err", err)
		return
	}
	if sr.Snapshot == nil {
		return
	}
	resources := sr.Resources
	if len(a.cfg.Engine.Resources) > 0 {
		resources = a.cfg.Engine.Resources
	}
	rep := engine.Apply(ctx, a.engine, resources, sr.Snapshot)
	a.log.Info("configuration applied", "revision", sr.Snapshot.Revision,
		"created", rep.Created, "updated", rep.Updated, "deleted", rep.Deleted, "unchanged", rep.Unchanged, "errors", len(rep.Errors))
	if err := rep.Err(); err != nil {
		// Retried on the next heartbeat because appliedRev is unchanged.
		a.configErr = err.Error()
		return
	}
	a.configErr = ""
	a.appliedRev = sr.Snapshot.Revision
	if err := os.MkdirAll(a.cfg.DataDir, 0o700); err == nil {
		_ = os.WriteFile(a.revFile(), []byte(a.appliedRev+"\n"), 0o600)
	}
}

func (a *Agent) call(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	u := *a.base
	u.Path += path
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.cfg.NodeToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "hcw-agent/"+Version)
	resp, err := a.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}
