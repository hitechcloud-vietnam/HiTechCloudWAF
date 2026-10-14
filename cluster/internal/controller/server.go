package controller

import (
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/api"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/auth"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/config"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/engine"
)

const maxClusterEvents = 5000

//go:embed dashboard.html
var dashboardHTML string

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

// SnapshotResponse is returned to agents: the configuration plus the
// resource definitions needed to apply it.
type SnapshotResponse struct {
	Snapshot  *api.Snapshot     `json:"snapshot"`
	Resources []config.Resource `json:"resources"`
	Error     string            `json:"error,omitempty"`
}

// Server is the controller.
type Server struct {
	cfg     *config.Controller
	store   *Store
	records *RecordStore
	creds   *CredStore
	log     *slog.Logger
	probe   *http.Client

	warnMu sync.Mutex
	warned map[string]time.Time // shared-token deprecation warnings

	primary *engine.Client

	evMu   sync.Mutex
	events []api.Event // newest last, capped at maxClusterEvents

	snapMu   sync.RWMutex
	snap     *api.Snapshot
	snapErr  string
	syncNow  chan struct{}
	dashTmpl *template.Template
}

// New builds a controller from cfg.
func New(cfg *config.Controller, log *slog.Logger) (*Server, error) {
	st, err := NewStore(cfg.StateFile)
	if err != nil {
		return nil, fmt.Errorf("load state: %w", err)
	}
	recPath := cfg.DNSRecordsFile
	if recPath == "" && cfg.StateFile != "" {
		recPath = filepath.Join(filepath.Dir(cfg.StateFile), "dns-records.json")
	}
	recs, err := NewRecordStore(recPath)
	if err != nil {
		return nil, fmt.Errorf("load dns records: %w", err)
	}
	credPath := cfg.CredentialsFile
	if credPath == "" && cfg.StateFile != "" {
		credPath = filepath.Join(filepath.Dir(cfg.StateFile), "node-credentials.json")
	}
	creds, err := NewCredStore(credPath)
	if err != nil {
		return nil, fmt.Errorf("load node credentials: %w", err)
	}
	switch {
	case cfg.RequireEnrollment && cfg.NodeToken != "":
		log.Info("require_enrollment is set: the shared node_token is ignored")
	case !cfg.RequireEnrollment:
		log.Warn("the shared node_token is accepted; it is deprecated, enroll nodes with one-time tokens and set require_enrollment: true")
	}
	s := &Server{
		cfg:     cfg,
		store:   st,
		records: recs,
		creds:   creds,
		warned:  map[string]time.Time{},
		log:     log,
		probe: &http.Client{
			Timeout: cfg.ProbeTimeout.Duration,
			Transport: &http.Transport{
				Proxy: nil,
				// Checked at dial time too, so DNS tricks cannot reach
				// internal addresses.
				DialContext: (&net.Dialer{Timeout: cfg.ProbeTimeout.Duration, Control: func(_, address string, _ syscall.RawConn) error {
					host, _, _ := net.SplitHostPort(address)
					if ip := net.ParseIP(host); ip == nil || (!cfg.AllowLoopbackNodes && reservedIP(ip)) {
						return fmt.Errorf("probe to %s refused", host)
					}
					return nil
				}}).DialContext,
				TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.ProbeInsecure}, //nolint:gosec // opt-in, probes carry no secrets
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		syncNow: make(chan struct{}, 1),
	}
	if cfg.Primary.BaseURL != "" {
		if s.primary, err = engine.New(cfg.Primary); err != nil {
			return nil, fmt.Errorf("primary engine: %w", err)
		}
	}
	s.dashTmpl, err = template.New("dash").Parse(dashboardHTML)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// Store exposes the registry (used by tests).
func (s *Server) Store() *Store { return s.store }

// Creds exposes the enrollment tokens and node secrets (used by tests).
func (s *Server) Creds() *CredStore { return s.creds }

// Records exposes the static DNS records (used by tests).
func (s *Server) Records() *RecordStore { return s.records }

// Handler returns the HTTP routes.
func (s *Server) Handler() http.Handler {
	admin := func(h http.HandlerFunc) http.Handler { return auth.Require(h, s.cfg.AdminToken) }
	node := s.requireNode
	dns := func(h http.HandlerFunc) http.Handler { return auth.Require(h, s.cfg.DNSToken, s.cfg.AdminToken) }

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /{$}", s.dashboard)
	mux.HandleFunc("GET /v1/brand", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, s.cfg.Brand) })

	mux.Handle("POST /v1/heartbeat", node(s.heartbeat))
	mux.Handle("GET /v1/config/snapshot", node(s.snapshot))
	// Authenticated by the one-time enrollment token itself.
	mux.HandleFunc("POST /v1/enroll", s.enroll)
	mux.Handle("GET /v1/enroll-tokens", admin(func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, s.creds.ListTokens()) }))
	mux.Handle("POST /v1/enroll-tokens", admin(s.createEnrollToken))
	mux.Handle("DELETE /v1/enroll-tokens/{id}", admin(s.deleteEnrollToken))
	mux.Handle("POST /v1/nodes/{id}/rotate", admin(s.rotateNode))

	mux.Handle("GET /v1/nodes", admin(func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, s.store.List()) }))
	mux.Handle("GET /v1/nodes/{id}", admin(s.getNode))
	mux.Handle("PATCH /v1/nodes/{id}", admin(s.patchNode))
	mux.Handle("DELETE /v1/nodes/{id}", admin(s.deleteNode))
	mux.Handle("GET /v1/pools", admin(s.pools))
	mux.Handle("GET /v1/events", admin(s.listEvents))
	mux.Handle("GET /v1/sync", admin(s.syncStatus))
	mux.Handle("POST /v1/sync", admin(s.triggerSync))
	mux.Handle("GET /v1/pools/{pool}/endpoints", dns(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.store.Endpoints(r.PathValue("pool")))
	}))
	mux.Handle("GET /v1/dns/records", dns(s.listRecords))
	mux.Handle("POST /v1/dns/records", admin(s.createRecord))
	mux.Handle("GET /v1/dns/records/{id}", admin(s.getRecord))
	mux.Handle("PUT /v1/dns/records/{id}", admin(s.updateRecord))
	mux.Handle("DELETE /v1/dns/records/{id}", admin(s.deleteRecord))
	return securityHeaders(mux)
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		h.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) dashboard(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' https: data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
	if err := s.dashTmpl.Execute(w, s.cfg.Brand); err != nil {
		s.log.Error("render dashboard", "err", err)
	}
}

// validateHeartbeat checks the agent report. The probe URL must point at the
// node's own address so a node token cannot make the controller request
// arbitrary internal URLs.
func validateHeartbeat(hb *api.Heartbeat, allowLoopback bool) error {
	if !idPattern.MatchString(hb.ID) {
		return errors.New("invalid node id")
	}
	if hb.Name == "" {
		hb.Name = hb.ID
	}
	if net.ParseIP(hb.IPv4) == nil || net.ParseIP(hb.IPv4).To4() == nil {
		return errors.New("ipv4 must be a valid IPv4 address")
	}
	if hb.IPv6 != "" {
		ip := net.ParseIP(hb.IPv6)
		if ip == nil || ip.To4() != nil {
			return errors.New("ipv6 must be a valid IPv6 address")
		}
	}
	if !allowLoopback {
		for _, a := range []string{hb.IPv4, hb.IPv6} {
			if ip := net.ParseIP(a); ip != nil && reservedIP(ip) {
				return fmt.Errorf("node address %s is loopback, link-local, multicast or unspecified", a)
			}
		}
	}
	if hb.Weight < 0 || hb.Weight > 10000 {
		return errors.New("weight must be between 0 and 10000")
	}
	for _, p := range hb.Pools {
		if !idPattern.MatchString(p) {
			return fmt.Errorf("invalid pool name %q", p)
		}
	}
	if hb.ProbeURL != "" {
		u, err := url.Parse(hb.ProbeURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return errors.New("probe_url must be an http(s) URL")
		}
		host := u.Hostname()
		if host != hb.IPv4 && (hb.IPv6 == "" || !sameIP(host, hb.IPv6)) {
			return errors.New("probe_url host must be the node's ipv4 or ipv6 address")
		}
	}
	return nil
}

// reservedIP reports addresses a node can never legitimately serve from.
func reservedIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast()
}

func sameIP(a, b string) bool {
	x, y := net.ParseIP(a), net.ParseIP(b)
	return x != nil && y != nil && x.Equal(y)
}

func (s *Server) heartbeat(w http.ResponseWriter, r *http.Request) {
	var hb api.Heartbeat
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := dec.Decode(&hb); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateHeartbeat(&hb, s.cfg.AllowLoopbackNodes); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	authKind := api.AuthSharedToken
	if c := identity(r).cred; c != nil {
		// A node secret reports for its own node only, with the pools and
		// region fixed at enrollment (when the token set them).
		if hb.ID != c.NodeID {
			s.log.Warn("heartbeat for another node refused", "node", hb.ID, "secret_of", c.NodeID, "remote", r.RemoteAddr)
			http.Error(w, "this node secret belongs to node "+c.NodeID+", not "+hb.ID, http.StatusForbidden)
			return
		}
		if len(c.Pools) > 0 {
			hb.Pools = c.Pools
		}
		if c.Region != "" {
			hb.Region = c.Region
		}
		authKind = api.AuthNodeSecret
	} else {
		if _, enrolled := s.creds.Get(hb.ID); enrolled {
			s.log.Warn("shared-token heartbeat for an enrolled node refused", "node", hb.ID, "remote", r.RemoteAddr)
			http.Error(w, "node "+hb.ID+" is enrolled and must authenticate with its node secret", http.StatusForbidden)
			return
		}
		s.warnSharedToken(hb.ID)
	}
	if old, ok := s.store.Get(hb.ID); ok && !s.cfg.AllowAddressChange &&
		(!sameIP(old.IPv4, hb.IPv4) || (old.IPv6 != hb.IPv6 && !sameIP(old.IPv6, hb.IPv6))) {
		s.log.Warn("heartbeat with a changed address refused", "node", hb.ID, "ipv4", hb.IPv4, "registered", old.IPv4)
		http.Error(w, "node "+hb.ID+" is registered with another address; an admin must delete it first", http.StatusConflict)
		return
	}
	evs := hb.Events
	hb.Events = nil // events are kept in memory only, not in the node state
	if len(evs) > 200 {
		evs = evs[:200]
	}
	s.addEvents(hb.ID, evs)
	n, err := s.store.Heartbeat(hb, authKind)
	if err != nil {
		s.log.Error("persist node", "node", hb.ID, "err", err)
	}
	s.store.Evaluate(s.cfg.HeartbeatTimeout.Duration, s.cfg.ForgetAfter.Duration)
	rev := ""
	s.snapMu.RLock()
	if s.snap != nil {
		rev = s.snap.Revision
	}
	s.snapMu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{"node": n.ID, "config_revision": rev})
}

func (s *Server) addEvents(node string, evs []api.Event) {
	if len(evs) == 0 {
		return
	}
	s.evMu.Lock()
	defer s.evMu.Unlock()
	// Agents send newest first; store oldest first.
	for i := len(evs) - 1; i >= 0; i-- {
		e := evs[i]
		e.Node = node
		if len(e.URI) > 512 {
			e.URI = e.URI[:512]
		}
		if len(e.Tags) > 10 {
			e.Tags = e.Tags[:10]
		}
		s.events = append(s.events, e)
	}
	if over := len(s.events) - maxClusterEvents; over > 0 {
		s.events = append([]api.Event(nil), s.events[over:]...)
	}
}

func (s *Server) listEvents(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	node := r.URL.Query().Get("node")
	s.evMu.Lock()
	out := make([]api.Event, 0, limit)
	for i := len(s.events) - 1; i >= 0 && len(out) < limit; i-- {
		if node == "" || s.events[i].Node == node {
			out = append(out, s.events[i])
		}
	}
	s.evMu.Unlock()
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) snapshot(w http.ResponseWriter, _ *http.Request) {
	s.snapMu.RLock()
	defer s.snapMu.RUnlock()
	if s.snap == nil {
		writeJSON(w, http.StatusServiceUnavailable, SnapshotResponse{Error: "no snapshot available: " + s.snapErr})
		return
	}
	writeJSON(w, http.StatusOK, SnapshotResponse{Snapshot: s.snap, Resources: s.cfg.Primary.Resources})
}

func (s *Server) getNode(w http.ResponseWriter, r *http.Request) {
	n, ok := s.store.Get(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, n)
}

func (s *Server) patchNode(w http.ResponseWriter, r *http.Request) {
	var p api.NodePatch
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&p); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	n, err := s.store.Patch(r.PathValue("id"), p)
	if errors.Is(err, os.ErrNotExist) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.store.Evaluate(s.cfg.HeartbeatTimeout.Duration, s.cfg.ForgetAfter.Duration)
	s.log.Info("node patched", "node", n.ID, "drain", n.Drain, "weight_override", n.WeightOverride)
	n, _ = s.store.Get(n.ID)
	writeJSON(w, http.StatusOK, n)
}

// deleteNode removes the node from the registry and revokes its node secret.
// An enrolled node can only come back with a new enrollment token.
func (s *Server) deleteNode(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	revoked, err := s.creds.Revoke(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = s.store.Delete(id)
	if errors.Is(err, os.ErrNotExist) && !revoked {
		http.NotFound(w, r)
		return
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.log.Info("node deleted", "node", id, "secret_revoked", revoked)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) pools(w http.ResponseWriter, _ *http.Request) {
	seen := map[string]bool{}
	for _, n := range s.store.List() {
		if len(n.Pools) == 0 {
			seen["default"] = true
		}
		for _, p := range n.Pools {
			seen[p] = true
		}
	}
	out := make([]api.PoolEndpoints, 0, len(seen))
	for p := range seen {
		out = append(out, s.store.Endpoints(p))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Pool < out[j].Pool })
	writeJSON(w, http.StatusOK, out)
}

// listRecords serves the static DNS records. DNS servers poll it with
// If-None-Match so an unchanged set costs a 304.
func (s *Server) listRecords(w http.ResponseWriter, r *http.Request) {
	set := s.records.Set(r.URL.Query().Get("zone"))
	etag := fmt.Sprintf(`"%d"`, set.Serial)
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	writeJSON(w, http.StatusOK, set)
}

func (s *Server) getRecord(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.records.Get(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

func (s *Server) createRecord(w http.ResponseWriter, r *http.Request) {
	var rec api.DNSRecord
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&rec); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	rec, err := s.records.Create(rec)
	if err != nil {
		recordError(w, r, err)
		return
	}
	s.log.Info("dns record created", "id", rec.ID, "zone", rec.Zone, "name", rec.Name, "type", rec.Type)
	writeJSON(w, http.StatusCreated, rec)
}

func (s *Server) updateRecord(w http.ResponseWriter, r *http.Request) {
	var rec api.DNSRecord
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&rec); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	rec, err := s.records.Update(r.PathValue("id"), rec)
	if err != nil {
		recordError(w, r, err)
		return
	}
	s.log.Info("dns record updated", "id", rec.ID, "zone", rec.Zone, "name", rec.Name, "type", rec.Type)
	writeJSON(w, http.StatusOK, rec)
}

func (s *Server) deleteRecord(w http.ResponseWriter, r *http.Request) {
	if err := s.records.Delete(r.PathValue("id")); err != nil {
		recordError(w, r, err)
		return
	}
	s.log.Info("dns record deleted", "id", r.PathValue("id"))
	w.WriteHeader(http.StatusNoContent)
}

func recordError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, os.ErrNotExist):
		http.NotFound(w, r)
	case errors.Is(err, errInvalidRecord):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, errRecordConflict):
		http.Error(w, err.Error(), http.StatusConflict)
	default:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) syncStatus(w http.ResponseWriter, _ *http.Request) {
	s.snapMu.RLock()
	defer s.snapMu.RUnlock()
	st := map[string]any{"enabled": s.primary != nil, "error": s.snapErr}
	if s.snap != nil {
		counts := map[string]int{}
		for k, v := range s.snap.Resources {
			counts[k] = len(v)
		}
		st["revision"], st["created_at"], st["counts"] = s.snap.Revision, s.snap.CreatedAt, counts
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) triggerSync(w http.ResponseWriter, _ *http.Request) {
	if s.primary == nil {
		http.Error(w, "configuration replication is disabled (controller.primary.base_url is empty)", http.StatusConflict)
		return
	}
	select {
	case s.syncNow <- struct{}{}:
	default:
	}
	w.WriteHeader(http.StatusAccepted)
}

// Run starts background loops and serves HTTP until ctx is done.
func (s *Server) Run(ctx context.Context) error {
	go s.probeLoop(ctx)
	if s.primary != nil {
		go s.syncLoop(ctx)
	}
	srv := &http.Server{
		Addr:              s.cfg.Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		<-ctx.Done()
		sh, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sh)
	}()
	s.log.Info("controller listening", "addr", s.cfg.Listen, "tls", s.cfg.TLSCert != "")
	var err error
	if s.cfg.TLSCert != "" {
		err = srv.ListenAndServeTLS(s.cfg.TLSCert, s.cfg.TLSKey)
	} else {
		err = srv.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) probeLoop(ctx context.Context) {
	t := time.NewTicker(s.cfg.ProbeInterval.Duration)
	defer t.Stop()
	for {
		s.ProbeAll(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// ProbeAll probes every node that has a probe URL, then re-evaluates health.
func (s *Server) ProbeAll(ctx context.Context) {
	var wg sync.WaitGroup
	for _, n := range s.store.List() {
		if n.ProbeURL == "" {
			continue
		}
		wg.Add(1)
		go func(n *api.Node) {
			defer wg.Done()
			start := time.Now()
			ok, msg := s.probeOnce(ctx, n.ProbeURL)
			s.store.SetProbe(n.ID, ok, msg, time.Since(start))
		}(n)
	}
	wg.Wait()
	s.store.Evaluate(s.cfg.HeartbeatTimeout.Duration, s.cfg.ForgetAfter.Duration)
}

func (s *Server) probeOnce(ctx context.Context, target string) (bool, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return false, err.Error()
	}
	req.Header.Set("User-Agent", "hitechcloud-waf-cluster-probe/1")
	resp, err := s.probe.Do(req)
	if err != nil {
		return false, strings.TrimSpace(err.Error())
	}
	resp.Body.Close()
	// Any answer below 500 means the proxy is up; 4xx/403 are normal for
	// a WAF answering an unknown Host header.
	if resp.StatusCode >= 500 {
		return false, fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	return true, ""
}

func (s *Server) syncLoop(ctx context.Context) {
	t := time.NewTicker(s.cfg.SyncInterval.Duration)
	defer t.Stop()
	for {
		s.RefreshSnapshot(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.syncNow:
		}
	}
}

// RefreshSnapshot rebuilds the configuration snapshot from the primary. On
// failure the previous snapshot is kept so nodes keep their configuration.
func (s *Server) RefreshSnapshot(ctx context.Context) {
	snap, err := engine.BuildSnapshot(ctx, s.primary, s.cfg.Primary.Resources)
	s.snapMu.Lock()
	defer s.snapMu.Unlock()
	if err != nil {
		s.snapErr = err.Error()
		s.log.Warn("snapshot from primary failed", "err", err)
		return
	}
	if s.snap == nil || s.snap.Revision != snap.Revision {
		s.log.Info("new configuration snapshot", "revision", snap.Revision)
		s.snap = snap
	}
	s.snapErr = ""
}
