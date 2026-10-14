// Package e2e is the end-to-end test of the HiTechCloud WAF platform: it
// builds hcw-waf, hcw and hcwctl from this repository and runs a whole
// cluster (primary + edge engine, controller, agent, DNS, upstream) on
// loopback high ports, without Docker or root.
//
//	cd e2e && HCW_E2E=1 go test -v -count=1 ./...
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	edgeIP   = "127.0.0.2" // the edge node's "public" address
	siteHost = "shop.e2e.test"
	zoneName = "e2e.test"
	nodeID   = "edge-1"
	// sqli is a classic tautology injection (CRS 942100, libinjection).
	sqli = "id=1%27%20OR%20%271%27%3D%271"
)

type platform struct {
	*cluster
	bins binaries
	pki  *pki
	up   *upstream

	primary, edge, controller *httpAPI
	primaryToken              string
	primaryTokenFile          string
	sitePort                  int
	primarySite, edgeSite     string // host:port of the site listeners
	dnsAddr                   string
}

func TestPlatform(t *testing.T) {
	if os.Getenv("HCW_E2E") != "1" {
		t.Skip("end-to-end suite: set HCW_E2E=1 to run it (builds and starts the whole platform)")
	}
	if runtime.GOOS == "windows" {
		t.Skip("the e2e suite needs a Unix-like OS")
	}
	if l, err := net.Listen("tcp", edgeIP+":0"); err != nil {
		t.Skipf("cannot bind %s (on macOS: sudo ifconfig lo0 alias %s up): %v", edgeIP, edgeIP, err)
	} else {
		l.Close()
	}
	start := time.Now()
	p := &platform{cluster: &cluster{t: t}}
	// Deferred, so the logs are printed while the processes still run (the
	// processes are stopped by t.Cleanup afterwards).
	defer func() {
		if t.Failed() {
			p.dumpLogs()
		}
	}()
	p.setup(t)
	t.Logf("platform up in %s (work dir %s)", time.Since(start).Round(time.Millisecond), p.dir)

	var eventID string
	if !t.Run("site replicates to edge, proxies and blocks SQLi", func(t *testing.T) {
		eventID = p.testReplication(t)
	}) {
		t.FailNow() // every other scenario needs the replicated site
	}
	t.Run("event reaches the controller", func(t *testing.T) { p.testControllerEvents(t, eventID) })
	t.Run("dns pool answers the edge node", p.testDNSPool)
	t.Run("dns static record from the controller", p.testDNSStatic)
	t.Run("draining the node removes it from dns", p.testDrain)
	t.Run("hcwctl sites list and events with --ca", p.testHcwctl)
	t.Run("path normalisation on the edge", p.testPathNormalisation)
}

// setup builds the binaries and starts every component.
func (p *platform) setup(t *testing.T) {
	dir := t.TempDir()
	if os.Getenv("HCW_E2E_KEEP") == "1" {
		var err error
		if dir, err = os.MkdirTemp("", "hcw-e2e-"); err != nil {
			t.Fatal(err)
		}
		t.Logf("HCW_E2E_KEEP=1: work dir %s is kept", dir)
	}
	p.dir = dir
	p.bins = buildBinaries(t, filepath.Join(dir, "bin"))
	p.pki = newPKI(t, filepath.Join(dir, "pki"))
	p.up = startUpstream(t)

	apiPrimary := freeTCPPort(t, "127.0.0.1")
	apiEdge := freeTCPPort(t, "127.0.0.1")
	ctlPort := freeTCPPort(t, "127.0.0.1")
	p.sitePort = freeTCPPort(t, "127.0.0.1", edgeIP)
	dnsPort := freeUDPTCPPort(t, "127.0.0.1")
	p.primarySite = net.JoinHostPort("127.0.0.1", strconv.Itoa(p.sitePort))
	p.edgeSite = net.JoinHostPort(edgeIP, strconv.Itoa(p.sitePort))
	p.dnsAddr = net.JoinHostPort("127.0.0.1", strconv.Itoa(dnsPort))

	tlsClient := newTLSClient(p.pki.pool)
	secrets := filepath.Join(dir, "secrets")
	tok := func(name string) (string, string) {
		v, f := randomToken(t), filepath.Join(secrets, name+".token")
		writeFile(t, f, v+"\n")
		return v, f
	}
	var edgeToken, edgeTokenFile string
	p.primaryToken, p.primaryTokenFile = tok("primary-engine")
	edgeToken, edgeTokenFile = tok("edge-engine")
	adminToken, adminTokenFile := tok("admin")
	_, nodeTokenFile := tok("node")
	_, dnsTokenFile := tok("dns")

	// --- WAF engines -------------------------------------------------------
	engine := func(name, bind string, apiPort int, tokenFile string) string {
		data := filepath.Join(dir, name)
		cfg := filepath.Join(dir, name+".yaml")
		writeFile(t, cfg, fmt.Sprintf(`data_dir: %q
bind: %q
api:
  listen: "127.0.0.1:%d"
  token_file: %q
  tls_cert: %q
  tls_key: %q
cache_mb: -1
events_kept: 1000
access_log:
  file: %q
node_name: %q
`, data, bind, apiPort, tokenFile, p.pki.certFile, p.pki.keyFile, filepath.Join(data, "access.log"), name))
		return cfg
	}
	p.start("primary", p.bins.waf, "-config", engine("primary", "127.0.0.1", apiPrimary, p.primaryTokenFile)).
		extra = []string{filepath.Join(dir, "primary", "access.log")}
	p.start("edge", p.bins.waf, "-config", engine("edge", edgeIP, apiEdge, edgeTokenFile)).
		extra = []string{filepath.Join(dir, "edge", "access.log")}
	p.primary = &httpAPI{name: "primary", base: fmt.Sprintf("https://127.0.0.1:%d", apiPrimary), header: "X-HCW-API-TOKEN", value: p.primaryToken, client: tlsClient}
	p.edge = &httpAPI{name: "edge", base: fmt.Sprintf("https://127.0.0.1:%d", apiEdge), header: "X-HCW-API-TOKEN", value: edgeToken, client: tlsClient}
	for _, e := range []*httpAPI{p.primary, p.edge} {
		p.must(t, 30*time.Second, e.name+" engine API healthy", func() error {
			return e.json(http.MethodGet, "/api/open/health", nil, http.StatusOK, nil)
		})
	}

	// --- Controller --------------------------------------------------------
	ctlDir := filepath.Join(dir, "controller")
	ctlCfg := filepath.Join(dir, "controller.yaml")
	writeFile(t, ctlCfg, fmt.Sprintf(`controller:
  listen: "127.0.0.1:%d"
  tls_cert: %q
  tls_key: %q
  state_file: %q
  admin_token_file: %q
  node_token_file: %q
  dns_token_file: %q
  heartbeat_timeout: 10s
  probe_interval: 1s
  probe_timeout: 2s
  allow_loopback_nodes: true
  primary:
    base_url: "https://127.0.0.1:%d"
    token_file: %q
    token_header: X-HCW-API-TOKEN
    ca_file: %q
    timeout: 10s
    resources:
      - name: cert
        path: /api/open/cert
        key_fields: [domains]
        ignore_fields: [created_at, updated_at, issuer, not_after]
        prune: true
      - name: site
        path: /api/open/site
        key_fields: [server_names]
        ignore_fields: [created_at, updated_at]
        refs: {cert_id: cert}
        prune: true
  sync_interval: 1s
`, ctlPort, p.pki.certFile, p.pki.keyFile, filepath.Join(ctlDir, "state.json"),
		adminTokenFile, nodeTokenFile, dnsTokenFile, apiPrimary, p.primaryTokenFile, p.pki.caFile))
	p.start("controller", p.bins.hcw, "controller", "-config", ctlCfg)
	p.controller = &httpAPI{name: "controller", base: fmt.Sprintf("https://127.0.0.1:%d", ctlPort), header: "Authorization", value: "Bearer " + adminToken, client: tlsClient}
	p.must(t, 30*time.Second, "controller healthz", func() error {
		return p.controller.json(http.MethodGet, "/healthz", nil, http.StatusOK, nil)
	})
	p.must(t, 30*time.Second, "controller snapshot from the primary", func() error {
		var st struct {
			Revision string `json:"revision"`
			Error    string `json:"error"`
		}
		if err := p.controller.json(http.MethodGet, "/v1/sync", nil, http.StatusOK, &st); err != nil {
			return err
		}
		if st.Revision == "" {
			return fmt.Errorf("no snapshot yet (error %q)", st.Error)
		}
		return nil
	})

	// --- Agent beside the edge engine --------------------------------------
	agentCfg := filepath.Join(dir, "agent.yaml")
	writeFile(t, agentCfg, fmt.Sprintf(`agent:
  controller_url: "https://127.0.0.1:%d"
  controller_ca: %q
  node_token_file: %q
  id: %s
  name: Edge 1
  region: hn
  pools: [web]
  ipv4: %s
  weight: 100
  probe_url: "http://%s/"
  data_dir: %q
  interval: 1s
  engine:
    base_url: "https://127.0.0.1:%d"
    token_file: %q
    ca_file: %q
    timeout: 10s
  apply_config: true
`, ctlPort, p.pki.caFile, nodeTokenFile, nodeID, edgeIP, p.edgeSite, filepath.Join(dir, "agent"), apiEdge, edgeTokenFile, p.pki.caFile))
	p.start("agent", p.bins.hcw, "agent", "-config", agentCfg)
	p.must(t, 30*time.Second, "agent registered at the controller", func() error {
		var n struct {
			ID            string `json:"id"`
			EngineHealthy bool   `json:"engine_healthy"`
			EngineError   string `json:"engine_error"`
		}
		if err := p.controller.json(http.MethodGet, "/v1/nodes/"+nodeID, nil, http.StatusOK, &n); err != nil {
			return err
		}
		if !n.EngineHealthy {
			return fmt.Errorf("node %s reports its engine unhealthy: %s", n.ID, n.EngineError)
		}
		return nil
	})

	// --- DNS ---------------------------------------------------------------
	dnsCfg := filepath.Join(dir, "dns.yaml")
	writeFile(t, dnsCfg, fmt.Sprintf(`dns:
  listen: %q
  controller_url: "https://127.0.0.1:%d"
  controller_ca: %q
  token_file: %q
  refresh: 1s
  zones:
    - name: %s
      ns: [ns1.%s]
      hostmaster: noc.%s
      ttl: 5
      records:
        - {name: ns1, type: A, value: 192.0.2.53}
        - {name: edge, pool: web}
`, p.dnsAddr, ctlPort, p.pki.caFile, dnsTokenFile, zoneName, zoneName, zoneName))
	p.start("dns", p.bins.hcw, "dns", "-config", dnsCfg)
	p.must(t, 30*time.Second, "dns server answers SOA", func() error {
		r, err := dnsQuery(p.dnsAddr, zoneName, dnsTypeSOA, time.Second)
		if err != nil {
			return err
		}
		if r.Rcode != rcodeNoError || !r.Authoritative || len(r.Answer) != 1 || r.Answer[0].Type != dnsTypeSOA {
			return fmt.Errorf("unexpected SOA reply: %s", r)
		}
		return nil
	})
}

// ---------------------------------------------------------------------------
// Scenarios

type engineEvent struct {
	ID     string `json:"id"`
	Node   string `json:"node"`
	SiteID int    `json:"site_id"`
	Host   string `json:"host"`
	URI    string `json:"uri"`
	Kind   string `json:"kind"`
	Action string `json:"action"`
	Status int    `json:"status"`
	Rules  []struct {
		ID int `json:"id"`
	} `json:"rules"`
}

type siteInfo struct {
	ID          int      `json:"id"`
	Name        string   `json:"name"`
	ServerNames []string `json:"server_names"`
	Ports       []string `json:"ports"`
	Upstreams   []string `json:"upstreams"`
	Mode        string   `json:"mode"`
}

func (p *platform) engineSites(e *httpAPI) ([]siteInfo, error) {
	var env struct {
		Data struct {
			Data []siteInfo `json:"data"`
		} `json:"data"`
	}
	err := e.json(http.MethodGet, "/api/open/site", nil, http.StatusOK, &env)
	return env.Data.Data, err
}

func (p *platform) engineEvents(e *httpAPI) ([]engineEvent, error) {
	var env struct {
		Data struct {
			Data []engineEvent `json:"data"`
		} `json:"data"`
	}
	err := e.json(http.MethodGet, "/api/open/events?limit=200", nil, http.StatusOK, &env)
	return env.Data.Data, err
}

// findEvent waits for an event of kind on engine e whose URI starts with
// prefix.
func (p *platform) findEvent(t *testing.T, e *httpAPI, kind, prefix string, status int) engineEvent {
	t.Helper()
	var found engineEvent
	p.must(t, 15*time.Second, fmt.Sprintf("%s event %q for %s on %s", kind, prefix, siteHost, e.name), func() error {
		evs, err := p.engineEvents(e)
		if err != nil {
			return err
		}
		for _, ev := range evs {
			if ev.Kind == kind && ev.Action == "block" && ev.Status == status && strings.HasPrefix(ev.URI, prefix) {
				found = ev
				return nil
			}
		}
		return fmt.Errorf("not among %d events: %+v", len(evs), evs)
	})
	return found
}

func (p *platform) testReplication(t *testing.T) string {
	site := map[string]any{
		"name":         "shop",
		"server_names": []string{siteHost},
		"ports":        []string{strconv.Itoa(p.sitePort)},
		"upstreams":    []string{"http://" + p.up.addr},
		"mode":         "block",
	}
	var created struct {
		Data siteInfo `json:"data"`
	}
	if err := p.primary.json(http.MethodPost, "/api/open/site", site, http.StatusOK, &created); err != nil {
		t.Fatalf("create site on the primary: %v", err)
	}
	if created.Data.ID == 0 {
		t.Fatalf("primary returned no site id: %+v", created)
	}
	t.Logf("site %d created on the primary", created.Data.ID)

	p.must(t, 30*time.Second, "site replicated to the edge engine", func() error {
		sites, err := p.engineSites(p.edge)
		if err != nil {
			return err
		}
		for _, s := range sites {
			if slices.Contains(s.ServerNames, siteHost) {
				if !slices.Equal(s.Upstreams, site["upstreams"].([]string)) || !slices.Equal(s.Ports, site["ports"].([]string)) || s.Mode != "block" {
					return fmt.Errorf("edge has the site with different settings: %+v", s)
				}
				return nil
			}
		}
		return fmt.Errorf("edge has %d sites, none for %s: %+v", len(sites), siteHost, sites)
	})

	p.must(t, 30*time.Second, "request to the edge reaches the upstream", func() error {
		code, body, err := siteRequest(p.edgeSite, siteHost, "/hello?from=e2e")
		if err != nil {
			return err
		}
		if code != http.StatusOK || !strings.Contains(body, upstreamMarker) || !strings.Contains(body, "/hello?from=e2e") {
			return fmt.Errorf("GET http://%s/hello (Host %s): HTTP %d, body %q", p.edgeSite, siteHost, code, truncate([]byte(body), 200))
		}
		return nil
	})

	code, body, err := siteRequest(p.edgeSite, siteHost, "/search?"+sqli)
	if err != nil {
		t.Fatalf("SQLi request to the edge: %v", err)
	}
	if code != http.StatusForbidden {
		t.Fatalf("SQLi request to the edge: got HTTP %d, want 403; body %q", code, truncate([]byte(body), 300))
	}
	if p.up.sawPrefix("/search") {
		t.Fatal("the blocked SQLi request reached the upstream")
	}
	ev := p.findEvent(t, p.edge, "waf", "/search?", http.StatusForbidden)
	if len(ev.Rules) == 0 {
		t.Errorf("WAF event %s lists no matched rules: %+v", ev.ID, ev)
	}
	t.Logf("edge blocked the SQLi request: event %s, %d rules", ev.ID, len(ev.Rules))
	return ev.ID
}

func (p *platform) testControllerEvents(t *testing.T, eventID string) {
	if eventID == "" {
		t.Skip("no edge event to look for")
	}
	p.must(t, 20*time.Second, "edge WAF event listed by GET /v1/events", func() error {
		var evs []engineEvent
		if err := p.controller.json(http.MethodGet, "/v1/events?limit=100&node="+nodeID, nil, http.StatusOK, &evs); err != nil {
			return err
		}
		for _, ev := range evs {
			if ev.ID == eventID {
				if ev.Node != nodeID || ev.Kind != "waf" || ev.Action != "block" || ev.Status != http.StatusForbidden || ev.Host != siteHost {
					return fmt.Errorf("controller has event %s with unexpected fields: %+v", eventID, ev)
				}
				return nil
			}
		}
		return fmt.Errorf("event %s not among %d controller events: %+v", eventID, len(evs), evs)
	})
}

// poolAnswer queries the pool name and returns the A records.
func (p *platform) poolAnswer() ([]string, *dnsReply, error) {
	r, err := dnsQuery(p.dnsAddr, "edge."+zoneName, dnsTypeA, time.Second)
	if err != nil {
		return nil, nil, err
	}
	if r.Rcode != rcodeNoError || !r.Authoritative {
		return nil, r, fmt.Errorf("edge.%s A: %s", zoneName, r)
	}
	return r.IPv4s(), r, nil
}

func (p *platform) nodeState() string {
	_, b, err := p.controller.do(http.MethodGet, "/v1/nodes/"+nodeID, nil)
	if err != nil {
		return err.Error()
	}
	return truncate(b, 600)
}

func (p *platform) testDNSPool(t *testing.T) {
	err := p.eventually(30*time.Second, "pool name resolves to the edge node", func() error {
		ips, r, err := p.poolAnswer()
		if err != nil {
			return err
		}
		if !slices.Equal(ips, []string{edgeIP}) {
			return fmt.Errorf("edge.%s A = %v, want [%s] (%s)", zoneName, ips, edgeIP, r)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("%v\nnode at the controller: %s", err, p.nodeState())
	}
}

func (p *platform) testDNSStatic(t *testing.T) {
	name := "www." + zoneName
	r, err := dnsQuery(p.dnsAddr, name, dnsTypeA, 2*time.Second)
	if err != nil {
		t.Fatalf("query %s before the record exists: %v", name, err)
	}
	if r.Rcode != rcodeNXDomain {
		t.Fatalf("%s before the record exists: %s, want NXDOMAIN", name, r)
	}

	bad := map[string]any{"zone": zoneName, "name": "bad", "type": "A", "value": "not-an-address"}
	if err := p.controller.json(http.MethodPost, "/v1/dns/records", bad, http.StatusBadRequest, nil); err != nil {
		t.Errorf("invalid record: %v", err)
	}

	rec := map[string]any{"zone": zoneName, "name": "www", "type": "A", "value": "192.0.2.10", "ttl": 60, "comment": "e2e"}
	var created struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := p.controller.json(http.MethodPost, "/v1/dns/records", rec, http.StatusCreated, &created); err != nil {
		t.Fatalf("create static record: %v", err)
	}
	if created.ID == "" {
		t.Fatal("controller returned no record id")
	}
	var set struct {
		Serial  uint32 `json:"serial"`
		Records []struct {
			ID string `json:"id"`
		} `json:"records"`
	}
	if err := p.controller.json(http.MethodGet, "/v1/dns/records?zone="+zoneName, nil, http.StatusOK, &set); err != nil {
		t.Fatal(err)
	}
	if set.Serial == 0 || !slices.ContainsFunc(set.Records, func(r struct {
		ID string `json:"id"`
	}) bool {
		return r.ID == created.ID
	}) {
		t.Fatalf("record %s missing from GET /v1/dns/records: %+v", created.ID, set)
	}

	p.must(t, 15*time.Second, "static record served by the dns server", func() error {
		r, err := dnsQuery(p.dnsAddr, name, dnsTypeA, time.Second)
		if err != nil {
			return err
		}
		if r.Rcode != rcodeNoError || !slices.Equal(r.IPv4s(), []string{"192.0.2.10"}) {
			return fmt.Errorf("%s A: %s, want 192.0.2.10", name, r)
		}
		if r.Answer[0].TTL != 60 {
			return fmt.Errorf("%s A ttl %d, want 60", name, r.Answer[0].TTL)
		}
		return nil
	})
}

func (p *platform) setDrain(t *testing.T, drain bool) {
	t.Helper()
	var n struct {
		Drain bool `json:"drain"`
	}
	if err := p.controller.json(http.MethodPatch, "/v1/nodes/"+nodeID, map[string]any{"drain": drain}, http.StatusOK, &n); err != nil {
		t.Fatalf("drain=%v: %v", drain, err)
	}
	if n.Drain != drain {
		t.Fatalf("PATCH drain=%v answered drain=%v", drain, n.Drain)
	}
}

func (p *platform) testDrain(t *testing.T) {
	if ips, r, err := p.poolAnswer(); err != nil || !slices.Equal(ips, []string{edgeIP}) {
		t.Fatalf("before draining, edge.%s should resolve to %s: %v %v %v", zoneName, edgeIP, ips, r, err)
	}
	p.setDrain(t, true)
	t.Cleanup(func() {
		// Leave the node in service for whatever runs next.
		_ = p.controller.json(http.MethodPatch, "/v1/nodes/"+nodeID, map[string]any{"drain": false}, http.StatusOK, nil)
	})
	p.must(t, 15*time.Second, "drained node gone from dns answers", func() error {
		ips, r, err := p.poolAnswer()
		if err != nil {
			return err
		}
		if len(ips) != 0 {
			return fmt.Errorf("edge.%s still answers %v (%s)", zoneName, ips, r)
		}
		return nil
	})
	var pe struct {
		Endpoints []struct {
			NodeID string `json:"node_id"`
		} `json:"endpoints"`
	}
	if err := p.controller.json(http.MethodGet, "/v1/pools/web/endpoints", nil, http.StatusOK, &pe); err != nil {
		t.Fatal(err)
	}
	if len(pe.Endpoints) != 0 {
		t.Errorf("drained node still listed as a pool endpoint: %+v", pe)
	}

	p.setDrain(t, false)
	p.must(t, 15*time.Second, "node back in dns answers after undrain", func() error {
		ips, r, err := p.poolAnswer()
		if err != nil {
			return err
		}
		if !slices.Equal(ips, []string{edgeIP}) {
			return fmt.Errorf("edge.%s A = %v after undrain (%s)", zoneName, ips, r)
		}
		return nil
	})
}

// hcwctl runs the CLI with an isolated profile file.
func (p *platform) hcwctl(args ...string) (stdout, stderr string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, p.bins.hcwctl, args...)
	cmd.Dir = p.dir
	cmd.Env = childEnv("HCWCTL_CONFIG=" + filepath.Join(p.dir, "hcwctl", "config.json"))
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	err = cmd.Run()
	return o.String(), e.String(), err
}

func (p *platform) testHcwctl(t *testing.T) {
	url := p.primary.base

	// Without --ca the test CA is not trusted: login must refuse.
	if out, errOut, err := p.hcwctl("login", "--url", url, "--token-file", p.primaryTokenFile); err == nil {
		t.Errorf("hcwctl login without --ca succeeded against a private CA:\n%s%s", out, errOut)
	} else if !strings.Contains(errOut, "--ca") {
		t.Errorf("hcwctl login without --ca: want a hint about --ca, got %v:\n%s", err, errOut)
	}

	if out, errOut, err := p.hcwctl("login", "--url", url, "--ca", p.pki.caFile, "--token-file", p.primaryTokenFile); err != nil {
		t.Fatalf("hcwctl login --ca: %v\nstdout: %s\nstderr: %s", err, out, errOut)
	}

	out, errOut, err := p.hcwctl("sites", "list")
	if err != nil {
		t.Fatalf("hcwctl sites list: %v\nstderr: %s", err, errOut)
	}
	if !strings.Contains(out, siteHost) || !strings.Contains(out, strconv.Itoa(p.sitePort)) {
		t.Errorf("hcwctl sites list does not show %s on port %d:\n%s", siteHost, p.sitePort, out)
	}

	// An attack on the primary itself, so its event log has something.
	code, body, err := siteRequest(p.primarySite, siteHost, "/primary-probe?"+sqli)
	if err != nil || code != http.StatusForbidden {
		t.Fatalf("SQLi to the primary site: HTTP %d, err %v, body %q", code, err, truncate([]byte(body), 200))
	}
	p.findEvent(t, p.primary, "waf", "/primary-probe?", http.StatusForbidden)

	out, errOut, err = p.hcwctl("events", "--limit", "20")
	if err != nil {
		t.Fatalf("hcwctl events: %v\nstderr: %s", err, errOut)
	}
	if !strings.Contains(out, "/primary-probe") || !strings.Contains(out, "waf") {
		t.Errorf("hcwctl events does not list the blocked request:\n%s", out)
	}

	out, errOut, err = p.hcwctl("-o", "json", "events")
	if err != nil {
		t.Fatalf("hcwctl -o json events: %v\nstderr: %s", err, errOut)
	}
	var evs []engineEvent
	if err := json.Unmarshal([]byte(out), &evs); err != nil {
		t.Fatalf("hcwctl -o json events is not a JSON array: %v\n%s", err, out)
	}
	if !slices.ContainsFunc(evs, func(e engineEvent) bool { return e.Kind == "waf" && strings.HasPrefix(e.URI, "/primary-probe") }) {
		t.Errorf("hcwctl -o json events lacks the WAF event: %+v", evs)
	}
}

func (p *platform) testPathNormalisation(t *testing.T) {
	for _, target := range []string{"/static/../admin", "/static/./admin", "/static//admin"} {
		code, err := rawHTTP(p.edgeSite, siteHost, target)
		if err != nil {
			t.Fatalf("GET %s on the edge: %v", target, err)
		}
		if code != http.StatusBadRequest {
			t.Errorf("GET %s on the edge: HTTP %d, want 400", target, code)
		}
	}
	if p.up.sawPrefix("/admin") || p.up.sawPrefix("/static") {
		t.Error("a non-canonical path reached the upstream")
	}
	p.findEvent(t, p.edge, "bad_path", "/static/../admin", http.StatusBadRequest)
	// A canonical path still works.
	if code, body, err := siteRequest(p.edgeSite, siteHost, "/static/app.css"); err != nil || code != http.StatusOK {
		t.Errorf("GET /static/app.css on the edge: HTTP %d, err %v, body %q", code, err, truncate([]byte(body), 200))
	}
}
