package agent

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/api"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/config"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/controller"
)

func TestAgentEnrollsOnceAndRotates(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctl, err := controller.New(&config.Controller{
		StateFile: filepath.Join(t.TempDir(), "s.json"), AdminToken: "a", RequireEnrollment: true,
		HeartbeatTimeout: config.Duration{Duration: time.Minute}, ProbeTimeout: config.Duration{Duration: time.Second},
	}, logger)
	if err != nil {
		t.Fatal(err)
	}
	var enrolls atomic.Int32
	h := ctl.Handler()
	cs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/enroll" {
			enrolls.Add(1)
		}
		h.ServeHTTP(w, r)
	}))
	defer cs.Close()

	tok, err := ctl.Creds().CreateToken(api.EnrollTokenRequest{NodeID: "edge-1", Pools: []string{"web"}})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	tokFile := filepath.Join(dir, "enroll.token")
	if err := os.WriteFile(tokFile, []byte(tok.Token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(dir, "data")
	newAgent := func() *Agent {
		t.Helper()
		// No id configured: the node takes the ID bound to the token.
		a, err := New(&config.Agent{
			ControllerURL: cs.URL, EnrollTokenFile: tokFile, IPv4: "203.0.113.10",
			DataDir: dataDir, Interval: config.Duration{Duration: time.Second},
		}, logger)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}

	a := newAgent()
	if err := a.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a.cfg.ID != "edge-1" || enrolls.Load() != 1 {
		t.Fatalf("id=%q enrolls=%d", a.cfg.ID, enrolls.Load())
	}
	n, ok := ctl.Store().Get("edge-1")
	if !ok || n.Auth != api.AuthNodeSecret || n.Pools[0] != "web" {
		t.Fatalf("node = %+v", n)
	}
	fi, err := os.Stat(filepath.Join(dataDir, "node-credential.json"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("stored secret: %v %v", fi, err)
	}
	first := a.cred.Secret

	// Restart: the stored secret is reused, the spent token is not sent again.
	a = newAgent()
	if a.cfg.ID != "edge-1" || a.cred == nil || a.cred.Secret != first {
		t.Fatalf("restart lost the credential: id=%q", a.cfg.ID)
	}
	for range 2 {
		if err := a.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if enrolls.Load() != 1 {
		t.Fatalf("agent enrolled again on restart: %d", enrolls.Load())
	}

	// Rotation: a new token dropped in the file is picked up without restart.
	rot, err := ctl.Creds().CreateToken(api.EnrollTokenRequest{NodeID: "edge-1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokFile, []byte(rot.Token), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if enrolls.Load() != 2 || a.cred.Secret == first {
		t.Fatalf("rotation not applied: enrolls=%d", enrolls.Load())
	}
	if _, ok := ctl.Creds().Authenticate(first); ok {
		t.Fatal("old secret still valid after rotation")
	}

	// Revoked by an admin: the agent reports it and does not retry the
	// spent token.
	if _, err := ctl.Creds().Revoke("edge-1"); err != nil {
		t.Fatal(err)
	}
	if err := a.Tick(context.Background()); err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("revoked secret: %v", err)
	}
	if enrolls.Load() != 2 {
		t.Fatalf("spent token retried: %d", enrolls.Load())
	}
}

func TestAgentRefusedTokenFallsBackToNodeToken(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctl, err := controller.New(&config.Controller{
		StateFile: filepath.Join(t.TempDir(), "s.json"), AdminToken: "a", NodeToken: "n",
		HeartbeatTimeout: config.Duration{Duration: time.Minute}, ProbeTimeout: config.Duration{Duration: time.Second},
	}, logger)
	if err != nil {
		t.Fatal(err)
	}
	cs := httptest.NewServer(ctl.Handler())
	defer cs.Close()
	a, err := New(&config.Agent{
		ControllerURL: cs.URL, NodeToken: "n", EnrollToken: "hcwe_bogus", ID: "legacy-1", IPv4: "203.0.113.11",
		DataDir: t.TempDir(), Interval: config.Duration{Duration: time.Second},
	}, logger)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n, _ := ctl.Store().Get("legacy-1"); n.Auth != api.AuthSharedToken {
		t.Fatalf("node = %+v", n)
	}

	// Without any token or stored secret the agent refuses to start.
	if _, err := New(&config.Agent{ControllerURL: cs.URL, EnrollTokenFile: filepath.Join(t.TempDir(), "missing"),
		IPv4: "203.0.113.12", DataDir: t.TempDir()}, logger); err == nil {
		t.Fatal("agent without credentials started")
	}
}
