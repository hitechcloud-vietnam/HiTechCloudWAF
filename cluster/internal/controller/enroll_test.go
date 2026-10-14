package controller

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/api"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/config"
)

func decode[T any](t *testing.T, r io.Reader) T {
	t.Helper()
	var v T
	if err := json.NewDecoder(r).Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// newToken creates an enrollment token through the admin API.
func newToken(t *testing.T, ts *httptest.Server, req api.EnrollTokenRequest) api.EnrollToken {
	t.Helper()
	r := do(t, ts, "POST", "/v1/enroll-tokens", "admin", req)
	if r.StatusCode != 201 {
		b, _ := io.ReadAll(r.Body)
		t.Fatalf("create enroll token: %d %s", r.StatusCode, b)
	}
	return decode[api.EnrollToken](t, r.Body)
}

// enroll exchanges token for a node secret and expects code.
func enroll(t *testing.T, ts *httptest.Server, token string, req api.EnrollRequest, code int) api.EnrollResponse {
	t.Helper()
	r := do(t, ts, "POST", "/v1/enroll", token, req)
	if r.StatusCode != code {
		b, _ := io.ReadAll(r.Body)
		t.Fatalf("enroll: got %d (%s), want %d", r.StatusCode, b, code)
	}
	if code != 200 {
		return api.EnrollResponse{}
	}
	return decode[api.EnrollResponse](t, r.Body)
}

func status(t *testing.T, ts *httptest.Server, method, path, token string, body any) int {
	t.Helper()
	return do(t, ts, method, path, token, body).StatusCode
}

func TestEnrollHappyPathAndReuse(t *testing.T) {
	s, ts := newTestServer(t)
	req := api.EnrollTokenRequest{NodeID: "edge-1", Pools: []string{"web"}, Region: "hn", Comment: "rack 3"}
	if c := status(t, ts, "POST", "/v1/enroll-tokens", "node", req); c != 401 {
		t.Fatalf("node token created an enrollment token: %d", c)
	}
	tok := newToken(t, ts, req)
	if !strings.HasPrefix(tok.Token, "hcwe_"+tok.ID+"_") || tok.Status != "active" || tok.ExpiresAt.Sub(tok.CreatedAt) != 24*time.Hour {
		t.Fatalf("token = %+v", tok)
	}
	list := decode[[]api.EnrollToken](t, do(t, ts, "GET", "/v1/enroll-tokens", "admin", nil).Body)
	if len(list) != 1 || list[0].Token != "" || list[0].NodeID != "edge-1" {
		t.Fatalf("list leaks the token or lost it: %+v", list)
	}

	res := enroll(t, ts, tok.Token, api.EnrollRequest{Hostname: "whatever"}, 200)
	if res.NodeID != "edge-1" || !strings.HasPrefix(res.Secret, "hcwn_") || len(res.Pools) != 1 || res.Region != "hn" {
		t.Fatalf("enroll = %+v", res)
	}
	// One time only.
	enroll(t, ts, tok.Token, api.EnrollRequest{Hostname: "whatever"}, 401)
	enroll(t, ts, "hcwe_0000000000000000_"+strings.Repeat("0", 64), api.EnrollRequest{ID: "x"}, 401)
	enroll(t, ts, "node", api.EnrollRequest{ID: "x"}, 401)
	list = decode[[]api.EnrollToken](t, do(t, ts, "GET", "/v1/enroll-tokens", "admin", nil).Body)
	if list[0].Status != "used" || list[0].UsedBy != "edge-1" || list[0].UsedAt == nil {
		t.Fatalf("used token = %+v", list[0])
	}

	// The secret authenticates the node; pools and region come from the token.
	h := hb("edge-1", "203.0.113.1", "elsewhere", "other")
	if c := status(t, ts, "POST", "/v1/heartbeat", res.Secret, h); c != 200 {
		t.Fatalf("heartbeat with node secret: %d", c)
	}
	n, _ := s.Store().Get("edge-1")
	if n.Auth != api.AuthNodeSecret || n.Region != "hn" || len(n.Pools) != 1 || n.Pools[0] != "web" {
		t.Fatalf("node = %+v", n)
	}
	if c := status(t, ts, "GET", "/v1/config/snapshot", res.Secret, nil); c != 503 {
		t.Fatalf("snapshot with node secret: %d (want 503, no snapshot yet)", c)
	}
	if c := status(t, ts, "GET", "/v1/nodes", res.Secret, nil); c != 401 {
		t.Fatalf("node secret reached the admin API: %d", c)
	}

	// Only hashes are stored, in a file readable by the owner only.
	path := filepath.Join(filepath.Dir(s.cfg.StateFile), "node-credentials.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), res.Secret) || strings.Contains(string(b), tok.Token) {
		t.Fatal("credentials file contains a plaintext secret")
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("credentials file mode %v", fi.Mode().Perm())
	}
}

func TestEnrollBindingAndWrongID(t *testing.T) {
	s, ts := newTestServer(t)
	bound := newToken(t, ts, api.EnrollTokenRequest{NodeID: "edge-1"})
	// A token bound to edge-1 cannot enroll edge-2, and stays usable.
	enroll(t, ts, bound.Token, api.EnrollRequest{ID: "edge-2"}, 403)
	one := enroll(t, ts, bound.Token, api.EnrollRequest{ID: "edge-1"}, 200)

	// An unbound token takes the agent's id or hostname...
	free := newToken(t, ts, api.EnrollTokenRequest{})
	two := enroll(t, ts, free.Token, api.EnrollRequest{Hostname: "Edge-2"}, 200)
	if two.NodeID != "edge-2" {
		t.Fatalf("hostname not used as node id: %+v", two)
	}
	// ...but never an id that holds an active secret.
	free2 := newToken(t, ts, api.EnrollTokenRequest{})
	enroll(t, ts, free2.Token, api.EnrollRequest{ID: "edge-1"}, 409)
	enroll(t, ts, free2.Token, api.EnrollRequest{Hostname: "../etc"}, 400)

	// A node secret only reports for its own node.
	if c := status(t, ts, "POST", "/v1/heartbeat", one.Secret, hb("edge-2", "203.0.113.2", "hn")); c != 403 {
		t.Fatalf("heartbeat for another node: %d", c)
	}
	if c := status(t, ts, "POST", "/v1/heartbeat", one.Secret, hb("edge-1", "203.0.113.1", "hn")); c != 200 {
		t.Fatalf("own heartbeat: %d", c)
	}
	// The shared token cannot speak for an enrolled node any more...
	if c := status(t, ts, "POST", "/v1/heartbeat", "node", hb("edge-1", "203.0.113.1", "hn")); c != 403 {
		t.Fatalf("shared token for an enrolled node: %d", c)
	}
	// ...but still works (deprecated) for nodes that have not enrolled.
	if c := status(t, ts, "POST", "/v1/heartbeat", "node", hb("legacy-1", "203.0.113.9", "hn")); c != 200 {
		t.Fatalf("shared token for a legacy node: %d", c)
	}
	if n, _ := s.Store().Get("legacy-1"); n.Auth != api.AuthSharedToken {
		t.Fatalf("legacy node auth = %q", n.Auth)
	}
	// Bad requests.
	for _, req := range []api.EnrollTokenRequest{{NodeID: "../x"}, {Pools: []string{"a b"}}, {ExpiresIn: -1}, {ExpiresIn: 31 * 86400}} {
		if c := status(t, ts, "POST", "/v1/enroll-tokens", "admin", req); c != 400 {
			t.Fatalf("invalid token request %+v accepted: %d", req, c)
		}
	}
}

func TestEnrollTokenExpiry(t *testing.T) {
	s, ts := newTestServer(t)
	tok := newToken(t, ts, api.EnrollTokenRequest{ExpiresIn: 60})
	s.creds.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	enroll(t, ts, tok.Token, api.EnrollRequest{ID: "edge-1"}, 401)
	list := decode[[]api.EnrollToken](t, do(t, ts, "GET", "/v1/enroll-tokens", "admin", nil).Body)
	if len(list) != 1 || list[0].Status != "expired" {
		t.Fatalf("list = %+v", list)
	}
	// Expired tokens are forgotten a week after expiry.
	s.creds.now = func() time.Time { return time.Now().Add(8 * 24 * time.Hour) }
	newToken(t, ts, api.EnrollTokenRequest{})
	if list := s.creds.ListTokens(); len(list) != 1 || list[0].ID == tok.ID {
		t.Fatalf("expired token kept: %+v", list)
	}
}

func TestRevokeAndRotate(t *testing.T) {
	s, ts := newTestServer(t)
	tok := newToken(t, ts, api.EnrollTokenRequest{NodeID: "edge-1", Pools: []string{"web"}})
	res := enroll(t, ts, tok.Token, api.EnrollRequest{}, 200)
	if c := status(t, ts, "POST", "/v1/heartbeat", res.Secret, hb("edge-1", "203.0.113.1", "hn")); c != 200 {
		t.Fatalf("heartbeat: %d", c)
	}

	// Rotation: a token bound to the node, keeping its pools; the old secret
	// works until the new token is used.
	r := do(t, ts, "POST", "/v1/nodes/edge-1/rotate", "admin", nil)
	if r.StatusCode != 201 {
		t.Fatalf("rotate: %d", r.StatusCode)
	}
	rot := decode[api.EnrollToken](t, r.Body)
	if rot.NodeID != "edge-1" || len(rot.Pools) != 1 || rot.Token == "" {
		t.Fatalf("rotate token = %+v", rot)
	}
	if c := status(t, ts, "POST", "/v1/heartbeat", res.Secret, hb("edge-1", "203.0.113.1", "hn")); c != 200 {
		t.Fatalf("old secret before rotation: %d", c)
	}
	res2 := enroll(t, ts, rot.Token, api.EnrollRequest{ID: "edge-1"}, 200)
	if c := status(t, ts, "POST", "/v1/heartbeat", res.Secret, hb("edge-1", "203.0.113.1", "hn")); c != 401 {
		t.Fatalf("old secret after rotation: %d", c)
	}
	if c := status(t, ts, "POST", "/v1/heartbeat", res2.Secret, hb("edge-1", "203.0.113.1", "hn")); c != 200 {
		t.Fatalf("new secret: %d", c)
	}
	if c := status(t, ts, "POST", "/v1/nodes/ghost/rotate", "admin", nil); c != 404 {
		t.Fatalf("rotate unknown node: %d", c)
	}

	// Delete revokes the secret; the shared token cannot bring it back.
	if c := status(t, ts, "DELETE", "/v1/nodes/edge-1", "admin", nil); c != 204 {
		t.Fatalf("delete: %d", c)
	}
	if c := status(t, ts, "POST", "/v1/heartbeat", res2.Secret, hb("edge-1", "203.0.113.1", "hn")); c != 401 {
		t.Fatalf("revoked secret accepted: %d", c)
	}
	if c := status(t, ts, "POST", "/v1/heartbeat", "node", hb("edge-1", "203.0.113.1", "hn")); c != 403 {
		t.Fatalf("shared token revived a revoked node: %d", c)
	}
	if _, ok := s.Store().Get("edge-1"); ok {
		t.Fatal("node still registered")
	}
	if c := status(t, ts, "DELETE", "/v1/nodes/edge-1", "admin", nil); c != 404 {
		t.Fatalf("second delete: %d", c)
	}
	// A revoked node comes back with a new token, even an unbound one.
	again := newToken(t, ts, api.EnrollTokenRequest{})
	res3 := enroll(t, ts, again.Token, api.EnrollRequest{ID: "edge-1"}, 200)
	if c := status(t, ts, "POST", "/v1/heartbeat", res3.Secret, hb("edge-1", "203.0.113.1", "hn")); c != 200 {
		t.Fatalf("re-enrolled node: %d", c)
	}

	// Revoking an unused enrollment token.
	unused := newToken(t, ts, api.EnrollTokenRequest{})
	if c := status(t, ts, "DELETE", "/v1/enroll-tokens/"+unused.ID, "admin", nil); c != 204 {
		t.Fatalf("revoke token: %d", c)
	}
	enroll(t, ts, unused.Token, api.EnrollRequest{ID: "edge-9"}, 401)
	if c := status(t, ts, "DELETE", "/v1/enroll-tokens/"+unused.ID, "admin", nil); c != 404 {
		t.Fatalf("revoke unknown token: %d", c)
	}

	// revoke_current cuts the node off at once.
	r = do(t, ts, "POST", "/v1/nodes/edge-1/rotate", "admin", api.RotateRequest{RevokeCurrent: true, ExpiresIn: 600})
	if r.StatusCode != 201 {
		t.Fatalf("rotate with revoke: %d", r.StatusCode)
	}
	if c := status(t, ts, "POST", "/v1/heartbeat", res3.Secret, hb("edge-1", "203.0.113.1", "hn")); c != 401 {
		t.Fatalf("secret still valid after revoke_current: %d", c)
	}
}

func TestRequireEnrollment(t *testing.T) {
	s, ts := newTestServer(t)
	s.cfg.RequireEnrollment = true
	if c := status(t, ts, "POST", "/v1/heartbeat", "node", hb("legacy-1", "203.0.113.9", "hn")); c != 401 {
		t.Fatalf("shared token accepted with require_enrollment: %d", c)
	}
	if c := status(t, ts, "GET", "/v1/config/snapshot", "node", nil); c != 401 {
		t.Fatalf("shared token read the snapshot with require_enrollment: %d", c)
	}
	tok := newToken(t, ts, api.EnrollTokenRequest{})
	res := enroll(t, ts, tok.Token, api.EnrollRequest{ID: "edge-1"}, 200)
	if c := status(t, ts, "POST", "/v1/heartbeat", res.Secret, hb("edge-1", "203.0.113.1", "hn")); c != 200 {
		t.Fatalf("enrolled node refused: %d", c)
	}
}

func TestCredentialsSurviveRestart(t *testing.T) {
	dir := t.TempDir()
	cfg := func() *config.Controller {
		return &config.Controller{
			StateFile: filepath.Join(dir, "state.json"), AdminToken: "admin", NodeToken: "node",
			HeartbeatTimeout: config.Duration{Duration: time.Minute}, ProbeTimeout: config.Duration{Duration: time.Second},
		}
	}
	start := func() *httptest.Server {
		s, err := New(cfg(), slog.New(slog.NewTextHandler(io.Discard, nil)))
		if err != nil {
			t.Fatal(err)
		}
		ts := httptest.NewServer(s.Handler())
		t.Cleanup(ts.Close)
		return ts
	}
	ts := start()
	used := newToken(t, ts, api.EnrollTokenRequest{NodeID: "edge-1", Region: "hn"})
	pending := newToken(t, ts, api.EnrollTokenRequest{})
	res := enroll(t, ts, used.Token, api.EnrollRequest{}, 200)
	revokedTok := newToken(t, ts, api.EnrollTokenRequest{})
	gone := enroll(t, ts, revokedTok.Token, api.EnrollRequest{ID: "edge-2"}, 200)
	if c := status(t, ts, "DELETE", "/v1/nodes/edge-2", "admin", nil); c != 204 {
		t.Fatalf("delete: %d", c)
	}
	ts.Close()

	ts = start()
	if c := status(t, ts, "POST", "/v1/heartbeat", res.Secret, hb("edge-1", "203.0.113.1", "x")); c != 200 {
		t.Fatalf("secret lost on restart: %d", c)
	}
	if c := status(t, ts, "POST", "/v1/heartbeat", gone.Secret, hb("edge-2", "203.0.113.2", "x")); c != 401 {
		t.Fatalf("revocation lost on restart: %d", c)
	}
	if c := status(t, ts, "POST", "/v1/heartbeat", "node", hb("edge-2", "203.0.113.2", "x")); c != 403 {
		t.Fatalf("tombstone lost on restart: %d", c)
	}
	enroll(t, ts, used.Token, api.EnrollRequest{}, 401)
	enroll(t, ts, pending.Token, api.EnrollRequest{ID: "edge-3"}, 200)
}
