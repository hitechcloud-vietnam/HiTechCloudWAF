package mgmt

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/audit"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/events"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/model"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/store"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/users"
)

func setupAudit(t *testing.T) (*httptest.Server, *audit.Log, *store.Store, *[]model.Site) {
	t.Helper()
	dir := t.TempDir()
	st, _ := store.Open(filepath.Join(dir, "c.json"))
	us, _ := users.Open(filepath.Join(dir, "u.json"))
	al, _ := audit.New(filepath.Join(dir, "audit.log"), 100)
	ev, _ := events.New(10, "")
	applied := &[]model.Site{}
	api := &API{Token: token, Store: st, Users: us, Audit: al, Events: ev, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Apply: func(s []model.Site, _ []model.Cert) error { *applied = s; return nil }}
	ts := httptest.NewServer(api.Handler())
	t.Cleanup(ts.Close)
	return ts, al, st, applied
}

func TestAuditRecordsChangesAndRedacts(t *testing.T) {
	ts, al, _, _ := setupAudit(t)
	call(t, ts, "POST", "/api/open/users", map[string]string{"username": "quantri", "password": "Mat-khau-dai-2026", "role": "admin"}, token)
	call(t, ts, "POST", "/api/open/users", map[string]string{"username": "xem", "password": "Mat-khau-dai-2026", "role": "viewer"}, token)
	_, sess, _ := login(t, ts, "quantri", "Mat-khau-dai-2026", "")
	login(t, ts, "quantri", "sai-mat-khau-roi", "")
	site := map[string]any{"server_names": []string{"a.vn"}, "upstreams": []string{"http://1.1.1.1"},
		"auth": map[string]any{"enabled": true, "password": "Bi-mat-cua-site"}}
	if code, _ := req(t, ts, "POST", "/api/open/site", sess, site); code != 200 {
		t.Fatalf("create: %d", code)
	}
	call(t, ts, "GET", "/api/open/site", nil, token) // reads are not audited

	entries := al.Latest(10)
	if len(entries) != 5 {
		t.Fatalf("entries = %d: %+v", len(entries), entries)
	}
	last := entries[0]
	if last.User != "quantri" || last.Action != "POST /api/open/site" || last.Status != 200 || last.IP != "127.0.0.1" {
		t.Fatalf("last = %+v", last)
	}
	raw, _ := json.Marshal(entries)
	if strings.Contains(string(raw), "Bi-mat-cua-site") || strings.Contains(string(raw), "Mat-khau-dai-2026") {
		t.Fatalf("secret leaked into audit log: %s", raw)
	}
	if entries[1].Action != "login" || entries[1].Status != 401 || entries[2].Status != 200 {
		t.Fatalf("login entries = %+v %+v", entries[1], entries[2])
	}

	_, viewer, _ := login(t, ts, "xem", "Mat-khau-dai-2026", "")
	for _, p := range []string{"/api/open/audit", "/api/open/backup"} {
		if code, _ := req(t, ts, "GET", p, viewer, nil); code != 403 {
			t.Fatalf("viewer %s: %d", p, code)
		}
	}
	if code, env := req(t, ts, "GET", "/api/open/audit", sess, nil); code != 200 || env.Data.(map[string]any)["total"].(float64) < 5 {
		t.Fatalf("audit list: %d", code)
	}
}

func TestBackupRestore(t *testing.T) {
	ts, _, st, applied := setupAudit(t)
	for _, n := range []string{"a.vn", "b.vn"} {
		call(t, ts, "POST", "/api/open/site", map[string]any{"server_names": []string{n}, "upstreams": []string{"http://1.1.1.1"}}, token)
	}
	_, env := call(t, ts, "GET", "/api/open/backup", nil, token)
	backup, _ := json.Marshal(env.Data)

	call(t, ts, "DELETE", "/api/open/site", map[string]any{"ids": []int{1}}, token)
	if len(st.Sites()) != 1 {
		t.Fatal("delete failed")
	}
	var b map[string]any
	_ = json.Unmarshal(backup, &b)
	if code, env := call(t, ts, "POST", "/api/open/restore", b, token); code != 200 {
		t.Fatalf("restore: %d %+v", code, env)
	}
	if len(st.Sites()) != 2 || st.Sites()[0].ServerNames[0] != "a.vn" || len(*applied) != 2 {
		t.Fatalf("after restore: %+v", st.Sites())
	}
	// IDs continue after the restored ones.
	_, env = call(t, ts, "POST", "/api/open/site", map[string]any{"server_names": []string{"c.vn"}, "upstreams": []string{"http://1.1.1.1"}}, token)
	if id := env.Data.(map[string]any)["id"].(float64); id != 3 {
		t.Fatalf("new id after restore = %v", id)
	}

	// A broken backup is refused and the running configuration stays.
	bad := map[string]any{"version": 1, "sites": []any{
		map[string]any{"id": 1, "server_names": []string{"x.vn"}, "upstreams": []string{"http://1.1.1.1"}},
		map[string]any{"id": 2, "server_names": []string{"x.vn"}, "upstreams": []string{"http://1.1.1.1"}},
	}}
	if code, _ := call(t, ts, "POST", "/api/open/restore", bad, token); code != 400 {
		t.Fatalf("conflicting backup accepted: %d", code)
	}
	if len(st.Sites()) != 3 {
		t.Fatalf("configuration changed by a refused restore: %d sites", len(st.Sites()))
	}
}
