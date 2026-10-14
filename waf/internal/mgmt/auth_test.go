package mgmt

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/events"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/model"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/store"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/users"
)

func setupUsers(t *testing.T) (*httptest.Server, *users.Store) {
	t.Helper()
	st, _ := store.Open(filepath.Join(t.TempDir(), "c.json"))
	us, _ := users.Open(filepath.Join(t.TempDir(), "u.json"))
	ev, _ := events.New(10, "")
	api := &API{Token: token, Store: st, Users: us, Events: ev, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Apply: func([]model.Site, []model.Cert) error { return nil }}
	ts := httptest.NewServer(api.Handler())
	t.Cleanup(ts.Close)
	return ts, us
}

func req(t *testing.T, ts *httptest.Server, method, path, session string, body any) (int, envelope) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	r, _ := http.NewRequest(method, ts.URL+path, rd)
	if session != "" {
		r.Header.Set(SessionHeader, session)
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var env envelope
	_ = json.NewDecoder(resp.Body).Decode(&env)
	return resp.StatusCode, env
}

func login(t *testing.T, ts *httptest.Server, user, pass, otp string) (int, string, string) {
	code, env := req(t, ts, "POST", "/api/auth/login", "", map[string]string{"username": user, "password": pass, "otp": otp})
	if code != 200 {
		e := ""
		if env.Err != nil {
			e = *env.Err
		}
		return code, "", e
	}
	return code, env.Data.(map[string]any)["token"].(string), ""
}

func TestRolesThroughAPI(t *testing.T) {
	ts, _ := setupUsers(t)
	// The API token creates the first accounts.
	if code, _ := call(t, ts, "POST", "/api/open/users", map[string]string{"username": "admin", "password": "Mat-khau-dai-2026", "role": "admin"}, token); code != 200 {
		t.Fatalf("create admin: %d", code)
	}
	call(t, ts, "POST", "/api/open/users", map[string]string{"username": "xem", "password": "Mat-khau-dai-2026", "role": "viewer"}, token)

	_, viewer, _ := login(t, ts, "xem", "Mat-khau-dai-2026", "")
	if code, _ := req(t, ts, "GET", "/api/open/site", viewer, nil); code != 200 {
		t.Fatalf("viewer read: %d", code)
	}
	site := map[string]any{"server_names": []string{"a.vn"}, "upstreams": []string{"http://1.1.1.1"}}
	if code, _ := req(t, ts, "POST", "/api/open/site", viewer, site); code != 403 {
		t.Fatalf("viewer write: %d", code)
	}
	if code, _ := req(t, ts, "POST", "/api/open/users", viewer, map[string]string{"username": "evil", "password": "Mat-khau-dai-2026", "role": "admin"}); code != 403 {
		t.Fatalf("viewer created a user: %d", code)
	}
	_, admin, _ := login(t, ts, "admin", "Mat-khau-dai-2026", "")
	if code, _ := req(t, ts, "POST", "/api/open/site", admin, site); code != 200 {
		t.Fatalf("admin write: %d", code)
	}
	if code, _ := req(t, ts, "GET", "/api/open/users", admin, nil); code != 200 {
		t.Fatal("admin list users")
	}
	// Logout invalidates the session.
	req(t, ts, "POST", "/api/auth/logout", admin, nil)
	if code, _ := req(t, ts, "GET", "/api/open/site", admin, nil); code != 401 {
		t.Fatalf("session after logout: %d", code)
	}
}

func TestTOTPThroughAPIAndLockout(t *testing.T) {
	ts, us := setupUsers(t)
	_ = us.Create("anh", "Mat-khau-dai-2026", users.RoleAdmin)
	_, sess, _ := login(t, ts, "anh", "Mat-khau-dai-2026", "")
	code, env := req(t, ts, "POST", "/api/open/me/totp/setup", sess, nil)
	if code != 200 {
		t.Fatalf("setup: %d", code)
	}
	d := env.Data.(map[string]any)
	if d["qr"].(string)[:22] != "data:image/png;base64," {
		t.Fatal("no QR image")
	}
	otp, _ := users.TOTPCode(d["secret"].(string), time.Now())
	if code, _ := req(t, ts, "POST", "/api/open/me/totp/enable", sess, map[string]string{"code": otp}); code != 200 {
		t.Fatalf("enable: %d", code)
	}
	if code, _, e := login(t, ts, "anh", "Mat-khau-dai-2026", ""); code != 401 || e != "otp_required" {
		t.Fatalf("login without otp: %d %s", code, e)
	}
	// The API token has no account.
	if code, _ := call(t, ts, "POST", "/api/open/me/totp/setup", nil, token); code != 400 {
		t.Fatalf("token me: %d", code)
	}
	// Ten failures lock the address, even for the right password.
	for i := 0; i < 10; i++ {
		login(t, ts, "anh", "wrong-password-x", "")
	}
	if code, _, e := login(t, ts, "anh", "Mat-khau-dai-2026", ""); code != 429 || e != "locked" {
		t.Fatalf("lockout: %d %s", code, e)
	}
}
