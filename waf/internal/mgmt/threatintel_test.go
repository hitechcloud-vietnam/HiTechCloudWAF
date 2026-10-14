package mgmt

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/events"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/model"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/store"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/threatintel"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/users"
)

func TestThreatIntelStatusAndSiteOption(t *testing.T) {
	dir := t.TempDir()
	st, _ := store.Open(filepath.Join(dir, "c.json"))
	us, _ := users.Open(filepath.Join(dir, "u.json"))
	ev, _ := events.New(10, "")
	ti, err := threatintel.New(threatintel.Config{Feeds: []threatintel.FeedConfig{{Name: "firehol_level1", URL: "https://lists.example.net/firehol_level1.netset"}}}, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Token: token, Store: st, Users: us, Events: ev, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Apply: func([]model.Site, []model.Cert) error { return nil }, ThreatIntel: func() any { return ti.Status() }}
	ts := httptest.NewServer(api.Handler())
	t.Cleanup(ts.Close)

	if code, _ := call(t, ts, "GET", "/api/open/threatintel", nil, ""); code != 401 {
		t.Fatalf("anonymous: %d", code)
	}
	call(t, ts, "POST", "/api/open/users", map[string]string{"username": "xem", "password": "Mat-khau-dai-2026", "role": "viewer"}, token)
	_, viewer, _ := login(t, ts, "xem", "Mat-khau-dai-2026", "")
	code, env := req(t, ts, "GET", "/api/open/threatintel", viewer, nil)
	if code != 200 {
		t.Fatalf("viewer: %d", code)
	}
	feeds := env.Data.(map[string]any)["feeds"].([]any)
	f := feeds[0].(map[string]any)
	if len(feeds) != 1 || f["name"] != "firehol_level1" || f["entries"].(float64) != 0 || f["refresh_sec"].(float64) != 3600 {
		t.Fatalf("feeds = %+v", feeds)
	}

	site := map[string]any{"server_names": []string{"a.vn"}, "upstreams": []string{"http://10.0.0.1"}, "threat_intel": "nuke"}
	if code, _ := call(t, ts, "POST", "/api/open/site", site, token); code != 400 {
		t.Fatalf("invalid threat_intel accepted: %d", code)
	}
	site["threat_intel"] = "challenge"
	site["bot_challenge"] = map[string]any{"allow_verified": true}
	if code, env := call(t, ts, "POST", "/api/open/site", site, token); code != 200 {
		t.Fatalf("create: %d %s", code, env.Msg)
	}
	s := st.Sites()[0]
	if s.ThreatIntel != "challenge" || !s.Bot.AllowVerified {
		t.Fatalf("site = %+v", s)
	}
	delete(site, "threat_intel")
	site["server_names"] = []string{"b.vn"}
	call(t, ts, "POST", "/api/open/site", site, token)
	if s := st.Sites()[1]; s.ThreatIntel != model.ModeOff {
		t.Fatalf("default threat_intel = %q", s.ThreatIntel)
	}

	// Without feeds configured the endpoint still answers.
	ts2 := httptest.NewServer((&API{Token: token, Store: st, Events: ev, Log: api.Log, Apply: api.Apply}).Handler())
	t.Cleanup(ts2.Close)
	if code, env := call(t, ts2, "GET", "/api/open/threatintel", nil, token); code != 200 || len(env.Data.(map[string]any)["feeds"].([]any)) != 0 {
		t.Fatalf("no feeds: %d %+v", code, env.Data)
	}
}
