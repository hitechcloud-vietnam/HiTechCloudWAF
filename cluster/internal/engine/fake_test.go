package engine

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/config"
)

// fakeEngine imitates the collection API of a WAF engine: list, create,
// update and delete with the {"data":...,"err":null,"msg":""} envelope.
type fakeEngine struct {
	mu     sync.Mutex
	token  string
	nextID int
	cols   map[string]map[int]map[string]any
	calls  []string
}

func newFake(token string, startID int) *fakeEngine {
	return &fakeEngine{token: token, nextID: startID, cols: map[string]map[int]map[string]any{}}
}

func (f *fakeEngine) add(col string, item map[string]any) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	item["id"] = f.nextID
	item["updated_at"] = time.Now().String()
	if f.cols[col] == nil {
		f.cols[col] = map[int]map[string]any{}
	}
	f.cols[col][f.nextID] = item
	return f.nextID
}

func (f *fakeEngine) items(col string) []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []map[string]any
	for _, it := range f.cols[col] {
		out = append(out, it)
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["id"].(int) < out[j]["id"].(int) })
	return out
}

func reply(w http.ResponseWriter, data any) {
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data, "err": nil, "msg": ""})
}

func (f *fakeEngine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-SLCE-API-TOKEN") != f.token {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if r.URL.Path == "/api/open/health" {
		reply(w, "ok")
		return
	}
	col := strings.TrimPrefix(r.URL.Path, "/api/open/")
	f.mu.Lock()
	f.calls = append(f.calls, r.Method+" "+col)
	f.mu.Unlock()
	switch r.Method {
	case http.MethodGet:
		reply(w, map[string]any{"data": f.items(col), "total": len(f.items(col))})
	case http.MethodPost:
		var it map[string]any
		_ = json.NewDecoder(r.Body).Decode(&it)
		f.add(col, it)
		reply(w, nil)
	case http.MethodPut:
		var it map[string]any
		_ = json.NewDecoder(r.Body).Decode(&it)
		id := int(it["id"].(float64))
		f.mu.Lock()
		it["id"] = id
		f.cols[col][id] = it
		f.mu.Unlock()
		reply(w, nil)
	case http.MethodDelete:
		var body struct {
			IDs []int `json:"ids"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		for _, id := range body.IDs {
			delete(f.cols[col], id)
		}
		f.mu.Unlock()
		reply(w, nil)
	}
}

func resources() []config.Resource {
	return []config.Resource{
		{Name: "cert", Path: "/api/open/cert", ItemsPath: "data.data", IDField: "id", KeyFields: []string{"domains"}, IgnoreFields: []string{"updated_at"}, UpdateMethod: "PUT", DeleteMode: "body_ids", Prune: true},
		{Name: "site", Path: "/api/open/site", ItemsPath: "data.data", IDField: "id", KeyFields: []string{"server_names"}, IgnoreFields: []string{"updated_at"}, Refs: map[string]string{"cert_id": "cert"}, UpdateMethod: "PUT", DeleteMode: "body_ids", Prune: true},
	}
}

func client(t *testing.T, srv *httptest.Server, token string) *Client {
	t.Helper()
	c, err := New(config.Engine{BaseURL: srv.URL, Token: token, TokenHeader: "X-SLCE-API-TOKEN", HealthPath: "/api/open/health", Timeout: config.Duration{Duration: 5 * time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}
