package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/model"
)

func manyArgs(n int, sep string, kv func(i int) string) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = kv(i)
	}
	return strings.Join(parts, sep)
}

func queryArgs(n int) string {
	return manyArgs(n, "&", func(i int) string { return fmt.Sprintf("a%d=%d", i, i) })
}

func jsonArgs(n int) string {
	return "{" + manyArgs(n, ",", func(i int) string { return fmt.Sprintf(`"field_%d":"gia tri %d"`, i, i) }) + "}"
}

func lastRules(h *harness) []int {
	ev := h.ev.Latest(1, 0)
	if len(ev) == 0 {
		return nil
	}
	var ids []int
	for _, r := range ev[0].Rules {
		ids = append(ids, r.ID)
	}
	return ids
}

func hasRule(ids []int, id int) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}

func TestArgumentLimit(t *testing.T) {
	h := newHarness(t, nil, model.Site{ServerNames: []string{"a.vn"}})
	if code, _ := h.get(t, "a.vn", "/list?"+queryArgs(model.DefaultMaxArgs), browser); code != 200 {
		t.Fatalf("%d query args: %d", model.DefaultMaxArgs, code)
	}
	if code, _ := h.get(t, "a.vn", "/list?"+queryArgs(model.DefaultMaxArgs+1), browser); code != http.StatusBadRequest || !hasRule(lastRules(h), 100002) {
		t.Fatalf("%d query args: %d, rules %v", model.DefaultMaxArgs+1, code, lastRules(h))
	}
	if code := h.post(t, "a.vn", "application/json", jsonArgs(200)); code != 200 {
		t.Fatalf("200 JSON fields: %d", code)
	}
	if code := h.post(t, "a.vn", "application/json", jsonArgs(1000)); code != http.StatusBadRequest || !hasRule(lastRules(h), 100003) {
		t.Fatalf("1000 JSON fields: %d, rules %v", code, lastRules(h))
	}
	// Query and body together: CRS 920380 (tx.max_num_args).
	req, _ := http.NewRequest("POST", fmt.Sprintf("http://127.0.0.1:%d/list?%s", h.port, queryArgs(200)), strings.NewReader(jsonArgs(200)))
	req.Host = "a.vn"
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || !hasRule(lastRules(h), 920380) {
		t.Fatalf("200+200 args: %d, rules %v", resp.StatusCode, lastRules(h))
	}

	// A site can raise the limit.
	h2 := newHarness(t, nil, model.Site{ServerNames: []string{"a.vn"}, MaxArgs: 1500})
	if code := h2.post(t, "a.vn", "application/json", jsonArgs(1000)); code != 200 {
		t.Fatalf("max_args 1500, 1000 fields: %d", code)
	}

	// Monitor mode lets it through and records what would have happened.
	h3 := newHarness(t, nil, model.Site{ServerNames: []string{"a.vn"}, Mode: model.ModeMonitor})
	if code := h3.post(t, "a.vn", "application/json", jsonArgs(1000)); code != 200 {
		t.Fatalf("monitor: %d", code)
	}
	if ev := h3.ev.Latest(1, 0); len(ev) != 1 || ev[0].Action != "monitor" || !hasRule(lastRules(h3), 100003) {
		t.Fatalf("monitor events = %+v", ev)
	}
}

func TestMaxArgsValidation(t *testing.T) {
	for _, n := range []int{-1, model.MaxMaxArgs + 1} {
		s := model.Site{ServerNames: []string{"a.vn"}, Upstreams: []string{"http://127.0.0.1:1"}, MaxArgs: n}
		if err := s.Normalize(); err == nil {
			t.Errorf("max_args %d accepted", n)
		}
	}
}

func TestJSONDepthLimit(t *testing.T) {
	h := newHarness(t, nil, model.Site{ServerNames: []string{"a.vn"}})
	nest := func(n int) string { return strings.Repeat(`{"a":`, n) + "1" + strings.Repeat("}", n) }
	if code := h.post(t, "a.vn", "application/json", nest(20)); code != 200 {
		t.Fatalf("depth 20: %d", code)
	}
	if code := h.post(t, "a.vn", "application/json", nest(jsonDepthLimit+10)); code != http.StatusBadRequest {
		t.Fatalf("depth %d: %d", jsonDepthLimit+10, code)
	}
}

func multipartBody(file string) (ctype, body string) {
	const boundary = "hcwtestboundary"
	body = "--" + boundary + "\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nAnh san pham\r\n" +
		"--" + boundary + "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\n" +
		file + "\r\n--" + boundary + "--\r\n"
	return "multipart/form-data; boundary=" + boundary, body
}

// sendBody posts body (with a Content-Length, or chunked) and returns the
// status and the response body.
func (h *harness) sendBody(t *testing.T, ctype, body string, chunked bool) (int, string) {
	t.Helper()
	var rd io.Reader = strings.NewReader(body)
	if chunked {
		rd = io.MultiReader(rd) // unknown length: sent chunked
	}
	req, _ := http.NewRequest("POST", fmt.Sprintf("http://127.0.0.1:%d/upload", h.port), rd)
	req.Host = "a.vn"
	req.Header.Set("Content-Type", ctype)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, string(got)
}

func digestOrigin(h *harness) {
	h.origin.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sum := sha256.New()
		n, _ := io.Copy(sum, r.Body)
		fmt.Fprintf(w, "%d %s", n, hex.EncodeToString(sum.Sum(nil)))
	})
}

func digest(body string) string {
	sum := sha256.Sum256([]byte(body))
	return fmt.Sprintf("%d %s", len(body), hex.EncodeToString(sum[:]))
}

// The transaction is closed before proxying, so the upstream must still get
// every byte of the body: in memory, spilled to a file, and beyond the
// inspected limit.
func TestBodyForwardedIntact(t *testing.T) {
	h := newHarness(t, nil, model.Site{ServerNames: []string{"a.vn"}})
	digestOrigin(h)
	mp1, mpBody1 := multipartBody(strings.Repeat("anh ", 75<<10))  // 300 KB: spilled to a file
	mp2, mpBody2 := multipartBody(strings.Repeat("anh ", 768<<10)) // 3 MB: beyond body_limit
	bodies := []struct{ ctype, body string }{
		{"application/json", jsonArgs(50)},
		{"application/x-www-form-urlencoded", "note=" + strings.Repeat("x", 100<<10)}, // under the arguments limit
		{mp1, mpBody1},
		{mp2, mpBody2},
		{"application/octet-stream", strings.Repeat("\x00\x01", 1<<20)}, // not inspected
	}
	for _, b := range bodies {
		for _, chunked := range []bool{false, true} {
			if code, got := h.sendBody(t, b.ctype, b.body, chunked); code != 200 || got != digest(b.body) {
				t.Fatalf("%s %d bytes (chunked %v): %d %q", b.ctype, len(b.body), chunked, code, got[:min(len(got), 200)])
			}
		}
	}
}

// Bodies parsed into arguments cost CPU per byte: above ArgsBodyLimit they
// are refused in block mode, and only their start is inspected in monitor
// mode.
func TestArgsBodyLimit(t *testing.T) {
	big := `{"blob":"` + strings.Repeat("QUJD", 50<<10) + `"}` // 200 KB
	form := "blob=" + strings.Repeat("x", 3<<20)               // beyond body_limit too
	h := newHarness(t, nil, model.Site{ServerNames: []string{"a.vn"}})
	digestOrigin(h)
	for _, chunked := range []bool{false, true} {
		for _, b := range []struct{ ctype, body string }{{"application/json", big}, {"application/x-www-form-urlencoded", form[:250<<10]}} {
			if code, _ := h.sendBody(t, b.ctype, b.body, chunked); code != http.StatusRequestEntityTooLarge {
				t.Fatalf("%s %d bytes (chunked %v): %d", b.ctype, len(b.body), chunked, code)
			}
			if ev := h.ev.Latest(1, 0); len(ev) != 1 || ev[0].Kind != "body_limit" || ev[0].Action != "block" {
				t.Fatalf("events = %+v", ev)
			}
		}
	}

	m := newHarness(t, nil, model.Site{ServerNames: []string{"a.vn"}, Mode: model.ModeMonitor})
	m.eng.opt.ArgsBodyLimit = 4 << 10 // keeps the test fast under -race
	digestOrigin(m)
	for _, chunked := range []bool{false, true} {
		start := time.Now()
		if code, got := m.sendBody(t, "application/x-www-form-urlencoded", form, chunked); code != 200 || got != digest(form) {
			t.Fatalf("monitor (chunked %v): %d %q", chunked, code, got)
		}
		if d := time.Since(start); d > 5*time.Second {
			t.Fatalf("monitor mode inspected the whole body: %v", d)
		}
		found := false
		for _, ev := range m.ev.Latest(5, 0) {
			found = found || ev.Kind == "body_limit" && ev.Action == "monitor"
		}
		if !found {
			t.Fatalf("no body_limit monitor event: %+v", m.ev.Latest(5, 0))
		}
	}
}

func TestSpoolBody(t *testing.T) {
	for _, n := range []int{0, 1, spoolMem - 1, spoolMem, spoolMem + 1, 3 * spoolMem} {
		src := strings.Repeat("z", n)
		for _, size := range []int64{int64(n), -1} {
			for _, limit := range []int64{int64(n) + 10, int64(n / 2)} {
				sp, err := spoolBody(strings.NewReader(src), size, limit)
				if err != nil {
					t.Fatal(err)
				}
				got, _ := io.ReadAll(sp.reader())
				again, _ := io.ReadAll(sp.reader())
				want := src[:min(int64(n), limit)]
				if string(got) != want || string(again) != want {
					t.Fatalf("n=%d size=%d limit=%d: got %d bytes", n, size, limit, len(got))
				}
				if (sp.file != nil) != (len(want) > spoolMem) {
					t.Fatalf("n=%d limit=%d: file=%v", n, limit, sp.file != nil)
				}
				sp.release()
				sp.release()
			}
		}
	}
}

// Inspection slots are freed as soon as the verdict is known, not when the
// proxied response ends: a stream that stays open does not hold one.
func TestInspectionSlotNotHeldWhileStreaming(t *testing.T) {
	h := newHarness(t, nil, model.Site{ServerNames: []string{"a.vn"}})
	h.eng.inspectSem = make(chan struct{}, 1)
	release := make(chan struct{})
	h.origin.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/events" {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			<-release
			return
		}
		io.WriteString(w, "ok")
	})
	defer close(release)
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/events?topic=orders", h.port), nil)
	req.Host = "a.vn"
	stream, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Body.Close()
	if stream.StatusCode != 200 {
		t.Fatalf("stream: %d", stream.StatusCode)
	}
	done := make(chan int, 1)
	go func() {
		code, _ := h.get(t, "a.vn", "/products?id=1", browser)
		done <- code
	}()
	select {
	case code := <-done:
		if code != 200 {
			t.Fatalf("second request: %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("second request waited for the stream to end")
	}
}

func TestInspectionSlotWaitEndsWithClient(t *testing.T) {
	h := newHarness(t, nil, model.Site{ServerNames: []string{"a.vn"}})
	h.eng.inspectSem = make(chan struct{}, 1)
	h.eng.inspectSem <- struct{}{} // the only slot is busy
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest("GET", "/products?id=1", nil).WithContext(ctx)
	req.Host = "a.vn"
	rec := httptest.NewRecorder()
	start := time.Now()
	h.eng.serve(h.port, rec, req, nil)
	if rec.Code != http.StatusServiceUnavailable || time.Since(start) > 5*time.Second {
		t.Fatalf("busy: %d after %v", rec.Code, time.Since(start))
	}
	<-h.eng.inspectSem
	rec = httptest.NewRecorder()
	h.eng.serve(h.port, rec, httptest.NewRequest("GET", "http://a.vn/products?id=1", nil), nil)
	if rec.Code != 200 {
		t.Fatalf("free slot: %d", rec.Code)
	}
	if len(h.eng.inspectSem) != 0 {
		t.Fatal("slot not released")
	}
}

func TestStaticRequest(t *testing.T) {
	cases := map[string]bool{
		"GET /assets/app.css":            true,
		"HEAD /img/logo.PNG":             true,
		"GET /v1.2.3/app.min.js":         true,
		"GET /fonts/a.woff2":             true,
		"POST /assets/app.css":           false,
		"GET /assets/app.css?v=3":        false,
		"GET /assets/app.css?":           false,
		"GET /index.php/app.css":         false,
		"GET /a/run.cgi/x/y.png":         false,
		"GET /app.jsp;jsessionid=1/x.js": false,
		"GET /page.html":                 false,
		"GET /api/data.json":             false,
		"GET /assets/":                   false,
	}
	for c, want := range cases {
		method, target, _ := strings.Cut(c, " ")
		r := httptest.NewRequest(method, "http://a.vn"+target, nil)
		if got := staticRequest(r); got != want {
			t.Errorf("%s: %v, want %v", c, got, want)
		}
	}
	r := httptest.NewRequest("GET", "http://a.vn/app.css", strings.NewReader("x=1"))
	if staticRequest(r) {
		t.Error("GET with a body is not static")
	}
}

func TestStaticFastPath(t *testing.T) {
	sqliCookie := map[string]string{"User-Agent": browser["User-Agent"], "Cookie": "id=" + url.QueryEscape("1' UNION SELECT password FROM users--")}
	scanner := map[string]string{"User-Agent": "sqlmap/1.7.2#stable (https://sqlmap.org)"}

	full := newHarness(t, nil, model.Site{ServerNames: []string{"a.vn"}})
	if code, _ := full.get(t, "a.vn", "/assets/app.css", sqliCookie); code != http.StatusForbidden {
		t.Fatalf("without fast path, cookie SQLi on a static file: %d", code)
	}

	h := newHarness(t, nil, model.Site{ServerNames: []string{"a.vn"}, StaticFastPath: true})
	if code, _ := h.get(t, "a.vn", "/assets/app.css", browser); code != 200 {
		t.Fatalf("static file: %d", code)
	}
	// Phase 2 (cookies, arguments) is skipped on static files only.
	if code, _ := h.get(t, "a.vn", "/assets/app.css", sqliCookie); code != 200 {
		t.Fatalf("fast path should skip phase 2: %d", code)
	}
	for _, p := range []string{"/products", "/assets/app.css?x=1", "/index.php/app.css"} {
		if code, _ := h.get(t, "a.vn", p, sqliCookie); code != http.StatusForbidden {
			t.Errorf("%s: %d, want full inspection", p, code)
		}
	}
	// Phase 1 still runs, with its anomaly score evaluated (early blocking).
	if code, _ := h.get(t, "a.vn", "/assets/app.css", scanner); code != http.StatusForbidden || !hasRule(lastRules(h), 913100) {
		t.Fatalf("scanner on a static file: %d, rules %v", code, lastRules(h))
	}
	// Early blocking is per transaction: other requests are still scored
	// at the end of phase 2.
	if code, _ := h.get(t, "a.vn", "/products", scanner); code != http.StatusForbidden || !hasRule(lastRules(h), 949110) {
		t.Fatalf("scanner on a page: %d, rules %v", code, lastRules(h))
	}

	m := newHarness(t, nil, model.Site{ServerNames: []string{"a.vn"}, StaticFastPath: true, Mode: model.ModeMonitor})
	if code, _ := m.get(t, "a.vn", "/assets/app.css", scanner); code != 200 {
		t.Fatalf("monitor: %d", code)
	}
	if ev := m.ev.Latest(1, 0); len(ev) != 1 || ev[0].Action != "monitor" {
		t.Fatalf("monitor events = %+v", ev)
	}
}
