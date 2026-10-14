package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/accesslog"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/model"
)

type memLog struct {
	mu sync.Mutex
	e  []accesslog.Entry
}

func (m *memLog) Log(e accesslog.Entry) { m.mu.Lock(); m.e = append(m.e, e); m.mu.Unlock() }
func (m *memLog) last() accesslog.Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.e[len(m.e)-1]
}

func TestAccessLogActions(t *testing.T) {
	h := newHarness(t, nil,
		model.Site{ServerNames: []string{"a.vn"}},
		model.Site{ServerNames: []string{"bot.vn"}, Bot: model.BotChallenge{Enabled: true, Difficulty: 8}},
	)
	ml := &memLog{}
	h.eng.opt.Access = ml

	h.get(t, "a.vn", "/ok?x=1", browser)
	if e := ml.last(); e.Action != "proxied" || e.Status != 200 || e.SiteID != 1 || e.Bytes == 0 || e.URI != "/ok?x=1" || e.ClientIP != "127.0.0.1" {
		t.Fatalf("proxied entry = %+v", e)
	}
	h.get(t, "a.vn", "/?id="+url.QueryEscape("1' UNION SELECT password FROM users--"), browser)
	if e := ml.last(); e.Action != "blocked" || e.Status != 403 || e.EventID == "" {
		t.Fatalf("blocked entry = %+v", e)
	}
	h.get(t, "bot.vn", "/", browser)
	if e := ml.last(); e.Action != "challenged" || e.SiteID != 2 {
		t.Fatalf("challenge entry = %+v", e)
	}
	h.get(t, "nobody.vn", "/", browser)
	if e := ml.last(); e.Action != "error" || e.Status != 404 {
		t.Fatalf("unknown host entry = %+v", e)
	}
}

// WebSockets (and any Upgrade) must pass through, with the access log on.
func TestWebSocketThroughProxy(t *testing.T) {
	h := newHarness(t, nil, model.Site{ServerNames: []string{"ws.vn"}})
	h.eng.opt.Access = &memLog{}
	h.origin.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			http.Error(w, "no upgrade", 400)
			return
		}
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		fmt.Fprint(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		rw.Flush()
		line, _ := rw.ReadString('\n')
		fmt.Fprint(rw, "echo:"+line)
		rw.Flush()
	})
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", h.port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprint(c, "GET /chat HTTP/1.1\r\nHost: ws.vn\r\nUser-Agent: Mozilla/5.0\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 101 {
		t.Fatalf("upgrade: %v %v", err, resp)
	}
	fmt.Fprint(c, "xin chào\n")
	got, _ := br.ReadString('\n')
	if strings.TrimSpace(got) != "echo:xin chào" {
		t.Fatalf("websocket echo = %q", got)
	}
	_ = io.Discard
}
