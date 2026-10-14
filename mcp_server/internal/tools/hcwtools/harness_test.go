package hcwtools

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/mcp_server/internal/config"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/mcp_server/internal/hcw"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/mcp_server/pkg/logger"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/mcp_server/pkg/mcp"
)

func TestMain(m *testing.M) {
	if err := logger.Init(&logger.Config{Level: "error"}); err != nil {
		panic(err)
	}
	now = func() time.Time { return fakeNow }
	os.Exit(m.Run())
}

// session is an MCP client talking to the server over the stdio transport,
// so every call goes through JSON-RPC framing and the server's input and
// output schema validation.
type session struct {
	t      *testing.T
	in     *io.PipeWriter
	out    *bufio.Reader
	mu     sync.Mutex
	nextID int
	cancel context.CancelFunc
	done   chan error
}

type serverOptions struct {
	readOnly         bool
	readOnlyInstance bool
	twoInstances     bool
}

// startServer runs the MCP server with the tools of the hcw-waf backend
// against node. The token reaches the server through token_env.
func startServer(t *testing.T, node *fakeNode, opts serverOptions) *session {
	t.Helper()
	t.Setenv("HCW_TEST_TOKEN", fakeToken)
	cfgs := []*config.InstanceConfig{{ID: "node-a", DisplayName: "Node A", BaseURL: node.srv.URL, TokenEnv: "HCW_TEST_TOKEN",
		CAFile: node.caFile, Timeout: 5, ReadOnly: opts.readOnlyInstance}}
	if opts.twoInstances {
		cfgs = append(cfgs, &config.InstanceConfig{ID: "node-b", DisplayName: "Node B", BaseURL: node.srv.URL, TokenEnv: "HCW_TEST_TOKEN",
			CAFile: node.caFile, Timeout: 5, ReadOnly: true})
	}
	reg, err := hcw.NewRegistry(cfgs)
	if err != nil {
		t.Fatal(err)
	}
	s := mcp.NewMCPServer("test", "1.0.0", "instructions")
	for _, tool := range Tools(reg, opts.readOnly) {
		if err := tool.Register(s); err != nil {
			t.Fatal(err)
		}
	}
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	sess := &session{t: t, in: inW, out: bufio.NewReader(outR), cancel: cancel, done: make(chan error, 1)}
	go func() {
		sess.done <- s.ServeStdio(ctx, inR, outW, io.Discard)
		_ = outW.Close()
	}()
	t.Cleanup(func() {
		_ = inW.Close()
		cancel()
		<-sess.done
	})
	sess.request("initialize", map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "test", "version": "1"},
	})
	sess.notify("notifications/initialized")
	return sess
}

func (s *session) write(msg map[string]any) {
	s.t.Helper()
	b, err := json.Marshal(msg)
	if err != nil {
		s.t.Fatal(err)
	}
	if _, err := s.in.Write(append(b, '\n')); err != nil {
		s.t.Fatal(err)
	}
}

func (s *session) notify(method string) {
	s.write(map[string]any{"jsonrpc": "2.0", "method": method})
}

// request sends a request and returns its result object.
func (s *session) request(method string, params any) map[string]any {
	s.t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	id := s.nextID
	s.write(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	for {
		line, err := s.out.ReadBytes('\n')
		if err != nil {
			s.t.Fatalf("read response: %v", err)
		}
		var resp struct {
			ID     any             `json:"id"`
			Result map[string]any  `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		if err := json.Unmarshal(line, &resp); err != nil {
			s.t.Fatalf("decode %q: %v", line, err)
		}
		if n, ok := resp.ID.(float64); !ok || int(n) != id {
			continue // a notification or another answer
		}
		if len(resp.Error) > 0 && string(resp.Error) != "null" {
			s.t.Fatalf("%s: JSON-RPC error %s", method, resp.Error)
		}
		return resp.Result
	}
}

// toolResult is a decoded tools/call result.
type toolResult struct {
	IsError    bool
	Text       string
	Structured json.RawMessage
}

func (s *session) call(name string, args map[string]any) toolResult {
	s.t.Helper()
	if args == nil {
		args = map[string]any{}
	}
	res := s.request("tools/call", map[string]any{"name": name, "arguments": args})
	var out toolResult
	out.IsError, _ = res["isError"].(bool)
	if content, ok := res["content"].([]any); ok {
		var parts []string
		for _, c := range content {
			if m, ok := c.(map[string]any); ok {
				if text, ok := m["text"].(string); ok {
					parts = append(parts, text)
				}
			}
		}
		out.Text = strings.Join(parts, "\n")
	}
	if sc, ok := res["structuredContent"]; ok {
		out.Structured, _ = json.Marshal(sc)
	}
	return out
}

// ok calls a tool, requires success and decodes the structured result.
func ok[R any](t *testing.T, s *session, name string, args map[string]any) R {
	t.Helper()
	res := s.call(name, args)
	if res.IsError {
		t.Fatalf("%s(%v) failed: %s", name, args, res.Text)
	}
	assertNoSecrets(t, name, res.Text)
	var out R
	if err := json.Unmarshal(res.Structured, &out); err != nil {
		t.Fatalf("%s: decode structured content %s: %v", name, res.Structured, err)
	}
	return out
}

// failed calls a tool, requires a tool error and returns its text.
func failed(t *testing.T, s *session, name string, args map[string]any) string {
	t.Helper()
	res := s.call(name, args)
	if !res.IsError {
		t.Fatalf("%s(%v) succeeded, want an error: %s", name, args, res.Text)
	}
	assertNoSecrets(t, name, res.Text)
	return res.Text
}

func assertNoSecrets(t *testing.T, name, text string) {
	t.Helper()
	for _, secret := range []string{fakeToken, "PRIVATE KEY", "secrethashvalue", "upstream-secret", "SECRETKEY", "should-not-leak", "user:pw", "u:p@"} {
		if strings.Contains(text, secret) {
			t.Fatalf("%s result contains secret %q: %s", name, secret, text)
		}
	}
}
