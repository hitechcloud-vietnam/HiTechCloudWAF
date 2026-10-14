package main

import (
	"bufio"
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/mcp_server/internal/config"
)

// TestStdioServesHCWTools starts the server the way Claude Desktop or Claude
// Code does (stdio transport) against a TLS fake of the management API.
func TestStdioServesHCWTools(t *testing.T) {
	const token = "stdio-test-token-9f8e7d"
	node := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-HCW-API-TOKEN") != token {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"data":null,"err":"unauthorized","msg":"missing or invalid API token or session"}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":{"data":[{"id":1,"name":"shop","server_names":["shop.example.vn"],"mode":"block"}],"total":1},"err":null,"msg":""}`))
	}))
	defer node.Close()

	dir := t.TempDir()
	ca := filepath.Join(dir, "node.crt")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: node.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte(`
read_only: true
server: {name: HiTechCloud WAF MCP, version: 2.0.0}
logger: {level: error, console: false}
instances:
  - id: local
    display_name: Local node
    base_url: `+node.URL+`
    token_env: HCW_STDIO_TEST_TOKEN
    ca_file: node.crt
`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HCW_STDIO_TEST_TOKEN", token)
	t.Setenv("MCP_TRANSPORT", "")

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- runServerIO(ctx, []string{"--config", cfg, "--transport", "stdio"}, inR, outW, io.Discard)
		_ = outW.Close()
	}()
	out := bufio.NewReader(outR)
	send := func(msg string) {
		if _, err := io.WriteString(inW, msg+"\n"); err != nil {
			t.Fatal(err)
		}
	}
	read := func() map[string]any {
		line, err := out.ReadBytes('\n')
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatalf("stdout carried a non-JSON-RPC line %q: %v", line, err)
		}
		return m
	}

	send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`)
	init := read()["result"].(map[string]any)
	instructions, _ := init["instructions"].(string)
	if !strings.Contains(instructions, `"Local node" -> instance_id "local" (read-only)`) || strings.Contains(instructions, node.URL) {
		t.Fatalf("instructions = %q", instructions)
	}
	send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	send(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`)
	tools := read()["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 11 {
		t.Fatalf("read_only server lists %d tools, want the 11 read tools", len(tools))
	}
	send(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_sites","arguments":{}}}`)
	result := read()["result"].(map[string]any)
	if result["isError"] == true || !strings.Contains(result["content"].([]any)[0].(map[string]any)["text"].(string), "shop.example.vn") {
		t.Fatalf("list_sites = %v", result)
	}

	_ = inW.Close()
	select {
	case err := <-done:
		if err != nil && err != io.EOF && !strings.Contains(err.Error(), "EOF") {
			t.Fatalf("server exit = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop when stdin closed")
	}
}

func TestBuildHCWInstructions(t *testing.T) {
	two := []*config.InstanceConfig{
		{ID: "a", DisplayName: "Alpha", BaseURL: "https://secret.internal", TokenEnv: "HCW_A"},
		{ID: "b", DisplayName: "Beta", ReadOnly: true, TokenFile: "/run/secrets/b"},
	}
	got := buildHCWInstructions(two, false)
	for _, want := range []string{`"Alpha" -> instance_id "a" (read-write)`, `"Beta" -> instance_id "b" (read-only)`, "Never guess an instance_id", "WRITE", "untrusted"} {
		if !strings.Contains(got, want) {
			t.Errorf("instructions lack %q: %s", want, got)
		}
	}
	for _, secret := range []string{"secret.internal", "HCW_A", "/run/secrets/b"} {
		if strings.Contains(got, secret) {
			t.Errorf("instructions expose %q", secret)
		}
	}
	if ro := buildHCWInstructions(two[:1], true); !strings.Contains(ro, "read-only: no tool can change") || !strings.Contains(ro, "may be omitted") {
		t.Errorf("read-only single instructions = %s", ro)
	}
}
