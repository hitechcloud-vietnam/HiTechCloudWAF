package config

import (
	"strings"
	"testing"
)

func TestLoadDefaultsToHCWBackendAndHTTP(t *testing.T) {
	path := writeConfigFile(t, `
server: {name: HiTechCloud WAF MCP, version: 1.0.0, host: 127.0.0.1, port: 5678}
logger: {level: info}
instances:
  - {id: a, base_url: "https://127.0.0.1:9443", token_env: HCW_WAF_TOKEN, read_only: true}
`)
	t.Setenv("MCP_TRANSPORT", "")
	if err := Load(path); err != nil {
		t.Fatal(err)
	}
	if GetBackend() != BackendHCW || GetReadOnly() || GetServer().Transport != TransportHTTP {
		t.Fatalf("backend %q read_only %v transport %q", GetBackend(), GetReadOnly(), GetServer().Transport)
	}
	if inst := GetInstances()[0]; inst.TokenEnv != "HCW_WAF_TOKEN" || !inst.ReadOnly {
		t.Fatalf("instance = %+v", inst)
	}
}

func TestLoadStdioNeedsNoListener(t *testing.T) {
	path := writeConfigFile(t, `
backend: hcw-waf
read_only: true
server: {name: HiTechCloud WAF MCP, version: 1.0.0}
logger: {level: info, console: false}
instances:
  - {id: a, base_url: "https://127.0.0.1:9443", token_file: /run/secrets/a.token}
`)
	t.Setenv("MCP_TRANSPORT", "")
	if err := Load(path); err == nil || !strings.Contains(err.Error(), "server.host") {
		t.Fatalf("http without host = %v", err)
	}
	if err := LoadWithTransport(path, "stdio"); err != nil {
		t.Fatal(err)
	}
	if GetServer().Transport != TransportStdio || !GetReadOnly() {
		t.Fatalf("server = %+v", GetServer())
	}
	t.Setenv("MCP_TRANSPORT", "STDIO")
	if err := Load(path); err != nil || GetServer().Transport != TransportStdio {
		t.Fatalf("MCP_TRANSPORT: %v %q", err, GetServer().Transport)
	}
	if err := LoadWithTransport(path, "sse"); err == nil || !strings.Contains(err.Error(), "server.transport") {
		t.Fatalf("unknown transport = %v", err)
	}
}

func TestLoadTokenSourceRules(t *testing.T) {
	t.Setenv("MCP_TRANSPORT", "")
	for name, tc := range map[string]struct{ body, want string }{
		"both":         {"backend: hcw-waf\n" + inst("token_file: /a\n    token_env: B"), "only one of token_file and token_env"},
		"none":         {"backend: hcw-waf\n" + inst(""), "token_file or token_env is required"},
		"bad env name": {inst("token_env: \"A B\""), "environment variable name"},
		"legacy env":   {"backend: legacy\n" + inst("token_env: A"), "only supported by the hcw-waf backend"},
		"legacy none":  {"backend: legacy\n" + inst(""), "token_file is required"},
		"bad backend":  {"backend: other\n" + inst("token_env: A"), "backend must be"},
	} {
		path := writeConfigFile(t, tc.body)
		if err := Load(path); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: Load() = %v, want %q", name, err, tc.want)
		}
	}
	path := writeConfigFile(t, "backend: legacy\n"+inst("token_file: /run/a.token"))
	if err := Load(path); err != nil || GetBackend() != BackendLegacy {
		t.Fatalf("legacy backend: %v %q", err, GetBackend())
	}
}

func inst(token string) string {
	return `server: {name: n, version: "1", host: 127.0.0.1, port: 5678}
logger: {level: info}
instances:
  - id: a
    base_url: https://127.0.0.1:9443
    ` + token + "\n"
}
