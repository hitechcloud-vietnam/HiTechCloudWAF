package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The shipped examples must stay valid: unknown keys are rejected.
func TestExamplesParse(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"controller", "agent", "dns", "controller-hcw-engine"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "examples", name+".yaml"))
		if err != nil {
			t.Fatal(err)
		}
		// Replace secret files by inline values so normalize succeeds.
		s := strings.NewReplacer(
			"admin_token_file: /etc/hcw/secrets/admin.token", "admin_token: a",
			"node_token_file: /etc/hcw/secrets/node.token", "node_token: n",
			"dns_token_file: /etc/hcw/secrets/dns.token", "dns_token: d",
			"token_file: /etc/hcw/secrets/primary-engine.token", "token: p",
			"token_file: /etc/hcw/secrets/local-engine.token", "token: l",
			"token_file: /etc/hcw/secrets/dns.token", "token: d",
		).Replace(string(b))
		p := filepath.Join(dir, name+".yaml")
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		f, err := Load(p)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if strings.HasPrefix(name, "controller") && (len(f.Controller.Primary.Resources) != 2 || f.Controller.Primary.Resources[1].Refs["cert_id"] != "cert") {
			t.Fatalf("controller resources = %+v", f.Controller.Primary.Resources)
		}
	}
}

func TestUnknownKeyRejected(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	_ = os.WriteFile(p, []byte("controller:\n  admin_token: a\n  node_token: n\n  typo_field: 1\n"), 0o600)
	if _, err := Load(p); err == nil {
		t.Fatal("unknown key accepted")
	}
}

func TestEnrollmentSettings(t *testing.T) {
	dir := t.TempDir()
	load := func(body string) (*File, error) {
		p := filepath.Join(dir, "c.yaml")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return Load(p)
	}
	// require_enrollment makes the shared node token optional.
	if _, err := load("controller:\n  admin_token: a\n"); err == nil {
		t.Fatal("controller without node_token nor require_enrollment accepted")
	}
	if f, err := load("controller:\n  admin_token: a\n  require_enrollment: true\n"); err != nil || !f.Controller.RequireEnrollment {
		t.Fatalf("require_enrollment: %v", err)
	}
	// An agent may enroll with a token file; the file may be gone once the
	// node is enrolled.
	tok := filepath.Join(dir, "enroll.token")
	_ = os.WriteFile(tok, []byte("hcwe_x\n"), 0o600)
	f, err := load("agent:\n  controller_url: https://c:7443\n  enroll_token_file: " + tok + "\n")
	if err != nil || f.Agent.EnrollToken != "hcwe_x" {
		t.Fatalf("enroll_token_file: %v %+v", err, f)
	}
	if _, err := load("agent:\n  controller_url: https://c:7443\n  enroll_token_file: " + tok + ".missing\n"); err != nil {
		t.Fatalf("missing enroll token file: %v", err)
	}
	if _, err := load("agent:\n  controller_url: https://c:7443\n  enroll_token: a\n  enroll_token_file: " + tok + "\n"); err == nil {
		t.Fatal("enroll_token and enroll_token_file both accepted")
	}
	if _, err := load("agent:\n  controller_url: https://c:7443\n"); err == nil {
		t.Fatal("agent without any token accepted")
	}
}

func TestControllerNeedsTokens(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	_ = os.WriteFile(p, []byte("controller:\n  listen: \":7443\"\n"), 0o600)
	if _, err := Load(p); err == nil {
		t.Fatal("controller without tokens accepted")
	}
}
