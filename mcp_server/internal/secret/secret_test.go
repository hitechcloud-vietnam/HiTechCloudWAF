package secret

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const token = "s3cr3t-token-value"

func TestReadTokenFile(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good")
	if err := os.WriteFile(good, []byte("  "+token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadTokenFile(good); err != nil || got != token {
		t.Fatalf("ReadTokenFile = %q, %v", got, err)
	}

	open := filepath.Join(dir, "open")
	_ = os.WriteFile(open, []byte(token), 0o644)
	empty := filepath.Join(dir, "empty")
	_ = os.WriteFile(empty, []byte("\n"), 0o600)
	spaced := filepath.Join(dir, "spaced")
	_ = os.WriteFile(spaced, []byte("two words"), 0o600)
	link := filepath.Join(dir, "link")
	_ = os.Symlink(good, link)
	for path, want := range map[string]string{
		open:                          "no group or other permissions",
		empty:                         "empty",
		spaced:                        "whitespace",
		link:                          "regular file",
		filepath.Join(dir, "missing"): "inspect token_file",
		"":                            "required",
	} {
		_, err := ReadTokenFile(path)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ReadTokenFile(%s) = %v, want %q", path, err, want)
		}
		if err != nil && strings.Contains(err.Error(), token) {
			t.Errorf("error leaks the token: %v", err)
		}
	}
}

func TestFromEnv(t *testing.T) {
	t.Setenv("HCW_SECRET_TEST", " "+token+" ")
	if got, err := FromEnv("HCW_SECRET_TEST"); err != nil || got != token {
		t.Fatalf("FromEnv = %q, %v", got, err)
	}
	t.Setenv("HCW_SECRET_BAD", "tok\nen")
	for name, want := range map[string]string{"HCW_SECRET_UNSET_X": "not set", "HCW_SECRET_BAD": "control"} {
		_, err := FromEnv(name)
		if err == nil || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), "tok\nen") {
			t.Errorf("FromEnv(%s) = %v", name, err)
		}
	}
}
