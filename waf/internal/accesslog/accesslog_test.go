package accesslog

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteAndRotate(t *testing.T) {
	p := filepath.Join(t.TempDir(), "access.log")
	l, err := New(Config{File: p, MaxSizeMB: 1, MaxFiles: 2})
	if err != nil {
		t.Fatal(err)
	}
	big := strings.Repeat("x", 2000)
	for i := 0; i < 1500; i++ { // ~3 MB -> rotations
		l.Log(Entry{Method: "GET", URI: "/" + big, Status: 200, Action: "proxied"})
	}
	l.Close()
	if l.Dropped() != 0 {
		t.Logf("dropped %d (buffer full)", l.Dropped())
	}
	for _, f := range []string{p, p + ".1", p + ".2"} {
		st, err := os.Stat(f)
		if err != nil {
			t.Fatalf("%s missing: %v", f, err)
		}
		if st.Size() > 1<<20 {
			t.Fatalf("%s is %d bytes, over the limit", f, st.Size())
		}
	}
	if _, err := os.Stat(p + ".3"); err == nil {
		t.Fatal("more files kept than max_files")
	}
	f, _ := os.Open(p)
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	sc.Scan()
	var e Entry
	if err := json.Unmarshal(sc.Bytes(), &e); err != nil || e.Status != 200 {
		t.Fatalf("line not valid JSON: %v", err)
	}
}
