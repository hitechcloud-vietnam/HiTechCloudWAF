package console

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const jsString = `"((?:[^"\\\n]|\\.)*)"`

var (
	// t("text", ...) and tc("context", "text", ...) with literal strings.
	tCall  = regexp.MustCompile(`\bt\(` + jsString)
	tcCall = regexp.MustCompile(`\btc\(` + jsString + `,\s*` + jsString)
	// data-i18n="text" and data-i18n-placeholder="text" in the page.
	htmlKey = regexp.MustCompile(`data-i18n(?:-placeholder)?="([^"]*)"`)
	// whole-line // comments (they show t() usage examples).
	lineComment = regexp.MustCompile(`(?m)^\s*//.*$`)
	// "key": "value" entries of a dictionary.
	dictEntry = regexp.MustCompile(`(?m)^\s*` + jsString + `\s*:\s*` + jsString + `\s*,?\s*$`)
)

func unquote(t *testing.T, s string) string {
	t.Helper()
	u, err := strconv.Unquote(`"` + s + `"`)
	if err != nil {
		t.Fatalf("cannot unquote %q: %v", s, err)
	}
	return u
}

// englishDict returns the keys of DICT.en in i18n.js.
func englishDict(t *testing.T) map[string]string {
	t.Helper()
	b, err := os.ReadFile("static/i18n.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	start := strings.Index(src, "DICT.en = {")
	if start < 0 {
		t.Fatal("DICT.en not found in i18n.js")
	}
	end := strings.Index(src[start:], "\n  };")
	if end < 0 {
		t.Fatal("end of DICT.en not found")
	}
	dict := map[string]string{}
	for _, m := range dictEntry.FindAllStringSubmatch(src[start:start+end], -1) {
		k := unquote(t, m[1])
		if _, dup := dict[k]; dup {
			t.Errorf("i18n.js: duplicate key %q", k)
		}
		dict[k] = unquote(t, m[2])
	}
	if len(dict) < 100 {
		t.Fatalf("only %d entries parsed from DICT.en; is the format still one entry per line?", len(dict))
	}
	return dict
}

// TestEnglishCoversConsoleText fails when a literal t()/tc() string in
// app.js or a data-i18n text in index.html has no English translation.
func TestEnglishCoversConsoleText(t *testing.T) {
	dict := englishDict(t)
	js, err := os.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	code := lineComment.ReplaceAllString(string(js), "")
	missing := map[string]bool{}
	for _, m := range tCall.FindAllStringSubmatch(code, -1) {
		if k := unquote(t, m[1]); dict[k] == "" {
			missing[k] = true
		}
	}
	for _, m := range tcCall.FindAllStringSubmatch(code, -1) {
		ctx, k := unquote(t, m[1]), unquote(t, m[2])
		if dict[ctx+"|"+k] == "" && dict[k] == "" {
			missing[ctx+"|"+k] = true
		}
	}
	html, err := os.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range htmlKey.FindAllStringSubmatch(string(html), -1) {
		if dict[m[1]] == "" {
			missing[m[1]] = true
		}
	}
	for k := range missing {
		t.Errorf("no English translation for %q (add it to DICT.en in static/i18n.js)", k)
	}
}

// TestTranslationsKeepPlaceholders checks that every {n} placeholder of a
// Vietnamese key also appears in its English text.
func TestTranslationsKeepPlaceholders(t *testing.T) {
	ph := regexp.MustCompile(`\{\d+\}`)
	for k, v := range englishDict(t) {
		for _, p := range ph.FindAllString(k, -1) {
			if !strings.Contains(v, p) {
				t.Errorf("%q: English text %q lacks %s", k, v, p)
			}
		}
	}
}
