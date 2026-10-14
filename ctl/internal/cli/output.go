package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"
)

// clean makes server-provided text safe for a terminal: control characters
// (escape sequences in attacker-controlled URIs or user agents) become '?'.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return ' '
		}
		if unicode.IsControl(r) || r == unicode.ReplacementChar {
			return '?'
		}
		return r
	}, s)
}

type table struct {
	tw *tabwriter.Writer
}

func newTable(w io.Writer, header ...string) *table {
	t := &table{tw: tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)}
	t.row(toAny(header)...)
	return t
}

func toAny(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

func (t *table) row(cols ...any) {
	for i, c := range cols {
		if i > 0 {
			fmt.Fprint(t.tw, "\t")
		}
		fmt.Fprint(t.tw, cell(c))
	}
	fmt.Fprint(t.tw, "\n")
}

func (t *table) flush() error { return t.tw.Flush() }

func cell(v any) string {
	switch x := v.(type) {
	case string:
		if x == "" {
			return "-"
		}
		return clean(x)
	case []string:
		if len(x) == 0 {
			return "-"
		}
		return clean(strings.Join(x, ","))
	case []int:
		if len(x) == 0 {
			return "-"
		}
		s := make([]string, len(x))
		for i, n := range x {
			s[i] = strconv.Itoa(n)
		}
		return strings.Join(s, ",")
	case bool:
		if x {
			return "yes"
		}
		return "no"
	case time.Time:
		return fmtTime(x)
	default:
		return clean(fmt.Sprint(x))
	}
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Local().Format("2006-01-02 15:04:05")
}

// printJSON writes v indented. Raw JSON is re-indented as is.
func (a *App) printJSON(v any) error {
	var b []byte
	if raw, ok := v.(json.RawMessage); ok {
		var buf bytes.Buffer
		if err := json.Indent(&buf, raw, "", "  "); err != nil {
			return err
		}
		b = buf.Bytes()
	} else {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(v); err != nil {
			return err
		}
		b = bytes.TrimRight(buf.Bytes(), "\n")
	}
	_, err := fmt.Fprintf(a.Stdout, "%s\n", b)
	return err
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
