package mgmt

import (
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// specPath is the OpenAPI description of this API, kept in the repo docs.
const specPath = "../../../docs/api/waf.openapi.yaml"

// registeredRoutes returns the "METHOD /path" patterns passed to
// mux.Handle/HandleFunc in the package's non-test sources, so a new route
// cannot be added without documenting it.
func registeredRoutes(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := gotoken.NewFileSet()
	var routes []string
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "Handle" && sel.Sel.Name != "HandleFunc") {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != gotoken.STRING {
				t.Errorf("%s: route pattern is not a string literal", fset.Position(call.Pos()))
				return true
			}
			p, err := strconv.Unquote(lit.Value)
			if err != nil {
				t.Fatal(err)
			}
			routes = append(routes, p)
			return true
		})
	}
	if len(routes) == 0 {
		t.Fatal("no routes found in the package sources")
	}
	return routes
}

// specOperations returns "METHOD /path" for every operation in the spec.
func specOperations(t *testing.T, path string) map[string]bool {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read OpenAPI spec: %v", err)
	}
	var doc struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	ops := map[string]bool{}
	for p, item := range doc.Paths {
		for m := range item {
			switch m {
			case "get", "put", "post", "delete", "patch", "head", "options", "trace":
				ops[strings.ToUpper(m)+" "+p] = true
			}
		}
	}
	return ops
}

// TestOpenAPICoversRoutes keeps docs/api/waf.openapi.yaml in step with the
// routes registered on the mux, in both directions.
func TestOpenAPICoversRoutes(t *testing.T) {
	ops := specOperations(t, specPath)
	seen := map[string]bool{}
	for _, r := range registeredRoutes(t) {
		method, path, ok := strings.Cut(r, " ")
		if !ok {
			t.Errorf("route %q has no method; register it as \"METHOD /path\"", r)
			continue
		}
		key := method + " " + path
		seen[key] = true
		if !ops[key] {
			t.Errorf("route %s is not documented in %s", key, specPath)
		}
	}
	var stale []string
	for op := range ops {
		if !seen[op] {
			stale = append(stale, op)
		}
	}
	sort.Strings(stale)
	for _, op := range stale {
		t.Errorf("%s documents %s, which is not a registered route", specPath, op)
	}
}
