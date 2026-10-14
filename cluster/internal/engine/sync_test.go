package engine

import (
	"context"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/config"
)

func TestReplicateCreateUpdatePruneAndRefs(t *testing.T) {
	ctx := context.Background()
	prim := newFake("p", 0)
	// IDs on the replica start elsewhere so reference translation matters.
	repl := newFake("r", 500)
	ps, rs := httptest.NewServer(prim), httptest.NewServer(repl)
	defer ps.Close()
	defer rs.Close()
	pc, rc := client(t, ps, "p"), client(t, rs, "r")

	certID := prim.add("cert", map[string]any{"domains": []any{"a.example.vn"}, "crt": "PEM-A"})
	prim.add("site", map[string]any{"server_names": []any{"a.example.vn"}, "ports": []any{"443_ssl"}, "upstreams": []any{"http://10.0.0.1"}, "cert_id": certID})
	prim.add("site", map[string]any{"server_names": []any{"b.example.vn"}, "ports": []any{"80"}, "upstreams": []any{"http://10.0.0.2"}, "cert_id": 0})
	// Stale object only on the replica, must be pruned.
	repl.add("site", map[string]any{"server_names": []any{"old.example.vn"}, "ports": []any{"80"}})

	snap, err := BuildSnapshot(ctx, pc, resources())
	if err != nil {
		t.Fatal(err)
	}
	rep := Apply(ctx, rc, resources(), snap)
	if err := rep.Err(); err != nil {
		t.Fatal(err)
	}
	if rep.Created != 3 || rep.Deleted != 1 {
		t.Fatalf("report = %+v", rep)
	}
	sites := repl.items("site")
	if len(sites) != 2 {
		t.Fatalf("replica sites = %v", sites)
	}
	replCert := repl.items("cert")[0]["id"]
	for _, s := range sites {
		if fmt.Sprint(s["server_names"]) == "[a.example.vn]" && fmt.Sprint(s["cert_id"]) != fmt.Sprint(replCert) {
			t.Fatalf("cert_id not translated: site has %v, replica cert is %v", s["cert_id"], replCert)
		}
	}

	// Second run is a no-op.
	rep = Apply(ctx, rc, resources(), snap)
	if rep.Err() != nil || rep.Created+rep.Updated+rep.Deleted != 0 || rep.Unchanged != 3 {
		t.Fatalf("second apply not idempotent: %+v", rep)
	}

	// Change on primary propagates as an update.
	for _, s := range prim.items("site") {
		if fmt.Sprint(s["server_names"]) == "[b.example.vn]" {
			s["upstreams"] = []any{"http://10.0.0.3"}
		}
	}
	snap2, err := BuildSnapshot(ctx, pc, resources())
	if err != nil {
		t.Fatal(err)
	}
	if snap2.Revision == snap.Revision {
		t.Fatal("revision did not change")
	}
	rep = Apply(ctx, rc, resources(), snap2)
	if rep.Err() != nil || rep.Updated != 1 {
		t.Fatalf("update not applied: %+v", rep)
	}
}

func TestSnapshotRevisionIgnoresServerFields(t *testing.T) {
	ctx := context.Background()
	prim := newFake("p", 0)
	ps := httptest.NewServer(prim)
	defer ps.Close()
	pc := client(t, ps, "p")
	prim.add("site", map[string]any{"server_names": []any{"a"}})
	r := []config.Resource{resources()[1]}
	r[0].Refs = nil
	s1, _ := BuildSnapshot(ctx, pc, r)
	for _, s := range prim.items("site") {
		s["updated_at"] = "later"
	}
	s2, _ := BuildSnapshot(ctx, pc, r)
	if s1.Revision != s2.Revision {
		t.Fatal("ignored field changed the revision")
	}
}

func TestClientRejectsTokenOverPlainHTTP(t *testing.T) {
	_, err := New(config.Engine{BaseURL: "http://10.1.2.3:9443", Token: "x", TokenHeader: "X"})
	if err == nil {
		t.Fatal("expected refusal")
	}
	_, err = New(config.Engine{BaseURL: "https://10.1.2.3:9443", InsecureSkipVerify: true})
	if err == nil {
		t.Fatal("insecure_skip_verify must be refused for non-loopback")
	}
}

func TestEngineErrorEnvelope(t *testing.T) {
	f := newFake("p", 0)
	s := httptest.NewServer(f)
	defer s.Close()
	c := client(t, s, "wrong")
	if _, err := c.List(context.Background(), resources()[0]); err == nil {
		t.Fatal("expected HTTP 401 error")
	}
}
