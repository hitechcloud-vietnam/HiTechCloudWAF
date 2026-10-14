package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/api"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/config"
)

// BuildSnapshot reads every replicated resource from the primary engine.
func BuildSnapshot(ctx context.Context, c *Client, resources []config.Resource) (*api.Snapshot, error) {
	snap := &api.Snapshot{CreatedAt: time.Now().UTC(), Resources: map[string][]json.RawMessage{}}
	for _, r := range resources {
		items, err := c.List(ctx, r)
		if err != nil {
			return nil, err
		}
		sort.SliceStable(items, func(i, j int) bool { return Key(r, items[i]) < Key(r, items[j]) })
		raw := make([]json.RawMessage, 0, len(items))
		for _, it := range items {
			clean := strip(r, it, false)
			b, err := json.Marshal(clean)
			if err != nil {
				return nil, err
			}
			raw = append(raw, b)
		}
		snap.Resources[r.Name] = raw
	}
	b, err := json.Marshal(snap.Resources)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	snap.Revision = hex.EncodeToString(sum[:8])
	return snap, nil
}

// strip drops ignored fields, and the ID field when dropID is set.
func strip(r config.Resource, it map[string]any, dropID bool) map[string]any {
	out := make(map[string]any, len(it))
	for k, v := range it {
		if dropID && k == r.IDField {
			continue
		}
		ignored := false
		for _, f := range r.IgnoreFields {
			if f == k {
				ignored = true
				break
			}
		}
		if !ignored {
			out[k] = v
		}
	}
	return out
}

// Key identifies an object across nodes.
func Key(r config.Resource, it map[string]any) string {
	parts := make([]string, 0, len(r.KeyFields))
	for _, f := range r.KeyFields {
		b, _ := json.Marshal(it[f])
		parts = append(parts, string(b))
	}
	return strings.Join(parts, "|")
}

func idString(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

// Report summarises one reconciliation.
type Report struct {
	Created, Updated, Deleted, Unchanged int
	Errors                               []string
}

func (r *Report) errf(format string, a ...any) {
	r.Errors = append(r.Errors, fmt.Sprintf(format, a...))
}

// Err returns the collected errors as one error, or nil.
func (r *Report) Err() error {
	if len(r.Errors) == 0 {
		return nil
	}
	return fmt.Errorf("%d sync errors: %s", len(r.Errors), strings.Join(r.Errors, "; "))
}

// Apply reconciles the local engine c so it matches snap. Resources are
// processed in order, so a resource that others reference (e.g. certificates
// referenced by sites) must be listed first.
func Apply(ctx context.Context, c *Client, resources []config.Resource, snap *api.Snapshot) Report {
	var rep Report
	// idMap[resource][primaryID] = localID
	idMap := map[string]map[string]any{}

	for _, r := range resources {
		raw, ok := snap.Resources[r.Name]
		if !ok {
			continue
		}
		idMap[r.Name] = map[string]any{}

		local, err := c.List(ctx, r)
		if err != nil {
			rep.errf("%s: list: %v", r.Name, err)
			continue
		}
		localByKey := map[string]map[string]any{}
		for _, l := range local {
			localByKey[Key(r, l)] = l
		}

		desiredKeys := map[string]bool{}
		created := map[string]string{} // key -> primary id
		for _, rb := range raw {
			d, err := decode(rb)
			if err != nil {
				rep.errf("%s: decode snapshot item: %v", r.Name, err)
				continue
			}
			pid := idString(d[r.IDField])
			body := strip(r, d, true)
			if err := translateRefs(r, body, idMap); err != nil {
				rep.errf("%s %s: %v", r.Name, Key(r, body), err)
				continue
			}
			k := Key(r, body)
			desiredKeys[k] = true

			l, exists := localByKey[k]
			if !exists {
				if _, err := c.Do(ctx, http.MethodPost, r.Path, "", body); err != nil {
					rep.errf("%s %s: create: %v", r.Name, k, err)
					continue
				}
				rep.Created++
				created[k] = pid
				continue
			}
			lid := l[r.IDField]
			idMap[r.Name][pid] = lid
			if subsetEqual(body, strip(r, l, true)) {
				rep.Unchanged++
				continue
			}
			body[r.IDField] = lid
			if _, err := c.Do(ctx, r.UpdateMethod, r.Path, "", body); err != nil {
				rep.errf("%s %s: update: %v", r.Name, k, err)
				continue
			}
			rep.Updated++
		}

		// Learn the local IDs of objects created above so later resources
		// can reference them.
		if len(created) > 0 {
			if fresh, err := c.List(ctx, r); err == nil {
				for _, l := range fresh {
					if pid, ok := created[Key(r, l)]; ok {
						idMap[r.Name][pid] = l[r.IDField]
					}
				}
			} else {
				rep.errf("%s: relist: %v", r.Name, err)
			}
		}

		if r.Prune {
			for k, l := range localByKey {
				if desiredKeys[k] {
					continue
				}
				if err := deleteItem(ctx, c, r, l[r.IDField]); err != nil {
					rep.errf("%s %s: delete: %v", r.Name, k, err)
					continue
				}
				rep.Deleted++
			}
		}
	}
	return rep
}

func deleteItem(ctx context.Context, c *Client, r config.Resource, id any) error {
	if r.DeleteMode == "path" {
		_, err := c.Do(ctx, http.MethodDelete, r.Path+"/"+idString(id), "", nil)
		return err
	}
	_, err := c.Do(ctx, http.MethodDelete, r.Path, "", map[string]any{"ids": []any{id}})
	return err
}

func decode(b []byte) (map[string]any, error) {
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.UseNumber()
	var m map[string]any
	return m, dec.Decode(&m)
}

// translateRefs rewrites fields holding primary IDs into local IDs.
func translateRefs(r config.Resource, body map[string]any, idMap map[string]map[string]any) error {
	for field, kind := range r.Refs {
		v, ok := body[field]
		if !ok || v == nil {
			continue
		}
		m, ok := idMap[kind]
		if !ok {
			return fmt.Errorf("field %s references %s, which is not replicated before %s", field, kind, r.Name)
		}
		conv := func(pid any) (any, error) {
			s := idString(pid)
			if s == "" || s == "0" {
				return pid, nil
			}
			lid, ok := m[s]
			if !ok {
				return nil, fmt.Errorf("field %s: %s %s is unknown on this node", field, kind, s)
			}
			return lid, nil
		}
		if arr, ok := v.([]any); ok {
			out := make([]any, len(arr))
			for i, x := range arr {
				y, err := conv(x)
				if err != nil {
					return err
				}
				out[i] = y
			}
			body[field] = out
			continue
		}
		y, err := conv(v)
		if err != nil {
			return err
		}
		body[field] = y
	}
	return nil
}

// subsetEqual reports whether every field of want has the same value in got.
func subsetEqual(want, got map[string]any) bool {
	for k, v := range want {
		if !reflect.DeepEqual(normalize(v), normalize(got[k])) {
			return false
		}
	}
	return true
}

// normalize makes values decoded from different JSON documents comparable.
func normalize(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var out any
	_ = json.Unmarshal(b, &out)
	return out
}
