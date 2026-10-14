package hcw

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/mcp_server/internal/config"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/mcp_server/internal/secret"
)

// Source identifies the instance a result was read from. It never holds an
// address or a credential.
type Source struct {
	InstanceID  string `json:"instance_id"`
	DisplayName string `json:"display_name"`
}

// Instance is one configured hcw-waf node.
type Instance struct {
	Source
	// ReadOnly refuses write tools on this instance.
	ReadOnly bool
	Client   *Client
}

// Registry maps instance IDs to independently authenticated clients.
type Registry struct {
	byID  map[string]*Instance
	order []string
}

// NewRegistry builds a client per instance. Tokens are read once, from the
// token file or the environment variable of each instance.
func NewRegistry(cfgs []*config.InstanceConfig) (*Registry, error) {
	if len(cfgs) == 0 {
		return nil, errors.New("at least one HiTechCloud WAF instance is required")
	}
	r := &Registry{byID: map[string]*Instance{}}
	for i, cfg := range cfgs {
		if cfg == nil || strings.TrimSpace(cfg.ID) == "" {
			return nil, fmt.Errorf("instances[%d].id is required", i)
		}
		if _, dup := r.byID[cfg.ID]; dup {
			return nil, fmt.Errorf("duplicate instance id %q", cfg.ID)
		}
		var token string
		var err error
		if cfg.TokenEnv != "" {
			token, err = secret.FromEnv(cfg.TokenEnv)
		} else {
			token, err = secret.ReadTokenFile(cfg.TokenFile)
		}
		if err != nil {
			return nil, fmt.Errorf("instance %q: %w", cfg.ID, err)
		}
		timeout := time.Duration(cfg.Timeout) * time.Second
		client, err := NewClient(ClientConfig{BaseURL: cfg.BaseURL, Token: token, CAFile: cfg.CAFile, Timeout: timeout})
		if err != nil {
			return nil, fmt.Errorf("instance %q: %w", cfg.ID, err)
		}
		name := cfg.DisplayName
		if name == "" {
			name = cfg.ID
		}
		r.byID[cfg.ID] = &Instance{Source: Source{InstanceID: cfg.ID, DisplayName: name}, ReadOnly: cfg.ReadOnly, Client: client}
		r.order = append(r.order, cfg.ID)
	}
	return r, nil
}

// Add registers an instance with a ready client (tests).
func (r *Registry) Add(id, displayName string, readOnly bool, client *Client) {
	if r.byID == nil {
		r.byID = map[string]*Instance{}
	}
	if displayName == "" {
		displayName = id
	}
	if _, ok := r.byID[id]; !ok {
		r.order = append(r.order, id)
	}
	r.byID[id] = &Instance{Source: Source{InstanceID: id, DisplayName: displayName}, ReadOnly: readOnly, Client: client}
}

// Resolve returns the instance named by id. An empty id selects the only
// instance when exactly one is configured; it never picks one of several.
func (r *Registry) Resolve(id string) (*Instance, error) {
	if r == nil || len(r.byID) == 0 {
		return nil, errors.New("no HiTechCloud WAF instance is configured")
	}
	id = strings.TrimSpace(id)
	if id == "" {
		if len(r.order) == 1 {
			return r.byID[r.order[0]], nil
		}
		return nil, fmt.Errorf("instance_id is required; configured instances: %s", strings.Join(r.IDs(), ", "))
	}
	inst, ok := r.byID[id]
	if !ok {
		return nil, fmt.Errorf("unknown instance_id %q; configured instances: %s", Clean(id, 64), strings.Join(r.IDs(), ", "))
	}
	return inst, nil
}

// IDs lists the configured instance IDs, sorted.
func (r *Registry) IDs() []string {
	ids := append([]string(nil), r.order...)
	sort.Strings(ids)
	return ids
}

// Instances lists the instances in configuration order.
func (r *Registry) Instances() []*Instance {
	out := make([]*Instance, 0, len(r.order))
	for _, id := range r.order {
		out = append(out, r.byID[id])
	}
	return out
}
