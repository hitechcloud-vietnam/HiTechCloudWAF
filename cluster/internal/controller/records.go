package controller

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/api"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/dnsrecord"
)

const (
	maxDNSRecords = 10000
	maxRecordTTL  = 7 * 24 * 3600
)

var (
	errInvalidRecord  = errors.New("invalid record")
	errRecordConflict = errors.New("record conflict")
)

// RecordStore holds the static DNS records managed through the API. It is
// persisted like the node registry: a JSON file replaced atomically.
type RecordStore struct {
	mu      sync.RWMutex
	path    string
	serial  uint32
	records map[string]*api.DNSRecord
	now     func() time.Time
}

type recordFile struct {
	Serial  uint32          `json:"serial"`
	Records []api.DNSRecord `json:"records"`
}

// NewRecordStore loads path when it exists.
func NewRecordStore(path string) (*RecordStore, error) {
	s := &RecordStore{path: path, records: map[string]*api.DNSRecord{}, now: time.Now}
	if path == "" {
		return s, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var f recordFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	s.serial = f.Serial
	for i := range f.Records {
		r := f.Records[i]
		s.records[r.ID] = &r
	}
	return s, nil
}

func (s *RecordStore) saveLocked() error {
	if s.path == "" {
		return nil
	}
	return writeJSONFile(s.path, recordFile{Serial: s.serial, Records: s.listLocked("")})
}

func (s *RecordStore) listLocked(zone string) []api.DNSRecord {
	out := make([]api.DNSRecord, 0, len(s.records))
	for _, r := range s.records {
		if zone == "" || r.Zone == zone {
			out = append(out, *r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Zone != b.Zone {
			return a.Zone < b.Zone
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		return a.ID < b.ID
	})
	return out
}

// bumpLocked moves the serial forward: the current time, or +1 when several
// changes happen within the same second.
func (s *RecordStore) bumpLocked() {
	next := uint32(s.now().Unix())
	if next <= s.serial {
		next = s.serial + 1
	}
	s.serial = next
}

// Set returns the records of zone (all zones when empty).
func (s *RecordStore) Set(zone string) api.DNSRecordSet {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return api.DNSRecordSet{Serial: s.serial, Records: s.listLocked(strings.TrimSuffix(strings.ToLower(zone), "."))}
}

// Get returns one record.
func (s *RecordStore) Get(id string) (api.DNSRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.records[id]
	if !ok {
		return api.DNSRecord{}, false
	}
	return *r, true
}

// Create validates and adds a record.
func (s *RecordStore) Create(r api.DNSRecord) (api.DNSRecord, error) {
	rr, err := normalizeRecord(&r)
	if err != nil {
		return r, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.records) >= maxDNSRecords {
		return r, fmt.Errorf("%w: at most %d records", errRecordConflict, maxDNSRecords)
	}
	if err := s.conflictLocked("", r, rr); err != nil {
		return r, err
	}
	r.ID = newID()
	r.UpdatedAt = s.now().UTC()
	s.records[r.ID] = &r
	s.bumpLocked()
	return r, s.saveLocked()
}

// Update replaces the record id.
func (s *RecordStore) Update(id string, r api.DNSRecord) (api.DNSRecord, error) {
	rr, err := normalizeRecord(&r)
	if err != nil {
		return r, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[id]; !ok {
		return r, os.ErrNotExist
	}
	if err := s.conflictLocked(id, r, rr); err != nil {
		return r, err
	}
	r.ID = id
	r.UpdatedAt = s.now().UTC()
	s.records[id] = &r
	s.bumpLocked()
	return r, s.saveLocked()
}

// Delete removes a record.
func (s *RecordStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[id]; !ok {
		return os.ErrNotExist
	}
	delete(s.records, id)
	s.bumpLocked()
	return s.saveLocked()
}

// conflictLocked checks rr against the other records of the same owner.
func (s *RecordStore) conflictLocked(skipID string, r api.DNSRecord, rr dns.RR) error {
	var same []dns.RR
	for id, o := range s.records {
		if id == skipID || o.Zone != r.Zone || o.Name != r.Name {
			continue
		}
		if orr, err := dnsrecord.Build(dnsrecord.Origin(o.Zone), o.Name, o.Type, o.Value, 0); err == nil {
			same = append(same, orr)
		}
	}
	if err := dnsrecord.Conflicts(same, rr); err != nil {
		return fmt.Errorf("%w: %v", errRecordConflict, err)
	}
	return nil
}

// normalizeRecord canonicalises r in place (lower-case zone without trailing
// dot, name relative to the zone, upper-case type) and validates it.
func normalizeRecord(r *api.DNSRecord) (dns.RR, error) {
	r.Zone = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(r.Zone)), ".")
	r.Type = strings.ToUpper(strings.TrimSpace(r.Type))
	r.Value = strings.TrimSpace(r.Value)
	r.Comment = strings.TrimSpace(r.Comment)
	if _, ok := dns.IsDomainName(r.Zone); !ok || r.Zone == "" {
		return nil, fmt.Errorf("%w: invalid zone %q", errInvalidRecord, r.Zone)
	}
	if r.TTL > maxRecordTTL {
		return nil, fmt.Errorf("%w: ttl must be at most %d", errInvalidRecord, maxRecordTTL)
	}
	if len(r.Comment) > 256 {
		return nil, fmt.Errorf("%w: comment is longer than 256 bytes", errInvalidRecord)
	}
	origin := dnsrecord.Origin(r.Zone)
	rr, err := dnsrecord.Build(origin, r.Name, r.Type, r.Value, r.TTL)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errInvalidRecord, err)
	}
	r.Name = dnsrecord.Relative(origin, rr.Header().Name)
	return rr, nil
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
