// Package geoip resolves client addresses to ISO country codes from a
// MaxMind-format database (GeoLite2-Country, DB-IP Country Lite, ...).
package geoip

import (
	"net"
	"sync/atomic"

	"github.com/oschwald/maxminddb-golang"
)

// DB is safe for concurrent use and can be reloaded.
type DB struct {
	r atomic.Pointer[maxminddb.Reader]
}

type record struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	// Some databases only fill registered_country.
	Registered struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"registered_country"`
}

// Open loads path.
func Open(path string) (*DB, error) {
	d := &DB{}
	return d, d.Reload(path)
}

// Reload swaps in a new database file (e.g. after a monthly update).
func (d *DB) Reload(path string) error {
	r, err := maxminddb.Open(path)
	if err != nil {
		return err
	}
	if old := d.r.Swap(r); old != nil {
		// Readers in flight keep their own reference to the mmap until done;
		// maxminddb unmaps on Close, so close lazily is not possible. The
		// swap happens rarely, so leaking the old mapping is acceptable.
		_ = old
	}
	return nil
}

// Country returns the ISO 3166-1 alpha-2 code, or "" when unknown.
func (d *DB) Country(ip net.IP) string {
	if d == nil {
		return ""
	}
	r := d.r.Load()
	if r == nil || ip == nil {
		return ""
	}
	var rec record
	if err := r.Lookup(ip, &rec); err != nil {
		return ""
	}
	if rec.Country.ISOCode != "" {
		return rec.Country.ISOCode
	}
	return rec.Registered.ISOCode
}
