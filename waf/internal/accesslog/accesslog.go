// Package accesslog writes one JSON line per request with size-based
// rotation. Writes are asynchronous: a full buffer drops lines (counted)
// rather than slowing traffic down.
package accesslog

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// Entry is one request.
type Entry struct {
	Time       time.Time `json:"time"`
	SiteID     int       `json:"site_id"`
	Host       string    `json:"host"`
	ClientIP   string    `json:"client_ip"`
	Country    string    `json:"country,omitempty"`
	Method     string    `json:"method"`
	URI        string    `json:"uri"`
	Proto      string    `json:"proto"`
	TLS        bool      `json:"tls"`
	Status     int       `json:"status"`
	Bytes      int64     `json:"bytes"`
	DurationMS float64   `json:"duration_ms"`
	UserAgent  string    `json:"user_agent,omitempty"`
	Referer    string    `json:"referer,omitempty"`
	// Action: proxied, cached, blocked, challenged, redirected, error.
	Action  string `json:"action"`
	EventID string `json:"event_id,omitempty"`
}

// Config controls the log file.
type Config struct {
	File      string `yaml:"file"`
	MaxSizeMB int    `yaml:"max_size_mb"` // rotate after this size (default 100)
	MaxFiles  int    `yaml:"max_files"`   // rotated files kept (default 5)
}

// Logger is safe for concurrent use.
type Logger struct {
	cfg     Config
	ch      chan Entry
	dropped atomic.Uint64
	wg      sync.WaitGroup

	f    *os.File
	w    *bufio.Writer
	size int64
}

// New opens cfg.File and starts the writer.
func New(cfg Config) (*Logger, error) {
	if cfg.MaxSizeMB <= 0 {
		cfg.MaxSizeMB = 100
	}
	if cfg.MaxFiles <= 0 {
		cfg.MaxFiles = 5
	}
	l := &Logger{cfg: cfg, ch: make(chan Entry, 8192)}
	if err := l.open(); err != nil {
		return nil, err
	}
	l.wg.Add(1)
	go l.loop()
	return l, nil
}

func (l *Logger) open() error {
	if err := os.MkdirAll(filepath.Dir(l.cfg.File), 0o750); err != nil {
		return err
	}
	f, err := os.OpenFile(l.cfg.File, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	l.f, l.w, l.size = f, bufio.NewWriterSize(f, 64<<10), st.Size()
	return nil
}

// Log queues e; it never blocks.
func (l *Logger) Log(e Entry) {
	select {
	case l.ch <- e:
	default:
		l.dropped.Add(1)
	}
}

// Dropped reports lines lost because the writer could not keep up.
func (l *Logger) Dropped() uint64 { return l.dropped.Load() }

func (l *Logger) loop() {
	defer l.wg.Done()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case e, ok := <-l.ch:
			if !ok {
				_ = l.w.Flush()
				_ = l.f.Close()
				return
			}
			b, err := json.Marshal(e)
			if err != nil {
				continue
			}
			b = append(b, '\n')
			if l.size+int64(len(b)) > int64(l.cfg.MaxSizeMB)<<20 {
				l.rotate()
			}
			n, _ := l.w.Write(b)
			l.size += int64(n)
		case <-tick.C:
			_ = l.w.Flush()
		}
	}
}

// rotate shifts file -> file.1 -> ... -> file.N (oldest removed).
func (l *Logger) rotate() {
	_ = l.w.Flush()
	_ = l.f.Close()
	for i := l.cfg.MaxFiles - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", l.cfg.File, i), fmt.Sprintf("%s.%d", l.cfg.File, i+1))
	}
	_ = os.Remove(fmt.Sprintf("%s.%d", l.cfg.File, l.cfg.MaxFiles+1))
	_ = os.Rename(l.cfg.File, l.cfg.File+".1")
	if err := l.open(); err != nil {
		// Keep running; entries are dropped until the file can be opened.
		l.f, _ = os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		l.w = bufio.NewWriter(l.f)
	}
}

// Close flushes and closes the file.
func (l *Logger) Close() {
	close(l.ch)
	l.wg.Wait()
}
