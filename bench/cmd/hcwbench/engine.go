package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// engine is one running hcw-waf process with a private data directory.
type engine struct {
	cmd     *exec.Cmd
	dir     string
	api     string // https://host:port
	token   string
	client  *http.Client
	logFile *os.File
	exited  chan struct{}
}

type engineOpts struct {
	bin      string
	apiAddr  string
	procs    int    // GOMAXPROCS of the engine (0 = leave unset)
	cpus     string // taskset CPU list ("" = no pinning)
	tmpRoot  string
	scenario string
}

func startEngine(o engineOpts) (*engine, error) {
	dir, err := os.MkdirTemp(o.tmpRoot, "engine-"+o.scenario+"-")
	if err != nil {
		return nil, err
	}
	tok := make([]byte, 20)
	_, _ = rand.Read(tok)
	e := &engine{dir: dir, api: "https://" + o.apiAddr, token: hex.EncodeToString(tok), exited: make(chan struct{})}
	cfg := fmt.Sprintf("data_dir: %q\nbind: 127.0.0.1\napi:\n  listen: %q\n  token: %q\n", filepath.Join(dir, "data"), o.apiAddr, e.token)
	cfgPath := filepath.Join(dir, "waf.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		return nil, err
	}
	if e.logFile, err = os.Create(filepath.Join(dir, "engine.log")); err != nil {
		return nil, err
	}
	args := []string{o.bin, "-config", cfgPath}
	if o.cpus != "" {
		args = append([]string{"taskset", "-c", o.cpus}, args...)
	}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout, cmd.Stderr = e.logFile, e.logFile
	cmd.Env = os.Environ()
	if o.procs > 0 {
		cmd.Env = append(cmd.Env, "GOMAXPROCS="+strconv.Itoa(o.procs))
	}
	// taskset execs the engine in place, so the PID is the engine's.
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", o.bin, err)
	}
	e.cmd = cmd
	go func() { _ = cmd.Wait(); close(e.exited) }()
	e.client = &http.Client{
		Timeout: 120 * time.Second,
		Transport: &http.Transport{
			Proxy: nil, // never route local traffic through HTTP(S)_PROXY
			// The management API uses a self-signed certificate on loopback.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // local benchmark only
		},
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		select {
		case <-e.exited:
			return nil, fmt.Errorf("engine exited during start-up, see %s:\n%s", e.logFile.Name(), e.tail())
		default:
		}
		if _, err := e.call("GET", "/api/open/health", nil); err == nil {
			return e, nil
		}
		if time.Now().After(deadline) {
			e.stop()
			return nil, fmt.Errorf("engine API did not come up within 60s:\n%s", e.tail())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (e *engine) pid() int { return e.cmd.Process.Pid }

func (e *engine) tail() string {
	b, _ := os.ReadFile(e.logFile.Name())
	if len(b) > 2000 {
		b = b[len(b)-2000:]
	}
	return string(b)
}

// call performs a management API request and returns the "data" field.
func (e *engine) call(method, path string, body any) (json.RawMessage, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, e.api+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-HCW-API-TOKEN", e.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var env struct {
		Data json.RawMessage `json:"data"`
		Err  *string         `json:"err"`
		Msg  string          `json:"msg"`
	}
	b, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(b, &env); err != nil {
		return nil, fmt.Errorf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if resp.StatusCode != http.StatusOK || env.Err != nil {
		return nil, fmt.Errorf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, env.Msg)
	}
	return env.Data, nil
}

// createSite POSTs a site; the call returns after the engine applied the whole
// configuration (the API applies synchronously), so its latency is the
// end-to-end Apply cost seen by an operator.
func (e *engine) createSite(site map[string]any) (time.Duration, error) {
	start := time.Now()
	_, err := e.call("POST", "/api/open/site", site)
	return time.Since(start), err
}

func (e *engine) stop() {
	if e.cmd == nil || e.cmd.Process == nil {
		return
	}
	_ = e.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-e.exited:
	case <-time.After(5 * time.Second):
		_ = e.cmd.Process.Kill()
		<-e.exited
	}
	if e.logFile != nil {
		_ = e.logFile.Close()
	}
}

// procSample is a snapshot of the engine process from /proc.
type procSample struct {
	cpu   time.Duration // utime+stime of all threads
	rssKB int64         // VmRSS
	hwmKB int64         // VmHWM (peak RSS since start)
}

// clockTicks is USER_HZ; it is 100 on every mainstream Linux architecture
// (the stdlib has no sysconf without cgo).
const clockTicks = 100

func sampleProc(pid int) (procSample, error) {
	var s procSample
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return s, err
	}
	// Fields after the command name, which is in parentheses and may contain spaces.
	i := bytes.LastIndexByte(b, ')')
	if i < 0 {
		return s, errors.New("malformed /proc/pid/stat")
	}
	f := strings.Fields(string(b[i+1:]))
	// f[0] is field 3 (state); utime is field 14, stime field 15.
	if len(f) < 13 {
		return s, errors.New("short /proc/pid/stat")
	}
	ut, _ := strconv.ParseInt(f[11], 10, 64)
	st, _ := strconv.ParseInt(f[12], 10, 64)
	s.cpu = time.Duration(ut+st) * time.Second / clockTicks
	st2, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return s, err
	}
	for _, line := range strings.Split(string(st2), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		n, _ := strconv.ParseInt(strings.TrimSuffix(strings.TrimSpace(v), " kB"), 10, 64)
		switch k {
		case "VmRSS":
			s.rssKB = n
		case "VmHWM":
			s.hwmKB = n
		}
	}
	return s, nil
}

// waitIdle lets the engine settle (GC after a CRS compile) before measuring.
func waitIdle(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}
