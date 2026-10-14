// Command hcwbench is a reproducible load benchmark of the HiTechCloud WAF
// engine (hcw-waf). It starts an in-process upstream, starts the engine from
// a given binary with a temporary configuration for every scenario, creates
// the scenario's sites through the management API and drives closed-loop
// keep-alive load against it, then prints a Markdown table.
//
//	cd waf && go build -o /tmp/hcwwaf ./cmd/hcw-waf
//	cd bench && go run ./cmd/hcwbench -waf /tmp/hcwwaf
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type config struct {
	bin          string
	apiAddr      string
	sitePort     int
	upstreamAddr string
	clients      int
	warmup       time.Duration
	measure      time.Duration
	settle       time.Duration
	manySites    int
	only         map[string]bool
	wafProcs     int
	benchProcs   int
	wafCPUs      string
	benchCPUs    string
	jsonOut      string
	keep         bool
	siteExtra    map[string]any // merged into every site definition
}

// result is one row of the report.
type result struct {
	ID, Name     string
	RPS          float64
	P50, P90     float64 // milliseconds
	P99, Max     float64
	Requests     int64
	Errors       int64
	ErrPct       float64
	FirstError   string  `json:",omitempty"`
	CPUCores     float64 // engine CPU seconds per wall second over the window
	CPUPerReqUS  float64 // engine CPU microseconds per request
	RSSIdleMB    float64 // after configuration, before load
	RSSEndMB     float64 // at the end of the window
	HWMMB        float64 // peak RSS of the engine process
	UpstreamConn int64   // new upstream TCP connections during the run
	FirstApplyMS float64 // POST of the first site (includes the CRS compile)
	LastApplyMS  float64 // POST of the last site (scenario with many sites)
	MedApplyMS   float64
	TotalApplyS  float64
	Sites        int
	BenchCPU     float64 // CPU seconds used by hcwbench (load + upstream) per wall second
	Note         string  `json:",omitempty"`
}

func main() {
	var c config
	var only, siteExtra string
	flag.StringVar(&c.bin, "waf", "/tmp/hcwwaf", "path of the hcw-waf binary")
	flag.StringVar(&c.apiAddr, "api", "127.0.0.1:19700", "management API address of the engine")
	flag.IntVar(&c.sitePort, "port", 18200, "site port served by the engine")
	flag.StringVar(&c.upstreamAddr, "upstream", "127.0.0.1:18201", "address of the in-process upstream")
	flag.IntVar(&c.clients, "c", 32, "concurrent keep-alive clients")
	flag.DurationVar(&c.warmup, "warmup", 3*time.Second, "warm-up before each measured window")
	flag.DurationVar(&c.measure, "d", 20*time.Second, "measured duration per scenario")
	flag.DurationVar(&c.settle, "settle", 2*time.Second, "pause after configuration before load (lets GC settle)")
	flag.IntVar(&c.manySites, "sites", 200, "number of sites in scenario 8")
	flag.StringVar(&only, "only", "", "comma-separated scenario IDs to run (default all), e.g. 3,6")
	flag.IntVar(&c.wafProcs, "waf-procs", 0, "GOMAXPROCS of the engine (default: half of the CPUs)")
	flag.IntVar(&c.benchProcs, "bench-procs", 0, "GOMAXPROCS of hcwbench (default: the other half)")
	flag.StringVar(&c.wafCPUs, "waf-cpus", "auto", `CPU list the engine is pinned to with taskset ("" = no pinning, "auto" = first half)`)
	flag.StringVar(&c.benchCPUs, "bench-cpus", "auto", `CPU list hcwbench is pinned to ("" = no pinning, "auto" = second half)`)
	flag.StringVar(&c.jsonOut, "json", "", "also write raw results as JSON to this file")
	flag.BoolVar(&c.keep, "keep", false, "keep the temporary directories (engine logs, configs)")
	flag.StringVar(&siteExtra, "site-extra", "", `JSON object merged into every site, e.g. '{"disabled_rules":[942100]}' (experiments)`)
	minimal := flag.Bool("minimal-headers", false, "send only User-Agent and Accept instead of browser-like headers with cookies (experiments)")
	flag.Parse()
	if *minimal {
		browserHeader = minimalHeader
	}

	if siteExtra != "" {
		if err := json.Unmarshal([]byte(siteExtra), &c.siteExtra); err != nil {
			fmt.Fprintln(os.Stderr, "hcwbench: -site-extra:", err)
			os.Exit(2)
		}
	}

	if only != "" {
		c.only = map[string]bool{}
		for _, id := range strings.Split(only, ",") {
			c.only[strings.TrimSpace(id)] = true
		}
	}
	if err := run(&c); err != nil {
		fmt.Fprintln(os.Stderr, "hcwbench:", err)
		os.Exit(1)
	}
}

func run(c *config) error {
	if _, err := os.Stat(c.bin); err != nil {
		return fmt.Errorf("engine binary: %w (build it with: cd waf && go build -o /tmp/hcwwaf ./cmd/hcw-waf)", err)
	}
	ncpu := runtime.NumCPU()
	half := max(1, ncpu/2)
	_, tasksetErr := exec.LookPath("taskset")
	if c.wafCPUs == "auto" {
		c.wafCPUs = ""
		if tasksetErr == nil && ncpu >= 2 {
			c.wafCPUs = fmt.Sprintf("0-%d", half-1)
		}
	}
	if c.benchCPUs == "auto" {
		c.benchCPUs = ""
		if tasksetErr == nil && ncpu >= 2 {
			c.benchCPUs = fmt.Sprintf("%d-%d", half, ncpu-1)
		}
	}
	if c.wafProcs == 0 {
		c.wafProcs = cpuListLen(c.wafCPUs, half)
	}
	if c.benchProcs == 0 {
		c.benchProcs = cpuListLen(c.benchCPUs, max(1, ncpu-half))
	}
	if c.benchCPUs != "" {
		// -a: every existing thread; threads created later inherit the mask.
		if out, err := exec.Command("taskset", "-a", "-cp", c.benchCPUs, strconv.Itoa(os.Getpid())).CombinedOutput(); err != nil {
			return fmt.Errorf("taskset: %v: %s", err, out)
		}
	}
	runtime.GOMAXPROCS(c.benchProcs)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	tmp, err := os.MkdirTemp("", "hcwbench-")
	if err != nil {
		return err
	}
	if !c.keep {
		defer os.RemoveAll(tmp)
	}

	up, err := startUpstream(c.upstreamAddr)
	if err != nil {
		return err
	}
	defer up.close()

	info := machineInfo(c)
	fmt.Println(info)

	var results []result
	start := time.Now()
	for _, sc := range scenarios() {
		if c.only != nil && !c.only[sc.ID] {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		fmt.Fprintf(os.Stderr, "[%s] kịch bản %s: %s …\n", time.Since(start).Round(time.Second), sc.ID, sc.Name)
		r, err := runScenario(ctx, c, tmp, up, sc)
		if err != nil {
			return fmt.Errorf("scenario %s: %w", sc.ID, err)
		}
		fmt.Fprintf(os.Stderr, "      %.0f req/s, p99 %.2f ms, lỗi %.2f%%, CPU %.0f µs/req\n", r.RPS, r.P99, r.ErrPct, r.CPUPerReqUS)
		results = append(results, r)
	}
	fmt.Println(table(results))
	fmt.Printf("Tổng thời gian chạy: %s; loadavg lúc kết thúc: %s\n", time.Since(start).Round(time.Second), loadAvg())
	if c.jsonOut != "" {
		b, _ := json.MarshalIndent(map[string]any{"machine": info, "results": results}, "", "  ")
		if err := os.WriteFile(c.jsonOut, b, 0o644); err != nil {
			return err
		}
	}
	if c.keep {
		fmt.Fprintln(os.Stderr, "thư mục tạm giữ lại:", tmp)
	}
	return ctx.Err()
}

func runScenario(ctx context.Context, c *config, tmp string, up *upstream, sc scenario) (result, error) {
	r := result{ID: sc.ID, Name: sc.Name}
	target := c.upstreamAddr
	hosts := []string{"bench.local"}
	var eng *engine
	if !sc.Direct {
		var err error
		eng, err = startEngine(engineOpts{bin: c.bin, apiAddr: c.apiAddr, procs: c.wafProcs, cpus: c.wafCPUs, tmpRoot: tmp, scenario: sc.ID})
		if err != nil {
			return r, err
		}
		defer eng.stop()
		sites := sc.Sites(c)
		hosts = hosts[:0]
		var applies []time.Duration
		for _, s := range sites {
			for k, v := range c.siteExtra {
				s[k] = v
			}
			d, err := eng.createSite(s)
			if err != nil {
				return r, err
			}
			applies = append(applies, d)
			hosts = append(hosts, s["server_names"].([]string)[0])
		}
		r.Sites = len(sites)
		r.FirstApplyMS = ms(applies[0])
		r.LastApplyMS = ms(applies[len(applies)-1])
		var total time.Duration
		for _, d := range applies {
			total += d
		}
		r.TotalApplyS = total.Seconds()
		sorted := append([]time.Duration(nil), applies...)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
		r.MedApplyMS = ms(sorted[len(sorted)/2])
		target = fmt.Sprintf("127.0.0.1:%d", c.sitePort)
	}

	// One request first: the scenario must behave as intended before it is timed.
	if err := sanity(target, sc, hosts, &r); err != nil {
		return r, err
	}
	waitIdle(ctx, c.settle)
	if eng != nil {
		if s, err := sampleProc(eng.pid()); err == nil {
			r.RSSIdleMB = mb(s.rssKB)
		}
	}

	var s0, s1 procSample
	var b0, b1 time.Duration
	var w0, w1 time.Time
	conns0 := up.newConns.Load()
	lr := runLoad(ctx, loadSpec{
		target: target, clients: c.clients, warmup: c.warmup, measure: c.measure,
		next:   func(n uint64) request { return sc.Next(n, hosts) },
		expect: sc.Expect,
		onWindow: func(start bool) {
			now := time.Now()
			var ps procSample
			if eng != nil {
				ps, _ = sampleProc(eng.pid())
			}
			bc := selfCPU()
			if start {
				s0, b0, w0 = ps, bc, now
			} else {
				s1, b1, w1 = ps, bc, now
			}
		},
	})
	r.UpstreamConn = up.newConns.Load() - conns0
	r.RPS, r.Requests, r.Errors = lr.RPS, lr.Requests, lr.Errors
	r.P50, r.P90, r.P99, r.Max = ms(lr.P50), ms(lr.P90), ms(lr.P99), ms(lr.Max)
	r.FirstError = lr.FirstError
	if lr.Requests > 0 {
		r.ErrPct = 100 * float64(lr.Errors) / float64(lr.Requests)
	}
	wall := w1.Sub(w0).Seconds()
	if wall > 0 {
		r.BenchCPU = (b1 - b0).Seconds() / wall
	}
	if eng != nil && wall > 0 {
		cpu := s1.cpu - s0.cpu
		r.CPUCores = cpu.Seconds() / wall
		if lr.Requests > 0 {
			r.CPUPerReqUS = float64(cpu.Microseconds()) / float64(lr.Requests)
		}
		r.RSSEndMB, r.HWMMB = mb(s1.rssKB), mb(s1.hwmKB)
	}
	return r, ctx.Err()
}

// sanity sends one request and checks status (and dynamic rewriting).
func sanity(target string, sc scenario, hosts []string, r *result) error {
	rq := sc.Next(0, hosts)
	req, _ := http.NewRequest(rq.method, "http://"+target+rq.path, strings.NewReader(string(rq.body)))
	req.Host = rq.host
	for k, v := range rq.header {
		req.Header[k] = v
	}
	cl := newClient(1)
	defer cl.CloseIdleConnections()
	resp, err := cl.Do(req)
	if err != nil {
		return fmt.Errorf("sanity request: %w", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != sc.Expect {
		return fmt.Errorf("sanity request: status %d, expected %d", resp.StatusCode, sc.Expect)
	}
	if sc.CheckDynamic {
		if resp.Header.Get("X-HCW-Protected") != "html" {
			return fmt.Errorf("sanity request: dynamic protection not applied (X-HCW-Protected=%q)", resp.Header.Get("X-HCW-Protected"))
		}
		r.Note = fmt.Sprintf("phản hồi %d B → %d B sau khi mã hoá", 50*1024, len(b))
	}
	return nil
}

func selfCPU() time.Duration {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

func loadAvg() string {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return "?"
	}
	f := strings.Fields(string(b))
	if len(f) < 3 {
		return "?"
	}
	return strings.Join(f[:3], " ")
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
func mb(kb int64) float64        { return float64(kb) / 1024 }

// cpuListLen counts CPUs in a taskset list such as "0-1,3".
func cpuListLen(list string, def int) int {
	if list == "" {
		return def
	}
	n := 0
	for _, part := range strings.Split(list, ",") {
		a, b, isRange := strings.Cut(part, "-")
		lo, err1 := strconv.Atoi(a)
		hi := lo
		var err2 error
		if isRange {
			hi, err2 = strconv.Atoi(b)
		}
		if err1 != nil || err2 != nil || hi < lo {
			return def
		}
		n += hi - lo + 1
	}
	return n
}

func machineInfo(c *config) string {
	model, procs := "?", 0
	if b, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			k, v, _ := strings.Cut(line, ":")
			k = strings.TrimSpace(k)
			if k == "model name" && model == "?" {
				model = strings.TrimSpace(v)
			}
			if k == "processor" {
				procs++
			}
		}
	}
	mem := "?"
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		line, _, _ := strings.Cut(string(b), "\n")
		mem = strings.TrimSpace(strings.TrimPrefix(line, "MemTotal:"))
	}
	kernel := "?"
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		kernel = strings.TrimSpace(string(b))
	}
	ver := "?"
	if out, err := exec.Command(c.bin, "-version").Output(); err == nil {
		ver = strings.TrimSpace(string(out))
	}
	pin := func(s string) string {
		if s == "" {
			return "không ghim"
		}
		return "CPU " + s
	}
	var b strings.Builder
	fmt.Fprintf(&b, "## Máy đo\n\n")
	fmt.Fprintf(&b, "- CPU: %s, nproc = %d (runtime.NumCPU = %d)\n", model, procs, runtime.NumCPU())
	fmt.Fprintf(&b, "- RAM: %s, kernel %s, %s/%s\n", mem, kernel, runtime.GOOS, runtime.GOARCH)
	fmt.Fprintf(&b, "- hcwbench: %s, GOMAXPROCS=%d, %s\n", runtime.Version(), c.benchProcs, pin(c.benchCPUs))
	fmt.Fprintf(&b, "- hcw-waf: %s (phiên bản %s), GOMAXPROCS=%d, %s\n", c.bin, ver, c.wafProcs, pin(c.wafCPUs))
	fmt.Fprintf(&b, "- Tải: %d client keep-alive vòng kín, khởi động %s + đo %s mỗi kịch bản\n", c.clients, c.warmup, c.measure)
	fmt.Fprintf(&b, "- loadavg lúc bắt đầu: %s (máy dùng chung thì số liệu dao động)\n", loadAvg())
	return b.String()
}

func table(rs []result) string {
	var b strings.Builder
	b.WriteString("## Kết quả\n\n")
	b.WriteString("| # | Kịch bản | req/s | p50 ms | p90 ms | p99 ms | max ms | Lỗi % | CPU engine (lõi) | CPU µs/req | RSS MB (nghỉ → cuối, đỉnh) | Kết nối upstream mới | Apply (POST) |\n")
	b.WriteString("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|---:|---|\n")
	for _, r := range rs {
		cpu, per, rss, apply := "–", "–", "–", "–"
		if r.Sites > 0 {
			cpu = fmt.Sprintf("%.2f", r.CPUCores)
			per = fmt.Sprintf("%.0f", r.CPUPerReqUS)
			rss = fmt.Sprintf("%.0f → %.0f, %.0f", r.RSSIdleMB, r.RSSEndMB, r.HWMMB)
			apply = fmt.Sprintf("%.0f ms", r.FirstApplyMS)
			if r.Sites > 1 {
				apply = fmt.Sprintf("%d site: đầu %.0f ms, trung vị %.0f ms, cuối %.0f ms, tổng %.1f s", r.Sites, r.FirstApplyMS, r.MedApplyMS, r.LastApplyMS, r.TotalApplyS)
			}
		}
		name := r.Name
		if r.Note != "" {
			name += " (" + r.Note + ")"
		}
		fmt.Fprintf(&b, "| %s | %s | %.0f | %.2f | %.2f | %.2f | %.2f | %.2f | %s | %s | %s | %d | %s |\n",
			r.ID, name, r.RPS, r.P50, r.P90, r.P99, r.Max, r.ErrPct, cpu, per, rss, r.UpstreamConn, apply)
	}
	for _, r := range rs {
		if r.FirstError != "" {
			fmt.Fprintf(&b, "\nLỗi đầu tiên ở kịch bản %s: %s\n", r.ID, r.FirstError)
		}
	}
	b.WriteString("\nCPU engine (lõi) = giây CPU (utime+stime, /proc/<pid>/stat) của hcw-waf trên mỗi giây đo; CPU µs/req = CPU engine chia cho số request. ")
	b.WriteString("Kết nối upstream mới = số kết nối TCP upstream nhận trong lúc chạy (keep-alive tốt ⇒ gần bằng số client). ")
	b.WriteString("Apply (POST) = thời gian POST /api/open/site trả về, gồm validate, ghi config.json và Engine.Apply (lần đầu có biên dịch CRS).\n")
	return b.String()
}
