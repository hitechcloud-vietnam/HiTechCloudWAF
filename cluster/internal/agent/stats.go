//go:build linux

package agent

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/api"
)

// collectStats reads host metrics from /proc. Missing files (non-Linux) leave
// zero values.
func collectStats(diskPath string) api.Stats {
	s := api.Stats{CPUs: runtime.NumCPU()}
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		f := strings.Fields(string(b))
		if len(f) >= 3 {
			s.Load1, _ = strconv.ParseFloat(f[0], 64)
			s.Load5, _ = strconv.ParseFloat(f[1], 64)
			s.Load15, _ = strconv.ParseFloat(f[2], 64)
		}
	}
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			v, _ := strconv.ParseFloat(f[0], 64)
			s.UptimeSec = uint64(v)
		}
	}
	if f, err := os.Open("/proc/meminfo"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 2 {
				continue
			}
			kb, _ := strconv.ParseUint(fields[1], 10, 64)
			switch fields[0] {
			case "MemTotal:":
				s.MemTotalMB = kb / 1024
			case "MemAvailable:":
				s.MemAvailMB = kb / 1024
			}
		}
		f.Close()
	}
	if diskPath == "" {
		diskPath = "/"
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(diskPath, &st); err != nil {
		_ = syscall.Statfs("/", &st)
	}
	s.DiskFreeMB = st.Bavail * uint64(st.Bsize) / (1 << 20)
	s.DiskTotalMB = st.Blocks * uint64(st.Bsize) / (1 << 20)
	return s
}
