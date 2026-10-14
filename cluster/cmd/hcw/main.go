// Command hcw runs the HiTechCloud WAF cluster roles:
//
//	hcw controller -config /etc/hcw/controller.yaml
//	hcw agent      -config /etc/hcw/agent.yaml
//	hcw dns        -config /etc/hcw/dns.yaml
//	hcw token                       # print a new random token
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/agent"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/config"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/controller"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/cluster/internal/dnsserver"
)

var version = "dev"

func usage() {
	fmt.Fprintf(os.Stderr, "HiTechCloud WAF cluster %s\n\nusage: hcw <controller|agent|dns|token|version> [-config file] [-debug]\n", version)
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	role := os.Args[1]
	switch role {
	case "token":
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(hex.EncodeToString(b))
		return
	case "version":
		fmt.Println(version)
		return
	case "controller", "agent", "dns":
	default:
		usage()
	}

	fs := flag.NewFlagSet(role, flag.ExitOnError)
	path := fs.String("config", "/etc/hcw/"+role+".yaml", "configuration file")
	debug := fs.Bool("debug", false, "debug logging")
	_ = fs.Parse(os.Args[2:])

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})).With("role", role)

	cfg, err := config.Load(*path)
	if err != nil {
		log.Error("load config", "err", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	agent.Version = version
	switch role {
	case "controller":
		if cfg.Controller == nil {
			log.Error("config has no controller section")
			os.Exit(1)
		}
		s, e := controller.New(cfg.Controller, log)
		if e == nil {
			e = s.Run(ctx)
		}
		err = e
	case "agent":
		if cfg.Agent == nil {
			log.Error("config has no agent section")
			os.Exit(1)
		}
		a, e := agent.New(cfg.Agent, log)
		if e == nil {
			e = a.Run(ctx)
		}
		err = e
	case "dns":
		if cfg.DNS == nil {
			log.Error("config has no dns section")
			os.Exit(1)
		}
		d, e := dnsserver.New(cfg.DNS, log)
		if e == nil {
			e = d.Run(ctx)
		}
		err = e
	}
	if err != nil {
		log.Error("exited", "err", err)
		os.Exit(1)
	}
}
