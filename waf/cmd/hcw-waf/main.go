// Command hcw-waf is the HiTechCloud WAF engine: a reverse proxy with OWASP
// CRS inspection, IP ACL and rate limiting, managed through an HTTP API.
//
//	hcw-waf -config /etc/hcw-waf/waf.yaml
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/accesslog"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/alerts"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/audit"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/config"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/console"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/events"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/geoip"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/mgmt"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/proxy"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/store"
	"github.com/hitechcloud-vietnam/HiTechCloudWAF/waf/internal/users"
)

var version = "dev"

func main() {
	path := flag.String("config", "/etc/hcw-waf/waf.yaml", "configuration file")
	debug := flag.Bool("debug", false, "debug logging")
	showVersion := flag.Bool("version", false, "print version")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	if err := run(*path, log); err != nil {
		log.Error("exited", "err", err)
		os.Exit(1)
	}
}

func run(path string, log *slog.Logger) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "config.json"))
	if err != nil {
		return err
	}
	evlog, err := events.New(cfg.EventsKept, cfg.EventsFile)
	if err != nil {
		return err
	}
	defer evlog.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var alertSender *alerts.Notifier
	secret, err := loadSecret(cfg.ChallengeSecretFile, filepath.Join(cfg.DataDir, "challenge.key"))
	if err != nil {
		return fmt.Errorf("challenge secret: %w", err)
	}
	var geo *geoip.DB
	if cfg.GeoIPDB != "" {
		if geo, err = geoip.Open(cfg.GeoIPDB); err != nil {
			return fmt.Errorf("geoip_db: %w", err)
		}
		hup := make(chan os.Signal, 1)
		signal.Notify(hup, syscall.SIGHUP)
		go func() {
			for range hup {
				if err := geo.Reload(cfg.GeoIPDB); err != nil {
					log.Error("geoip reload failed", "err", err)
				} else {
					log.Info("geoip database reloaded")
				}
			}
		}()
	}
	var geoIface interface{ Country(net.IP) string }
	if geo != nil {
		geoIface = geo
	}
	var access interface{ Log(accesslog.Entry) }
	if cfg.AccessLog.File != "" {
		al, err := accesslog.New(cfg.AccessLog)
		if err != nil {
			return fmt.Errorf("access_log: %w", err)
		}
		defer al.Close()
		access = al
	}
	eng := proxy.New(ctx, proxy.Options{
		Access: access,
		GeoIP:  geoIface,
		Bind:   cfg.Bind, BodyLimit: cfg.BodyLimitKB * 1024, TrustedProxies: cfg.TrustedNets, CacheMB: cfg.CacheMB,
		Brand: cfg.Brand, ExtraRules: cfg.ExtraRules, Secret: secret, Log: log, Events: evlog,
	})
	if cfg.ACME.Enabled {
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Email:      cfg.ACME.Email,
			Cache:      autocert.DirCache(filepath.Join(cfg.DataDir, "acme")),
			HostPolicy: eng.ACMEHostPolicy,
		}
		if cfg.ACME.DirectoryURL != "" {
			m.Client = &acme.Client{DirectoryURL: cfg.ACME.DirectoryURL}
		}
		eng.SetCertProvider(m)
		log.Info("ACME enabled", "directory", cfg.ACME.DirectoryURL)
	}
	start := time.Now()
	if err := eng.Apply(st.Sites(), st.Certs()); err != nil {
		// Keep running so the configuration can be fixed through the API.
		log.Error("initial configuration not fully applied", "err", err)
	}
	log.Info("engine ready", "version", version, "sites", len(st.Sites()), "took", time.Since(start).String())

	if cfg.Alerts.Enabled() {
		notifier := alerts.New(cfg.Alerts, cfg.NodeName, func(id int) string {
			for _, s := range st.Sites() {
				if s.ID == id {
					return s.Name
				}
			}
			return fmt.Sprintf("site #%d", id)
		}, log)
		evlog.OnAdd(notifier.Observe)
		go notifier.Run(ctx, 10*time.Second)
		alertSender = notifier
		log.Info("alerts enabled", "telegram", cfg.Alerts.Telegram.ChatID != "", "webhooks", len(cfg.Alerts.Webhooks))
	}
	api := &mgmt.API{Token: cfg.API.Token, Store: st, Events: evlog, Apply: eng.Apply, Log: log,
		Brand: cfg.Brand, Version: version, Started: start, Console: console.Handler(), Allow: cfg.APIAllow,
		Upstreams: func() any { return eng.UpstreamStatus() }}
	if alertSender != nil {
		api.Alerts = alertSender
	}
	if api.Audit, err = audit.New(filepath.Join(cfg.DataDir, "audit.log"), 2000); err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	defer api.Audit.Close()
	if api.Users, err = users.Open(filepath.Join(cfg.DataDir, "users.json")); err != nil {
		return fmt.Errorf("users: %w", err)
	}
	crt, key := cfg.API.TLSCert, cfg.API.TLSKey
	if crt == "" {
		crt, key = filepath.Join(cfg.DataDir, "api.crt"), filepath.Join(cfg.DataDir, "api.key")
		if err := ensureSelfSigned(crt, key); err != nil {
			return fmt.Errorf("api certificate: %w", err)
		}
	}
	srv := &http.Server{
		Addr: cfg.API.Listen, Handler: api.Handler(),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		sh, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sh)
		eng.Shutdown(sh)
	}()
	log.Info("management API listening", "addr", cfg.API.Listen)
	if err := srv.ListenAndServeTLS(crt, key); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// loadSecret reads the configured secret file, or creates a random one at
// fallback so challenge passes survive restarts.
func loadSecret(configured, fallback string) ([]byte, error) {
	if configured != "" {
		b, err := os.ReadFile(configured)
		if err != nil {
			return nil, err
		}
		b = []byte(strings.TrimSpace(string(b)))
		if len(b) < 32 {
			return nil, fmt.Errorf("%s must hold at least 32 characters", configured)
		}
		return b, nil
	}
	if b, err := os.ReadFile(fallback); err == nil && len(b) >= 32 {
		return b, nil
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	s := []byte(fmt.Sprintf("%x", b))
	return s, os.WriteFile(fallback, s, 0o600)
}

// ensureSelfSigned creates a certificate for the local management API.
func ensureSelfSigned(crtPath, keyPath string) error {
	if _, err := os.Stat(crtPath); err == nil {
		return nil
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"HiTechCloud WAF"}, CommonName: "hcw-waf api"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", host},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		return err
	}
	kb, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return err
	}
	return os.WriteFile(crtPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}
