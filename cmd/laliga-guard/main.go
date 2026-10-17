package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/alperdevv/laliga-bypass/internal/cloudflare"
	"github.com/alperdevv/laliga-bypass/internal/collector"
	"github.com/alperdevv/laliga-bypass/internal/config"
	"github.com/alperdevv/laliga-bypass/internal/controller"
	"github.com/alperdevv/laliga-bypass/internal/detector"
	"github.com/alperdevv/laliga-bypass/internal/discover"
	"github.com/alperdevv/laliga-bypass/internal/monitor"
	"github.com/alperdevv/laliga-bypass/internal/notifier"
	"github.com/alperdevv/laliga-bypass/internal/preflight"
	"github.com/alperdevv/laliga-bypass/internal/sources"
	"github.com/alperdevv/laliga-bypass/internal/state"
)

var version = "dev"

func resolveVersion(linked string, info *debug.BuildInfo, ok bool) string {
	if linked != "" && linked != "dev" {
		return linked
	}
	if !ok || info == nil {
		return "dev"
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	var rev string
	var dirty bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev == "" {
		return "dev"
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	if dirty {
		rev += "-dirty"
	}
	return "dev-" + rev
}

func main() {
	info, ok := debug.ReadBuildInfo()
	version = resolveVersion(version, info, ok)
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	cmd := "run"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", envOr("CONFIG_PATH", "/etc/laliga-guard/config.yaml"), "path to the YAML config file")
	domain := fs.String("domain", "", "rollback: domain to roll back (empty = all); discover: zone name")
	zoneID := fs.String("zone-id", "", "discover: zone ID (use with -domain when the token lacks Zone:Read)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	log := newLogger(stdout)

	switch cmd {
	case "run":
		return cmdRun(*cfgPath, log)
	case "validate":
		return cmdValidate(*cfgPath, stdout, log)
	case "status":
		return cmdStatus(*cfgPath, stdout, stderr)
	case "healthcheck":
		return cmdHealthcheck(*cfgPath, stderr)
	case "rollback":
		return cmdRollback(*cfgPath, *domain, log)
	case "discover":
		return cmdDiscover(*domain, *zoneID, stdout, stderr)
	case "notify-test":
		return cmdNotifyTest(*cfgPath, stdout, log)
	case "version":
		fmt.Fprintln(stdout, version)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q (run, validate, discover, notify-test, status, healthcheck, rollback, version)\n", cmd)
		return 2
	}
}

func newLogger(w io.Writer) *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(os.Getenv("LOG_LEVEL")) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level}))
}

func loadConfig(path string) (*config.Config, error) {
	if inline := os.Getenv("CONFIG_YAML"); strings.TrimSpace(inline) != "" {
		cfg, err := config.Parse([]byte(inline), os.Getenv)
		if err != nil {
			return nil, fmt.Errorf("CONFIG_YAML: %w", err)
		}
		return cfg, nil
	}
	return config.Load(path, os.Getenv)
}

func cmdRun(cfgPath string, log *slog.Logger) int {
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		log.Error("invalid configuration", "error", err.Error())
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	notify := buildNotifier(cfg, log)
	if !cfg.DryRun {
		if problems := cfg.AutomaticModeProblems(); len(problems) > 0 {
			cfg.DryRun = true
			_ = notify.Notify(ctx, notifier.Event{
				Time: time.Now(), Level: notifier.LevelCritical, Kind: "automatic_mode_refused",
				Message: "DRY_RUN=false requested but detection is not reliable enough: running in observation mode (DRY_RUN=true)",
				Reasons: problems,
			})
		}
	}

	store := state.Store{Path: cfg.StateFile}
	if err := os.MkdirAll(filepath.Dir(cfg.StateFile), 0o700); err != nil {
		log.Error("cannot create state directory", "error", err.Error())
		return 1
	}
	unlock, err := store.Lock()
	if err != nil {
		log.Error("cannot lock state", "error", err.Error())
		return 1
	}
	defer unlock()

	dns, err := buildDNS(cfg)
	if err != nil {
		log.Error("cannot create Cloudflare client", "error", err.Error())
		return 1
	}
	logStartup(log, cfg, dns != nil)
	if dns != nil {
		checkRecords(ctx, cfg, dns, log)
	}
	for _, d := range cfg.Domains {
		for _, f := range preflight.Check(ctx, &monitor.Checker{}, d) {
			log.Warn("DNS-only readiness problem", "domain", d.Name, "level", f.Level, "url", f.URL, "problem", f.Message)
		}
	}

	var dnsIface controller.DNS
	if dns != nil {
		dnsIface = dns
	}
	ctrl, err := controller.New(ctx, controller.Options{
		Config:    cfg,
		Collector: buildCollector(cfg, log),
		DNS:       dnsIface,
		Store:     store,
		Notifier:  notify,
		Logger:    log,
	})
	if err != nil {
		log.Error("cannot start controller", "error", err.Error())
		return 1
	}

	srv := statusServer(cfg, ctrl)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("status server failed", "error", err.Error())
		}
	}()
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()

	_ = ctrl.Run(ctx)
	log.Info("shutting down")
	return 0
}

func buildDNS(cfg *config.Config) (*cloudflare.Client, error) {
	if cfg.Secrets.CloudflareToken == "" {
		if !cfg.DryRun {
			return nil, errors.New("CF_API_TOKEN is required when DRY_RUN=false")
		}
		return nil, nil
	}
	var allow []cloudflare.RecordRef
	for _, d := range cfg.Domains {
		for _, r := range d.Records {
			allow = append(allow, cloudflare.RecordRef{ZoneID: d.ZoneID, RecordID: r.RecordID})
		}
	}
	return cloudflare.New(cloudflare.Options{
		BaseURL:   os.Getenv("CF_API_BASE_URL"),
		Token:     cfg.Secrets.CloudflareToken,
		DryRun:    cfg.DryRun,
		Allowlist: allow,
	})
}

func buildCollector(cfg *config.Config, log *slog.Logger) *collector.Collector {
	c := &collector.Collector{
		Checker:  &monitor.Checker{},
		Resolver: monitor.Resolver{Addr: cfg.Resolver},
		HayaCfg:  cfg.Sources.Hayahora,
		GPCfg:    cfg.Sources.Globalping,
		Log:      log,
	}
	if h := cfg.Sources.Hayahora; h.Enabled {
		c.Hayahora = &sources.Hayahora{
			URL:             h.URL,
			RefreshInterval: h.RefreshInterval,
			HTTP:            &http.Client{Timeout: h.Timeout},
		}
	}
	if g := cfg.Sources.Globalping; g.Enabled {
		c.Globalping = &sources.Globalping{
			BaseURL:     g.APIURL,
			Token:       cfg.Secrets.GlobalpingToken,
			WaitTimeout: g.WaitTimeout,
			HTTP:        &http.Client{Timeout: 20 * time.Second},
		}
	}
	return c
}

func buildNotifier(cfg *config.Config, log *slog.Logger) notifier.Notifier {
	m := notifier.Multi{Notifiers: []notifier.Notifier{notifier.Log{Logger: log}}, Logger: log}
	if cfg.Secrets.WebhookURL != "" {
		m.Notifiers = append(m.Notifiers, notifier.Webhook{
			URL:      cfg.Secrets.WebhookURL,
			Format:   cfg.Notifier.WebhookFormat,
			MinLevel: notifier.LevelWarning,
			HTTP:     &http.Client{Timeout: cfg.Notifier.Timeout},
		})
	}
	return m
}

func logStartup(log *slog.Logger, cfg *config.Config, haveDNS bool) {
	var domains []string
	for _, d := range cfg.Domains {
		domains = append(domains, fmt.Sprintf("%s (%d records)", d.Name, len(d.Records)))
	}
	log.Info("starting laliga-guard",
		"version", version,
		"dry_run", cfg.DryRun,
		"cloudflare_client", haveDNS,
		"domains", domains,
		"hayahora", cfg.Sources.Hayahora.Enabled,
		"globalping", cfg.Sources.Globalping.Enabled,
		"globalping_token", cfg.Secrets.GlobalpingToken != "",
		"webhook", cfg.Secrets.WebhookURL != "",
		"min_isps", cfg.Detector.MinISPs,
		"min_confirming_sources", cfg.Detector.MinConfirmingSources,
		"min_failures", cfg.Controller.MinFailures,
		"recovery_window", cfg.Controller.RecoveryWindow.String(),
		"max_contingency", cfg.Controller.MaxContingency.String(),
		"min_change_interval", cfg.Controller.MinChangeInterval.String(),
	)
	if cfg.DryRun {
		log.Warn("DRY_RUN is enabled: no DNS record will be modified")
	}
	if !haveDNS {
		log.Warn("CF_API_TOKEN not set: records cannot be validated against Cloudflare")
	}
}

func checkRecords(ctx context.Context, cfg *config.Config, dns *cloudflare.Client, log *slog.Logger) int {
	failures := 0
	for _, d := range cfg.Domains {
		if z, err := dns.GetZone(ctx, d.ZoneID); err != nil {
			log.Warn("cannot read zone (Zone:Read permission is optional)", "domain", d.Name, "zone_id", d.ZoneID, "error", err.Error())
		} else if !config.HostInDomain(d.Name, strings.ToLower(z.Name)) {
			failures++
			log.Error("zone does not match domain", "domain", d.Name, "zone_name", z.Name)
		}
		for _, r := range d.Records {
			live, err := dns.GetRecord(ctx, d.ZoneID, r.RecordID)
			if err != nil {
				failures++
				log.Error("cannot read record", "domain", d.Name, "record_id", r.RecordID, "error", err.Error())
				continue
			}
			if problems := controller.MatchExpected(r, live); len(problems) > 0 {
				failures++
				log.Error("record does not match configuration", "domain", d.Name, "record_id", r.RecordID, "problems", problems)
				continue
			}
			log.Info("record verified", "domain", d.Name, "record_id", r.RecordID, "name", live.Name, "type", live.Type, "proxied", live.Proxied)
		}
	}
	return failures
}

func statusServer(cfg *config.Config, ctrl *controller.Controller) *http.Server {
	maxAge := 3*cfg.PollInterval + cfg.Sources.Globalping.WaitTimeout + 2*time.Minute
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		if ctrl.Healthy(maxAge) {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "ok\n")
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "no recent successful cycle\n")
	})
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(ctrl.Status())
	})
	return &http.Server{Addr: cfg.Listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
}

func cmdValidate(cfgPath string, stdout io.Writer, log *slog.Logger) int {
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		fmt.Fprintf(stdout, "INVALID configuration:\n%v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "configuration OK: %d domain(s), dry_run=%v\n", len(cfg.Domains), cfg.DryRun)
	if problems := cfg.AutomaticModeProblems(); len(problems) > 0 {
		fmt.Fprintln(stdout, "automatic mode (DRY_RUN=false) would be REFUSED:")
		for _, p := range problems {
			fmt.Fprintln(stdout, "  -", p)
		}
	} else {
		fmt.Fprintln(stdout, "automatic mode prerequisites: OK")
	}
	pctx, pcancel := context.WithTimeout(context.Background(), time.Minute)
	defer pcancel()
	failed := false
	for _, d := range cfg.Domains {
		findings := preflight.Check(pctx, &monitor.Checker{}, d)
		for _, f := range findings {
			fmt.Fprintf(stdout, "%s: %s: %s\n", strings.ToUpper(string(f.Level)), f.URL, f.Message)
		}
		if preflight.HasErrors(findings) {
			failed = true
		}
	}
	if !failed {
		fmt.Fprintln(stdout, "DNS-only readiness checks: OK")
	}
	if cfg.Secrets.CloudflareToken == "" {
		fmt.Fprintln(stdout, "CF_API_TOKEN not set: skipping read-only Cloudflare checks")
		if failed {
			return 1
		}
		return 0
	}
	cfg.DryRun = true
	dns, err := buildDNS(cfg)
	if err != nil {
		fmt.Fprintln(stdout, "Cloudflare client error:", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if n := checkRecords(ctx, cfg, dns, log); n > 0 {
		fmt.Fprintf(stdout, "%d Cloudflare check(s) failed (see logs)\n", n)
		return 1
	}
	fmt.Fprintln(stdout, "Cloudflare read-only checks: OK")
	if failed {
		return 1
	}
	return 0
}

func cmdStatus(cfgPath string, stdout, stderr io.Writer) int {
	path := os.Getenv("STATE_FILE")
	if path == "" {
		cfg, err := loadConfig(cfgPath)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		path = cfg.StateFile
	}
	st, err := state.Store{Path: path}.Load()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(st)
	return 0
}

func cmdHealthcheck(cfgPath string, stderr io.Writer) int {
	listen := os.Getenv("HEALTHCHECK_ADDR")
	if listen == "" {
		cfg, err := loadConfig(cfgPath)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		listen = cfg.Listen
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + listen + "/healthz")
	if err != nil {
		fmt.Fprintln(stderr, "unhealthy:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(stderr, "unhealthy: HTTP", resp.StatusCode)
		return 1
	}
	return 0
}

type noCollector struct{}

func (noCollector) Collect(context.Context, config.Domain, collector.Phase) detector.Evidence {
	return detector.Evidence{}
}

func cmdRollback(cfgPath, domain string, log *slog.Logger) int {
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		log.Error("invalid configuration", "error", err.Error())
		return 1
	}
	store := state.Store{Path: cfg.StateFile}
	unlock, err := store.Lock()
	if err != nil {
		log.Error("stop the service before running a rollback", "error", err.Error())
		return 1
	}
	defer unlock()
	dns, err := buildDNS(cfg)
	if err != nil {
		log.Error("cannot create Cloudflare client", "error", err.Error())
		return 1
	}
	var dnsIface controller.DNS
	if dns != nil {
		dnsIface = dns
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	ctrl, err := controller.New(ctx, controller.Options{
		Config: cfg, Collector: noCollector{}, DNS: dnsIface, Store: store,
		Notifier: buildNotifier(cfg, log), Logger: log,
	})
	if err != nil {
		log.Error("cannot load state", "error", err.Error())
		return 1
	}
	var targets []string
	for name, ds := range ctrl.State().Domains {
		if (domain == "" || name == domain) && len(ds.Pending()) > 0 {
			targets = append(targets, name)
		}
	}
	if len(targets) == 0 {
		log.Info("nothing to roll back")
		return 0
	}
	code := 0
	for _, name := range targets {
		if err := ctrl.Rollback(ctx, name); err != nil {
			log.Error("rollback failed", "domain", name, "error", err.Error())
			code = 1
			continue
		}
		log.Info("rollback done", "domain", name)
	}
	return code
}

func cmdDiscover(domain, zoneID string, stdout, stderr io.Writer) int {
	lister, err := cloudflare.NewLister(os.Getenv("CF_API_BASE_URL"), os.Getenv("CF_API_TOKEN"), nil)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var zones []cloudflare.Zone
	switch {
	case zoneID != "":
		z, err := lister.Zone(ctx, zoneID)
		if err != nil {
			if domain == "" {
				fmt.Fprintf(stderr, "cannot read zone %s (%v); without Zone:Read pass -domain with the zone name\n", zoneID, err)
				return 1
			}
			z = cloudflare.Zone{ID: zoneID, Name: domain}
		}
		zones = []cloudflare.Zone{z}
	default:
		zones, err = lister.Zones(ctx, domain)
		if err != nil {
			fmt.Fprintf(stderr, "cannot list zones (%v); listing needs Zone:Read, otherwise use -zone-id ID -domain example.com\n", err)
			return 1
		}
	}
	if len(zones) == 0 {
		fmt.Fprintln(stderr, "no zones visible with this token")
		return 1
	}

	var domains []config.Domain
	for _, z := range zones {
		recs, err := lister.Records(ctx, z.ID)
		if err != nil {
			fmt.Fprintf(stderr, "%s: cannot list records: %v\n", z.Name, err)
			continue
		}
		res := discover.Build(z, recs)
		fmt.Fprintf(stderr, "\n# %s (%s)\n", z.Name, z.ID)
		if res.Domain != nil {
			for _, r := range res.Domain.Records {
				fmt.Fprintf(stderr, "  + %-6s %-40s %s\n", r.ExpectedType, r.ExpectedName, r.ExpectedContent)
			}
			domains = append(domains, *res.Domain)
		}
		for _, sk := range res.Skipped {
			fmt.Fprintf(stderr, "  - %-6s %-40s %s\n", sk.Type, sk.Name, sk.Reason)
		}
		for _, w := range res.Warnings {
			fmt.Fprintln(stderr, "  ! "+w)
		}
	}
	if len(domains) == 0 {
		fmt.Fprintln(stderr, "\nno proxied web records found that DNS-only could help")
		return 1
	}
	fmt.Fprint(stdout, discover.Render(domains))
	fmt.Fprintln(stderr, "\nconfig written to stdout. Remove the records you do not want managed, review expected_status and origin.address, then run validate.")
	return 0
}

func cmdNotifyTest(cfgPath string, stdout io.Writer, log *slog.Logger) int {
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		fmt.Fprintln(stdout, "invalid configuration:", err)
		return 1
	}
	if cfg.Secrets.WebhookURL == "" {
		fmt.Fprintln(stdout, "WEBHOOK_URL is not set: alerts only go to the logs")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err = buildNotifier(cfg, log).Notify(ctx, notifier.Event{
		Time:    time.Now(),
		Level:   notifier.LevelWarning,
		Kind:    "notification_test",
		Message: "test alert from laliga-guard: if you can read this, alerts work",
	})
	if err != nil {
		fmt.Fprintln(stdout, "webhook delivery failed:", err)
		return 1
	}
	fmt.Fprintf(stdout, "test alert delivered (format: %s)\n", cfg.Notifier.WebhookFormat)
	return 0
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
