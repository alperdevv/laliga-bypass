package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

type Config struct {
	PollInterval time.Duration `yaml:"poll_interval"`
	DryRun       bool          `yaml:"dry_run"`
	Listen       string        `yaml:"listen"`
	StateFile    string        `yaml:"state_file"`
	Resolver     string        `yaml:"resolver"`

	Detector   DetectorConfig   `yaml:"detector"`
	Sources    SourcesConfig    `yaml:"sources"`
	Controller ControllerConfig `yaml:"controller"`
	Notifier   NotifierConfig   `yaml:"notifier"`
	Domains    []Domain         `yaml:"domains"`

	Secrets Secrets `yaml:"-"`
}

type Secrets struct {
	CloudflareToken string
	GlobalpingToken string
	WebhookURL      string
}

func (Secrets) String() string { return "[redacted]" }

func (s Secrets) GoString() string { return s.String() }

type DetectorConfig struct {
	MinISPs              int `yaml:"min_isps"`
	MinConfirmingSources int `yaml:"min_confirming_sources"`
}

type SourcesConfig struct {
	Hayahora   HayahoraConfig   `yaml:"hayahora"`
	Globalping GlobalpingConfig `yaml:"globalping"`
}

type HayahoraConfig struct {
	Enabled               bool          `yaml:"enabled"`
	URL                   string        `yaml:"url"`
	RefreshInterval       time.Duration `yaml:"refresh_interval"`
	MaxFeedAge            time.Duration `yaml:"max_feed_age"`
	IgnoreBlocksOlderThan time.Duration `yaml:"ignore_blocks_older_than"`
	ISPs                  []string      `yaml:"isps"`
	Timeout               time.Duration `yaml:"timeout"`
}

type GlobalpingConfig struct {
	Enabled          bool          `yaml:"enabled"`
	APIURL           string        `yaml:"api_url"`
	MinInterval      time.Duration `yaml:"min_interval"`
	BaselineInterval time.Duration `yaml:"baseline_interval"`
	MaxResultAge     time.Duration `yaml:"max_result_age"`
	WaitTimeout      time.Duration `yaml:"wait_timeout"`
	Targets          []ProbeGroup  `yaml:"targets"`
	Controls         []ProbeGroup  `yaml:"controls"`
}

type ProbeGroup struct {
	Name  string `yaml:"name"`
	Magic string `yaml:"magic"`
	Limit int    `yaml:"limit"`
}

type ControllerConfig struct {
	MinFailures       int           `yaml:"min_failures"`
	RecoveryWindow    time.Duration `yaml:"recovery_window"`
	MaxContingency    time.Duration `yaml:"max_contingency"`
	MinChangeInterval time.Duration `yaml:"min_change_interval"`
	VerifyDelay       time.Duration `yaml:"verify_delay"`
	VerifyTimeout     time.Duration `yaml:"verify_timeout"`
	ManualHold        time.Duration `yaml:"manual_hold"`
}

type NotifierConfig struct {
	WebhookFormat string        `yaml:"webhook_format"`
	Timeout       time.Duration `yaml:"timeout"`
}

type Domain struct {
	Name       string     `yaml:"name"`
	ZoneID     string     `yaml:"zone_id"`
	CanaryHost string     `yaml:"canary_host"`
	Endpoints  []Endpoint `yaml:"endpoints"`
	Origin     Origin     `yaml:"origin"`
	Records    []Record   `yaml:"records"`
}

type Endpoint struct {
	URL            string        `yaml:"url"`
	ExpectedStatus []int         `yaml:"expected_status"`
	Timeout        time.Duration `yaml:"timeout"`
}

type Origin struct {
	Address            string `yaml:"address"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
}

type Record struct {
	RecordID        string `yaml:"record_id"`
	ExpectedType    string `yaml:"expected_type"`
	ExpectedName    string `yaml:"expected_name"`
	ExpectedContent string `yaml:"expected_content"`
}

var ManageableTypes = []string{"A", "AAAA", "CNAME"}

func Load(path string, env func(string) string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %q: %w", path, err)
	}
	return Parse(raw, env)
}

func Parse(raw []byte, env func(string) string) (*Config, error) {
	cfg := Default()
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("invalid YAML: %w", err)
	}
	if err := cfg.applyEnv(env); err != nil {
		return nil, err
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func Default() *Config {
	return &Config{
		PollInterval: 30 * time.Second,
		DryRun:       true,
		Listen:       "127.0.0.1:8080",
		StateFile:    "/data/state.json",
		Resolver:     "1.1.1.1:53",
		Detector: DetectorConfig{
			MinISPs:              2,
			MinConfirmingSources: 2,
		},
		Sources: SourcesConfig{
			Hayahora: HayahoraConfig{
				Enabled:               true,
				URL:                   "https://hayahora.futbol/estado/data.json",
				RefreshInterval:       5 * time.Minute,
				MaxFeedAge:            30 * time.Minute,
				IgnoreBlocksOlderThan: 12 * time.Hour,
				Timeout:               30 * time.Second,
			},
			Globalping: GlobalpingConfig{
				Enabled:          true,
				APIURL:           "https://api.globalping.io",
				MinInterval:      10 * time.Minute,
				BaselineInterval: 20 * time.Minute,
				MaxResultAge:     20 * time.Minute,
				WaitTimeout:      60 * time.Second,
			},
		},
		Controller: ControllerConfig{
			MinFailures:       3,
			RecoveryWindow:    10 * time.Minute,
			MaxContingency:    60 * time.Minute,
			MinChangeInterval: 15 * time.Minute,
			VerifyDelay:       6 * time.Minute,
			VerifyTimeout:     45 * time.Minute,
			ManualHold:        6 * time.Hour,
		},
		Notifier: NotifierConfig{
			WebhookFormat: "generic",
			Timeout:       10 * time.Second,
		},
	}
}

func (c *Config) applyEnv(env func(string) string) error {
	if env == nil {
		env = func(string) string { return "" }
	}
	if v := strings.TrimSpace(env("DRY_RUN")); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("invalid DRY_RUN %q: must be true or false", v)
		}
		c.DryRun = b
	}
	if v := strings.TrimSpace(env("STATE_FILE")); v != "" {
		c.StateFile = v
	}
	c.Secrets = Secrets{
		CloudflareToken: strings.TrimSpace(env("CF_API_TOKEN")),
		GlobalpingToken: strings.TrimSpace(env("GLOBALPING_TOKEN")),
		WebhookURL:      strings.TrimSpace(env("WEBHOOK_URL")),
	}
	if env("CF_API_KEY") != "" || env("CLOUDFLARE_API_KEY") != "" || env("CF_API_EMAIL") != "" {
		return errors.New("global API key variables detected (CF_API_KEY/CLOUDFLARE_API_KEY/CF_API_EMAIL): global keys are not allowed, use a scoped CF_API_TOKEN")
	}
	return nil
}

func (c *Config) applyDefaults() {
	for i := range c.Domains {
		d := &c.Domains[i]
		d.Name = normalizeHost(d.Name)
		d.CanaryHost = normalizeHost(d.CanaryHost)
		for j := range d.Endpoints {
			e := &d.Endpoints[j]
			if len(e.ExpectedStatus) == 0 {
				e.ExpectedStatus = []int{200}
			}
			if e.Timeout == 0 {
				e.Timeout = 10 * time.Second
			}
		}
		for j := range d.Records {
			r := &d.Records[j]
			r.ExpectedType = strings.ToUpper(strings.TrimSpace(r.ExpectedType))
			r.ExpectedName = normalizeHost(r.ExpectedName)
			r.ExpectedContent = strings.TrimSpace(r.ExpectedContent)
			if r.ExpectedType == "CNAME" {
				r.ExpectedContent = normalizeHost(r.ExpectedContent)
			}
		}
	}
	gp := &c.Sources.Globalping
	for i := range gp.Targets {
		if gp.Targets[i].Limit == 0 {
			gp.Targets[i].Limit = 1
		}
	}
	for i := range gp.Controls {
		if gp.Controls[i].Limit == 0 {
			gp.Controls[i].Limit = 1
		}
	}
}

func normalizeHost(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

func (c *Config) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if c.PollInterval < 5*time.Second {
		add("poll_interval must be >= 5s")
	}
	if c.StateFile == "" {
		add("state_file is required")
	}
	if c.Listen != "" {
		host, _, err := net.SplitHostPort(c.Listen)
		if err != nil {
			add("invalid listen %q: %v", c.Listen, err)
		} else if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			add("listen must be a loopback address (127.0.0.1 or ::1): the status endpoint must not be exposed")
		}
	}
	if c.Resolver != "" {
		if _, _, err := net.SplitHostPort(c.Resolver); err != nil {
			add("invalid resolver %q (host:port): %v", c.Resolver, err)
		}
	}
	if c.Detector.MinISPs < 1 {
		add("detector.min_isps must be >= 1")
	}
	if c.Detector.MinConfirmingSources < 1 {
		add("detector.min_confirming_sources must be >= 1")
	}

	h := c.Sources.Hayahora
	if h.Enabled {
		if _, err := url.ParseRequestURI(h.URL); err != nil {
			add("invalid sources.hayahora.url: %v", err)
		}
		if h.RefreshInterval < time.Minute {
			add("sources.hayahora.refresh_interval must be >= 1m")
		}
		if h.MaxFeedAge <= 0 {
			add("sources.hayahora.max_feed_age must be > 0")
		}
		if h.Timeout <= 0 {
			add("sources.hayahora.timeout must be > 0")
		}
	}

	g := c.Sources.Globalping
	if g.Enabled {
		if _, err := url.ParseRequestURI(g.APIURL); err != nil {
			add("invalid sources.globalping.api_url: %v", err)
		}
		if g.MinInterval < time.Minute {
			add("sources.globalping.min_interval must be >= 1m")
		}
		if len(g.Targets) == 0 {
			add("sources.globalping.targets must not be empty when globalping is enabled")
		}
		if len(g.Controls) == 0 {
			add("sources.globalping.controls must not be empty: without controls a selective block cannot be told apart from a general outage")
		}
		for _, p := range slices.Concat(g.Targets, g.Controls) {
			if p.Name == "" || p.Magic == "" {
				add("sources.globalping: every probe group needs name and magic")
			}
			if p.Limit < 1 || p.Limit > 10 {
				add("sources.globalping: limit of %q must be between 1 and 10", p.Name)
			}
		}
		if g.MaxResultAge < g.MinInterval {
			add("sources.globalping.max_result_age must be >= min_interval")
		}
		if g.WaitTimeout <= 0 {
			add("sources.globalping.wait_timeout must be > 0")
		}
	}

	cc := c.Controller
	if cc.MinFailures < 1 {
		add("controller.min_failures must be >= 1")
	}
	if cc.RecoveryWindow <= 0 || cc.MaxContingency <= 0 || cc.VerifyTimeout <= 0 {
		add("controller.recovery_window, max_contingency and verify_timeout must be > 0")
	}
	if cc.MinChangeInterval < time.Minute {
		add("controller.min_change_interval must be >= 1m to prevent flapping")
	}
	if cc.ManualHold < 0 {
		add("controller.manual_hold must not be negative")
	}
	if cc.VerifyDelay < 0 {
		add("controller.verify_delay must not be negative")
	}
	switch c.Notifier.WebhookFormat {
	case "generic", "slack", "discord":
	default:
		add("notifier.webhook_format must be generic, slack or discord")
	}

	if len(c.Domains) == 0 {
		add("domains must not be empty")
	}
	seenDomain := map[string]bool{}
	seenRecord := map[string]bool{}
	for _, d := range c.Domains {
		errs = append(errs, validateDomain(d)...)
		if seenDomain[d.Name] {
			add("duplicate domain %q", d.Name)
		}
		seenDomain[d.Name] = true
		for _, r := range d.Records {
			key := d.ZoneID + "/" + r.RecordID
			if seenRecord[key] {
				add("duplicate record %s", key)
			}
			seenRecord[key] = true
		}
	}
	return errors.Join(errs...)
}

func validateDomain(d Domain) []error {
	var errs []error
	add := func(format string, a ...any) {
		errs = append(errs, fmt.Errorf("domain %q: "+format, append([]any{d.Name}, a...)...))
	}
	if d.Name == "" {
		add("name is required")
	}
	if d.ZoneID == "" {
		add("zone_id is required")
	}
	if len(d.Endpoints) == 0 {
		add("at least one endpoint is required")
	}
	for _, e := range d.Endpoints {
		u, err := url.Parse(e.URL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			add("invalid endpoint %q (absolute http/https URL required)", e.URL)
			continue
		}
		if !HostInDomain(normalizeHost(u.Hostname()), d.Name) {
			add("endpoint %q does not belong to the domain", e.URL)
		}
		for _, s := range e.ExpectedStatus {
			if s < 100 || s > 599 {
				add("expected_status %d out of range", s)
			}
		}
	}
	if d.Origin.Address == "" {
		add("origin.address is required: without a direct origin check an origin outage cannot be told apart from a block")
	} else if _, _, err := net.SplitHostPort(d.Origin.Address); err != nil {
		add("invalid origin.address %q (host:port): %v", d.Origin.Address, err)
	}
	if d.CanaryHost != "" && !HostInDomain(d.CanaryHost, d.Name) {
		add("canary_host %q must belong to the domain", d.CanaryHost)
	}
	if len(d.Records) == 0 {
		add("at least one allowed record is required")
	}
	for _, r := range d.Records {
		if r.RecordID == "" || r.ExpectedName == "" || r.ExpectedContent == "" {
			add("incomplete record: record_id, expected_name and expected_content are required")
		}
		if !slices.Contains(ManageableTypes, r.ExpectedType) {
			add("record %s: type %q is not manageable (only A, AAAA, CNAME)", r.RecordID, r.ExpectedType)
		}
		if r.ExpectedName != "" && !HostInDomain(r.ExpectedName, d.Name) {
			add("record %s: %q does not belong to the domain", r.RecordID, r.ExpectedName)
		}
		if d.CanaryHost != "" && r.ExpectedName == d.CanaryHost {
			add("record %s: canary_host must not be a managed record", r.RecordID)
		}
		switch r.ExpectedType {
		case "A":
			if ip := net.ParseIP(r.ExpectedContent); ip == nil || ip.To4() == nil {
				add("record %s: expected_content %q is not an IPv4 address", r.RecordID, r.ExpectedContent)
			}
		case "AAAA":
			if ip := net.ParseIP(r.ExpectedContent); ip == nil || ip.To4() != nil {
				add("record %s: expected_content %q is not an IPv6 address", r.RecordID, r.ExpectedContent)
			}
		}
	}
	return errs
}

func HostInDomain(host, domain string) bool {
	return host == domain || strings.HasSuffix(host, "."+domain)
}

func (c *Config) AutomaticModeProblems() []string {
	var p []string
	if c.Secrets.CloudflareToken == "" {
		p = append(p, "CF_API_TOKEN is not set")
	}
	external := 0
	if c.Sources.Hayahora.Enabled {
		external++
	}
	if c.Sources.Globalping.Enabled {
		external++
	}
	if external == 0 {
		p = append(p, "no external evidence source is enabled")
	} else if external < c.Detector.MinConfirmingSources {
		p = append(p, fmt.Sprintf("%d external sources enabled but detector.min_confirming_sources=%d: a block could never be confirmed", external, c.Detector.MinConfirmingSources))
	}
	return p
}

func (c *Config) Allowlist() map[string]Record {
	out := map[string]Record{}
	for _, d := range c.Domains {
		for _, r := range d.Records {
			out[d.ZoneID+"/"+r.RecordID] = r
		}
	}
	return out
}
