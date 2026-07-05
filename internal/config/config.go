package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Environment string

const (
	EnvironmentDevelopment Environment = "development"
	EnvironmentTest        Environment = "test"
	EnvironmentProduction  Environment = "production"
)

type Config struct {
	Environment Environment `json:"environment"`
	HTTP        HTTPConfig  `json:"http"`
	Database    Database    `json:"database"`
	Providers   Providers   `json:"providers"`
	Secrets     Secrets     `json:"secrets"`
}

type HTTPConfig struct {
	Address           string        `json:"address"`
	PublicBaseURL     string        `json:"public_base_url"`
	AllowedOrigins    []string      `json:"allowed_origins"`
	ReadHeaderTimeout time.Duration `json:"read_header_timeout"`
	RequestTimeout    time.Duration `json:"request_timeout"`
	ShutdownTimeout   time.Duration `json:"shutdown_timeout"`
	MaxBodyBytes      int64         `json:"max_body_bytes"`
	TrustedProxyCIDRs []string      `json:"trusted_proxy_cidrs"`
}

type Database struct {
	Driver string `json:"driver"`
	DSN    string `json:"dsn"`
}

type Providers struct {
	FakeMode   bool           `json:"fake_mode"`
	WorkOS     ProviderConfig `json:"workos"`
	Polar      ProviderConfig `json:"polar"`
	GitHub     ProviderConfig `json:"github"`
	Fly        ProviderConfig `json:"fly"`
	Agentunnel ProviderConfig `json:"agentunnel"`
}

type ProviderConfig struct {
	BaseURL string `json:"base_url"`
	Ready   bool   `json:"ready"`
}

type Secrets struct {
	SessionKeys        []string `json:"session_keys"`
	EncryptionKey      string   `json:"encryption_key"`
	WorkOSAPIKey       string   `json:"workos_api_key"`
	PolarWebhookSecret string   `json:"polar_webhook_secret"`
	FlyAPIToken        string   `json:"fly_api_token"`
}

type LoadOptions struct {
	Environment string
	FilePath    string
	LookupEnv   func(string) (string, bool)
	ReadFile    func(string) ([]byte, error)
}

func Load(ctx context.Context, opts LoadOptions) (Config, error) {
	_ = ctx
	cfg := Default()
	if opts.LookupEnv == nil {
		opts.LookupEnv = os.LookupEnv
	}
	if opts.ReadFile == nil {
		opts.ReadFile = os.ReadFile
	}
	if opts.Environment != "" {
		cfg.Environment = Environment(opts.Environment)
	}
	if opts.FilePath != "" {
		b, err := opts.ReadFile(opts.FilePath)
		if err != nil {
			return Config{}, fmt.Errorf("read config file: %w", err)
		}
		if err := json.Unmarshal(b, &cfg); err != nil {
			return Config{}, fmt.Errorf("parse config file: %w", err)
		}
	}
	if err := overlayEnv(&cfg, opts.LookupEnv, opts.ReadFile); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func Default() Config {
	return Config{
		Environment: EnvironmentDevelopment,
		HTTP: HTTPConfig{
			Address:           "127.0.0.1:8080",
			PublicBaseURL:     "http://127.0.0.1:8080",
			AllowedOrigins:    []string{"http://localhost:3000", "http://127.0.0.1:3000"},
			ReadHeaderTimeout: 5 * time.Second,
			RequestTimeout:    15 * time.Second,
			ShutdownTimeout:   10 * time.Second,
			MaxBodyBytes:      1 << 20,
		},
		Database: Database{
			Driver: "memory",
			DSN:    "memory://local",
		},
		Providers: Providers{FakeMode: true},
		Secrets: Secrets{
			SessionKeys:   []string{"development-session-key-change-me"},
			EncryptionKey: "development-encryption-key-change-me",
		},
	}
}

func (c Config) Validate() error {
	var errs []error
	if c.Environment != EnvironmentDevelopment && c.Environment != EnvironmentTest && c.Environment != EnvironmentProduction {
		errs = append(errs, fmt.Errorf("environment must be development, test, or production"))
	}
	if _, _, err := net.SplitHostPort(c.HTTP.Address); err != nil {
		errs = append(errs, fmt.Errorf("http.address must be host:port: %w", err))
	}
	if c.HTTP.PublicBaseURL == "" {
		errs = append(errs, fmt.Errorf("http.public_base_url is required"))
	} else if _, err := url.ParseRequestURI(c.HTTP.PublicBaseURL); err != nil {
		errs = append(errs, fmt.Errorf("http.public_base_url must be a valid absolute URL"))
	}
	if c.HTTP.ReadHeaderTimeout <= 0 || c.HTTP.RequestTimeout <= 0 || c.HTTP.ShutdownTimeout <= 0 {
		errs = append(errs, fmt.Errorf("http timeouts must be positive"))
	}
	if c.HTTP.MaxBodyBytes <= 0 {
		errs = append(errs, fmt.Errorf("http.max_body_bytes must be positive"))
	}
	if c.Database.Driver == "" || c.Database.DSN == "" {
		errs = append(errs, fmt.Errorf("database.driver and database.dsn are required"))
	}
	if len(c.Secrets.SessionKeys) == 0 || c.Secrets.EncryptionKey == "" {
		errs = append(errs, fmt.Errorf("session and encryption secrets are required"))
	}
	if c.Environment == EnvironmentProduction {
		if c.Providers.FakeMode {
			errs = append(errs, fmt.Errorf("providers.fake_mode cannot be enabled in production"))
		}
		if len(c.HTTP.AllowedOrigins) == 0 {
			errs = append(errs, fmt.Errorf("http.allowed_origins is required in production"))
		}
		if c.Secrets.WorkOSAPIKey == "" || c.Secrets.PolarWebhookSecret == "" || c.Secrets.FlyAPIToken == "" {
			errs = append(errs, fmt.Errorf("production provider secrets are required"))
		}
		for _, secret := range append(c.Secrets.SessionKeys, c.Secrets.EncryptionKey) {
			if strings.Contains(secret, "development") || len(secret) < 32 {
				errs = append(errs, fmt.Errorf("production secrets must be strong and non-development"))
				break
			}
		}
	}
	return errors.Join(errs...)
}

func overlayEnv(c *Config, lookup func(string) (string, bool), readFile func(string) ([]byte, error)) error {
	setString := func(name string, target *string) {
		if v, ok := lookup(name); ok {
			*target = v
		}
	}
	setSecret := func(name string, target *string) error {
		if v, ok := lookup(name); ok {
			*target = v
		}
		if path, ok := lookup(name + "_FILE"); ok {
			b, err := readFile(path)
			if err != nil {
				return fmt.Errorf("read %s: %w", name+"_FILE", err)
			}
			*target = strings.TrimSpace(string(b))
		}
		return nil
	}

	setString("PAPERBOAT_ENV", (*string)(&c.Environment))
	setString("PAPERBOAT_HTTP_ADDRESS", &c.HTTP.Address)
	setString("PAPERBOAT_PUBLIC_BASE_URL", &c.HTTP.PublicBaseURL)
	setString("PAPERBOAT_DATABASE_DRIVER", &c.Database.Driver)
	setString("PAPERBOAT_DATABASE_DSN", &c.Database.DSN)
	setString("PAPERBOAT_WORKOS_BASE_URL", &c.Providers.WorkOS.BaseURL)
	setString("PAPERBOAT_POLAR_BASE_URL", &c.Providers.Polar.BaseURL)
	setString("PAPERBOAT_GITHUB_BASE_URL", &c.Providers.GitHub.BaseURL)
	setString("PAPERBOAT_FLY_BASE_URL", &c.Providers.Fly.BaseURL)
	setString("PAPERBOAT_AGENTUNNEL_BASE_URL", &c.Providers.Agentunnel.BaseURL)
	if v, ok := lookup("PAPERBOAT_ALLOWED_ORIGINS"); ok {
		c.HTTP.AllowedOrigins = splitCSV(v)
	}
	if v, ok := lookup("PAPERBOAT_FAKE_PROVIDERS"); ok {
		parsed, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("PAPERBOAT_FAKE_PROVIDERS: %w", err)
		}
		c.Providers.FakeMode = parsed
	}
	if v, ok := lookup("PAPERBOAT_MAX_BODY_BYTES"); ok {
		parsed, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return fmt.Errorf("PAPERBOAT_MAX_BODY_BYTES: %w", err)
		}
		c.HTTP.MaxBodyBytes = parsed
	}
	if err := setSecret("PAPERBOAT_ENCRYPTION_KEY", &c.Secrets.EncryptionKey); err != nil {
		return err
	}
	if err := setSecret("PAPERBOAT_WORKOS_API_KEY", &c.Secrets.WorkOSAPIKey); err != nil {
		return err
	}
	if err := setSecret("PAPERBOAT_POLAR_WEBHOOK_SECRET", &c.Secrets.PolarWebhookSecret); err != nil {
		return err
	}
	if err := setSecret("PAPERBOAT_FLY_API_TOKEN", &c.Secrets.FlyAPIToken); err != nil {
		return err
	}
	if v, ok := lookup("PAPERBOAT_SESSION_KEYS"); ok {
		c.Secrets.SessionKeys = splitCSV(v)
	}
	if path, ok := lookup("PAPERBOAT_SESSION_KEYS_FILE"); ok {
		b, err := readFile(path)
		if err != nil {
			return fmt.Errorf("read PAPERBOAT_SESSION_KEYS_FILE: %w", err)
		}
		c.Secrets.SessionKeys = splitCSV(string(b))
	}
	return nil
}

func splitCSV(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
