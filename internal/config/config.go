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
	Catalogs    Catalogs    `json:"catalogs"`
	Billing     Billing     `json:"billing"`
	Metering    Metering    `json:"metering"`
	CLIAuth     CLIAuth     `json:"cli_auth"`
	GitHub      GitHub      `json:"github"`
	Fly         Fly         `json:"fly"`
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

// NormalizeIssuer returns the canonical server identity used in CLI
// connection descriptors and papercode credentials. It intentionally mirrors
// the CLI's issuer normalization so equivalent URLs cannot fail validation.
func NormalizeIssuer(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return strings.TrimRight(strings.TrimSpace(raw), "/")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	hostname := strings.ToLower(u.Hostname())
	port := u.Port()
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	if port == "" {
		if strings.Contains(hostname, ":") {
			u.Host = "[" + hostname + "]"
		} else {
			u.Host = hostname
		}
	} else {
		u.Host = net.JoinHostPort(hostname, port)
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

type Database struct {
	Driver string `json:"driver"`
	DSN    string `json:"dsn"`
}

type Catalogs struct {
	SeedFile string `json:"seed_file"`
}

type Billing struct {
	PolarWebhookTolerance time.Duration `json:"polar_webhook_tolerance"`
}

type Metering struct {
	MinimumStartCreditWindow time.Duration `json:"minimum_start_credit_window"`
	MaxKeepAliveDuration     time.Duration `json:"max_keep_alive_duration"`
}

type CLIAuth struct {
	VerificationURL          string        `json:"verification_url"`
	ClientID                 string        `json:"client_id"`
	AllowedScopes            []string      `json:"allowed_scopes"`
	DeviceGrantLifetime      time.Duration `json:"device_grant_lifetime"`
	AccessTokenLifetime      time.Duration `json:"access_token_lifetime"`
	RefreshTokenLifetime     time.Duration `json:"refresh_token_lifetime"`
	PollInterval             time.Duration `json:"poll_interval"`
	MaxClientLabelLength     int           `json:"max_client_label_length"`
	NetworkRequestsPerMinute int           `json:"network_requests_per_minute"`
	GrantPollsPerMinute      int           `json:"grant_polls_per_minute"`
	AccountActionsPerMinute  int           `json:"account_actions_per_minute"`
	MintActiveKeyID          string        `json:"mint_active_key_id"`
	MintJWKSMaxAge           time.Duration `json:"mint_jwks_max_age"`
	MintProofLifetime        time.Duration `json:"mint_proof_lifetime"`
}

type GitHub struct {
	OAuthAuthorizeURL string   `json:"oauth_authorize_url"`
	OAuthTokenURL     string   `json:"oauth_token_url"`
	OAuthScopes       []string `json:"oauth_scopes"`
	ConfigRepoName    string   `json:"config_repo_name"`
	ConfigRepoBranch  string   `json:"config_repo_branch"`
}

type Fly struct {
	AppName           string   `json:"app_name"`
	OrgSlug           string   `json:"org_slug"`
	ImageRef          string   `json:"image_ref"`
	VolumeNamePrefix  string   `json:"volume_name_prefix"`
	MachineNamePrefix string   `json:"machine_name_prefix"`
	Hostname          string   `json:"hostname"`
	MountPath         string   `json:"mount_path"`
	BootCommand       []string `json:"boot_command"`
	AgentunnelSecret  string   `json:"agentunnel_secret"`
	GitHubSecret      string   `json:"github_secret"`
	SetupScriptSecret string   `json:"setup_script_secret"`
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
	BaseURL              string        `json:"base_url"`
	Ready                bool          `json:"ready"`
	MachineMode          string        `json:"machine_mode,omitempty"`
	PapercodeLocalURL    string        `json:"papercode_local_url,omitempty"`
	RouteExpiresIn       time.Duration `json:"route_expires_in,omitempty"`
	RouteSubdomainPrefix string        `json:"route_subdomain_prefix,omitempty"`
	ConnectReadyTimeout  time.Duration `json:"connect_ready_timeout,omitempty"`
	ConnectPollInterval  time.Duration `json:"connect_poll_interval,omitempty"`
	AccessPolicyID       string        `json:"access_policy_id,omitempty"`
	UploadMaxBytes       int64         `json:"upload_max_bytes,omitempty"`
	UploadAllowedMIMEs   []string      `json:"upload_allowed_mime_types,omitempty"`
	UploadRetention      time.Duration `json:"upload_retention,omitempty"`
}

type Secrets struct {
	SessionKeys            []string `json:"session_keys"`
	EncryptionKey          string   `json:"encryption_key"`
	WorkOSAPIKey           string   `json:"workos_api_key"`
	WorkOSClientID         string   `json:"workos_client_id"`
	WorkOSClientSecret     string   `json:"workos_client_secret"`
	PolarAPIKey            string   `json:"polar_api_key"`
	PolarWebhookSecret     string   `json:"polar_webhook_secret"`
	GitHubClientID         string   `json:"github_client_id"`
	GitHubClientSecret     string   `json:"github_client_secret"`
	FlyAPIToken            string   `json:"fly_api_token"`
	AgentunnelAPIKey       string   `json:"agentunnel_api_key"`
	AgentunnelMachineToken string   `json:"agentunnel_machine_token"`
	MachineActivityToken   string   `json:"machine_activity_token"`
	MintSigningKeys        []string `json:"mint_signing_keys"`
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
			Driver: "postgres",
			DSN:    "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable",
		},
		Catalogs: Catalogs{
			SeedFile: "config/catalogs.example.json",
		},
		Billing: Billing{
			PolarWebhookTolerance: 5 * time.Minute,
		},
		Metering: Metering{
			MinimumStartCreditWindow: 5 * time.Minute,
			MaxKeepAliveDuration:     12 * time.Hour,
		},
		CLIAuth: CLIAuth{
			VerificationURL:          "http://localhost:3000/cli/authorize",
			ClientID:                 "paperboat-cli",
			AllowedScopes:            []string{"account:read", "clients:revoke", "projects:read", "projects:connect", "session:refresh"},
			DeviceGrantLifetime:      10 * time.Minute,
			AccessTokenLifetime:      15 * time.Minute,
			RefreshTokenLifetime:     30 * 24 * time.Hour,
			PollInterval:             5 * time.Second,
			MaxClientLabelLength:     120,
			NetworkRequestsPerMinute: 30,
			GrantPollsPerMinute:      30,
			AccountActionsPerMinute:  30,
			MintJWKSMaxAge:           5 * time.Minute,
			MintProofLifetime:        2 * time.Minute,
		},
		Providers: Providers{
			FakeMode: true,
			GitHub: ProviderConfig{
				BaseURL: "https://api.github.com",
			},
			Agentunnel: ProviderConfig{
				MachineMode:          "required",
				PapercodeLocalURL:    "http://127.0.0.1:4099",
				RouteExpiresIn:       30 * 24 * time.Hour,
				RouteSubdomainPrefix: "pb",
				ConnectReadyTimeout:  2 * time.Second,
				ConnectPollInterval:  100 * time.Millisecond,
				UploadMaxBytes:       10 << 20,
				UploadAllowedMIMEs:   []string{"image/png", "image/jpeg", "image/webp"},
				UploadRetention:      7 * 24 * time.Hour,
			},
		},
		GitHub: GitHub{
			OAuthAuthorizeURL: "https://github.com/login/oauth/authorize",
			OAuthTokenURL:     "https://github.com/login/oauth/access_token",
			OAuthScopes:       []string{"repo"},
			ConfigRepoName:    "paperboat-config",
			ConfigRepoBranch:  "main",
		},
		Fly: Fly{
			AppName:           "paperboat-projects-dev",
			OrgSlug:           "personal",
			ImageRef:          "registry.example.invalid/paperboat/project-vm:dev",
			VolumeNamePrefix:  "pbvol",
			MachineNamePrefix: "pbvm",
			Hostname:          "paperboat",
			MountPath:         "/workspace",
			BootCommand:       []string{"/usr/local/bin/paperboat-entrypoint"},
			AgentunnelSecret:  "AGENTUNNEL_MACHINE_TOKEN",
			GitHubSecret:      "PAPERBOAT_GITHUB_CONFIG_TOKEN",
			SetupScriptSecret: "PAPERBOAT_SETUP_SCRIPT",
		},
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
	for _, raw := range c.HTTP.TrustedProxyCIDRs {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(raw)); err != nil {
			errs = append(errs, fmt.Errorf("http.trusted_proxy_cidrs contains invalid CIDR %q", raw))
		}
	}
	if c.Database.Driver == "" || c.Database.DSN == "" {
		errs = append(errs, fmt.Errorf("database.driver and database.dsn are required"))
	} else if c.Database.Driver != "postgres" && c.Database.Driver != "pgx" {
		errs = append(errs, fmt.Errorf("database.driver must be postgres"))
	}
	if strings.TrimSpace(c.Catalogs.SeedFile) == "" {
		errs = append(errs, fmt.Errorf("catalogs.seed_file is required"))
	}
	if c.Billing.PolarWebhookTolerance <= 0 {
		errs = append(errs, fmt.Errorf("billing.polar_webhook_tolerance must be positive"))
	}
	if c.Metering.MinimumStartCreditWindow <= 0 {
		errs = append(errs, fmt.Errorf("metering.minimum_start_credit_window must be positive"))
	}
	if c.Metering.MaxKeepAliveDuration <= 0 {
		errs = append(errs, fmt.Errorf("metering.max_keep_alive_duration must be positive"))
	}
	if strings.TrimSpace(c.CLIAuth.VerificationURL) == "" || strings.TrimSpace(c.CLIAuth.ClientID) == "" || len(c.CLIAuth.AllowedScopes) == 0 {
		errs = append(errs, fmt.Errorf("cli_auth verification_url, client_id, and allowed_scopes are required"))
	}
	if verificationURL, err := url.Parse(c.CLIAuth.VerificationURL); err != nil || (verificationURL.Scheme != "http" && verificationURL.Scheme != "https") || verificationURL.Host == "" {
		errs = append(errs, fmt.Errorf("cli_auth.verification_url must be an absolute http or https URL"))
	}
	if c.CLIAuth.DeviceGrantLifetime <= 0 || c.CLIAuth.AccessTokenLifetime <= 0 || c.CLIAuth.RefreshTokenLifetime <= 0 || c.CLIAuth.PollInterval <= 0 {
		errs = append(errs, fmt.Errorf("cli_auth lifetimes and poll_interval must be positive"))
	}
	if c.CLIAuth.MaxClientLabelLength <= 0 || c.CLIAuth.NetworkRequestsPerMinute <= 0 || c.CLIAuth.GrantPollsPerMinute <= 0 || c.CLIAuth.AccountActionsPerMinute <= 0 {
		errs = append(errs, fmt.Errorf("cli_auth limits must be positive"))
	}
	if c.CLIAuth.MintJWKSMaxAge <= 0 {
		errs = append(errs, fmt.Errorf("cli_auth.mint_jwks_max_age must be positive"))
	}
	if c.CLIAuth.MintProofLifetime <= 0 || c.CLIAuth.MintProofLifetime > 5*time.Minute {
		errs = append(errs, fmt.Errorf("cli_auth.mint_proof_lifetime must be positive and at most five minutes"))
	}
	switch c.Providers.Agentunnel.MachineMode {
	case "required", "optional":
	default:
		errs = append(errs, fmt.Errorf("agentunnel.machine_mode must be \"required\" or \"optional\""))
	}
	if strings.TrimSpace(c.Providers.Agentunnel.PapercodeLocalURL) == "" {
		errs = append(errs, fmt.Errorf("agentunnel.papercode_local_url is required"))
	} else if u, err := url.Parse(c.Providers.Agentunnel.PapercodeLocalURL); err != nil || u.Scheme == "" || u.Host == "" {
		errs = append(errs, fmt.Errorf("agentunnel.papercode_local_url must be a valid absolute URL"))
	}
	if c.Providers.Agentunnel.RouteExpiresIn <= 0 {
		errs = append(errs, fmt.Errorf("agentunnel.route_expires_in must be positive"))
	}
	if strings.TrimSpace(c.Providers.Agentunnel.RouteSubdomainPrefix) == "" {
		errs = append(errs, fmt.Errorf("agentunnel.route_subdomain_prefix is required"))
	}
	if c.Providers.Agentunnel.ConnectReadyTimeout <= 0 {
		errs = append(errs, fmt.Errorf("agentunnel.connect_ready_timeout must be positive"))
	}
	if c.Providers.Agentunnel.ConnectPollInterval <= 0 || c.Providers.Agentunnel.ConnectPollInterval > c.Providers.Agentunnel.ConnectReadyTimeout {
		errs = append(errs, fmt.Errorf("agentunnel.connect_poll_interval must be positive and no greater than connect_ready_timeout"))
	}
	if c.Providers.Agentunnel.UploadMaxBytes <= 0 || len(c.Providers.Agentunnel.UploadAllowedMIMEs) == 0 || c.Providers.Agentunnel.UploadRetention <= 0 {
		errs = append(errs, fmt.Errorf("agentunnel upload_max_bytes, upload_allowed_mime_types, and upload_retention are required"))
	}
	for _, mimeType := range c.Providers.Agentunnel.UploadAllowedMIMEs {
		switch mimeType {
		case "image/png", "image/jpeg", "image/webp":
		default:
			errs = append(errs, fmt.Errorf("agentunnel upload MIME type %q is not supported", mimeType))
		}
	}
	if strings.TrimSpace(c.GitHub.OAuthAuthorizeURL) == "" || strings.TrimSpace(c.GitHub.OAuthTokenURL) == "" {
		errs = append(errs, fmt.Errorf("github oauth urls are required"))
	}
	if len(c.GitHub.OAuthScopes) == 0 {
		errs = append(errs, fmt.Errorf("github.oauth_scopes is required"))
	}
	if strings.TrimSpace(c.GitHub.ConfigRepoName) == "" || strings.TrimSpace(c.GitHub.ConfigRepoBranch) == "" {
		errs = append(errs, fmt.Errorf("github config repo name and branch are required"))
	}
	if strings.TrimSpace(c.Fly.AppName) == "" || strings.TrimSpace(c.Fly.ImageRef) == "" || strings.TrimSpace(c.Fly.VolumeNamePrefix) == "" || strings.TrimSpace(c.Fly.MachineNamePrefix) == "" || strings.TrimSpace(c.Fly.MountPath) == "" || strings.TrimSpace(c.Fly.AgentunnelSecret) == "" || strings.TrimSpace(c.Fly.GitHubSecret) == "" || strings.TrimSpace(c.Fly.SetupScriptSecret) == "" {
		errs = append(errs, fmt.Errorf("fly app, image, naming prefixes, mount path, and secret env names are required"))
	}
	if c.Environment == EnvironmentProduction && strings.TrimSpace(c.Fly.OrgSlug) == "" {
		errs = append(errs, fmt.Errorf("fly.org_slug is required in production"))
	}
	if len(c.Fly.BootCommand) == 0 {
		errs = append(errs, fmt.Errorf("fly.boot_command is required"))
	}
	if strings.TrimSpace(c.Fly.AgentunnelSecret) == "" || strings.TrimSpace(c.Fly.GitHubSecret) == "" {
		errs = append(errs, fmt.Errorf("fly secret names are required"))
	}
	if len(c.Secrets.SessionKeys) == 0 || c.Secrets.EncryptionKey == "" {
		errs = append(errs, fmt.Errorf("session and encryption secrets are required"))
	}
	if c.Environment == EnvironmentProduction {
		if c.Providers.FakeMode {
			errs = append(errs, fmt.Errorf("providers.fake_mode cannot be enabled in production"))
		}
		if c.Providers.Agentunnel.MachineMode != "required" {
			errs = append(errs, fmt.Errorf("agentunnel.machine_mode must be \"required\" in production"))
		}
		if len(c.HTTP.AllowedOrigins) == 0 {
			errs = append(errs, fmt.Errorf("http.allowed_origins is required in production"))
		}
		if c.Secrets.WorkOSAPIKey == "" || c.Secrets.WorkOSClientID == "" || c.Secrets.WorkOSClientSecret == "" || c.Secrets.PolarAPIKey == "" || c.Secrets.PolarWebhookSecret == "" || c.Secrets.GitHubClientID == "" || c.Secrets.GitHubClientSecret == "" || c.Secrets.FlyAPIToken == "" || c.Secrets.AgentunnelAPIKey == "" {
			errs = append(errs, fmt.Errorf("production provider secrets are required"))
		}
		if strings.TrimSpace(c.CLIAuth.MintActiveKeyID) == "" || len(c.Secrets.MintSigningKeys) == 0 {
			errs = append(errs, fmt.Errorf("production mint active key id and signing keys are required"))
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
	setString("PAPERBOAT_CATALOG_SEED_FILE", &c.Catalogs.SeedFile)
	setString("PAPERBOAT_CLI_VERIFICATION_URL", &c.CLIAuth.VerificationURL)
	setString("PAPERBOAT_CLI_CLIENT_ID", &c.CLIAuth.ClientID)
	setString("PAPERBOAT_MINT_ACTIVE_KEY_ID", &c.CLIAuth.MintActiveKeyID)
	setString("PAPERBOAT_GITHUB_OAUTH_AUTHORIZE_URL", &c.GitHub.OAuthAuthorizeURL)
	setString("PAPERBOAT_GITHUB_OAUTH_TOKEN_URL", &c.GitHub.OAuthTokenURL)
	setString("PAPERBOAT_GITHUB_CONFIG_REPO_NAME", &c.GitHub.ConfigRepoName)
	setString("PAPERBOAT_GITHUB_CONFIG_REPO_BRANCH", &c.GitHub.ConfigRepoBranch)
	setString("PAPERBOAT_FLY_APP_NAME", &c.Fly.AppName)
	setString("PAPERBOAT_FLY_ORG_SLUG", &c.Fly.OrgSlug)
	setString("PAPERBOAT_FLY_IMAGE_REF", &c.Fly.ImageRef)
	setString("PAPERBOAT_FLY_VOLUME_NAME_PREFIX", &c.Fly.VolumeNamePrefix)
	setString("PAPERBOAT_FLY_MACHINE_NAME_PREFIX", &c.Fly.MachineNamePrefix)
	setString("PAPERBOAT_FLY_HOSTNAME", &c.Fly.Hostname)
	setString("PAPERBOAT_FLY_MOUNT_PATH", &c.Fly.MountPath)
	setString("PAPERBOAT_FLY_AGENTUNNEL_SECRET", &c.Fly.AgentunnelSecret)
	setString("PAPERBOAT_FLY_GITHUB_SECRET", &c.Fly.GitHubSecret)
	setString("PAPERBOAT_FLY_SETUP_SCRIPT_SECRET", &c.Fly.SetupScriptSecret)
	setString("PAPERBOAT_WORKOS_BASE_URL", &c.Providers.WorkOS.BaseURL)
	setString("PAPERBOAT_POLAR_BASE_URL", &c.Providers.Polar.BaseURL)
	setString("PAPERBOAT_GITHUB_BASE_URL", &c.Providers.GitHub.BaseURL)
	setString("PAPERBOAT_FLY_BASE_URL", &c.Providers.Fly.BaseURL)
	setString("PAPERBOAT_AGENTUNNEL_BASE_URL", &c.Providers.Agentunnel.BaseURL)
	setString("PAPERBOAT_AGENTUNNEL_MACHINE_MODE", &c.Providers.Agentunnel.MachineMode)
	setString("PAPERBOAT_AGENTUNNEL_PAPERCODE_LOCAL_URL", &c.Providers.Agentunnel.PapercodeLocalURL)
	setString("PAPERBOAT_AGENTUNNEL_ROUTE_SUBDOMAIN_PREFIX", &c.Providers.Agentunnel.RouteSubdomainPrefix)
	setString("PAPERBOAT_AGENTUNNEL_ACCESS_POLICY_ID", &c.Providers.Agentunnel.AccessPolicyID)
	if v, ok := lookup("PAPERBOAT_AGENTUNNEL_UPLOAD_ALLOWED_MIME_TYPES"); ok {
		c.Providers.Agentunnel.UploadAllowedMIMEs = splitCSV(v)
	}
	if v, ok := lookup("PAPERBOAT_AGENTUNNEL_UPLOAD_MAX_BYTES"); ok {
		parsed, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return fmt.Errorf("parse PAPERBOAT_AGENTUNNEL_UPLOAD_MAX_BYTES: %w", err)
		}
		c.Providers.Agentunnel.UploadMaxBytes = parsed
	}
	if v, ok := lookup("PAPERBOAT_AGENTUNNEL_UPLOAD_RETENTION"); ok {
		parsed, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("parse PAPERBOAT_AGENTUNNEL_UPLOAD_RETENTION: %w", err)
		}
		c.Providers.Agentunnel.UploadRetention = parsed
	}
	if v, ok := lookup("PAPERBOAT_ALLOWED_ORIGINS"); ok {
		c.HTTP.AllowedOrigins = splitCSV(v)
	}
	if v, ok := lookup("PAPERBOAT_TRUSTED_PROXY_CIDRS"); ok {
		c.HTTP.TrustedProxyCIDRs = splitCSV(v)
	}
	if v, ok := lookup("PAPERBOAT_CLI_ALLOWED_SCOPES"); ok {
		c.CLIAuth.AllowedScopes = splitCSV(v)
	}
	for name, target := range map[string]*time.Duration{
		"PAPERBOAT_CLI_DEVICE_GRANT_LIFETIME":  &c.CLIAuth.DeviceGrantLifetime,
		"PAPERBOAT_CLI_ACCESS_TOKEN_LIFETIME":  &c.CLIAuth.AccessTokenLifetime,
		"PAPERBOAT_CLI_REFRESH_TOKEN_LIFETIME": &c.CLIAuth.RefreshTokenLifetime,
		"PAPERBOAT_CLI_POLL_INTERVAL":          &c.CLIAuth.PollInterval,
		"PAPERBOAT_MINT_JWKS_MAX_AGE":          &c.CLIAuth.MintJWKSMaxAge,
		"PAPERBOAT_MINT_PROOF_LIFETIME":        &c.CLIAuth.MintProofLifetime,
	} {
		if v, ok := lookup(name); ok {
			parsed, err := time.ParseDuration(v)
			if err != nil {
				return fmt.Errorf("parse %s: %w", name, err)
			}
			*target = parsed
		}
	}
	for name, target := range map[string]*int{
		"PAPERBOAT_CLI_MAX_CLIENT_LABEL_LENGTH":     &c.CLIAuth.MaxClientLabelLength,
		"PAPERBOAT_CLI_NETWORK_REQUESTS_PER_MINUTE": &c.CLIAuth.NetworkRequestsPerMinute,
		"PAPERBOAT_CLI_GRANT_POLLS_PER_MINUTE":      &c.CLIAuth.GrantPollsPerMinute,
		"PAPERBOAT_CLI_ACCOUNT_ACTIONS_PER_MINUTE":  &c.CLIAuth.AccountActionsPerMinute,
	} {
		if v, ok := lookup(name); ok {
			parsed, err := strconv.Atoi(v)
			if err != nil {
				return fmt.Errorf("parse %s: %w", name, err)
			}
			*target = parsed
		}
	}
	if v, ok := lookup("PAPERBOAT_GITHUB_OAUTH_SCOPES"); ok {
		c.GitHub.OAuthScopes = splitCSV(v)
	}
	if v, ok := lookup("PAPERBOAT_FLY_BOOT_COMMAND"); ok {
		c.Fly.BootCommand = splitCSV(v)
	}
	if v, ok := lookup("PAPERBOAT_AGENTUNNEL_ROUTE_EXPIRES_IN"); ok {
		parsed, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("parse PAPERBOAT_AGENTUNNEL_ROUTE_EXPIRES_IN: %w", err)
		}
		c.Providers.Agentunnel.RouteExpiresIn = parsed
	}
	if v, ok := lookup("PAPERBOAT_AGENTUNNEL_CONNECT_READY_TIMEOUT"); ok {
		parsed, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("parse PAPERBOAT_AGENTUNNEL_CONNECT_READY_TIMEOUT: %w", err)
		}
		c.Providers.Agentunnel.ConnectReadyTimeout = parsed
	}
	if v, ok := lookup("PAPERBOAT_AGENTUNNEL_CONNECT_POLL_INTERVAL"); ok {
		parsed, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("parse PAPERBOAT_AGENTUNNEL_CONNECT_POLL_INTERVAL: %w", err)
		}
		c.Providers.Agentunnel.ConnectPollInterval = parsed
	}
	if v, ok := lookup("PAPERBOAT_FAKE_PROVIDERS"); ok {
		parsed, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("PAPERBOAT_FAKE_PROVIDERS: %w", err)
		}
		c.Providers.FakeMode = parsed
	}
	if v, ok := lookup("PAPERBOAT_MINIMUM_START_CREDIT_WINDOW"); ok {
		parsed, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("PAPERBOAT_MINIMUM_START_CREDIT_WINDOW: %w", err)
		}
		c.Metering.MinimumStartCreditWindow = parsed
	}
	if v, ok := lookup("PAPERBOAT_MAX_KEEP_ALIVE_DURATION"); ok {
		parsed, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("PAPERBOAT_MAX_KEEP_ALIVE_DURATION: %w", err)
		}
		c.Metering.MaxKeepAliveDuration = parsed
	}
	if v, ok := lookup("PAPERBOAT_MAX_BODY_BYTES"); ok {
		parsed, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return fmt.Errorf("PAPERBOAT_MAX_BODY_BYTES: %w", err)
		}
		c.HTTP.MaxBodyBytes = parsed
	}
	if v, ok := lookup("PAPERBOAT_POLAR_WEBHOOK_TOLERANCE_SECONDS"); ok {
		parsed, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return fmt.Errorf("PAPERBOAT_POLAR_WEBHOOK_TOLERANCE_SECONDS: %w", err)
		}
		c.Billing.PolarWebhookTolerance = time.Duration(parsed) * time.Second
	}
	if err := setSecret("PAPERBOAT_ENCRYPTION_KEY", &c.Secrets.EncryptionKey); err != nil {
		return err
	}
	if err := setSecret("PAPERBOAT_WORKOS_API_KEY", &c.Secrets.WorkOSAPIKey); err != nil {
		return err
	}
	if err := setSecret("PAPERBOAT_WORKOS_CLIENT_ID", &c.Secrets.WorkOSClientID); err != nil {
		return err
	}
	if err := setSecret("PAPERBOAT_WORKOS_CLIENT_SECRET", &c.Secrets.WorkOSClientSecret); err != nil {
		return err
	}
	if err := setSecret("PAPERBOAT_POLAR_API_KEY", &c.Secrets.PolarAPIKey); err != nil {
		return err
	}
	if err := setSecret("PAPERBOAT_POLAR_WEBHOOK_SECRET", &c.Secrets.PolarWebhookSecret); err != nil {
		return err
	}
	if err := setSecret("PAPERBOAT_GITHUB_CLIENT_ID", &c.Secrets.GitHubClientID); err != nil {
		return err
	}
	if err := setSecret("PAPERBOAT_GITHUB_CLIENT_SECRET", &c.Secrets.GitHubClientSecret); err != nil {
		return err
	}
	if err := setSecret("PAPERBOAT_FLY_API_TOKEN", &c.Secrets.FlyAPIToken); err != nil {
		return err
	}
	if err := setSecret("PAPERBOAT_AGENTUNNEL_API_KEY", &c.Secrets.AgentunnelAPIKey); err != nil {
		return err
	}
	if err := setSecret("PAPERBOAT_AGENTUNNEL_MACHINE_TOKEN", &c.Secrets.AgentunnelMachineToken); err != nil {
		return err
	}
	if err := setSecret("PAPERBOAT_MACHINE_ACTIVITY_TOKEN", &c.Secrets.MachineActivityToken); err != nil {
		return err
	}
	if v, ok := lookup("PAPERBOAT_SESSION_KEYS"); ok {
		c.Secrets.SessionKeys = splitCSV(v)
	}
	if v, ok := lookup("PAPERBOAT_MINT_SIGNING_KEYS"); ok {
		c.Secrets.MintSigningKeys = splitCSV(v)
	}
	if path, ok := lookup("PAPERBOAT_MINT_SIGNING_KEYS_FILE"); ok {
		b, err := readFile(path)
		if err != nil {
			return fmt.Errorf("read PAPERBOAT_MINT_SIGNING_KEYS_FILE: %w", err)
		}
		c.Secrets.MintSigningKeys = splitCSV(string(b))
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
