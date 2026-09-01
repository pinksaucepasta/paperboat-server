package config

import (
	"context"
	"encoding/base64"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestLoadOverlaysEnvAndSecretFiles(t *testing.T) {
	files := map[string][]byte{
		"/run/secrets/encryption": []byte("secret-from-file\n"),
	}
	env := map[string]string{
		"PAPERBOAT_ENV":                                         "test",
		"PAPERBOAT_RUNTIME_BASE_DOMAIN":                         "runtime.example.test",
		"PAPERBOAT_PREVIEW_BASE_DOMAIN":                         "preview.example.test",
		"PAPERBOAT_TUNNEL_BASE_DOMAIN":                          "tunnels.example.test",
		"PAPERBOAT_HTTP_ADDRESS":                                "127.0.0.1:9090",
		"PAPERBOAT_CATALOG_SEED_FILE":                           "/etc/paperboat/catalogs.json",
		"PAPERBOAT_POLAR_WEBHOOK_TOLERANCE_SECONDS":             "120",
		"PAPERBOAT_ENCRYPTION_KEY_FILE":                         "/run/secrets/encryption",
		"PAPERBOAT_PREVIEW_SUBDOMAIN_PREFIX":                    "pc",
		"PAPERBOAT_ACCESS_CONNECT_READY_TIMEOUT":                "7s",
		"PAPERBOAT_ACCESS_CONNECT_POLL_INTERVAL":                "250ms",
		"PAPERBOAT_TERMINAL_SESSIONS_MAX_ACTIVE_PER_PROJECT":    "16",
		"PAPERBOAT_TERMINAL_SESSIONS_OPERATION_TIMEOUT":         "20s",
		"PAPERBOAT_TERMINAL_SESSIONS_RETRY_BACKOFF":             "3s",
		"PAPERBOAT_TERMINAL_SESSIONS_WORKER_INTERVAL":           "2s",
		"PAPERBOAT_TERMINAL_SESSIONS_MAX_ATTEMPTS_BEFORE_ALERT": "7",
		"PAPERBOAT_SESSION_KEYS":                                "one,two",
		"PAPERBOAT_CONFIG_SYNC_MODE":                            "read_only",
		"PAPERBOAT_CONFIG_SYNC_BYOD_ENABLED":                    "true",
		"PAPERBOAT_CONFIG_SYNC_INCLUDES":                        ".bashrc,.gitconfig",
		"PAPERBOAT_CONFIG_SYNC_ENVIRONMENT_ALLOWLIST":           "env_one,env_two",
		"PAPERBOAT_MACHINES_URL":                                "https://dashboard.example.test/machines",
		"PAPERBOAT_FLY_HOSTED_SSH_USER":                         "workspace",
		"PAPERBOAT_FLY_HOSTED_SSH_PORT":                         "2222",
	}
	cfg, err := Load(context.Background(), LoadOptions{
		LookupEnv: func(key string) (string, bool) {
			v, ok := env[key]
			return v, ok
		},
		ReadFile: func(path string) ([]byte, error) {
			return files[path], nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Environment != EnvironmentTest {
		t.Fatalf("environment = %q", cfg.Environment)
	}
	if cfg.CLIAuth.MachinesURL != env["PAPERBOAT_MACHINES_URL"] {
		t.Fatalf("machines URL = %q", cfg.CLIAuth.MachinesURL)
	}
	if cfg.RuntimeBaseDomain != "runtime.example.test" {
		t.Fatalf("runtime base domain = %q", cfg.RuntimeBaseDomain)
	}
	if cfg.Preview.BaseDomain != "preview.example.test" || cfg.Tunnel.BaseDomain != "tunnels.example.test" {
		t.Fatalf("preview/tunnel base domains = %q/%q", cfg.Preview.BaseDomain, cfg.Tunnel.BaseDomain)
	}
	if cfg.Fly.HostedSSHUser != "workspace" || cfg.Fly.HostedSSHPort != 2222 {
		t.Fatalf("hosted SSH config = %q:%d", cfg.Fly.HostedSSHUser, cfg.Fly.HostedSSHPort)
	}
	if cfg.HTTP.Address != "127.0.0.1:9090" {
		t.Fatalf("address = %q", cfg.HTTP.Address)
	}
	if cfg.Catalogs.SeedFile != "/etc/paperboat/catalogs.json" {
		t.Fatalf("catalog seed file = %q", cfg.Catalogs.SeedFile)
	}
	if cfg.Billing.PolarWebhookTolerance.String() != "2m0s" {
		t.Fatalf("polar webhook tolerance = %s", cfg.Billing.PolarWebhookTolerance)
	}
	if cfg.Secrets.EncryptionKey != "secret-from-file" {
		t.Fatalf("encryption key was not loaded from secret file")
	}
	if cfg.Access.RouteSubdomainPrefix != "pc" ||
		cfg.Access.ConnectReadyTimeout.String() != "7s" ||
		cfg.Access.ConnectPollInterval.String() != "250ms" {
		t.Fatalf("access config was not loaded from env: %#v", cfg.Access)
	}
	if got := strings.Join(cfg.Secrets.SessionKeys, ","); got != "one,two" {
		t.Fatalf("session keys = %q", got)
	}
	if cfg.TerminalSessions.MaxActivePerProject != 16 || cfg.TerminalSessions.OperationTimeout.String() != "20s" || cfg.TerminalSessions.RetryBackoff.String() != "3s" || cfg.TerminalSessions.WorkerInterval.String() != "2s" || cfg.TerminalSessions.MaxAttemptsBeforeAlert != 7 {
		t.Fatalf("terminal session config was not loaded from env: %#v", cfg.TerminalSessions)
	}
	if cfg.ConfigSync.Mode != "read_only" || !cfg.ConfigSync.BYODEnabled ||
		!slices.Equal(cfg.ConfigSync.EnvironmentAllowlist, []string{"env_one", "env_two"}) {
		t.Fatalf("config sync rollout was not loaded from env: %#v", cfg.ConfigSync)
	}
}

func TestValidationRejectsInvalidRuntimeBaseDomain(t *testing.T) {
	cfg := Default()
	cfg.RuntimeBaseDomain = "https://runtime.example.test/path"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "runtime_base_domain") {
		t.Fatalf("validation error = %v", err)
	}
}

func TestValidationRejectsInvalidPreviewAndTunnelBaseDomains(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{name: "preview URL", mutate: func(cfg *Config) { cfg.Preview.BaseDomain = "https://preview.example.test" }, want: "preview.base_domain"},
		{name: "tunnel port", mutate: func(cfg *Config) { cfg.Tunnel.BaseDomain = "tunnels.example.test:443" }, want: "tunnel.base_domain"},
		{name: "tunnel single label", mutate: func(cfg *Config) { cfg.Tunnel.BaseDomain = "localhost" }, want: "tunnel.base_domain"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := Default()
			test.mutate(&cfg)
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error = %v", err)
			}
		})
	}
}

func TestValidationRejectsInvalidHostedSSHAuthority(t *testing.T) {
	for _, mutate := range []func(*Config){
		func(cfg *Config) { cfg.Fly.HostedSSHUser = "bad user" },
		func(cfg *Config) { cfg.Fly.HostedSSHUser = " workspace" },
		func(cfg *Config) { cfg.Fly.HostedSSHUser = "-root" },
		func(cfg *Config) { cfg.Fly.HostedSSHUser = "Root" },
		func(cfg *Config) { cfg.Fly.HostedSSHUser = "root" },
		func(cfg *Config) { cfg.Fly.HostedSSHPort = 0 },
		func(cfg *Config) { cfg.Fly.HostedSSHPort = 65536 },
	} {
		cfg := Default()
		mutate(&cfg)
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "hosted SSH") {
			t.Fatalf("validation error = %v", err)
		}
	}
}

func TestValidationRejectsInvalidTerminalSessionAlertThreshold(t *testing.T) {
	cfg := Default()
	cfg.TerminalSessions.MaxAttemptsBeforeAlert = 0
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "terminal_sessions") {
		t.Fatalf("validation error = %v", err)
	}
}

func TestValidationAcceptsAllowlistFirstManifestConfiguration(t *testing.T) {
	for _, mutate := range []func(*Config){
		func(cfg *Config) { cfg.ConfigSync.Mode = "read_only" },
		func(cfg *Config) { cfg.ConfigSync.BYODEnabled = true },
	} {
		cfg := Default()
		mutate(&cfg)
		if err := cfg.Validate(); err != nil {
			t.Fatalf("manifest configuration rejected: %v", err)
		}
	}
}

func TestValidationRejectsConfigSyncPoliciesHelpersCannotConsume(t *testing.T) {
	tests := map[string]func(*Config){
		"file size":        func(cfg *Config) { cfg.ConfigSync.MaxFileBytes = 100<<20 + 1 },
		"batch size":       func(cfg *Config) { cfg.ConfigSync.MaxBatchBytes = 500<<20 + 1 },
		"manifest bytes":   func(cfg *Config) { cfg.ConfigSync.ManifestMaxBytes = 4<<20 + 1 },
		"manifest lines":   func(cfg *Config) { cfg.ConfigSync.ManifestMaxLines = 65537 },
		"manifest pattern": func(cfg *Config) { cfg.ConfigSync.ManifestMaxPatternBytes = 8193 },
		"debounce":         func(cfg *Config) { cfg.ConfigSync.Debounce = 5*time.Minute + 1 },
		"push interval":    func(cfg *Config) { cfg.ConfigSync.MinPushInterval = 24*time.Hour + 1 },
		"dirty delay":      func(cfg *Config) { cfg.ConfigSync.MaxDirtyDelay = cfg.ConfigSync.Debounce - 1 },
		"poll interval":    func(cfg *Config) { cfg.ConfigSync.RemotePollInterval = time.Hour + 1 },
		"retry limit":      func(cfg *Config) { cfg.ConfigSync.RetryLimit = 21 },
		"flush timeout":    func(cfg *Config) { cfg.ConfigSync.ShutdownFlushTimeout = 10*time.Minute + 1 },
		"summary limit":    func(cfg *Config) { cfg.ConfigSync.SummaryLimit = 1001 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := Default()
			mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("helper-incompatible config sync policy was accepted")
			}
		})
	}
}

func TestValidationRejectsRelativeConfigHomeOverride(t *testing.T) {
	cfg := Default()
	cfg.ConfigSync.HomeOverride = "relative/home"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "config_sync.home_override") {
		t.Fatalf("relative home validation error = %v", err)
	}
}

func TestProductionValidationRejectsFakeProvidersAndWeakSecrets(t *testing.T) {
	cfg := Default()
	cfg.Environment = EnvironmentProduction
	cfg.HTTP.PublicBaseURL = "https://pb.example.test"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected production validation error")
	}
	got := err.Error()
	for _, want := range []string{"fake_mode", "production provider secrets", "production secrets"} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected %q in validation error %q", want, got)
		}
	}
}

func validProductionConfig() Config {
	cfg := Default()
	cfg.Environment = EnvironmentProduction
	cfg.HTTP.PublicBaseURL = "https://pb.example.test"
	cfg.Providers.FakeMode = false
	cfg.Secrets.SessionKeys = []string{"0123456789abcdef0123456789abcdef"}
	cfg.Secrets.EncryptionKey = "abcdef0123456789abcdef0123456789"
	cfg.Secrets.WorkOSAPIKey = "workos-api-key"
	cfg.Secrets.WorkOSClientID = "workos-client-id"
	cfg.Secrets.WorkOSClientSecret = "workos-client-secret"
	cfg.Secrets.PolarAPIKey = "polar-api-key"
	cfg.Secrets.PolarWebhookSecret = "polar-webhook-secret"
	cfg.Secrets.GitHubClientID = "github-client-id"
	cfg.Secrets.GitHubClientSecret = "github-client-secret"
	cfg.GitHub.AppID = "12345"
	cfg.Secrets.GitHubAppPrivateKey = "configured-outside-this-validation-test"
	cfg.Secrets.FlyAPIToken = "fly-api-token"
	cfg.Secrets.EdgeControlCredential = "edge-control-credential-0123456789"
	cfg.Fly.ImageRef = "registry.example.test/paperboat/project-vm@sha256:" + strings.Repeat("a", 64)
	cfg.ReleaseDirectory = "/srv/paperboat-releases"
	cfg.ReleaseBaseURL = "https://get.example.test"
	cfg.Preview.BaseDomain = "preview.example.test"
	cfg.Tunnel.BaseDomain = "tunnels.example.test"
	cfg.CLIAuth.MintActiveKeyID = "current"
	cfg.Secrets.MintSigningKeys = []string{"current:" + base64.RawURLEncoding.EncodeToString(make([]byte, 32))}
	cfg.Diagnostics.ObjectEndpoint = "https://diagnostics.example.test"
	cfg.Diagnostics.ObjectRegion = "fsn1"
	cfg.Diagnostics.ObjectBucket = "paperboat-diagnostics"
	cfg.Secrets.DiagnosticsAccessKey = "diagnostics-access-key"
	cfg.Secrets.DiagnosticsSecretKey = "diagnostics-secret-key"
	cfg.Certificates = Certificates{
		Enabled:                         true,
		DirectoryURL:                    "https://acme.example.test/directory",
		Issuer:                          "letsencrypt",
		AccountKeyReference:             "secret://acme/account",
		MasterKeyReference:              "secret://paperboat/master",
		DNSProvider:                     "cloudflare",
		DNSZoneID:                       "zone_01",
		DNSTokenReference:               "secret://cloudflare/dns",
		ChallengeZone:                   "challenges.example.test",
		CAAResolver:                     "127.0.0.1:53",
		DistributionCredentialReference: "secret://edge/distribution",
		OwnerID:                         "server_01",
	}
	return cfg
}

func TestProductionValidationRequiresManagedCertificates(t *testing.T) {
	cfg := validProductionConfig()
	cfg.Certificates.Enabled = false
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "managed certificates are required in production") {
		t.Fatalf("disabled production certificate runtime error = %v", err)
	}
}

func TestProductionValidationRequiresGitHubAppOnlyWhenConfigSyncEnabled(t *testing.T) {
	cfg := validProductionConfig()
	cfg.GitHub.AppID = ""
	cfg.Secrets.GitHubAppPrivateKey = ""
	cfg.ConfigSync.Mode = "disabled"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("disabled config sync required GitHub App credentials: %v", err)
	}
	cfg.ConfigSync.Mode = "read_only"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "GitHub App credentials") {
		t.Fatalf("enabled config sync error = %v", err)
	}
}

func TestValidationRequiresPostgresAndCatalogSeedFile(t *testing.T) {
	cfg := Default()
	cfg.Database.Driver = "memory"
	cfg.Catalogs.SeedFile = ""
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error")
	}
	got := err.Error()
	for _, want := range []string{"database.driver", "catalogs.seed_file"} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected %q in validation error %q", want, got)
		}
	}
}

func TestValidationRejectsInvalidCLIAuthURLAndTrustedProxyCIDR(t *testing.T) {
	for _, raw := range []string{"dashboard.example.com/cli/authorize", "ftp://dashboard.example.com/cli/authorize", "://bad"} {
		cfg := Default()
		cfg.CLIAuth.VerificationURL = raw
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "cli_auth.verification_url") {
			t.Fatalf("verification URL %q error = %v", raw, err)
		}
	}
	for _, raw := range []string{"dashboard.example.com/machines", "ftp://dashboard.example.com/machines", "://bad"} {
		cfg := Default()
		cfg.CLIAuth.MachinesURL = raw
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "cli_auth.machines_url") {
			t.Fatalf("machines URL %q error = %v", raw, err)
		}
	}
	cfg := Default()
	cfg.HTTP.TrustedProxyCIDRs = []string{"not-a-cidr"}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "trusted_proxy_cidrs") {
		t.Fatalf("trusted proxy error = %v", err)
	}
}

func TestValidationRequiresCLIAndPreviewTunnelScopes(t *testing.T) {
	for _, missing := range []string{
		"projects:read", "projects:connect", "previews:read", "previews:write",
		"tunnels:read", "tunnels:write", "operations:read", "operations:write",
	} {
		t.Run(missing, func(t *testing.T) {
			cfg := Default()
			filtered := make([]string, 0, len(cfg.CLIAuth.AllowedScopes)-1)
			for _, scope := range cfg.CLIAuth.AllowedScopes {
				if scope != missing {
					filtered = append(filtered, scope)
				}
			}
			cfg.CLIAuth.AllowedScopes = filtered
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), "cli_auth.allowed_scopes") || !strings.Contains(err.Error(), missing) {
				t.Fatalf("missing scope %q validation error = %v", missing, err)
			}
		})
	}

	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default CLI enrollment scopes rejected: %v", err)
	}
}

func TestValidationAcceptsAbsoluteCLIAuthURLAndTrustedProxyCIDR(t *testing.T) {
	cfg := Default()
	cfg.CLIAuth.VerificationURL = "https://dashboard.example.com/cli/authorize"
	cfg.CLIAuth.MachinesURL = "https://dashboard.example.com/dashboard/machines"
	cfg.HTTP.TrustedProxyCIDRs = []string{"10.0.0.0/8", "2001:db8::/32"}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestRedactedJSONDoesNotExposeSecrets(t *testing.T) {
	cfg := Default()
	cfg.Secrets.EncryptionKey = "super-secret-encryption-key"
	cfg.Secrets.FlyAPIToken = "fly-token-secret"
	cfg.Secrets.EdgeControlCredential = "edge-control-credential-secret"
	cfg.Secrets.GitHubClientID = "github-client-id-secret"
	cfg.Secrets.GitHubClientSecret = "github-client-secret"
	out := cfg.RedactedJSON()
	if strings.Contains(out, "super-secret-encryption-key") ||
		strings.Contains(out, "fly-token-secret") ||
		strings.Contains(out, "edge-control-credential-secret") ||
		strings.Contains(out, "github-client-id-secret") ||
		strings.Contains(out, "github-client-secret") {
		t.Fatalf("redacted config leaked secrets: %s", out)
	}
	if !strings.Contains(out, "supe") || !strings.Contains(out, "cret") {
		t.Fatalf("redacted config should retain diagnostic prefix/suffix: %s", out)
	}
}

func TestCertificatesValidationRequiresReferenceOnlyProductionInputs(t *testing.T) {
	cfg := Default()
	cfg.Certificates.Enabled = true
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "certificates.") {
		t.Fatalf("enabled certificates accepted incomplete configuration: %v", err)
	}
	cfg.Certificates = Certificates{
		Enabled:                         true,
		DirectoryURL:                    "https://acme.example.test/directory",
		Issuer:                          "letsencrypt",
		AccountKeyReference:             "secret://acme/account",
		MasterKeyReference:              "secret://paperboat/master",
		DNSProvider:                     "cloudflare",
		DNSZoneID:                       "zone_01",
		DNSTokenReference:               "secret://cloudflare/dns",
		ChallengeZone:                   "challenges.example.test",
		CAAResolver:                     "127.0.0.1:53",
		DistributionCredentialReference: "secret://edge/distribution",
		OwnerID:                         "server_01",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid certificate configuration rejected: %v", err)
	}
	cfg.Certificates.DirectoryURL = "http://acme.example.test/directory"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "directory_url") {
		t.Fatalf("non-loopback HTTP ACME directory accepted: %v", err)
	}
}

func TestCertificatesEnvironmentReferencesOverlayWithoutSecretFields(t *testing.T) {
	cfg, err := Load(context.Background(), LoadOptions{
		LookupEnv: func(name string) (string, bool) {
			values := map[string]string{
				"PAPERBOAT_CERTIFICATES_ENABLED":                           "true",
				"PAPERBOAT_CERTIFICATES_DIRECTORY_URL":                     "https://acme.example.test/directory",
				"PAPERBOAT_CERTIFICATES_ISSUER":                            "letsencrypt",
				"PAPERBOAT_CERTIFICATES_ACCOUNT_KEY_REFERENCE":             "secret://acme/account",
				"PAPERBOAT_CERTIFICATES_MASTER_KEY_REFERENCE":              "secret://paperboat/master",
				"PAPERBOAT_CERTIFICATES_DNS_PROVIDER":                      "cloudflare",
				"PAPERBOAT_CERTIFICATES_DNS_ZONE_ID":                       "zone_01",
				"PAPERBOAT_CERTIFICATES_DNS_TOKEN_REFERENCE":               "secret://cloudflare/dns",
				"PAPERBOAT_CERTIFICATES_CHALLENGE_ZONE":                    "challenges.example.test",
				"PAPERBOAT_CERTIFICATES_CAA_RESOLVER":                      "127.0.0.1:53",
				"PAPERBOAT_CERTIFICATES_DISTRIBUTION_CREDENTIAL_REFERENCE": "secret://edge/distribution",
				"PAPERBOAT_CERTIFICATES_OWNER_ID":                          "server_01",
			}
			value, ok := values[name]
			return value, ok
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Certificates.Enabled || cfg.Certificates.MasterKeyReference != "secret://paperboat/master" {
		t.Fatalf("certificate references were not overlaid: %#v", cfg.Certificates)
	}
	if strings.Contains(cfg.RedactedJSON(), "secret-value") {
		t.Fatal("certificate configuration unexpectedly exposed a secret value")
	}
}
