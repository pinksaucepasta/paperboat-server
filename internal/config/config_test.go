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
		"PAPERBOAT_HELPER_BASE_DOMAIN":                          "helper.example.test",
		"PAPERBOAT_HTTP_ADDRESS":                                "127.0.0.1:9090",
		"PAPERBOAT_CATALOG_SEED_FILE":                           "/etc/paperboat/catalogs.json",
		"PAPERBOAT_POLAR_WEBHOOK_TOLERANCE_SECONDS":             "120",
		"PAPERBOAT_ENCRYPTION_KEY_FILE":                         "/run/secrets/encryption",
		"PAPERBOAT_PREVIEW_SUBDOMAIN_PREFIX":                    "pc",
		"PAPERBOAT_ACCESS_CONNECT_READY_TIMEOUT":                "7s",
		"PAPERBOAT_ACCESS_CONNECT_POLL_INTERVAL":                "250ms",
		"PAPERBOAT_UPLOAD_MAX_BYTES":                            "7340032",
		"PAPERBOAT_UPLOAD_ALLOWED_MIME_TYPES":                   "image/png,image/webp",
		"PAPERBOAT_UPLOAD_RETENTION":                            "24h",
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
		"PAPERBOAT_USER_MACHINES_URL":                           "https://dashboard.example.test/machines",
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
	if cfg.CLIAuth.UserMachinesURL != env["PAPERBOAT_USER_MACHINES_URL"] {
		t.Fatalf("user machines URL = %q", cfg.CLIAuth.UserMachinesURL)
	}
	if cfg.HelperBaseDomain != "helper.example.test" {
		t.Fatalf("helper base domain = %q", cfg.HelperBaseDomain)
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
		cfg.Access.ConnectPollInterval.String() != "250ms" ||
		cfg.Access.UploadMaxBytes != 7340032 || cfg.Access.UploadRetention.String() != "24h0m0s" ||
		!slices.Equal(cfg.Access.UploadAllowedMIMEs, []string{"image/png", "image/webp"}) {
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

func TestValidationRejectsInvalidHelperBaseDomain(t *testing.T) {
	cfg := Default()
	cfg.HelperBaseDomain = "https://helper.example.test/path"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "helper_base_domain") {
		t.Fatalf("validation error = %v", err)
	}
}

func TestDefaultUploadMIMEPolicyAllowsAllFiles(t *testing.T) {
	cfg := Default()
	if cfg.Access.UploadMaxBytes != 50<<20 {
		t.Fatalf("default upload max bytes = %d", cfg.Access.UploadMaxBytes)
	}
	if !slices.Equal(cfg.Access.UploadAllowedMIMEs, []string{"*/*"}) {
		t.Fatalf("default upload MIME types = %v", cfg.Access.UploadAllowedMIMEs)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("file wildcard policy rejected: %v", err)
	}
}

func TestValidationRejectsInvalidTerminalSessionAlertThreshold(t *testing.T) {
	cfg := Default()
	cfg.TerminalSessions.MaxAttemptsBeforeAlert = 0
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "terminal_sessions") {
		t.Fatalf("validation error = %v", err)
	}
}

func TestMandatoryConfigSyncExclusionsCanOnlyBeExtended(t *testing.T) {
	cfg, err := Load(context.Background(), LoadOptions{
		LookupEnv: func(key string) (string, bool) {
			if key == "PAPERBOAT_CONFIG_SYNC_MANDATORY_EXCLUDES" {
				return ".custom-secret", true
			}
			return "", false
		},
		ReadFile: func(string) ([]byte, error) { return nil, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{".custom-secret", ".paperboat", "**/.paperboat", ".config/git/credentials", ".config/hub", ".claude/shell-snapshots", ".codex/log"} {
		if !slices.Contains(cfg.ConfigSync.MandatoryExcludes, required) {
			t.Fatalf("mandatory exclusion %q was removed: %v", required, cfg.ConfigSync.MandatoryExcludes)
		}
	}
}

func TestConfigFileCannotReplaceMandatoryConfigSyncExcludes(t *testing.T) {
	cfg, err := Load(context.Background(), LoadOptions{
		FilePath: "config.json",
		ReadFile: func(string) ([]byte, error) {
			return []byte(`{"config_sync":{"mandatory_excludes":[".custom-secret"]}}`), nil
		},
		LookupEnv: func(string) (string, bool) { return "", false },
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{".custom-secret", ".ssh", ".config/git/credentials", "**/credentials.*"} {
		if !slices.Contains(cfg.ConfigSync.MandatoryExcludes, required) {
			t.Fatalf("mandatory exclusion %q was replaced by config file", required)
		}
	}
	unsafe := cfg
	unsafe.ConfigSync.MandatoryExcludes = []string{".custom-secret"}
	if err := unsafe.Validate(); err == nil {
		t.Fatal("configuration without the built-in mandatory exclusion floor was accepted")
	}
}

func TestValidationRejectsUnsafeConfigSyncPatterns(t *testing.T) {
	for _, pattern := range []string{
		"/absolute", "../traversal", "safe/../traversal", "[invalid", `back\slash`,
		"nul\x00path", strings.Repeat("a", 513),
	} {
		cfg := Default()
		cfg.ConfigSync.Includes = []string{pattern}
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "config_sync path pattern") {
			t.Fatalf("pattern %q validation error = %v", pattern, err)
		}
	}
}

func TestValidationRequiresExplicitConfigSyncIncludes(t *testing.T) {
	for _, mutate := range []func(*Config){
		func(cfg *Config) { cfg.ConfigSync.Mode = "read_only" },
		func(cfg *Config) { cfg.ConfigSync.BYODEnabled = true },
	} {
		cfg := Default()
		mutate(&cfg)
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "config_sync.includes") {
			t.Fatalf("empty includes validation error = %v", err)
		}
		cfg.ConfigSync.Includes = []string{".bashrc"}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("explicit include rejected: %v", err)
		}
	}

	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("disabled config sync rejected empty includes: %v", err)
	}
}

func TestValidationRejectsConfigSyncPoliciesHelpersCannotConsume(t *testing.T) {
	patterns := func(count int) []string {
		result := make([]string, count)
		for i := range result {
			result[i] = ".bashrc"
		}
		return result
	}
	tests := map[string]func(*Config){
		"file size":  func(cfg *Config) { cfg.ConfigSync.MaxFileBytes = 100<<20 + 1 },
		"batch size": func(cfg *Config) { cfg.ConfigSync.MaxBatchBytes = 500<<20 + 1 },
		"includes":   func(cfg *Config) { cfg.ConfigSync.Includes = patterns(257) },
		"excludes":   func(cfg *Config) { cfg.ConfigSync.Excludes = patterns(513) },
		"mandatory excludes": func(cfg *Config) {
			cfg.ConfigSync.MandatoryExcludes = append(cfg.ConfigSync.MandatoryExcludes, patterns(1025-len(cfg.ConfigSync.MandatoryExcludes))...)
		},
		"debounce":      func(cfg *Config) { cfg.ConfigSync.Debounce = 5*time.Minute + 1 },
		"push interval": func(cfg *Config) { cfg.ConfigSync.MinPushInterval = 24*time.Hour + 1 },
		"dirty delay":   func(cfg *Config) { cfg.ConfigSync.MaxDirtyDelay = cfg.ConfigSync.Debounce - 1 },
		"poll interval": func(cfg *Config) { cfg.ConfigSync.RemotePollInterval = time.Hour + 1 },
		"retry limit":   func(cfg *Config) { cfg.ConfigSync.RetryLimit = 21 },
		"flush timeout": func(cfg *Config) { cfg.ConfigSync.ShutdownFlushTimeout = 10*time.Minute + 1 },
		"summary limit": func(cfg *Config) { cfg.ConfigSync.SummaryLimit = 1001 },
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
	cfg.Secrets.ClassifierAPIKey = "classifier-api-key"
	cfg.Fly.ImageRef = "registry.example.test/paperboat/project-vm@sha256:" + strings.Repeat("a", 64)
	cfg.UserMachines.BootstrapCommand = "pbh bootstrap --server https://pb.example.test"
	cfg.UserMachines.HelperArtifactsJSON = `[{"schema":"paperboat.helper-artifact/v1"}]`
	cfg.UserMachines.HelperArtifactPublicKey = "helper-artifact-public-key"
	cfg.Preview.BaseDomain = "preview.example.test"
	cfg.Secrets.PreviewIdentityKey = "preview-identity-key-012345678901234567890123456789"
	cfg.CLIAuth.MintActiveKeyID = "current"
	cfg.Secrets.MintSigningKeys = []string{"current:" + base64.RawURLEncoding.EncodeToString(make([]byte, 32))}
	return cfg
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
		cfg.CLIAuth.UserMachinesURL = raw
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "cli_auth.user_machines_url") {
			t.Fatalf("user machines URL %q error = %v", raw, err)
		}
	}
	cfg := Default()
	cfg.HTTP.TrustedProxyCIDRs = []string{"not-a-cidr"}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "trusted_proxy_cidrs") {
		t.Fatalf("trusted proxy error = %v", err)
	}
}

func TestValidationAcceptsAbsoluteCLIAuthURLAndTrustedProxyCIDR(t *testing.T) {
	cfg := Default()
	cfg.CLIAuth.VerificationURL = "https://dashboard.example.com/cli/authorize"
	cfg.CLIAuth.UserMachinesURL = "https://dashboard.example.com/dashboard/user-machines"
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
