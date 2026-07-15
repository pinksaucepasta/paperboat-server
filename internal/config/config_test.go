package config

import (
	"context"
	"encoding/base64"
	"slices"
	"strings"
	"testing"
)

func TestLoadOverlaysEnvAndSecretFiles(t *testing.T) {
	files := map[string][]byte{
		"/run/secrets/encryption": []byte("secret-from-file\n"),
	}
	env := map[string]string{
		"PAPERBOAT_ENV":                                         "test",
		"PAPERBOAT_HTTP_ADDRESS":                                "127.0.0.1:9090",
		"PAPERBOAT_CATALOG_SEED_FILE":                           "/etc/paperboat/catalogs.json",
		"PAPERBOAT_POLAR_WEBHOOK_TOLERANCE_SECONDS":             "120",
		"PAPERBOAT_ENCRYPTION_KEY_FILE":                         "/run/secrets/encryption",
		"PAPERBOAT_AGENTUNNEL_API_KEY":                          "agentunnel-api-key-from-env",
		"PAPERBOAT_AGENTUNNEL_PAPERCODE_LOCAL_URL":              "http://127.0.0.1:4999",
		"PAPERBOAT_AGENTUNNEL_ROUTE_EXPIRES_IN":                 "12h",
		"PAPERBOAT_AGENTUNNEL_ROUTE_SUBDOMAIN_PREFIX":           "pc",
		"PAPERBOAT_AGENTUNNEL_CONNECT_READY_TIMEOUT":            "7s",
		"PAPERBOAT_AGENTUNNEL_CONNECT_POLL_INTERVAL":            "250ms",
		"PAPERBOAT_AGENTUNNEL_ACCESS_POLICY_ID":                 "apol_test",
		"PAPERBOAT_AGENTUNNEL_UPLOAD_MAX_BYTES":                 "7340032",
		"PAPERBOAT_AGENTUNNEL_UPLOAD_ALLOWED_MIME_TYPES":        "image/png,image/webp",
		"PAPERBOAT_TERMINAL_SESSIONS_MAX_ACTIVE_PER_PROJECT":    "16",
		"PAPERBOAT_TERMINAL_SESSIONS_OPERATION_TIMEOUT":         "20s",
		"PAPERBOAT_TERMINAL_SESSIONS_RETRY_BACKOFF":             "3s",
		"PAPERBOAT_TERMINAL_SESSIONS_WORKER_INTERVAL":           "2s",
		"PAPERBOAT_TERMINAL_SESSIONS_MAX_ATTEMPTS_BEFORE_ALERT": "7",
		"PAPERBOAT_FLY_SETUP_SCRIPT_SECRET":                     "PAPERBOAT_SETUP_SCRIPT_FROM_ENV",
		"PAPERBOAT_SESSION_KEYS":                                "one,two",
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
	if cfg.Secrets.AgentunnelAPIKey != "agentunnel-api-key-from-env" {
		t.Fatalf("agentunnel api key was not loaded from env")
	}
	if cfg.Providers.Agentunnel.PapercodeLocalURL != "http://127.0.0.1:4999" ||
		cfg.Providers.Agentunnel.RouteExpiresIn.String() != "12h0m0s" ||
		cfg.Providers.Agentunnel.RouteSubdomainPrefix != "pc" ||
		cfg.Providers.Agentunnel.ConnectReadyTimeout.String() != "7s" ||
		cfg.Providers.Agentunnel.ConnectPollInterval.String() != "250ms" ||
		cfg.Providers.Agentunnel.AccessPolicyID != "apol_test" ||
		cfg.Providers.Agentunnel.UploadMaxBytes != 7340032 ||
		!slices.Equal(cfg.Providers.Agentunnel.UploadAllowedMIMEs, []string{"image/png", "image/webp"}) {
		t.Fatalf("agentunnel route config was not loaded from env: %#v", cfg.Providers.Agentunnel)
	}
	if got := strings.Join(cfg.Secrets.SessionKeys, ","); got != "one,two" {
		t.Fatalf("session keys = %q", got)
	}
	if cfg.Fly.SetupScriptSecret != "PAPERBOAT_SETUP_SCRIPT_FROM_ENV" {
		t.Fatalf("setup script secret env name = %q", cfg.Fly.SetupScriptSecret)
	}
	if cfg.TerminalSessions.MaxActivePerProject != 16 || cfg.TerminalSessions.OperationTimeout.String() != "20s" || cfg.TerminalSessions.RetryBackoff.String() != "3s" || cfg.TerminalSessions.WorkerInterval.String() != "2s" || cfg.TerminalSessions.MaxAttemptsBeforeAlert != 7 {
		t.Fatalf("terminal session config was not loaded from env: %#v", cfg.TerminalSessions)
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
	for _, required := range []string{".custom-secret", ".config/git/credentials", ".config/hub", ".claude/shell-snapshots", ".codex/log"} {
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
	for _, pattern := range []string{"/absolute", "../traversal", "safe/../traversal", "[invalid"} {
		cfg := Default()
		cfg.ConfigSync.Includes = []string{pattern}
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "config_sync path pattern") {
			t.Fatalf("pattern %q validation error = %v", pattern, err)
		}
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

func TestProductionValidationDoesNotRequireMachineActivityToken(t *testing.T) {
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
	cfg.Secrets.FlyAPIToken = "fly-api-token"
	cfg.Secrets.AgentunnelAPIKey = "agentunnel-api-key"
	cfg.Secrets.ClassifierAPIKey = "classifier-api-key"
	cfg.Secrets.MachineActivityToken = ""
	cfg.CLIAuth.MintActiveKeyID = "current"
	cfg.Secrets.MintSigningKeys = []string{"current:" + base64.RawURLEncoding.EncodeToString(make([]byte, 32))}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestProductionValidationRequiresFailFastAgentunnel(t *testing.T) {
	cfg := Default()
	cfg.Environment = EnvironmentProduction
	cfg.Providers.Agentunnel.MachineMode = "optional"

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), `agentunnel.machine_mode must be "required" in production`) {
		t.Fatalf("Validate() error = %v, want production agentunnel mode rejection", err)
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
	cfg := Default()
	cfg.HTTP.TrustedProxyCIDRs = []string{"not-a-cidr"}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "trusted_proxy_cidrs") {
		t.Fatalf("trusted proxy error = %v", err)
	}
}

func TestValidationAcceptsAbsoluteCLIAuthURLAndTrustedProxyCIDR(t *testing.T) {
	cfg := Default()
	cfg.CLIAuth.VerificationURL = "https://dashboard.example.com/cli/authorize"
	cfg.HTTP.TrustedProxyCIDRs = []string{"10.0.0.0/8", "2001:db8::/32"}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestRedactedJSONDoesNotExposeSecrets(t *testing.T) {
	cfg := Default()
	cfg.Secrets.EncryptionKey = "super-secret-encryption-key"
	cfg.Secrets.FlyAPIToken = "fly-token-secret"
	cfg.Secrets.AgentunnelAPIKey = "agentunnel-api-key-secret"
	cfg.Secrets.GitHubClientID = "github-client-id-secret"
	cfg.Secrets.GitHubClientSecret = "github-client-secret"
	out := cfg.RedactedJSON()
	if strings.Contains(out, "super-secret-encryption-key") ||
		strings.Contains(out, "fly-token-secret") ||
		strings.Contains(out, "agentunnel-api-key-secret") ||
		strings.Contains(out, "github-client-id-secret") ||
		strings.Contains(out, "github-client-secret") {
		t.Fatalf("redacted config leaked secrets: %s", out)
	}
	if !strings.Contains(out, "supe") || !strings.Contains(out, "cret") {
		t.Fatalf("redacted config should retain diagnostic prefix/suffix: %s", out)
	}
}
