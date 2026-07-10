package config

import (
	"context"
	"strings"
	"testing"
)

func TestLoadOverlaysEnvAndSecretFiles(t *testing.T) {
	files := map[string][]byte{
		"/run/secrets/encryption": []byte("secret-from-file\n"),
	}
	env := map[string]string{
		"PAPERBOAT_ENV":                               "test",
		"PAPERBOAT_HTTP_ADDRESS":                      "127.0.0.1:9090",
		"PAPERBOAT_CATALOG_SEED_FILE":                 "/etc/paperboat/catalogs.json",
		"PAPERBOAT_POLAR_WEBHOOK_TOLERANCE_SECONDS":   "120",
		"PAPERBOAT_ENCRYPTION_KEY_FILE":               "/run/secrets/encryption",
		"PAPERBOAT_AGENTUNNEL_API_KEY":                "agentunnel-api-key-from-env",
		"PAPERBOAT_AGENTUNNEL_PAPERCODE_LOCAL_URL":    "http://127.0.0.1:4999",
		"PAPERBOAT_AGENTUNNEL_ROUTE_EXPIRES_IN":       "12h",
		"PAPERBOAT_AGENTUNNEL_ROUTE_SUBDOMAIN_PREFIX": "pc",
		"PAPERBOAT_AGENTUNNEL_CONNECT_READY_TIMEOUT":  "7s",
		"PAPERBOAT_AGENTUNNEL_CONNECT_POLL_INTERVAL":  "250ms",
		"PAPERBOAT_AGENTUNNEL_SSH_LOCAL_HOST":         "127.0.0.2",
		"PAPERBOAT_AGENTUNNEL_SSH_LOCAL_PORT":         "2222",
		"PAPERBOAT_AGENTUNNEL_SSH_REMOTE_PORT_START":  "26000",
		"PAPERBOAT_AGENTUNNEL_SSH_REMOTE_PORT_END":    "26999",
		"PAPERBOAT_AGENTUNNEL_ACCESS_POLICY_ID":       "apol_test",
		"PAPERBOAT_FLY_SETUP_SCRIPT_SECRET":           "PAPERBOAT_SETUP_SCRIPT_FROM_ENV",
		"PAPERBOAT_SESSION_KEYS":                      "one,two",
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
		cfg.Providers.Agentunnel.SSHLocalHost != "127.0.0.2" ||
		cfg.Providers.Agentunnel.SSHLocalPort != 2222 ||
		cfg.Providers.Agentunnel.SSHRemotePortStart != 26000 ||
		cfg.Providers.Agentunnel.SSHRemotePortEnd != 26999 ||
		cfg.Providers.Agentunnel.AccessPolicyID != "apol_test" {
		t.Fatalf("agentunnel route config was not loaded from env: %#v", cfg.Providers.Agentunnel)
	}
	if got := strings.Join(cfg.Secrets.SessionKeys, ","); got != "one,two" {
		t.Fatalf("session keys = %q", got)
	}
	if cfg.Fly.SetupScriptSecret != "PAPERBOAT_SETUP_SCRIPT_FROM_ENV" {
		t.Fatalf("setup script secret env name = %q", cfg.Fly.SetupScriptSecret)
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
	cfg.Secrets.MachineActivityToken = ""

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
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
