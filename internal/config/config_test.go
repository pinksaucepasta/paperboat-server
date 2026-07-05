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
		"PAPERBOAT_ENV":                 "test",
		"PAPERBOAT_HTTP_ADDRESS":        "127.0.0.1:9090",
		"PAPERBOAT_CATALOG_SEED_FILE":   "/etc/paperboat/catalogs.json",
		"PAPERBOAT_ENCRYPTION_KEY_FILE": "/run/secrets/encryption",
		"PAPERBOAT_SESSION_KEYS":        "one,two",
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
	if cfg.Secrets.EncryptionKey != "secret-from-file" {
		t.Fatalf("encryption key was not loaded from secret file")
	}
	if got := strings.Join(cfg.Secrets.SessionKeys, ","); got != "one,two" {
		t.Fatalf("session keys = %q", got)
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

func TestRedactedJSONDoesNotExposeSecrets(t *testing.T) {
	cfg := Default()
	cfg.Secrets.EncryptionKey = "super-secret-encryption-key"
	cfg.Secrets.FlyAPIToken = "fly-token-secret"
	out := cfg.RedactedJSON()
	if strings.Contains(out, "super-secret-encryption-key") || strings.Contains(out, "fly-token-secret") {
		t.Fatalf("redacted config leaked secrets: %s", out)
	}
	if !strings.Contains(out, "supe") || !strings.Contains(out, "cret") {
		t.Fatalf("redacted config should retain diagnostic prefix/suffix: %s", out)
	}
}
