package tunnelcert

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

type task30LiveDNSConfig struct {
	DSN            string `json:"dsn"`
	ZoneID         string `json:"zone_id"`
	TokenReference string `json:"token_reference"`
	DesiredPath    string `json:"desired_path"`
	ResultPath     string `json:"result_path"`
	Migrate        bool   `json:"migrate"`
}

type task30LiveDNSResult struct {
	State                     string   `json:"state"`
	ErrorKind                 string   `json:"error_kind,omitempty"`
	ObservedProviderAddresses []string `json:"observed_provider_addresses"`
	PublicationGeneration     uint64   `json:"publication_generation,omitempty"`
}

// TestTask30LiveDNSReconcile is an opt-in executable fixture for the isolated
// Task 30 DNS qualification database and Cloudflare zone. It performs one
// bounded reconciliation pass; the coordinator owns retries and assertions.
func TestTask30LiveDNSReconcile(t *testing.T) {
	configPath := strings.TrimSpace(os.Getenv("PAPERBOAT_TASK30_LIVE_DNS_CONFIG"))
	if configPath == "" {
		t.Skip("run by the Task 30 live DNS coordinator")
	}
	var fixture task30LiveDNSConfig
	readTask30JSON(t, configPath, &fixture, "live DNS config")
	if fixture.DSN == "" || fixture.ZoneID == "" || fixture.TokenReference == "" || fixture.DesiredPath == "" || fixture.ResultPath == "" {
		t.Fatal("live DNS config is incomplete")
	}
	if err := db.ValidateIsolatedTestDSN(fixture.DSN, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal("live DNS database must be an isolated test database")
	}
	var desired DesiredAddressPublication
	readTask30JSON(t, fixture.DesiredPath, &desired, "desired DNS publication")

	database, err := db.Open(config.Database{Driver: "postgres", DSN: fixture.DSN})
	if err != nil {
		t.Fatal("open isolated live DNS database")
	}
	t.Cleanup(func() { _ = database.Close() })
	if fixture.Migrate {
		if err := db.Migrate(context.Background(), database); err != nil {
			t.Fatal("migrate isolated live DNS database")
		}
	}
	admission, err := NewDatabaseCloudflareAddressAdmission(database, fixture.ZoneID)
	if err != nil {
		t.Fatal("create live DNS admission")
	}
	provider, err := NewCloudflareDNSProvider(CloudflareDNSConfig{
		ZoneID: fixture.ZoneID, TokenReference: fixture.TokenReference,
		TokenSource:      EnvironmentReferenceSource{Prefix: defaultCertificateSecretEnvPrefix, LookupEnv: os.LookupEnv},
		AddressAdmission: admission,
	})
	if err != nil {
		t.Fatal("create live DNS provider")
	}
	reconciler, err := NewAddressReconciler(database, provider, net.DefaultResolver)
	if err != nil {
		t.Fatal("create live DNS reconciler")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	reconcileErr := reconciler.Reconcile(ctx, desired)
	result := task30LiveDNSResult{State: "unknown", ErrorKind: task30LiveDNSErrorKind(reconcileErr), ObservedProviderAddresses: []string{}}
	hostname := desired.Hostname
	if normalized, _, normalizeErr := normalizeHostname(hostname); normalizeErr == nil {
		hostname = normalized
	}
	if row, rowErr := database.Queries().GetEdgeDNSPublication(ctx, hostname); rowErr == nil && row.OwnerID == desired.Owner {
		result.State = row.State
		if row.PublicationGeneration > 0 {
			result.PublicationGeneration = uint64(row.PublicationGeneration)
		}
	}
	if row, rowErr := database.Queries().GetEdgeDNSPublication(ctx, hostname); rowErr == nil && row.OwnerID == desired.Owner {
		var records []AddressRecord
		if json.Unmarshal(row.ProviderRecords, &records) == nil {
			for _, record := range records {
				result.ObservedProviderAddresses = append(result.ObservedProviderAddresses, record.Address)
			}
			sort.Strings(result.ObservedProviderAddresses)
		}
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal("encode sanitized live DNS result")
	}
	if err := os.WriteFile(fixture.ResultPath, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal("write sanitized live DNS result")
	}
}

func readTask30JSON(t *testing.T, path string, output any, label string) {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s", label)
	}
	if len(contents) == 0 || len(contents) > 1<<20 || json.Unmarshal(contents, output) != nil {
		t.Fatalf("invalid %s", label)
	}
}

func task30LiveDNSErrorKind(err error) string {
	if err == nil {
		return ""
	}
	var publicationError *AddressPublicationError
	if errors.As(err, &publicationError) {
		return string(publicationError.Kind)
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "deadline"
	}
	if errors.Is(err, ErrInvalid) {
		return "invalid"
	}
	return "unavailable"
}
