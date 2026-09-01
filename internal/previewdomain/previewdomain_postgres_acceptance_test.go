package previewdomain_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/previewdomain"
	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelstore"
)

// TestPreviewDomainAtomicLifecycleOnPostgres is opt-in and intentionally uses
// only a caller-provided isolated PostgreSQL database. It proves that preview
// aliases are inserted with their lease, moved with the lease generation, and
// withdrawn/quarantined in the same lifecycle transaction.
func TestPreviewDomainAtomicLifecycleOnPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_DATABASE_DSN"))
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run preview-domain PostgreSQL acceptance")
	}
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(dsn), "_test") {
		t.Fatal("PAPERBOAT_TEST_DATABASE_DSN must name an isolated *_test database")
	}
	productionDSN := strings.TrimSpace(os.Getenv("PAPERBOAT_DATABASE_DSN"))
	if productionDSN != "" && strings.TrimSpace(productionDSN) == dsn {
		t.Fatal("refusing to run preview-domain acceptance against PAPERBOAT_DATABASE_DSN")
	}

	ctx := context.Background()
	database, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := db.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	accountID := "usr_preview_domain_" + suffix
	otherAccountID := "usr_preview_domain_other_" + suffix
	for _, account := range []string{accountID, otherAccountID} {
		if _, err := database.SQL().ExecContext(ctx, `
INSERT INTO paperboat.users (id, workos_subject, primary_email, status)
VALUES ($1, $2, $3, 'active')`, account, "workos_"+account, account+"@example.test"); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = database.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.users WHERE id IN ($1, $2)`, accountID, otherAccountID)
	})

	var sequence atomic.Uint64
	idFactory := func(prefix string) (string, error) {
		return fmt.Sprintf("%s_%s_%d", prefix, suffix, sequence.Add(1)), nil
	}
	repository, err := previewdomain.NewSQLRepository(database, previewdomain.Config{
		NewID: idFactory,
		Now:   func() time.Time { return time.Now().UTC() },
	})
	if err != nil {
		t.Fatal(err)
	}
	store, err := previewtunnelstore.New(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ConfigurePreviewDomains(previewDomainBatchAdapter{repository: repository}); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	hostname := "alias-" + suffix + ".example.test"
	wildcard := "*.apps-" + suffix + ".example.test"
	created, err := store.CreatePreviewLeaseV1(ctx, previewtunnelstore.CreatePreviewLeaseV1Input{
		OperationID: "op_preview_domain_create_" + suffix, LeaseID: "prv_preview_domain_" + suffix,
		AuditEventID: "aud_preview_domain_create_" + suffix, AccountID: accountID,
		ActorID: accountID, ActorType: "user", OwnerDeviceID: "device_preview_domain_" + suffix,
		OwnerSessionID: "session_preview_domain_" + suffix, TargetScheme: "http", TargetAddress: "127.0.0.1:3000",
		AccessMode: "public", EndpointID: "endpoint_preview_domain_" + suffix,
		Endpoint: "https://preview-domain-" + suffix + ".preview.example.test", LeaseDeadline: now.Add(time.Hour),
		RequestHash: sha256Bytes("preview-domain-create:" + suffix), IdempotencyKey: "preview-domain-create:" + suffix,
		CorrelationID: "cor_preview_domain_create_" + suffix, RequestID: "req_preview_domain_create_" + suffix,
		SourceDeviceID: "device_preview_domain_" + suffix, Now: now,
		Domains: []previewtunnelstore.PreviewDomainCreateRequest{
			{Hostname: hostname, Provider: "generic", CertificateStrategy: "managed"},
			{Hostname: wildcard, Provider: "generic", CertificateStrategy: "managed"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.Lease.Generation != 1 || created.Operation.State != "running" {
		t.Fatalf("create lease = %#v", created)
	}
	assertPreviewDomainRows(t, database, ctx, created.Lease.ID, accountID, 2, 1, 2)

	renewed, err := store.RenewPreviewLeaseV1(ctx, previewtunnelstore.RenewPreviewLeaseV1Input{
		OperationID: "op_preview_domain_renew_" + suffix, AuditEventID: "aud_preview_domain_renew_" + suffix,
		AccountID: accountID, ActorID: accountID, ActorType: "user", PreviewID: created.Lease.ID,
		OwnerDeviceID: "device_preview_domain_" + suffix, OwnerSessionID: "session_preview_domain_" + suffix,
		ExpectedGeneration: 1, LeaseDeadline: now.Add(2 * time.Hour), RequestHash: sha256Bytes("preview-domain-renew:" + suffix),
		IdempotencyKey: "preview-domain-renew:" + suffix, CorrelationID: "cor_preview_domain_renew_" + suffix,
		RequestID: "req_preview_domain_renew_" + suffix, SourceDeviceID: "device_preview_domain_" + suffix,
		Now: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if renewed.Lease.Generation != 2 || renewed.Lease.TerminalState != "active" {
		t.Fatalf("renewed lease = %#v", renewed.Lease)
	}
	assertPreviewDomainRows(t, database, ctx, created.Lease.ID, accountID, 2, 2, 2)

	stopped, err := store.StopPreviewLeaseV1(ctx, previewtunnelstore.StopPreviewLeaseV1Input{
		OperationID: "op_preview_domain_stop_" + suffix, AuditEventID: "aud_preview_domain_stop_" + suffix,
		AccountID: accountID, ActorID: accountID, ActorType: "user", PreviewID: created.Lease.ID,
		OwnerDeviceID: "device_preview_domain_" + suffix, OwnerSessionID: "session_preview_domain_" + suffix,
		ExpectedGeneration: 2, RequestHash: sha256Bytes("preview-domain-stop:" + suffix),
		IdempotencyKey: "preview-domain-stop:" + suffix, CorrelationID: "cor_preview_domain_stop_" + suffix,
		RequestID: "req_preview_domain_stop_" + suffix, SourceDeviceID: "device_preview_domain_" + suffix,
		Now: now.Add(2 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if stopped.Lease.Generation != 3 || stopped.Lease.TerminalState != "stopped" {
		t.Fatalf("stopped lease = %#v", stopped.Lease)
	}
	assertWithdrawnPreviewDomains(t, database, ctx, created.Lease.ID, accountID, now.Add(2*time.Minute))

	// A different account cannot reclaim the hostname during quarantine. The
	// failed create is transactional, so it leaves no partial lease or alias.
	_, err = store.CreatePreviewLeaseV1(ctx, previewtunnelstore.CreatePreviewLeaseV1Input{
		OperationID: "op_preview_domain_other_" + suffix, LeaseID: "prv_preview_domain_other_" + suffix,
		AuditEventID: "aud_preview_domain_other_" + suffix, AccountID: otherAccountID,
		ActorID: otherAccountID, ActorType: "user", OwnerDeviceID: "device_other_" + suffix,
		OwnerSessionID: "session_other_" + suffix, TargetScheme: "http", TargetAddress: "127.0.0.1:3001",
		AccessMode: "public", EndpointID: "endpoint_other_" + suffix,
		Endpoint: "https://preview-other-" + suffix + ".preview.example.test", LeaseDeadline: now.Add(time.Hour),
		RequestHash: sha256Bytes("preview-domain-other:" + suffix), IdempotencyKey: "preview-domain-other:" + suffix,
		CorrelationID: "cor_preview_domain_other_" + suffix, RequestID: "req_preview_domain_other_" + suffix,
		SourceDeviceID: "device_other_" + suffix, Now: now.Add(3 * time.Minute),
		Domains: []previewtunnelstore.PreviewDomainCreateRequest{{Hostname: hostname, Provider: "generic", CertificateStrategy: "managed"}},
	})
	if !errors.Is(err, previewdomain.ErrDomainConflict) {
		t.Fatalf("cross-account quarantined hostname error = %v, want ErrDomainConflict", err)
	}

	// The original account may reuse a withdrawn hostname after the atomic
	// stop. The new live row gets a new ID and begins at its own generation.
	reused, err := store.CreatePreviewLeaseV1(ctx, previewtunnelstore.CreatePreviewLeaseV1Input{
		OperationID: "op_preview_domain_reuse_" + suffix, LeaseID: "prv_preview_domain_reuse_" + suffix,
		AuditEventID: "aud_preview_domain_reuse_" + suffix, AccountID: accountID,
		ActorID: accountID, ActorType: "user", OwnerDeviceID: "device_reuse_" + suffix,
		OwnerSessionID: "session_reuse_" + suffix, TargetScheme: "http", TargetAddress: "127.0.0.1:3002",
		AccessMode: "public", EndpointID: "endpoint_reuse_" + suffix,
		Endpoint: "https://preview-reuse-" + suffix + ".preview.example.test", LeaseDeadline: now.Add(time.Hour),
		RequestHash: sha256Bytes("preview-domain-reuse:" + suffix), IdempotencyKey: "preview-domain-reuse:" + suffix,
		CorrelationID: "cor_preview_domain_reuse_" + suffix, RequestID: "req_preview_domain_reuse_" + suffix,
		SourceDeviceID: "device_reuse_" + suffix, Now: now.Add(4 * time.Minute),
		Domains: []previewtunnelstore.PreviewDomainCreateRequest{{Hostname: hostname, Provider: "generic", CertificateStrategy: "managed"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if reused.Lease.Generation != 1 {
		t.Fatalf("reused lease generation = %d, want 1", reused.Lease.Generation)
	}
	assertPreviewDomainRows(t, database, ctx, reused.Lease.ID, accountID, 1, 1, 1)
}

type previewDomainBatchAdapter struct {
	repository *previewdomain.SQLRepository
}

func (a previewDomainBatchAdapter) CreateForPreviewTx(ctx context.Context, tx *db.Tx, input previewtunnelstore.PreviewDomainBatchInput) error {
	domains := make([]previewdomain.Request, len(input.Domains))
	for index, domain := range input.Domains {
		domains[index] = previewdomain.Request{Hostname: domain.Hostname, Provider: domain.Provider, CertificateStrategy: domain.CertificateStrategy}
	}
	_, err := a.repository.CreateForPreviewTx(ctx, tx, previewdomain.BatchCreateRequest{
		AccountID: input.AccountID, PreviewID: input.PreviewID, PreviewGeneration: input.PreviewGeneration,
		StableEndpoint: input.StableEndpoint, Domains: domains, ActorID: input.ActorID, ActorType: input.ActorType,
		RequestID: input.RequestID, CorrelationID: input.CorrelationID, Now: input.Now,
	})
	return err
}

func assertPreviewDomainRows(t *testing.T, database *db.DB, ctx context.Context, previewID, accountID string, wantCount int, wantGeneration int64, wantLive int) {
	t.Helper()
	var count, generation, live int
	if err := database.SQL().QueryRowContext(ctx, `
SELECT count(*), COALESCE(min(preview_generation), 0), count(*) FILTER (WHERE deleted_at IS NULL)
FROM paperboat.preview_domains WHERE preview_id=$1 AND account_id=$2`, previewID, accountID).Scan(&count, &generation, &live); err != nil {
		t.Fatal(err)
	}
	if count != wantCount || int64(generation) != wantGeneration || live != wantLive {
		t.Fatalf("preview domains count=%d generation=%d live=%d, want %d/%d/%d", count, generation, live, wantCount, wantGeneration, wantLive)
	}
}

func assertWithdrawnPreviewDomains(t *testing.T, database *db.DB, ctx context.Context, previewID, accountID string, now time.Time) {
	t.Helper()
	var count, withdrawn, expired, revoked, quarantined int
	var quarantineFuture bool
	if err := database.SQL().QueryRowContext(ctx, `
	SELECT count(*), count(*) FILTER (WHERE deleted_at IS NOT NULL),
	       count(*) FILTER (WHERE ownership_state='expired'),
	       count(*) FILTER (WHERE certificate_state='revoked'),
	       count(*) FILTER (WHERE conflict_state='quarantined'),
	       COALESCE(bool_and(quarantine_until > $3), false)
FROM paperboat.preview_domains WHERE preview_id=$1 AND account_id=$2`, previewID, accountID, now).Scan(&count, &withdrawn, &expired, &revoked, &quarantined, &quarantineFuture); err != nil {
		t.Fatal(err)
	}
	if count != 2 || withdrawn != 2 || expired != 2 || revoked != 2 || quarantined != 2 || !quarantineFuture {
		t.Fatalf("withdrawn preview domains count=%d deleted=%d expired=%d revoked_certificates=%d quarantined=%d future=%v", count, withdrawn, expired, revoked, quarantined, quarantineFuture)
	}
}

func sha256Bytes(value string) []byte {
	hash := sha256.Sum256([]byte(value))
	return hash[:]
}
