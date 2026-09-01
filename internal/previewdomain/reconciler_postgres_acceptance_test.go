package previewdomain_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/previewdomain"
	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelstore"
	"github.com/pinksaucepasta/paperboat-server/internal/tunnelv1"
)

// TestPreviewDomainDNSReconcilerOnPostgres exercises the real generation and
// operation fences with an injected authoritative resolver. It is opt-in so
// normal unit runs never require a local database.
func TestPreviewDomainDNSReconcilerOnPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_DATABASE_DSN"))
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run preview-domain DNS reconciliation acceptance")
	}
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(dsn), "_test") {
		t.Fatal("PAPERBOAT_TEST_DATABASE_DSN must name an isolated *_test database")
	}
	productionDSN := strings.TrimSpace(os.Getenv("PAPERBOAT_DATABASE_DSN"))
	if productionDSN != "" && productionDSN == dsn {
		t.Fatal("refusing to run preview-domain DNS reconciliation against PAPERBOAT_DATABASE_DSN")
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
	accountID := "usr_preview_dns_reconciler_" + suffix
	if _, err := database.SQL().ExecContext(ctx, `
INSERT INTO paperboat.users (id, workos_subject, primary_email, status)
VALUES ($1, $2, $3, 'active')`, accountID, "workos_"+accountID, accountID+"@example.test"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = database.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.users WHERE id = $1`, accountID)
	})

	now := time.Now().UTC().Truncate(time.Microsecond)
	leaseID := "prv_preview_dns_reconciler_" + suffix
	store, err := previewtunnelstore.New(database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreatePreviewLeaseV1(ctx, previewtunnelstore.CreatePreviewLeaseV1Input{
		OperationID: "op_preview_dns_lease_" + suffix, LeaseID: leaseID,
		AuditEventID: "aud_preview_dns_lease_" + suffix, AccountID: accountID,
		ActorID: accountID, ActorType: "user", OwnerDeviceID: "device_preview_dns_" + suffix,
		OwnerSessionID: "session_preview_dns_" + suffix, TargetScheme: "http", TargetAddress: "127.0.0.1:4100",
		AccessMode: "public", EndpointID: "endpoint_preview_dns_" + suffix,
		Endpoint: "https://preview-dns-" + suffix + ".preview.example.test", LeaseDeadline: now.Add(time.Hour),
		RequestHash: hashBytes("lease:" + suffix), IdempotencyKey: "preview-dns-lease:" + suffix,
		CorrelationID: "cor_preview_dns_lease_" + suffix, RequestID: "req_preview_dns_lease_" + suffix,
		SourceDeviceID: "device_preview_dns_" + suffix, Now: now,
	}); err != nil {
		t.Fatal(err)
	}

	repository, err := previewdomain.NewSQLRepository(database, previewdomain.Config{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	hostname := "alias-" + suffix + ".example.test"
	target := "preview-dns-" + suffix + ".preview.example.test"
	expected := []byte(`[{"name":"` + hostname + `","type":"CNAME","value":"` + target + `","ttl":300}]`)
	created, err := repository.Create(ctx, previewdomain.CreateRecord{
		OperationID: "op_preview_dns_create_" + suffix, AuditEventID: "aud_preview_dns_create_" + suffix,
		AccountID: accountID, PreviewID: leaseID, DomainID: "pdom_preview_dns_" + suffix, PreviewGeneration: 1,
		Hostname: hostname, MatchType: "exact", ChallengeReference: "dns-challenge://preview-" + suffix,
		DNSTarget: target, DNSProvider: "generic", ExpectedRecords: expected, CertificateStrategy: "managed",
		IdempotencyKey: "preview-dns-create:" + suffix, RequestHash: hashArray("domain-create:" + suffix),
		ActorID: accountID, ActorType: "user", RequestID: "req_preview_dns_create_" + suffix,
		CorrelationID: "cor_preview_dns_create_" + suffix, SourceDeviceID: "device_preview_dns_" + suffix, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	verifiedRequestHash := hashArray("domain-verify:" + suffix)
	verified, err := repository.Verify(ctx, previewdomain.MutationRecord{
		OperationID: "op_preview_dns_verify_" + suffix, AuditEventID: "aud_preview_dns_verify_" + suffix,
		AccountID: accountID, PreviewID: leaseID, DomainID: created.Domain.ID, ExpectedGeneration: created.Domain.Generation,
		IdempotencyKey: "preview-dns-verify:" + suffix, RequestHash: verifiedRequestHash, ActorID: accountID,
		ActorType: "user", RequestID: "req_preview_dns_verify_" + suffix, CorrelationID: "cor_preview_dns_verify_" + suffix,
		SourceDeviceID: "device_preview_dns_" + suffix, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if verified.Domain.Generation != created.Domain.Generation+1 {
		t.Fatalf("verification generation = %d, want %d", verified.Domain.Generation, created.Domain.Generation+1)
	}

	resolver := postgresAuthoritativeResolver{target: target}
	reconciler, err := previewdomain.NewDNSReconciler(repository, resolver, previewdomain.ReconcilerConfig{Now: func() time.Time { return now.Add(time.Second) }})
	if err != nil {
		t.Fatal(err)
	}
	if processed, err := reconciler.Reconcile(ctx, 10); err != nil || processed != 1 {
		t.Fatalf("authoritative reconcile = %d, %v", processed, err)
	}

	verifyOperation, err := database.Queries().GetPreviewTunnelOperationByIdempotency(ctx, dbsqlc.GetPreviewTunnelOperationByIdempotencyParams{AccountID: accountID, IdempotencyKey: "preview-dns-verify:" + suffix})
	if err != nil {
		t.Fatal(err)
	}
	if verifyOperation.State != "succeeded" || verifyOperation.Phase != "ready" || verifyOperation.Progress != 100 {
		t.Fatalf("verify operation = %#v, want succeeded/ready", verifyOperation)
	}
	createOperation, err := database.Queries().GetPreviewTunnelOperationByIdempotency(ctx, dbsqlc.GetPreviewTunnelOperationByIdempotencyParams{AccountID: accountID, IdempotencyKey: "preview-dns-create:" + suffix})
	if err != nil {
		t.Fatal(err)
	}
	if createOperation.State != "running" || createOperation.Phase != "issuing_certificate" || createOperation.Progress < 60 || createOperation.CompletedAt.Valid {
		t.Fatalf("create operation = %#v, want issuing and incomplete", createOperation)
	}

	current, err := repository.Get(ctx, accountID, leaseID, created.Domain.ID)
	if err != nil {
		t.Fatal(err)
	}
	staleObservation := previewdomain.DNSReconciliationObservation{
		DomainID: current.ID, AccountID: accountID, PreviewID: leaseID, PreviewGeneration: 1,
		ExpectedGeneration: verified.Domain.Generation, ObservedRecords: expected, OwnershipState: "verified",
		ConflictState: "clear", NextCheckAt: now.Add(10 * time.Minute), TTLSeconds: 300, Verified: true, Now: now.Add(2 * time.Second),
	}
	if _, err := repository.ApplyDNSObservationForReconciliation(ctx, staleObservation); !errors.Is(err, previewdomain.ErrGenerationConflict) {
		t.Fatalf("renewal-stale observation error = %v, want ErrGenerationConflict", err)
	}

	if _, err := store.RenewPreviewLeaseV1(ctx, previewtunnelstore.RenewPreviewLeaseV1Input{
		OperationID: "op_preview_dns_renew_" + suffix, AuditEventID: "aud_preview_dns_renew_" + suffix,
		AccountID: accountID, ActorID: accountID, ActorType: "user", PreviewID: leaseID,
		OwnerDeviceID: "device_preview_dns_" + suffix, OwnerSessionID: "session_preview_dns_" + suffix,
		ExpectedGeneration: 1, LeaseDeadline: now.Add(2 * time.Hour), RequestHash: hashBytes("renew:" + suffix),
		IdempotencyKey: "preview-dns-renew:" + suffix, CorrelationID: "cor_preview_dns_renew_" + suffix,
		RequestID: "req_preview_dns_renew_" + suffix, SourceDeviceID: "device_preview_dns_" + suffix, Now: now.Add(3 * time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	postRenew, err := repository.Get(ctx, accountID, leaseID, created.Domain.ID)
	if err != nil {
		t.Fatal(err)
	}
	terminalObservation := staleObservation
	terminalObservation.PreviewGeneration = 2
	terminalObservation.ExpectedGeneration = postRenew.Generation
	terminalObservation.Now = now.Add(4 * time.Second)
	if _, err := store.StopPreviewLeaseV1(ctx, previewtunnelstore.StopPreviewLeaseV1Input{
		OperationID: "op_preview_dns_stop_" + suffix, AuditEventID: "aud_preview_dns_stop_" + suffix,
		AccountID: accountID, ActorID: accountID, ActorType: "user", PreviewID: leaseID,
		OwnerDeviceID: "device_preview_dns_" + suffix, OwnerSessionID: "session_preview_dns_" + suffix,
		ExpectedGeneration: 2, RequestHash: hashBytes("stop:" + suffix), IdempotencyKey: "preview-dns-stop:" + suffix,
		CorrelationID: "cor_preview_dns_stop_" + suffix, RequestID: "req_preview_dns_stop_" + suffix,
		SourceDeviceID: "device_preview_dns_" + suffix, Now: now.Add(5 * time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.ApplyDNSObservationForReconciliation(ctx, terminalObservation); !errors.Is(err, previewdomain.ErrGenerationConflict) {
		t.Fatalf("terminal observation error = %v, want ErrGenerationConflict", err)
	}
}

type postgresAuthoritativeResolver struct {
	target string
}

func (r postgresAuthoritativeResolver) Observe(ctx context.Context, hostname, recordType, target, challenge string) (tunnelv1.DNSObservation, error) {
	if err := ctx.Err(); err != nil {
		return tunnelv1.DNSObservation{}, err
	}
	if hostname == "" || recordType != "CNAME" || target != r.target || challenge == "" {
		return tunnelv1.DNSObservation{FailureCode: "wrong_record"}, nil
	}
	return tunnelv1.DNSObservation{Records: []string{"CNAME " + r.target}, TTL: 5 * time.Minute}, nil
}

func hashBytes(value string) []byte {
	hash := sha256.Sum256([]byte(value))
	return hash[:]
}

func hashArray(value string) [sha256.Size]byte {
	return sha256.Sum256([]byte(value))
}
