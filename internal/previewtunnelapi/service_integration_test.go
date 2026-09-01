package previewtunnelapi

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelstore"
)

func TestPreviewTunnelCommonAPIOnPostgres(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run Postgres integration tests")
	}
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
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
	store, err := previewtunnelstore.New(database)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(store, []byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	accountID := "usr_trk04_" + suffix
	otherAccountID := "usr_trk04_other_" + suffix
	for _, user := range []string{accountID, otherAccountID} {
		if _, err := database.SQL().ExecContext(ctx, `
INSERT INTO paperboat.users (id, workos_subject, primary_email, status)
VALUES ($1, $2, $3, 'active')`, user, "workos_"+user, user+"@example.test"); err != nil {
			t.Fatal(err)
		}
	}

	requestHash := sha256.Sum256([]byte("operation:" + suffix))
	now := time.Now().UTC()
	operation, err := database.Queries().CreatePreviewTunnelOperation(ctx, dbsqlc.CreatePreviewTunnelOperationParams{
		ID: "op_pending_" + suffix, AccountID: accountID, IdempotencyKey: "pending:" + suffix,
		RequestHash: requestHash[:], OperationType: "tunnel.create", ResourceKind: "tunnel",
		ResourceID: sql.NullString{String: "tun_" + suffix, Valid: true}, Phase: "validating",
		State: "pending", Progress: 0, Outcome: "unchanged", CorrelationID: "corr_" + suffix,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := RequestContext{
		Actor:     Actor{AccountID: accountID, ActorID: accountID, DeviceID: "dev_" + suffix, Role: "user", Scopes: []string{"operations:read", "operations:write", "tunnels:read"}},
		RequestID: "req_" + suffix, CorrelationID: "corr_" + suffix,
	}
	got, err := service.GetOperation(ctx, request, operation.ID)
	if err != nil || got.ID != operation.ID || got.State != "pending" {
		t.Fatalf("GetOperation = %#v, %v", got, err)
	}
	cancelled, err := service.CancelOperation(ctx, request, operation.ID)
	if err != nil || cancelled.State != "canceled" {
		t.Fatalf("CancelOperation = %#v, %v", cancelled, err)
	}
	replayed, err := service.CancelOperation(ctx, request, operation.ID)
	if err != nil || replayed.State != "canceled" {
		t.Fatalf("idempotent CancelOperation = %#v, %v", replayed, err)
	}
	other := request
	other.Actor.AccountID = otherAccountID
	other.Actor.ActorID = otherAccountID
	if _, err := service.GetOperation(ctx, other, operation.ID); !errors.Is(err, previewtunnelstore.ErrNotFound) {
		t.Fatalf("cross-account operation error = %v", err)
	}

	runningHash := sha256.Sum256([]byte("running:" + suffix))
	running, err := database.Queries().CreatePreviewTunnelOperation(ctx, dbsqlc.CreatePreviewTunnelOperationParams{
		ID: "op_running_" + suffix, AccountID: accountID, IdempotencyKey: "running:" + suffix,
		RequestHash: runningHash[:], OperationType: "tunnel.create", ResourceKind: "tunnel",
		ResourceID: sql.NullString{String: "tun_" + suffix, Valid: true}, Phase: "connecting",
		State: "running", Progress: 60, Outcome: "uncertain", CorrelationID: "corr_running_" + suffix,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CancelOperation(ctx, request, running.ID); !errors.Is(err, ErrOperationNotCancellable) {
		t.Fatalf("running cancellation error = %v", err)
	}

	resourceID := "tun_events_" + suffix
	for index := 1; index <= 3; index++ {
		metadata := []byte(fmt.Sprintf(`{"generation":%d,"credential_reference":"vault://connector/%d"}`, index, index))
		if _, err := database.Queries().InsertPreviewTunnelAuditEvent(ctx, dbsqlc.InsertPreviewTunnelAuditEventParams{
			ID: fmt.Sprintf("aud_event_%d_%s", index, suffix), AccountID: sql.NullString{String: accountID, Valid: true},
			ActorID: sql.NullString{String: accountID, Valid: true}, ActorUserID: sql.NullString{String: accountID, Valid: true},
			ActorType: "user", EventType: "tunnel.updated", ChangeType: "update", Outcome: "changed",
			ResourceType: "tunnel", ResourceID: resourceID, IdempotencyKey: sql.NullString{String: fmt.Sprintf("event:%d:%s", index, suffix), Valid: true},
			RequestID:      sql.NullString{String: fmt.Sprintf("req_%d_%s", index, suffix), Valid: true},
			CorrelationID:  sql.NullString{String: fmt.Sprintf("corr_%d_%s", index, suffix), Valid: true},
			SourceDeviceID: sql.NullString{String: "dev_" + suffix, Valid: true}, Metadata: metadata,
			CreatedAt: now.Add(time.Duration(index) * time.Second),
		}); err != nil {
			t.Fatal(err)
		}
	}
	page1, err := service.ListEvents(ctx, request, "tunnel", resourceID, "", 2)
	if err != nil || len(page1.Items) != 2 || page1.NextCursor == "" {
		t.Fatalf("first event page = %#v, %v", page1, err)
	}
	page2, err := service.ListEvents(ctx, request, "tunnel", resourceID, page1.NextCursor, 2)
	if err != nil || len(page2.Items) != 1 || page2.NextCursor != "" || page2.Items[0].ID == page1.Items[1].ID {
		t.Fatalf("resumed event page = %#v, %v", page2, err)
	}
	if _, err := service.ListEvents(ctx, request, "tunnel", "other", page1.NextCursor, 2); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("cross-resource cursor error = %v", err)
	}

	if _, err := database.Queries().InsertPreviewTunnelAuditEvent(ctx, dbsqlc.InsertPreviewTunnelAuditEventParams{
		ID: "aud_unsafe_" + suffix, AccountID: sql.NullString{String: accountID, Valid: true},
		ActorID: sql.NullString{String: accountID, Valid: true}, ActorUserID: sql.NullString{String: accountID, Valid: true},
		ActorType: "user", EventType: "tunnel.updated", ChangeType: "update", Outcome: "changed",
		ResourceType: "tunnel", ResourceID: "tun_unsafe_" + suffix,
		CorrelationID: sql.NullString{String: "corr_unsafe_" + suffix, Valid: true}, Metadata: []byte(`{"access_token":"must-not-leak"}`), CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ListEvents(ctx, request, "tunnel", "tun_unsafe_"+suffix, "", 10); !errors.Is(err, ErrUnsafeMetadata) {
		t.Fatalf("unsafe persisted event error = %v", err)
	}
}
