package previewattachment

import (
	"context"
	"encoding/hex"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"strings"
	"time"
)

// LazyActivationFixture exposes the established attachment SQL fixture only to
// external tests, avoiding the previewv1/previewdomain production import cycle.
type LazyActivationFixture struct {
	AccountID, MachineID, EnvironmentID, NodeID, Epoch, Suffix string
	fixture                                                    previewCarrierPostgresFixture
}

func NewLazyActivationFixture(ctx context.Context, database *db.DB, suffix string) (LazyActivationFixture, error) {
	f := previewCarrierPostgresFixture{suffix: suffix}
	if err := f.insert(ctx, database, time.Now().UTC()); err != nil {
		return LazyActivationFixture{}, err
	}
	return LazyActivationFixture{AccountID: f.accountID, MachineID: f.machineID, EnvironmentID: f.envID, NodeID: f.nodeID, Epoch: f.epochOne, Suffix: f.suffix, fixture: f}, nil
}
func (f LazyActivationFixture) Attachment(previewID, operationID, sessionID string) Attachment {
	current := f.fixture
	current.previewID[0], current.operation[0], current.sessionID = previewID, operationID, sessionID
	current.suffix += "_" + previewID
	return current.attachment(1, current.epochOne)
}

// ApplyLazyReadyFixture publishes the already-qualified remote observation in
// one SQL round trip. This avoids charging WAN fixture setup to the production
// activation deadline; real attachment admission has separate live SQL coverage.
func ApplyLazyReadyFixture(ctx context.Context, database *db.DB, a Attachment) error {
	if err := a.Validate(time.Time{}); err != nil {
		return err
	}
	hash, err := hex.DecodeString(a.RequestHash)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	insert := strings.Replace(insertAttachmentSQL, "issued_at, expires_at, created_at, updated_at", "issued_at, expires_at, created_at, updated_at, ready_at", 1)
	insert = strings.Replace(insert, "1,'pending',false,false,$27,$28,$29,$30)", "1,'ready',true,true,$27,$28,$29,$30,$29)", 1)
	query := `WITH ready AS (UPDATE preview_leases SET allocation_state='ready',edge_state='ready',origin_state='ready',ready_at=now(),generation=generation+1 WHERE id=$2 AND terminal_state='active' RETURNING id) ` + insert
	_, err = database.Pool().Exec(ctx, query,
		a.AccountID, a.PreviewID, a.OperationID, a.IdempotencyKey, a.RequestID, a.CorrelationID, hash,
		a.OwnerDeviceID, a.OwnerSessionID, a.HostID, a.EdgeNodeID, a.MachineIdentityPublicKey, a.MachineIdentityThumbprint,
		a.LeaseGeneration+1, a.TunnelID, a.ConnectorID, a.SessionID, a.ProcessGeneration, a.ConfigGeneration, a.ConfigContentHash,
		a.RouteID, a.RouteGeneration, a.EdgeEndpoints, a.EdgeProcessEpoch, a.EdgeCarrierServerSPKISHA256, a.EdgeCarrierServerCertificateChainPEM,
		a.IssuedAt.UTC(), a.ExpiresAt.UTC(), now, now)
	return err
}
