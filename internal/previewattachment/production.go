package previewattachment

import (
	"fmt"

	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

// Production is the complete server-side composition for preview carrier
// attachment. It intentionally exposes the concrete seams so app wiring can
// pass the same service to the machine-proof HTTP handler and the trusted edge
// observation adapter.
type Production struct {
	Repository       *SQLRepository
	LeaseResolver    *DBPreviewLeaseResolver
	CarrierAllocator *EphemeralCarrierAllocator
	Authority        ServerAuthority
	Service          *Service
}

// NewProduction wires durable lease lookup, preview-ephemeral carrier issue,
// SQL attachment persistence, and the durable pull/ACK edge boundary. The
// optional issuer exists for deterministic tests or a future carrier runtime;
// production uses the concrete DB issuer. The publisher is always the SQL
// outbox publisher: it reports retryable until an authenticated edge ACK, so
// the server never fabricates admission from a queue insert.
func NewProduction(database *db.DB, issuers ...PreviewCarrierIssuer) (*Production, error) {
	if database == nil || len(issuers) > 1 {
		return nil, fmt.Errorf("%w: preview attachment production dependencies are incomplete", ErrInvalid)
	}
	var issuer PreviewCarrierIssuer
	if len(issuers) == 1 {
		issuer = issuers[0]
	}
	if issuer == nil {
		var err error
		issuer, err = NewDBPreviewCarrierIssuer(database)
		if err != nil {
			return nil, err
		}
	}
	repository, err := NewSQLRepository(database)
	if err != nil {
		return nil, err
	}
	publisher, err := NewOutboxAdmissionPublisher(repository)
	if err != nil {
		return nil, err
	}
	leaseResolver, err := NewDBPreviewLeaseResolver(database)
	if err != nil {
		return nil, err
	}
	edgeNodeSelector, err := NewDBPreviewEdgeNodeSelector(database)
	if err != nil {
		return nil, err
	}
	carrierAllocator, err := NewEphemeralCarrierAllocator(issuer, edgeNodeSelector)
	if err != nil {
		return nil, err
	}
	authority := ServerAuthority{Leases: leaseResolver, Carriers: carrierAllocator}
	service, err := NewService(repository, authority, publisher)
	if err != nil {
		return nil, err
	}
	return &Production{
		Repository: repository, LeaseResolver: leaseResolver,
		CarrierAllocator: carrierAllocator, Authority: authority, Service: service,
	}, nil
}
