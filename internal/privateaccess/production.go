package privateaccess

import (
	"fmt"

	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/mint"
)

// Production is the concrete private-access composition used by the server.
// It shares the canonical attachment repository with preview readiness and
// the existing edge verifier, while the grant issuer remains ephemeral and
// signs only short-lived route-bound claims.
type Production struct {
	Resolver       *SQLResolver
	GrantIssuer    *MintGrantIssuer
	MachineState   *SQLMachineStateVerifier
	Service        *Service
	AuthorizeHTTP  *HTTPHandler
	GrantIssueHTTP *GrantHTTPHandler
	AccessorRoutes *AccessorHTTPHandler
}

func NewProduction(database *db.DB, attachments AttachmentStore, provider *mint.Provider, issuer string, machine MachineRequestVerifier, edge EdgeVerifier, auditSink AuditSink) (*Production, error) {
	if database == nil || attachments == nil || provider == nil || machine == nil || edge == nil || auditSink == nil {
		return nil, fmt.Errorf("%w: private access production dependencies are incomplete", ErrInvalid)
	}
	resolver, err := NewSQLResolver(database, attachments)
	if err != nil {
		return nil, err
	}
	grantIssuer, err := NewMintGrantIssuer(provider, issuer)
	if err != nil {
		return nil, err
	}
	machineState, err := NewSQLMachineStateVerifier(database)
	if err != nil {
		return nil, err
	}
	service, err := NewService(resolver, auditSink, Config{
		GrantVerifier: grantIssuer,
		GrantMinter:   grantIssuer,
		MachineState:  machineState,
	})
	if err != nil {
		return nil, err
	}
	authorizeHTTP, err := NewHTTPHandler(service, edge)
	if err != nil {
		return nil, err
	}
	grantIssueHTTP, err := NewGrantHTTPHandler(service, machine)
	if err != nil {
		return nil, err
	}
	accessorRepository, err := NewAccessorRepository(database)
	if err != nil {
		return nil, err
	}
	accessorRoutes, err := NewAccessorHTTPHandler(accessorRepository, machine, edge)
	if err != nil {
		return nil, err
	}
	return &Production{
		Resolver: resolver, GrantIssuer: grantIssuer,
		MachineState: machineState, Service: service, AuthorizeHTTP: authorizeHTTP,
		GrantIssueHTTP: grantIssueHTTP, AccessorRoutes: accessorRoutes,
	}, nil
}
