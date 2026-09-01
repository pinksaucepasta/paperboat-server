package tunnelv1

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelapi"
)

// fakeResourceRepository keeps service policy tests independent from
// PostgreSQL. Repository integration tests cover the SQL transaction and
// constraints; this fake makes the HTTP-facing invariants deterministic.
type fakeResourceRepository struct {
	verifyErr error

	listRoutes        []dbsqlc.TunnelRoute
	listRoutesErr     error
	listRoutesAccount string
	listRoutesTunnel  string
	listRoutesAfter   *ListPosition
	listRoutesLimit   int
	route             dbsqlc.TunnelRoute
	getRouteErr       error
	createRoute       RouteRecord
	createRouteResult ResourceMutationRecord
	createRouteErr    error
	patchRoute        RouteRecord
	patchRouteResult  ResourceMutationRecord
	patchRouteErr     error
	deleteRouteResult ResourceMutationRecord
	deleteRouteErr    error

	listDomains        []dbsqlc.TunnelDomain
	listDomainsErr     error
	domain             dbsqlc.TunnelDomain
	getDomainErr       error
	createDomain       DomainRecord
	createDomainResult ResourceMutationRecord
	createDomainErr    error
	deleteDomainResult ResourceMutationRecord
	deleteDomainErr    error
	verifyDomainResult ResourceMutationRecord
	verifyDomainErr    error

	listConnectors      []dbsqlc.TunnelConnector
	listConnectorsErr   error
	listConnectorsAfter *ListPosition
	listConnectorsLimit int
	connector           dbsqlc.TunnelConnector
	getConnectorErr     error
	enrollmentResult    EnrollmentRecord
	enrollmentErr       error
	enrollmentInput     EnrollmentRecordInput
	exchangeResult      ResourceMutationRecord
	exchangeErr         error
	exchangeInput       EnrollmentExchangeRecord
	drainResult         ResourceMutationRecord
	drainErr            error
	revokeResult        ResourceMutationRecord
	revokeErr           error
	rotationResult      dbsqlc.Operation
	rotationErr         error
	rotationInput       RotationRecord

	tunnelLogs     []dbsqlc.ListTunnelLogsV1Row
	tunnelLogsErr  error
	previewLogs    []dbsqlc.TunnelLogEntry
	previewLogsErr error
	lastLogAccount string
	lastLogScope   string
	lastLogAfter   int64
	lastLogLimit   int
}

func (f *fakeResourceRepository) VerifyHost(context.Context, string, string) error {
	return f.verifyErr
}

func (f *fakeResourceRepository) ListResourceRoutes(_ context.Context, accountID, tunnelID string, after *ListPosition, limit int) ([]dbsqlc.TunnelRoute, error) {
	f.listRoutesAccount, f.listRoutesTunnel, f.listRoutesAfter, f.listRoutesLimit = accountID, tunnelID, after, limit
	return f.listRoutes, f.listRoutesErr
}

func (f *fakeResourceRepository) GetResourceRoute(context.Context, string, string, string) (dbsqlc.TunnelRoute, error) {
	return f.route, f.getRouteErr
}

func (f *fakeResourceRepository) CreateResourceRoute(_ context.Context, input RouteRecord) (ResourceMutationRecord, error) {
	f.createRoute = input
	if f.createRouteResult.Route.ID == "" {
		f.createRouteResult = ResourceMutationRecord{Route: resourceRoute("rte_1", "private_tcp", "catch_all"), Operation: resourceOperation("op_1", "rte_1", "connecting", "running", "changed"), Changed: true}
	}
	return f.createRouteResult, f.createRouteErr
}

func (f *fakeResourceRepository) PatchResourceRoute(_ context.Context, input RouteRecord) (ResourceMutationRecord, error) {
	f.patchRoute = input
	if f.patchRouteResult.Route.ID == "" {
		f.patchRouteResult = ResourceMutationRecord{Route: resourceRoute("rte_1", "http", "managed"), Operation: resourceOperation("op_1", "rte_1", "connecting", "running", "changed"), Changed: true}
	}
	return f.patchRouteResult, f.patchRouteErr
}

func (f *fakeResourceRepository) DeleteResourceRoute(context.Context, RouteRecord) (ResourceMutationRecord, error) {
	if f.deleteRouteResult.Route.ID == "" {
		f.deleteRouteResult = ResourceMutationRecord{Route: resourceRoute("rte_1", "http", "managed"), Operation: resourceOperation("op_1", "rte_1", "draining", "running", "changed"), Changed: true}
	}
	return f.deleteRouteResult, f.deleteRouteErr
}

func (f *fakeResourceRepository) ListResourceDomains(context.Context, string, string, *ListPosition, int) ([]dbsqlc.TunnelDomain, error) {
	return f.listDomains, f.listDomainsErr
}

func (f *fakeResourceRepository) GetResourceDomain(context.Context, string, string, string) (dbsqlc.TunnelDomain, error) {
	return f.domain, f.getDomainErr
}

func (f *fakeResourceRepository) CreateResourceDomain(_ context.Context, input DomainRecord) (ResourceMutationRecord, error) {
	f.createDomain = input
	if f.createDomainResult.Domain.ID == "" {
		f.createDomainResult = ResourceMutationRecord{Domain: resourceDomain("dom_1", "foo.example.test", "verified", "clear"), Operation: resourceOperation("op_1", "dom_1", "connecting", "running", "changed"), Changed: true}
	}
	return f.createDomainResult, f.createDomainErr
}

func (f *fakeResourceRepository) DeleteResourceDomain(context.Context, DomainRecord) (ResourceMutationRecord, error) {
	if f.deleteDomainResult.Domain.ID == "" {
		f.deleteDomainResult = ResourceMutationRecord{Domain: resourceDomain("dom_1", "foo.example.test", "revoked", "quarantined"), Operation: resourceOperation("op_1", "dom_1", "draining", "running", "changed"), Changed: true}
	}
	return f.deleteDomainResult, f.deleteDomainErr
}

func (f *fakeResourceRepository) BeginResourceDomainVerification(context.Context, DomainRecord) (ResourceMutationRecord, error) {
	if f.verifyDomainResult.Domain.ID == "" {
		f.verifyDomainResult = ResourceMutationRecord{Domain: resourceDomain("dom_1", "foo.example.test", "pending", "clear"), Operation: resourceOperation("op_1", "dom_1", "waiting_dns", "running", "changed"), Changed: true}
	}
	return f.verifyDomainResult, f.verifyDomainErr
}

func (f *fakeResourceRepository) ListResourceConnectors(_ context.Context, _ string, _ string, after *ListPosition, limit int) ([]dbsqlc.TunnelConnector, error) {
	f.listConnectorsAfter, f.listConnectorsLimit = after, limit
	return f.listConnectors, f.listConnectorsErr
}

func (f *fakeResourceRepository) GetResourceConnector(context.Context, string, string, string) (dbsqlc.TunnelConnector, error) {
	return f.connector, f.getConnectorErr
}

func (f *fakeResourceRepository) IssueConnectorEnrollment(_ context.Context, input EnrollmentRecordInput) (EnrollmentRecord, error) {
	f.enrollmentInput = input
	if f.enrollmentResult.Enrollment.ID == "" {
		f.enrollmentResult = EnrollmentRecord{Enrollment: dbsqlc.TunnelConnectorEnrollment{ID: input.EnrollmentID, AccountID: input.AccountID, TunnelID: input.TunnelID, HostID: input.HostID, Capabilities: input.Capabilities, ExpiresAt: input.ExpiresAt}, Operation: resourceOperation(input.OperationID, input.EnrollmentID, "ready", "succeeded", "changed"), Token: input.Token}
	}
	return f.enrollmentResult, f.enrollmentErr
}

func (f *fakeResourceRepository) ExchangeConnectorEnrollment(_ context.Context, input EnrollmentExchangeRecord) (ResourceMutationRecord, error) {
	f.exchangeInput = input
	if f.exchangeResult.Connector.ID == "" {
		connector := resourceConnector("con_1")
		connector.RotationGeneration = 1
		f.exchangeResult = ResourceMutationRecord{Connector: connector, Operation: resourceOperation(input.OperationID, "con_1", "connecting", "running", "changed"), StableEndpointID: "11111111-1111-4111-8111-111111111111", ProcessGeneration: 1, Changed: true}
	}
	return f.exchangeResult, f.exchangeErr
}

func (f *fakeResourceRepository) DrainResourceConnector(context.Context, ConnectorRecord) (ResourceMutationRecord, error) {
	if f.drainResult.Connector.ID == "" {
		f.drainResult = ResourceMutationRecord{Connector: resourceConnector("con_1"), Operation: resourceOperation("op_1", "con_1", "draining", "running", "changed"), Changed: true}
	}
	return f.drainResult, f.drainErr
}

func (f *fakeResourceRepository) RevokeResourceConnector(context.Context, ConnectorRecord) (ResourceMutationRecord, error) {
	if f.revokeResult.Connector.ID == "" {
		f.revokeResult = ResourceMutationRecord{Connector: resourceConnector("con_1"), Operation: resourceOperation("op_1", "con_1", "draining", "running", "changed"), Changed: true}
	}
	return f.revokeResult, f.revokeErr
}

func (f *fakeResourceRepository) RotateResourceCredentials(_ context.Context, input RotationRecord) (dbsqlc.Operation, error) {
	f.rotationInput = input
	if f.rotationResult.ID == "" {
		f.rotationResult = resourceOperation(input.OperationID, input.TunnelID, "connecting", "running", "changed")
		f.rotationResult.ResourceKind = "tunnel"
	}
	return f.rotationResult, f.rotationErr
}

func (f *fakeResourceRepository) ListResourceTunnelLogs(_ context.Context, accountID, scopeID string, after int64, limit int) ([]dbsqlc.ListTunnelLogsV1Row, error) {
	f.lastLogAccount, f.lastLogScope, f.lastLogAfter, f.lastLogLimit = accountID, scopeID, after, limit
	return f.tunnelLogs, f.tunnelLogsErr
}

func (f *fakeResourceRepository) ListResourcePreviewLogs(_ context.Context, accountID, scopeID string, after int64, limit int) ([]dbsqlc.TunnelLogEntry, error) {
	f.lastLogAccount, f.lastLogScope, f.lastLogAfter, f.lastLogLimit = accountID, scopeID, after, limit
	return f.previewLogs, f.previewLogsErr
}

func resourceServiceForTest(t *testing.T, repo *fakeResourceRepository, overlap time.Duration) *ResourceService {
	t.Helper()
	if overlap == 0 {
		overlap = 10 * time.Minute
	}
	service, err := NewResourceService(repo, ResourceConfig{
		CursorKey:          bytes.Repeat([]byte{9}, 32),
		Now:                func() time.Time { return testNow },
		NewID:              sequentialID(),
		EnrollmentTTL:      5 * time.Minute,
		RotationOverlap:    overlap,
		CredentialLifetime: 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func resourceRoute(id, protocol, matchType string) dbsqlc.TunnelRoute {
	route := dbsqlc.TunnelRoute{ID: id, TunnelID: "tun_1", Name: "route", Protocol: protocol, MatchType: matchType, OriginScheme: "http", OriginAddress: "127.0.0.1:3000", PreserveHost: true,
		TlsVerification: "not_applicable", ConnectTimeoutMs: 10000, IdleTimeoutMs: 90000, MaxConcurrentStreams: 128, DesiredState: "active", Generation: 2, CreatedAt: testNow.Add(-time.Minute), UpdatedAt: testNow}
	if matchType == "managed" {
		route.MatchHostname = sql.NullString{String: "foo.example.test", Valid: true}
	}
	if matchType == "one_label_wildcard" {
		route.WildcardSuffix = sql.NullString{String: "example.test", Valid: true}
	}
	return route
}

func resourceDomain(id, hostname, ownership, conflict string) dbsqlc.TunnelDomain {
	return dbsqlc.TunnelDomain{ID: id, AccountID: "acct_1", TunnelID: "tun_1", RouteID: "rte_1", Hostname: hostname, MatchType: "exact", OwnershipChallengeReference: "dns-challenge://dns_1", OwnershipState: ownership, DnsTarget: "target.example.net", ObservedRecords: []byte(`[]`), CertificateStrategy: "managed", CertificateState: "pending", ConflictState: conflict, Generation: 2, CreatedAt: testNow.Add(-time.Minute), UpdatedAt: testNow}
}

func resourceConnector(id string) dbsqlc.TunnelConnector {
	return dbsqlc.TunnelConnector{ID: id, TunnelID: "tun_1", HostID: "host_1", CredentialReference: "keychain://paperboat/connector", CredentialThumbprint: "thumbprint", RotationGeneration: 2, DesiredState: "active", ProtocolVersion: "1.0", OperatingSystem: sql.NullString{String: "darwin", Valid: true}, Architecture: sql.NullString{String: "arm64", Valid: true}, DrainState: "accepting", Generation: 3, CreatedAt: testNow.Add(-time.Minute), UpdatedAt: testNow}
}

func resourceOperation(id, resourceID, phase, state, outcome string) dbsqlc.Operation {
	return dbsqlc.Operation{ID: id, AccountID: "acct_1", ResourceID: sql.NullString{String: resourceID, Valid: resourceID != ""}, OperationType: "resource.mutation", ResourceKind: "connector", Phase: phase, State: state, Progress: 60, Outcome: outcome, CorrelationID: "corr_1", CreatedAt: testNow, UpdatedAt: testNow}
}

func resourceStringPtr(value string) *string {
	return &value
}

func TestResourceServiceRouteNormalizationAndCanonicalWireVocabulary(t *testing.T) {
	repo := &fakeResourceRepository{}
	service := resourceServiceForTest(t, repo, 0)
	result, err := service.CreateRoute(context.Background(), testRequest(false), "tun_1", RouteCreateRequest{
		Name: "private", Protocol: "tcp_private", MatchType: "catch_all", Origin: RouteOriginRequest{Scheme: "tcp", Address: "127.0.0.1:5432"}, Mutation: ResourceMutationInput{IdempotencyKey: "route_1", RequestHash: testHash()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if repo.createRoute.Protocol != "private_tcp" || repo.createRoute.MatchType != "catch_all" || repo.createRoute.Hostname.Valid || repo.createRoute.WildcardSuffix.Valid || repo.createRoute.PathPrefix.Valid {
		t.Fatalf("database route projection = %+v", repo.createRoute)
	}
	if repo.createRoute.ConnectTimeoutMS != 10000 || repo.createRoute.IdleTimeoutMS != 90000 || repo.createRoute.MaxConcurrentStreams != 128 {
		t.Fatalf("default route limits = %d/%d/%d", repo.createRoute.ConnectTimeoutMS, repo.createRoute.IdleTimeoutMS, repo.createRoute.MaxConcurrentStreams)
	}
	if result.Route.Protocol != "tcp_private" || result.Route.HostMatch.Type != "catch_all" || result.Route.HostMatch.Hostname != "" {
		t.Fatalf("canonical route view = %+v", result.Route)
	}

	wildcard := "Example.COM"
	_, err = service.CreateRoute(context.Background(), testRequest(false), "tun_1", RouteCreateRequest{
		Name: "wild", Protocol: "http", MatchType: "one_label_wildcard", WildcardSuffix: wildcard, Origin: RouteOriginRequest{Scheme: "http", Address: "127.0.0.1:3000"}, Mutation: ResourceMutationInput{IdempotencyKey: "route_2", RequestHash: testHash()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if repo.createRoute.WildcardSuffix.String != "example.com" || !repo.createRoute.WildcardSuffix.Valid {
		t.Fatalf("wildcard normalization = %+v", repo.createRoute.WildcardSuffix)
	}

	badTimeout := int32(99)
	_, err = service.CreateRoute(context.Background(), testRequest(false), "tun_1", RouteCreateRequest{
		Name: "bad", Protocol: "http", MatchType: "catch_all", Origin: RouteOriginRequest{Scheme: "http", Address: "127.0.0.1:3000"}, ConnectTimeoutMS: badTimeout, Mutation: ResourceMutationInput{IdempotencyKey: "route_3", RequestHash: testHash()},
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid timeout error = %v", err)
	}
}

func TestResourceServicePatchCarriesFullOriginTLSAndLimitProjection(t *testing.T) {
	repo := &fakeResourceRepository{}
	service := resourceServiceForTest(t, repo, 0)
	name, protocol, priority := "renamed", "http", int32(7)
	connect, idle, streams := int32(500), int32(2500), int32(64)
	serverName, caReference, mtlsReference := "backend.example.test", "keychain://paperboat/origins/rte_1/ca", "keychain://paperboat/origins/rte_1/client"
	result, err := service.PatchRoute(context.Background(), testRequest(false), "tun_1", "rte_1", RoutePatchRequest{
		Name: &name, Protocol: &protocol, Priority: &priority, ConnectTimeoutMS: &connect, IdleTimeoutMS: &idle, MaxConcurrentStreams: &streams,
		Origin:   &RouteOriginRequest{Scheme: "https", Address: "backend.example.test:443", PreserveHost: false, HostOverride: resourceStringPtr("origin.example.test"), TLS: &RouteTLSRequest{Verification: "custom_ca", ServerName: &serverName, CAReference: &caReference, ClientCredentialReference: &mtlsReference}},
		Mutation: ResourceMutationInput{ExpectedGeneration: 2, IdempotencyKey: "route_patch_1", RequestHash: testHash()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !repo.patchRoute.NameSet || !repo.patchRoute.ProtocolSet || !repo.patchRoute.PrioritySet || !repo.patchRoute.OriginSet || !repo.patchRoute.ConnectTimeoutSet || !repo.patchRoute.IdleTimeoutSet || !repo.patchRoute.MaxStreamsSet {
		t.Fatalf("patch presence flags = %+v", repo.patchRoute)
	}
	origin := repo.patchRoute.Origin
	if origin.Scheme != "https" || origin.PreserveHost || origin.HostOverride == nil || *origin.HostOverride != "origin.example.test" || origin.TLS == nil || origin.TLS.Verification != "custom_ca" || origin.TLS.ServerName == nil || *origin.TLS.ServerName != serverName || origin.TLS.CAReference == nil || origin.TLS.ClientCredentialReference == nil {
		t.Fatalf("full origin projection = %+v", origin)
	}
	if repo.patchRoute.ConnectTimeoutMS != connect || repo.patchRoute.IdleTimeoutMS != idle || repo.patchRoute.MaxConcurrentStreams != streams || result.Operation.State != "running" {
		t.Fatalf("patch projection = %+v operation=%+v", repo.patchRoute, result.Operation)
	}
}

func TestRouteTLSValidationKeepsVerificationAndCredentialReferencesCoherent(t *testing.T) {
	ca := "keychain://paperboat/origins/ca_01"
	client := "keychain://paperboat/origins/client_01"
	plainPath := "/etc/paperboat/origin-ca.pem"
	pem := "-----BEGIN CERTIFICATE-----"
	for _, test := range []struct {
		name    string
		value   RouteTLSRequest
		wantErr bool
	}{
		{name: "system", value: RouteTLSRequest{Verification: "system"}},
		{name: "system mTLS", value: RouteTLSRequest{Verification: "system", ClientCredentialReference: &client}},
		{name: "custom CA and mTLS", value: RouteTLSRequest{Verification: "custom_ca", CAReference: &ca, ClientCredentialReference: &client}},
		{name: "development explicit", value: RouteTLSRequest{Verification: "insecure_development"}},
		{name: "custom CA missing reference", value: RouteTLSRequest{Verification: "custom_ca"}, wantErr: true},
		{name: "system with irrelevant CA", value: RouteTLSRequest{Verification: "system", CAReference: &ca}, wantErr: true},
		{name: "development with irrelevant CA", value: RouteTLSRequest{Verification: "insecure_development", CAReference: &ca}, wantErr: true},
		{name: "raw filesystem path", value: RouteTLSRequest{Verification: "custom_ca", CAReference: &plainPath}, wantErr: true},
		{name: "raw PEM", value: RouteTLSRequest{Verification: "custom_ca", CAReference: &pem}, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateRouteTLS(test.value)
			if test.wantErr != (err != nil) {
				t.Fatalf("validateRouteTLS() error=%v wantErr=%t", err, test.wantErr)
			}
		})
	}
}

func TestRouteInsecureDevelopmentRequiresExplicitServerPolicy(t *testing.T) {
	origin := RouteOriginRequest{Scheme: "https", TLS: &RouteTLSRequest{Verification: "insecure_development"}}
	if err := (&ResourceService{}).validateOriginPolicy(origin); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("production policy error = %v", err)
	}
	if err := (&ResourceService{allowInsecureDevelopment: true}).validateOriginPolicy(origin); err != nil {
		t.Fatalf("explicit development policy error = %v", err)
	}
}

func TestRouteAuditMetadataMarksInsecureDevelopmentWithoutSecretReferences(t *testing.T) {
	route := dbsqlc.TunnelRoute{Generation: 4, Protocol: "http", OriginScheme: "https", TlsVerification: "insecure_development", DesiredState: "active", CaReference: sql.NullString{String: "keychain://paperboat/origins/secret", Valid: true}}
	metadata := routeAuditMetadata(route)
	if metadata["origin_tls_insecure_development"] != true || metadata["origin_tls_verification"] != "insecure_development" {
		t.Fatalf("metadata=%v", metadata)
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "keychain") || !strings.Contains(routeAuditMessage("route updated", route), "warning") {
		t.Fatalf("unsafe audit projection metadata=%s message=%q", encoded, routeAuditMessage("route updated", route))
	}
}

func TestRouteJSONContainsOnlyOpaqueTLSReferences(t *testing.T) {
	row := resourceRoute("rte_tls", "http", "managed")
	row.OriginScheme = "https"
	row.TlsVerification = "custom_ca"
	row.TlsServerName = sql.NullString{String: "origin.example.test", Valid: true}
	row.CaReference = sql.NullString{String: "keychain://paperboat/origins/rte_tls/ca", Valid: true}
	row.MtlsCredentialReference = sql.NullString{String: "keychain://paperboat/origins/rte_tls/client", Valid: true}
	encoded, err := json.Marshal(routeView(row))
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, reference := range []string{row.CaReference.String, row.MtlsCredentialReference.String} {
		if !strings.Contains(text, reference) {
			t.Fatalf("route JSON omitted opaque reference %q: %s", reference, text)
		}
	}
	for _, forbidden := range []string{"BEGIN CERTIFICATE", "BEGIN PRIVATE KEY", "private_key_pem", "certificate_pem", "bearer"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("route JSON contains resolved secret marker %q: %s", forbidden, text)
		}
	}
}

func TestResourceServiceListCursorsAreScopedAndTailBounded(t *testing.T) {
	repo := &fakeResourceRepository{listRoutes: []dbsqlc.TunnelRoute{resourceRoute("rte_1", "http", "managed"), resourceRoute("rte_2", "http", "managed")}}
	repo.listRoutes[1].CreatedAt = testNow.Add(-2 * time.Minute)
	service := resourceServiceForTest(t, repo, 0)
	page, err := service.ListRoutes(context.Background(), testRequest(false), "tun_1", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.NextCursor == "" || repo.listRoutesLimit != 2 || repo.listRoutesAccount != "acct_1" || repo.listRoutesTunnel != "tun_1" {
		t.Fatalf("bounded first page = %+v repo=%+v", page, repo)
	}
	otherAccount := testRequest(false)
	otherAccount.Actor.AccountID = "acct_2"
	if _, err := service.ListRoutes(context.Background(), otherAccount, "tun_1", page.NextCursor, 1); !errors.Is(err, previewtunnelapi.ErrInvalidCursor) {
		t.Fatalf("cross-account cursor error = %v", err)
	}
	repo.listRoutes = repo.listRoutes[:1]
	page, err = service.ListRoutes(context.Background(), testRequest(false), "tun_1", "", 1)
	if err != nil || page.NextCursor != "" {
		t.Fatalf("tail page = %+v, %v", page, err)
	}

	repo.listConnectors = []dbsqlc.TunnelConnector{resourceConnector("con_1"), resourceConnector("con_2")}
	connectorPage, err := service.ListConnectors(context.Background(), testRequest(false), "tun_1", "", 1)
	if err != nil || connectorPage.NextCursor == "" || repo.listConnectorsLimit != 2 {
		t.Fatalf("connector keyset page = %+v repo limit=%d err=%v", connectorPage, repo.listConnectorsLimit, err)
	}
}

func TestResourceServiceDomainInstructionsUsePersistedStateAndSupportApex(t *testing.T) {
	repo := &fakeResourceRepository{domain: resourceDomain("dom_1", "foo.example.co.uk", "verified", "clear")}
	service := resourceServiceForTest(t, repo, 0)
	instructions, err := service.DomainInstructions(context.Background(), testRequest(false), "tun_1", "dom_1")
	if err != nil {
		t.Fatal(err)
	}
	if instructions.VerificationState != "verified" || instructions.Provider != "generic" || len(instructions.Records) != 1 || instructions.Records[0].Type != "CNAME" {
		t.Fatalf("domain instructions = %+v", instructions)
	}
	for _, hostname := range []string{"example.com", "example.co.uk"} {
		repo.domain = resourceDomain("dom_1", hostname, "pending", "clear")
		instructions, err = service.DomainInstructions(context.Background(), testRequest(false), "tun_1", "dom_1")
		if err != nil || instructions.Records[0].Type != "ANAME" {
			t.Fatalf("apex %q instructions = %+v, %v", hostname, instructions, err)
		}
	}
	repo.domain = resourceDomain("dom_1", "*.example.co.uk", "pending", "clear")
	instructions, err = service.DomainInstructions(context.Background(), testRequest(false), "tun_1", "dom_1")
	if err != nil || instructions.VerificationState != "waiting_dns" {
		t.Fatalf("wildcard instructions = %+v, %v", instructions, err)
	}
}

func resourceLog(sequence int64, message, correlation string, preview bool) dbsqlc.TunnelLogEntry {
	entry := dbsqlc.TunnelLogEntry{ID: fmt.Sprintf("log_%d", sequence), AccountID: "acct_1", Level: "info", Component: "control", Code: "route_updated", Message: message, Metadata: []byte(`{"attempt":2,"nested":{"state":"ready"}}`), CorrelationID: correlation, OccurredAt: testNow, CursorSequence: sql.NullInt64{Int64: sequence, Valid: true}}
	if preview {
		entry.PreviewID = sql.NullString{String: "pre_1", Valid: true}
	} else {
		entry.TunnelID = sql.NullString{String: "tun_1", Valid: true}
	}
	return entry
}

func TestResourceServiceLogsAreBoundedResumableAndRedacted(t *testing.T) {
	repo := &fakeResourceRepository{tunnelLogs: []dbsqlc.ListTunnelLogsV1Row{{ID: "log_1", AccountID: "acct_1", TunnelID: sql.NullString{String: "tun_1", Valid: true}, Level: "info", Component: "control", Code: "route_updated", Message: "route persisted", Metadata: []byte(`{"attempt":2,"nested":{"state":"ready"}}`), CorrelationID: "corr_1", OccurredAt: testNow, CursorSequence: sql.NullInt64{Int64: 3, Valid: true}}}}
	service := resourceServiceForTest(t, repo, 0)
	page, err := service.ListTunnelLogs(context.Background(), testRequest(false), "tun_1", "", 2)
	if err != nil || len(page.Items) != 1 || page.NextCursor != "" || repo.lastLogAccount != "acct_1" || repo.lastLogScope != "tun_1" || repo.lastLogLimit != 3 {
		t.Fatalf("tail tunnel logs = %+v repo=%+v err=%v", page, repo, err)
	}
	if page.Items[0].Metadata["attempt"] != json.Number("2") || page.Items[0].Cursor != "3" {
		t.Fatalf("safe log projection = %+v", page.Items[0])
	}
	repo.previewLogs = []dbsqlc.TunnelLogEntry{resourceLog(8, "preview ready", "corr_2", true)}
	previewRequest := testRequest(false)
	previewRequest.Actor.Scopes = append(previewRequest.Actor.Scopes, "previews:read")
	previewPage, err := service.ListPreviewLogs(context.Background(), previewRequest, "pre_1", "", 1)
	if err != nil || len(previewPage.Items) != 1 || previewPage.NextCursor != "" || repo.lastLogScope != "pre_1" {
		t.Fatalf("preview logs = %+v repo=%+v err=%v", previewPage, repo, err)
	}
	for _, message := range []string{"origin failed: https://user:pass@example.test", "request failed: Bearer abc", "BEGIN PRIVATE KEY"} {
		repo.tunnelLogs[0].Message = message
		if _, err := service.ListTunnelLogs(context.Background(), testRequest(false), "tun_1", "", 1); !errors.Is(err, previewtunnelapi.ErrUnsafeMetadata) {
			t.Errorf("unsafe log %q error = %v", message, err)
		}
	}
}

func TestResourceServiceEnrollmentRejectsUnrecoverableReplayAndProofBindsVerifier(t *testing.T) {
	repo := &fakeResourceRepository{enrollmentResult: EnrollmentRecord{Enrollment: dbsqlc.TunnelConnectorEnrollment{ID: "enr_1", AccountID: "acct_1", TunnelID: "tun_1", HostID: "host_1", ExpiresAt: testNow.Add(time.Minute)}, Operation: resourceOperation("op_1", "enr_1", "ready", "succeeded", "changed"), Replayed: true}}
	service := resourceServiceForTest(t, repo, 0)
	request := testRequest(false)
	if _, err := service.IssueEnrollment(context.Background(), request, "tun_1", EnrollmentRequest{HostID: "host_1", Capabilities: []string{"http"}, Mutation: ResourceMutationInput{IdempotencyKey: "enr_1", RequestHash: testHash()}}); !errors.Is(err, ErrEnrollmentAlreadyIssued) {
		t.Fatalf("unrecoverable enrollment replay error = %v", err)
	}

	seed := bytes.Repeat([]byte{21}, ed25519.SeedSize)
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	thumbprint := ConnectorCredentialThumbprint(public)
	const token = "pbce_token_for_exchange"
	const reference = "keychain://paperboat/connector"
	proof := ed25519.Sign(private, ConnectorCredentialProofPayload("tun_1", "host_1", token, reference, thumbprint, "exchange_1"))
	hostRequest := testRequest(true)
	result, err := service.ExchangeEnrollment(context.Background(), hostRequest, EnrollmentExchangeRequest{TunnelID: "tun_1", Token: token, HostID: "host_1", ProtocolVersion: "1.0", CredentialReference: reference, CredentialThumbprint: thumbprint,
		CredentialVerifierAlgorithm: "ed25519", CredentialVerifierPublicKey: public, CredentialProof: proof, Mutation: ResourceMutationInput{IdempotencyKey: "exchange_1", RequestHash: testHash()}})
	if err != nil {
		t.Fatal(err)
	}
	if repo.exchangeInput.CredentialVerifierAlgorithm != "ed25519" || !bytes.Equal(repo.exchangeInput.CredentialVerifierPublicKey, public) || repo.exchangeInput.CredentialOverlap != 10*time.Minute || result.Operation.State != "running" || result.Activation == nil || result.Activation.AccountID != hostRequest.Actor.AccountID || result.Activation.StableEndpointID != "11111111-1111-4111-8111-111111111111" || result.Activation.CredentialGeneration != 1 || result.Activation.ProcessGeneration != 1 {
		t.Fatalf("exchange proof projection = %+v result=%+v", repo.exchangeInput, result)
	}
	if _, err := service.ExchangeEnrollment(context.Background(), hostRequest, EnrollmentExchangeRequest{TunnelID: "tun_1", Token: token + "-changed", HostID: "host_1", ProtocolVersion: "1.0", CredentialReference: reference, CredentialThumbprint: thumbprint,
		CredentialVerifierAlgorithm: "ed25519", CredentialVerifierPublicKey: public, CredentialProof: proof, Mutation: ResourceMutationInput{IdempotencyKey: "exchange_2", RequestHash: testHash()}}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("changed token proof error = %v", err)
	}
}

func TestResourceServiceRotationUsesConfiguredOverlapAndReturnsOperationOnly(t *testing.T) {
	repo := &fakeResourceRepository{}
	service := resourceServiceForTest(t, repo, 3*time.Minute)
	operation, err := service.RotateCredentials(context.Background(), testRequest(false), "tun_1", ResourceMutationInput{ExpectedGeneration: 4, IdempotencyKey: "rotate_1", RequestHash: testHash()})
	if err != nil {
		t.Fatal(err)
	}
	if !repo.rotationInput.OverlapUntil.Equal(testNow.Add(3*time.Minute)) || repo.rotationInput.NewID == nil || operation.State != "running" || operation.Phase != "connecting" {
		t.Fatalf("rotation projection = %+v operation=%+v", repo.rotationInput, operation)
	}
	if operation.ResourceKind != "tunnel" || operation.ResourceID != "tun_1" {
		t.Fatalf("rotation operation scope = kind=%q id=%#v", operation.ResourceKind, operation.ResourceID)
	}
	encoded, err := json.Marshal(operation)
	if err != nil || bytes.Contains(encoded, []byte("keychain://")) || strings.Contains(string(encoded), "thumbprint") {
		t.Fatalf("operation contains credential material: %s (%v)", encoded, err)
	}
}
