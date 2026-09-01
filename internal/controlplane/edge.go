package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/mint"
	"github.com/pinksaucepasta/paperboat-server/internal/observability"
	"github.com/pinksaucepasta/paperboat-server/internal/secrets"
)

const maxEdgeDocument = 1 << 20

type EdgeService struct {
	store                   *db.DB
	credential              string
	clock                   func() time.Time
	bandwidth               BandwidthDebiter
	audit                   *audit.Writer
	signer                  *mint.Provider
	issuer                  string
	encryptionKey           string
	fileTransferPolicy      mint.FileTransferPolicy
	certificateDistribution http.Handler
}

func (s *EdgeService) SetBandwidthDebiter(debiter BandwidthDebiter) { s.bandwidth = debiter }
func (s *EdgeService) SetAuditWriter(writer *audit.Writer)          { s.audit = writer }
func (s *EdgeService) SetCredentialIssuer(signer *mint.Provider, issuer, encryptionKey string) {
	s.signer, s.issuer, s.encryptionKey = signer, strings.TrimRight(strings.TrimSpace(issuer), "/"), encryptionKey
}
func (s *EdgeService) SetFileTransferPolicy(policy mint.FileTransferPolicy) {
	s.fileTransferPolicy = policy
}

// SetCertificateDistribution mounts the internal certificate distribution
// transport beneath the already authenticated edge-control handler. The
// handler is deliberately injected by deployment composition because it
// owns the in-memory issuance queue and server-side envelope key source.
func (s *EdgeService) SetCertificateDistribution(handler http.Handler) {
	s.certificateDistribution = handler
}

type ConnectorAdmission struct {
	OperationID         string `json:"operation_id"`
	Credential          string `json:"credential"`
	EnvironmentID       string `json:"environment_id"`
	MachineID           string `json:"machine_id"`
	ConnectorID         string `json:"connector_id"`
	ConnectorGeneration int64  `json:"connector_generation"`
	EdgePool            string `json:"edge_pool"`
	EdgeNodeID          string `json:"edge_node_id"`
	RelayHTTPEndpoint   string `json:"relay_http_endpoint"`
	EdgeEndpoint        struct {
		Host     string `json:"host"`
		Port     int32  `json:"port"`
		TCPPort  int32  `json:"tcp_port"`
		QUICPort int32  `json:"quic_port"`
	} `json:"edge_endpoint"`
	Routes             []ConnectorRouteHandoff `json:"routes"`
	ProtocolVersion    string                  `json:"protocol_version"`
	Capabilities       []string                `json:"capabilities,omitempty"`
	FileTransferPolicy mint.FileTransferPolicy `json:"file_transfer_policy"`
	ExpiresAt          time.Time               `json:"-"`
}

type ConnectorRouteHandoff struct {
	RouteID       string `json:"route_id"`
	RouteRevision int64  `json:"route_revision"`
	Kind          string `json:"kind"`
	PublicHost    string `json:"public_host"`
	ProxyName     string `json:"proxy_name"`
	Target        struct {
		Host string `json:"host"`
		Port int32  `json:"port"`
	} `json:"target"`
}

func connectorRouteBinding(routes []ConnectorRouteHandoff) string {
	hash := sha256.New()
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(routes)))
	_, _ = hash.Write(size[:])
	for _, route := range routes {
		for _, value := range []string{route.RouteID, route.Kind, route.PublicHost, route.ProxyName, route.Target.Host} {
			binary.BigEndian.PutUint64(size[:], uint64(len(value)))
			_, _ = hash.Write(size[:])
			_, _ = io.WriteString(hash, value)
		}
		binary.BigEndian.PutUint64(size[:], uint64(route.RouteRevision))
		_, _ = hash.Write(size[:])
		binary.BigEndian.PutUint64(size[:], uint64(route.Target.Port))
		_, _ = hash.Write(size[:])
	}
	return base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}

type connectorAdmissionRequest struct {
	OperationID     string `json:"operation_id"`
	EnvironmentID   string `json:"environment_id"`
	MachineID       string `json:"machine_id"`
	ConnectorID     string `json:"connector_id"`
	EdgePool        string `json:"edge_pool"`
	ProtocolVersion string `json:"protocol_version"`
}

type RevocationDocument struct {
	JTIs         []string                     `json:"jtis"`
	Environments []string                     `json:"environments"`
	Connectors   []RevokedConnectorGeneration `json:"connector_generations"`
	KeyIDs       []string                     `json:"key_ids"`
}

type RevokedConnectorGeneration struct {
	MachineID   string `json:"machine_id"`
	ConnectorID string `json:"connector_id"`
	Generation  uint64 `json:"connector_generation"`
}

type RouteObservation struct {
	RouteID                    string `json:"route_id"`
	AssignmentID               string `json:"assignment_id,omitempty"`
	AssignmentGeneration       int64  `json:"assignment_generation,omitempty"`
	RouteRevision              int64  `json:"route_revision"`
	EdgeNodeID                 string `json:"edge_node_id"`
	EdgeProcessEpoch           string `json:"edge_process_epoch,omitempty"`
	ConnectorID                string `json:"connector_id,omitempty"`
	HostID                     string `json:"host_id,omitempty"`
	ConnectorGeneration        int64  `json:"connector_generation"`
	ConnectorSessionID         string `json:"connector_session_id,omitempty"`
	ConnectorProcessGeneration int64  `json:"connector_process_generation,omitempty"`
	ConfigGeneration           int64  `json:"config_generation,omitempty"`
	ConfigContentHash          string `json:"config_content_hash,omitempty"`
	State                      string `json:"state,omitempty"`
	ObservedState              string `json:"observed_state,omitempty"`
}

func (o RouteObservation) canonicalObservedState() (string, error) {
	state := strings.TrimSpace(o.State)
	observed := strings.TrimSpace(o.ObservedState)
	if state != "" && observed != "" && state != observed {
		return "", ErrInvalidUsageReport
	}
	if state == "" {
		state = observed
	}
	switch state {
	case "ready", "degraded", "draining", "failed", "detached":
		return state, nil
	default:
		return "", ErrInvalidUsageReport
	}
}

func (s *EdgeService) ObserveRoutes(ctx context.Context, nodeID string, observations []RouteObservation) error {
	if nodeID == "" || len(observations) > 1000 {
		return ErrInvalidUsageReport
	}
	now := s.clock().UTC()
	detachedCount := int64(0)
	err := s.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		// Legacy routes have one observation per route ID. Canonical route
		// replacement deliberately reports the new and old assignment for the
		// same route in one batch, so its idempotency key is the immutable
		// assignment ID instead.
		observedLegacy := make(map[string]struct{}, len(observations))
		observedCanonical := make(map[string]struct{}, len(observations))
		for _, observation := range observations {
			if observation.RouteID == "" || observation.RouteRevision < 1 || observation.EdgeNodeID != nodeID || observation.ConnectorGeneration < 1 {
				return ErrInvalidUsageReport
			}
			if observation.ConfigGeneration > 0 {
				if observation.AssignmentID == "" || observation.AssignmentGeneration < 1 || observation.EdgeProcessEpoch == "" || observation.ConnectorID == "" || observation.HostID == "" || observation.ConnectorSessionID == "" || observation.ConnectorProcessGeneration < 1 {
					return ErrInvalidUsageReport
				}
				configHash, err := parseTunnelEdgeConfigHash(observation.ConfigContentHash)
				if err != nil {
					return ErrInvalidUsageReport
				}
				if _, duplicate := observedCanonical[observation.AssignmentID]; duplicate {
					return ErrInvalidUsageReport
				}
				observedCanonical[observation.AssignmentID] = struct{}{}
				state, err := observation.canonicalObservedState()
				if err != nil {
					return err
				}
				if state == "detached" {
					if _, err := tx.Queries().FinalizeDrainingTunnelEdgeRouteAssignmentV1(ctx, dbsqlc.FinalizeDrainingTunnelEdgeRouteAssignmentV1Params{
						Now: sql.NullTime{Time: now, Valid: true}, AssignmentID: observation.AssignmentID, RouteID: observation.RouteID,
						AssignmentGeneration: observation.AssignmentGeneration, EdgeNodeID: observation.EdgeNodeID,
						EdgeProcessEpoch: observation.EdgeProcessEpoch, ConnectorID: observation.ConnectorID,
						HostID:              observation.HostID,
						ConnectorGeneration: observation.ConnectorGeneration, ConnectorSessionID: observation.ConnectorSessionID,
						ConnectorProcessGeneration: observation.ConnectorProcessGeneration, ConfigGeneration: observation.ConfigGeneration,
						ConfigContentHash: configHash,
					}); err != nil {
						if !errors.Is(err, sql.ErrNoRows) {
							return err
						}
						existing, getErr := tx.Queries().GetTunnelEdgeRouteAssignmentForObservationV1(ctx, dbsqlc.GetTunnelEdgeRouteAssignmentForObservationV1Params{
							AssignmentID: observation.AssignmentID, RouteID: observation.RouteID, AssignmentGeneration: observation.AssignmentGeneration,
							EdgeNodeID: observation.EdgeNodeID, EdgeProcessEpoch: observation.EdgeProcessEpoch, ConnectorID: observation.ConnectorID,
							ConnectorGeneration: observation.ConnectorGeneration, ConnectorSessionID: observation.ConnectorSessionID,
							HostID: observation.HostID, ConnectorProcessGeneration: observation.ConnectorProcessGeneration, ConfigGeneration: observation.ConfigGeneration,
							ConfigContentHash: configHash,
						})
						if getErr != nil || existing.State != "detached" {
							return ErrAssignmentConflict
						}
					}
					continue
				}
				_, err = tx.Queries().ApplyTunnelEdgeRouteObservationV1(ctx, dbsqlc.ApplyTunnelEdgeRouteObservationV1Params{
					ObservedState: state,
					Now:           sql.NullTime{Time: now, Valid: true}, AssignmentID: observation.AssignmentID, AssignmentGeneration: observation.AssignmentGeneration,
					RouteID: observation.RouteID, RouteRevision: observation.RouteRevision, EdgeNodeID: observation.EdgeNodeID,
					EdgeProcessEpoch: observation.EdgeProcessEpoch, ConnectorID: observation.ConnectorID,
					HostID:              observation.HostID,
					ConnectorGeneration: observation.ConnectorGeneration, ConnectorSessionID: observation.ConnectorSessionID,
					ConnectorProcessGeneration: observation.ConnectorProcessGeneration, ConfigGeneration: observation.ConfigGeneration,
					ConfigContentHash: configHash,
				})
				if err != nil {
					if errors.Is(err, sql.ErrNoRows) {
						return ErrAssignmentConflict
					}
					return err
				}
				switch state {
				case "ready":
					if _, err := tx.Queries().ActivateTunnelEdgeRouteAssignmentV1(ctx, dbsqlc.ActivateTunnelEdgeRouteAssignmentV1Params{
						AssignmentID: observation.AssignmentID, RouteID: observation.RouteID, Now: now,
					}); err != nil {
						return ErrAssignmentConflict
					}
				}
				continue
			}
			if _, duplicate := observedLegacy[observation.RouteID]; duplicate {
				return ErrInvalidUsageReport
			}
			observedLegacy[observation.RouteID] = struct{}{}
			if _, err := tx.Queries().ApplyControlRouteObservation(ctx, dbsqlc.ApplyControlRouteObservationParams{ID: observation.RouteID, RouteRevision: observation.RouteRevision, EdgeNodeID: sql.NullString{String: observation.EdgeNodeID, Valid: true}, ConnectorGeneration: sql.NullInt64{Int64: observation.ConnectorGeneration, Valid: true}, Now: now}); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return ErrAssignmentConflict
				}
				return err
			}
		}
		detaching, err := tx.Queries().ListDetachingControlRoutesForNode(ctx, sql.NullString{String: nodeID, Valid: true})
		if err != nil {
			return err
		}
		for _, route := range detaching {
			if _, present := observedLegacy[route.ID]; present {
				continue
			}
			if _, err := tx.Queries().FinalizeDetachedControlRoute(ctx, dbsqlc.FinalizeDetachedControlRouteParams{ID: route.ID, DesiredRevision: route.DesiredRevision, EdgeNodeID: sql.NullString{String: nodeID, Valid: true}, Now: now}); err != nil {
				return err
			}
			detachedCount++
		}
		return nil
	})
	if err == nil {
		observability.ControlRouteObserved(int64(len(observations)))
		observability.ControlRouteDetached(detachedCount)
	}
	return err
}

func (s *EdgeService) Revocations(ctx context.Context) (RevocationDocument, error) {
	jtis, err := s.store.Queries().ListRevokedControlCredentialJTIs(ctx, dbsqlc.ListRevokedControlCredentialJTIsParams{Now: s.clock().UTC(), RowLimit: 10000})
	if err != nil {
		return RevocationDocument{}, err
	}
	environments, err := s.store.Queries().ListRevokedControlEnvironments(ctx, 10000)
	if err != nil {
		return RevocationDocument{}, err
	}
	connectors, err := s.store.Queries().ListRevokedConnectorGenerations(ctx, 10000)
	if err != nil {
		return RevocationDocument{}, err
	}
	keyIDs, err := s.store.Queries().ListRevokedControlSigningKeyIDs(ctx, 10000)
	if err != nil {
		return RevocationDocument{}, err
	}
	if jtis == nil {
		jtis = []string{}
	}
	if environments == nil {
		environments = []string{}
	}
	if keyIDs == nil {
		keyIDs = []string{}
	}
	document := RevocationDocument{JTIs: jtis, Environments: environments, Connectors: make([]RevokedConnectorGeneration, 0, len(connectors)), KeyIDs: keyIDs}
	for _, connector := range connectors {
		if connector.Generation > 0 {
			document.Connectors = append(document.Connectors, RevokedConnectorGeneration{MachineID: connector.MachineID, ConnectorID: connector.ConnectorID, Generation: uint64(connector.Generation)})
		}
	}
	observability.ControlRevocationFetched()
	return document, nil
}

func (s *EdgeService) RevokeSigningKey(ctx context.Context, actorID, idempotencyKey, keyID, reason string, revokedAt time.Time) error {
	actorID, idempotencyKey, keyID, reason = strings.TrimSpace(actorID), strings.TrimSpace(idempotencyKey), strings.TrimSpace(keyID), strings.TrimSpace(reason)
	if actorID == "" || idempotencyKey == "" || keyID == "" || reason == "" || revokedAt.IsZero() {
		return ErrInvalidUsageReport
	}
	return s.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		_, err := tx.Queries().ReserveControlSigningKeyRevocation(ctx, dbsqlc.ReserveControlSigningKeyRevocationParams{OperationKey: idempotencyKey, KeyID: keyID, Reason: reason})
		if errors.Is(err, sql.ErrNoRows) {
			existing, getErr := tx.Queries().GetControlSigningKeyRevocationOperation(ctx, idempotencyKey)
			if getErr != nil || existing.KeyID != keyID || existing.Reason != reason {
				return ErrUsageOperationConflict
			}
		} else if err != nil {
			return err
		}
		if _, err := tx.Queries().RevokeControlSigningKey(ctx, dbsqlc.RevokeControlSigningKeyParams{KeyID: keyID, Reason: reason, RevokedAt: revokedAt.UTC(), ActorUserID: sql.NullString{String: actorID, Valid: true}}); err != nil {
			return err
		}
		return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: actorID, ActorType: audit.ActorAdmin, EventType: "mint.signing_key_revoked", ResourceType: "mint_signing_key", ResourceID: keyID, IdempotencyKey: idempotencyKey, Metadata: map[string]any{"reason": reason}})
	})
}

func (s *EdgeService) IssueConnectorAdmission(ctx context.Context, identityToken string, proof, body []byte, edgePool, method, path string) (ConnectorAdmission, error) {
	if s.signer == nil || s.issuer == "" || s.encryptionKey == "" || edgePool == "" {
		return ConnectorAdmission{}, ErrHelperProof
	}
	claims, err := (&EnrollmentService{store: s.store, signer: s.signer, issuer: s.issuer, clock: s.clock}).VerifyMachineRequest(ctx, identityToken, proof, method, path, body)
	if err != nil {
		return ConnectorAdmission{}, err
	}
	var request connectorAdmissionRequest
	if strictProofJSON(body, &request) != nil || request.OperationID != claims.OperationID || request.EnvironmentID != claims.EnvironmentID || request.MachineID != claims.MachineID || !validConnectorID(request.ConnectorID) || request.EdgePool != edgePool || request.ProtocolVersion != "1.0" {
		return ConnectorAdmission{}, ErrHelperProof
	}
	now := s.clock().UTC()
	requestHash := sha256.Sum256(append([]byte(claims.MachineID+"\x00"+claims.EnvironmentID+"\x00"+request.ConnectorID+"\x00"+edgePool+"\x00"), body...))
	operationKey := "connector-admission:" + claims.MachineID + ":" + request.ConnectorID + ":" + claims.OperationID
	var result ConnectorAdmission
	// The connector generation row lock serializes admission for the same
	// connector. Node selection is observational and does not require SSI
	// predicate protection across otherwise independent connectors.
	err = s.store.InReadCommittedTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		routes, err := tx.Queries().ListControlRoutesForEnvironmentAdmission(ctx, dbsqlc.ListControlRoutesForEnvironmentAdmissionParams{EnvironmentID: claims.EnvironmentID, ConnectorID: request.ConnectorID})
		if err != nil || len(routes) == 0 || len(routes) > 128 {
			return ErrHelperProof
		}
		generation, err := tx.Queries().GetControlConnectorGenerationForUpdate(ctx, dbsqlc.GetControlConnectorGenerationForUpdateParams{EnvironmentID: claims.EnvironmentID, ConnectorID: request.ConnectorID})
		if errors.Is(err, sql.ErrNoRows) {
			generation, err = tx.Queries().EnsureControlConnectorMachine(ctx, dbsqlc.EnsureControlConnectorMachineParams{EnvironmentID: claims.EnvironmentID, ConnectorID: request.ConnectorID, MachineID: claims.MachineID, EdgePool: edgePool})
		}
		if err != nil || generation.MachineID != claims.MachineID || generation.State == "revoked" {
			return ErrHelperProof
		}
		if generation.AdmissionOperationKey.Valid {
			if generation.AdmissionOperationKey.String == operationKey {
				if !bytes.Equal(generation.AdmissionRequestHash, requestHash[:]) {
					return ErrUsageOperationConflict
				}
				plaintext, decryptErr := secrets.Decrypt(s.encryptionKey, generation.AdmissionCredentialCiphertext)
				if decryptErr != nil || json.Unmarshal([]byte(plaintext), &result) != nil {
					return ErrHelperProof
				}
				return nil
			}
		}
		node, err := tx.Queries().SelectReadyControlTunnelNode(ctx, dbsqlc.SelectReadyControlTunnelNodeParams{EdgePool: edgePool, StaleAfter: sql.NullTime{Time: now.Add(-controlTunnelNodeStaleAfter), Valid: true}})
		if err != nil || !node.EndpointHost.Valid || !node.EndpointTcpPort.Valid || !node.EndpointQuicPort.Valid || !node.SignalingHost.Valid || strings.TrimSpace(node.SignalingHost.String) == "" {
			return ErrHelperProof
		}
		jti, err := randomHex("jti_", 24)
		if err != nil {
			return err
		}
		expiresAt := now.Add(5 * time.Minute)
		policy := s.fileTransferPolicy
		if policy.Revision == "" {
			policy = mint.DefaultFileTransferPolicy
		}
		handoffs := make([]ConnectorRouteHandoff, 0, len(routes))
		for _, route := range routes {
			handoff := ConnectorRouteHandoff{RouteID: route.RouteID, RouteRevision: route.RouteRevision, Kind: route.Kind, PublicHost: route.PublicHost, ProxyName: route.RouteID}
			handoff.Target.Host, handoff.Target.Port = route.TargetHost, route.TargetPort
			handoffs = append(handoffs, handoff)
		}
		binding := connectorRouteBinding(handoffs)
		token, err := s.signer.SignCredential(mint.CredentialInput{Issuer: s.issuer, Audience: "paperboat-edge", Subject: claims.MachineID, JTI: jti, IssuedAt: now, ExpiresAt: expiresAt, CredentialClass: "connector_admission", Scopes: []string{"connector:admit"}, EnvironmentID: claims.EnvironmentID, MachineID: claims.MachineID, InstallationGeneration: claims.InstallationGeneration, ConnectorID: request.ConnectorID, ConnectorGeneration: generation.Generation, EdgePool: edgePool, EdgeNodeID: node.ID, RouteBinding: binding, FileTransferPolicy: &policy})
		if err != nil {
			return err
		}
		result = ConnectorAdmission{OperationID: claims.OperationID, Credential: token, EnvironmentID: claims.EnvironmentID, MachineID: claims.MachineID, ConnectorID: request.ConnectorID, ConnectorGeneration: generation.Generation, EdgePool: edgePool, EdgeNodeID: node.ID, RelayHTTPEndpoint: "https://" + strings.TrimSpace(node.SignalingHost.String), Routes: handoffs, ProtocolVersion: "1.0", FileTransferPolicy: policy, ExpiresAt: expiresAt}
		result.EdgeEndpoint.Host, result.EdgeEndpoint.Port = node.EndpointHost.String, node.EndpointTcpPort.Int32
		result.EdgeEndpoint.TCPPort, result.EdgeEndpoint.QUICPort = node.EndpointTcpPort.Int32, node.EndpointQuicPort.Int32
		resultJSON, err := json.Marshal(result)
		if err != nil {
			return err
		}
		ciphertext, err := secrets.Encrypt(s.encryptionKey, string(resultJSON))
		if err != nil {
			return err
		}
		jtiHash := sha256.Sum256([]byte(jti))
		_, err = tx.Queries().SetControlConnectorAdmission(ctx, dbsqlc.SetControlConnectorAdmissionParams{EnvironmentID: claims.EnvironmentID, ConnectorID: request.ConnectorID, Generation: generation.Generation, EdgeNodeID: sql.NullString{String: node.ID, Valid: true}, AdmissionJtiHash: jtiHash[:], AdmissionOperationKey: sql.NullString{String: operationKey, Valid: true}, AdmissionRequestHash: requestHash[:], AdmissionCredentialCiphertext: ciphertext, ExpiresAt: sql.NullTime{Time: expiresAt, Valid: true}, UpdatedAt: now})
		return err
	})
	return result, err
}

func validConnectorID(value string) bool {
	if value == "runtime" {
		return true
	}
	return strings.HasPrefix(value, "p-") && len(value) == 28
}

func (s *EdgeService) ProvisionUsageKey(ctx context.Context, actorID, idempotencyKey, keyID, nodeID string, publicKey []byte, notBefore, expiresAt time.Time) error {
	if strings.TrimSpace(actorID) == "" || strings.TrimSpace(idempotencyKey) == "" || keyID == "" || nodeID == "" || len(publicKey) != ed25519.PublicKeySize || !expiresAt.After(notBefore) {
		return ErrInvalidUsageReport
	}
	return s.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		_, err := tx.Queries().CreateControlUsageVerificationKey(ctx, dbsqlc.CreateControlUsageVerificationKeyParams{KeyID: keyID, EdgeNodeID: nodeID, PublicKey: publicKey, NotBefore: notBefore, ExpiresAt: expiresAt})
		if errors.Is(err, sql.ErrNoRows) {
			existing, getErr := tx.Queries().GetControlUsageVerificationKey(ctx, keyID)
			if getErr != nil || existing.EdgeNodeID != nodeID || !bytes.Equal(existing.PublicKey, publicKey) || !existing.NotBefore.Equal(notBefore) || !existing.ExpiresAt.Equal(expiresAt) {
				return ErrUsageOperationConflict
			}
		} else if err != nil {
			return err
		}
		return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: actorID, ActorType: audit.ActorAdmin, EventType: "edge.usage_key_provisioned", ResourceType: "usage_key", ResourceID: keyID, IdempotencyKey: idempotencyKey, Metadata: map[string]any{"edge_node_id": nodeID, "not_before": notBefore, "expires_at": expiresAt}})
	})
}

func (s *EdgeService) RevokeUsageKey(ctx context.Context, actorID, idempotencyKey, keyID, reason string, revokedAt time.Time) error {
	if strings.TrimSpace(actorID) == "" || strings.TrimSpace(idempotencyKey) == "" || keyID == "" || strings.TrimSpace(reason) == "" {
		return ErrInvalidUsageReport
	}
	return s.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if _, err := tx.Queries().RevokeControlUsageVerificationKey(ctx, dbsqlc.RevokeControlUsageVerificationKeyParams{KeyID: keyID, RevokedAt: sql.NullTime{Time: revokedAt, Valid: true}}); err != nil {
			return err
		}
		return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: actorID, ActorType: audit.ActorAdmin, EventType: "edge.usage_key_revoked", ResourceType: "usage_key", ResourceID: keyID, IdempotencyKey: idempotencyKey, Metadata: map[string]any{"reason": strings.TrimSpace(reason)}})
	})
}

func NewEdgeService(store *db.DB, credential string) *EdgeService {
	return &EdgeService{store: store, credential: credential, clock: func() time.Time { return time.Now().UTC() }}
}

func (s *EdgeService) SetClock(clock func() time.Time) {
	if clock != nil {
		s.clock = clock
	}
}

type edgeNodeRegistration struct {
	NodeID       string `json:"edge_node_id"`
	EdgePool     string `json:"edge_pool"`
	RelayID      string `json:"relay_id"`
	RelayRegion  string `json:"relay_region"`
	RelayName    string `json:"relay_name"`
	Artifact     string `json:"artifact"`
	Protocol     string `json:"protocol"`
	ProcessEpoch string `json:"process_epoch"`
	Capacity     uint32 `json:"capacity"`
	Endpoint     struct {
		Host     string `json:"host"`
		TCPPort  uint16 `json:"tcp_port"`
		QUICPort uint16 `json:"quic_port"`
	} `json:"connector_endpoint"`
	// CarrierEndpoint is the canonical data-carrier listener. It is kept
	// separate from ConnectorEndpoint because the latter is the legacy FRP
	// connector transport and must never be used for preview carrier routes.
	CarrierEndpoint struct {
		Host     string `json:"host"`
		TCPPort  uint16 `json:"tcp_port"`
		QUICPort uint16 `json:"quic_port"`
	} `json:"carrier_endpoint"`
	CarrierServerSPKISHA256          string `json:"carrier_server_spki_sha256"`
	CarrierServerCertificateChainPEM string `json:"carrier_server_certificate_chain_pem"`
	SignalingHost                    string `json:"signaling_host"`
	STUNEndpoint                     struct {
		Host string `json:"host"`
		Port uint16 `json:"port"`
	} `json:"stun_endpoint"`
}

type edgeNodeObservation struct {
	NodeID        string    `json:"edge_node_id"`
	ProcessEpoch  string    `json:"process_epoch"`
	Ready         bool      `json:"ready"`
	Draining      bool      `json:"draining"`
	ActiveStreams uint32    `json:"active_streams"`
	At            time.Time `json:"at"`
}

type edgeUsageRequest struct {
	OperationID string          `json:"operation_id"`
	Node        string          `json:"edge_node_id"`
	Epoch       string          `json:"counter_epoch"`
	Environment string          `json:"environment_id"`
	Route       string          `json:"route_id"`
	Revision    int64           `json:"route_revision"`
	Direction   string          `json:"direction"`
	Bytes       int64           `json:"bytes"`
	Start       time.Time       `json:"interval_start"`
	End         time.Time       `json:"interval_end"`
	Payload     json.RawMessage `json:"signed_payload,omitempty"`
}

const controlTunnelNodeStaleAfter = 2 * time.Minute

const maxProbeRegions = 32

type ProbeRegion struct {
	RelayID  string `json:"relay_id"`
	Region   string `json:"region"`
	Name     string `json:"name"`
	STUNURL  string `json:"stun_url"`
	HTTPSURL string `json:"https_url"`
}

func (s *EdgeService) ListProbeRegions(ctx context.Context) ([]ProbeRegion, error) {
	rows, err := s.store.Queries().ListReadyControlTunnelProbeRegions(ctx, sql.NullTime{
		Time:  s.clock().UTC().Add(-controlTunnelNodeStaleAfter),
		Valid: true,
	})
	if err != nil {
		return nil, err
	}
	regions := make([]ProbeRegion, 0, min(len(rows), maxProbeRegions))
	for _, row := range rows {
		region := strings.TrimSpace(row.RelayRegion.String)
		relayID := strings.TrimSpace(row.RelayID.String)
		name := strings.TrimSpace(row.RelayName.String)
		signalingHost := strings.TrimSpace(row.SignalingHost.String)
		stunHost := strings.TrimSpace(row.StunHost.String)
		if !validProbeRegion(relayID) || !validProbeRegion(region) || name == "" || len(name) > 80 || !validRouteHost(signalingHost) || !validRouteHost(stunHost) || !row.StunPort.Valid || row.StunPort.Int32 < 1 || row.StunPort.Int32 > 65535 {
			continue
		}
		regions = append(regions, ProbeRegion{
			RelayID:  relayID,
			Region:   region,
			Name:     name,
			STUNURL:  "stun:" + net.JoinHostPort(stunHost, strconv.Itoa(int(row.StunPort.Int32))),
			HTTPSURL: (&url.URL{Scheme: "https", Host: signalingHost, Path: "/network-check/v1"}).String(),
		})
	}
	return regions, nil
}

func validProbeRegion(value string) bool {
	if value == "" || len(value) > 63 {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return value[0] != '-' && value[len(value)-1] != '-'
}

func (s *EdgeService) RegisterNode(ctx context.Context, r edgeNodeRegistration) error {
	if r.RelayRegion == "" {
		r.RelayRegion = r.EdgePool
	}
	if r.RelayID == "" {
		r.RelayID = r.NodeID
	}
	if r.RelayName == "" {
		r.RelayName = r.RelayRegion
	}
	if r.NodeID == "" || r.EdgePool == "" || !validProbeRegion(r.RelayID) || !validProbeRegion(r.RelayRegion) || strings.TrimSpace(r.RelayName) == "" || len(r.RelayName) > 80 || r.Protocol == "" || r.ProcessEpoch == "" || r.Capacity == 0 || r.Endpoint.Host == "" || r.Endpoint.TCPPort == 0 || r.Endpoint.QUICPort == 0 || r.SignalingHost == "" || r.STUNEndpoint.Host == "" || r.STUNEndpoint.Port == 0 || validateCarrierServerCertificateChain(r.CarrierServerCertificateChainPEM, r.CarrierServerSPKISHA256, r.CarrierEndpoint.Host, s.clock().UTC()) != nil {
		return ErrInvalidUsageReport
	}
	if err := validateCarrierEndpoint(r.CarrierEndpoint); err != nil {
		return err
	}
	capacity, _ := json.Marshal(map[string]any{"connectors": r.Capacity, "artifact": r.Artifact})
	now := sql.NullTime{Time: s.clock().UTC(), Valid: true}
	_, err := s.store.Queries().RegisterControlTunnelNode(ctx, dbsqlc.RegisterControlTunnelNodeParams{
		ID: r.NodeID, EdgePool: r.EdgePool,
		RelayID: sql.NullString{String: r.RelayID, Valid: true}, RelayRegion: sql.NullString{String: r.RelayRegion, Valid: true}, RelayName: sql.NullString{String: r.RelayName, Valid: true},
		ProtocolVersion: r.Protocol, ProcessEpoch: r.ProcessEpoch,
		EndpointHost: sql.NullString{String: r.Endpoint.Host, Valid: true}, EndpointTcpPort: sql.NullInt32{Int32: int32(r.Endpoint.TCPPort), Valid: true}, EndpointQuicPort: sql.NullInt32{Int32: int32(r.Endpoint.QUICPort), Valid: true},
		CarrierEndpointHost: sql.NullString{String: r.CarrierEndpoint.Host, Valid: true}, CarrierEndpointTcpPort: sql.NullInt32{Int32: int32(r.CarrierEndpoint.TCPPort), Valid: true}, CarrierEndpointQuicPort: sql.NullInt32{Int32: int32(r.CarrierEndpoint.QUICPort), Valid: true},
		CarrierServerSpkiSha256:          sql.NullString{String: r.CarrierServerSPKISHA256, Valid: true},
		CarrierServerCertificateChainPem: sql.NullString{String: r.CarrierServerCertificateChainPEM, Valid: true},
		SignalingHost:                    sql.NullString{String: r.SignalingHost, Valid: true}, StunHost: sql.NullString{String: r.STUNEndpoint.Host, Valid: true}, StunPort: sql.NullInt32{Int32: int32(r.STUNEndpoint.Port), Valid: true},
		Capacity: capacity, Now: now,
	})
	return err
}

func validCarrierServerSPKISHA256(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size
}

func validateCarrierServerCertificateChain(chainPEM, pin, hostname string, now time.Time) error {
	if len(chainPEM) == 0 || len(chainPEM) > 64<<10 || !validCarrierServerSPKISHA256(pin) {
		return ErrInvalidUsageReport
	}
	rest := []byte(chainPEM)
	count := 0
	var leaf *x509.Certificate
	for len(rest) > 0 {
		block, next := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return ErrInvalidUsageReport
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return ErrInvalidUsageReport
		}
		if count == 0 {
			leaf = certificate
		}
		count++
		if count > 8 {
			return ErrInvalidUsageReport
		}
		rest = next
	}
	if leaf == nil {
		return ErrInvalidUsageReport
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || leaf.VerifyHostname(hostname) != nil {
		return ErrInvalidUsageReport
	}
	digest := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	if pin != "sha256:"+hex.EncodeToString(digest[:]) {
		return ErrInvalidUsageReport
	}
	return nil
}

func validateCarrierEndpoint(endpoint struct {
	Host     string `json:"host"`
	TCPPort  uint16 `json:"tcp_port"`
	QUICPort uint16 `json:"quic_port"`
}) error {
	host := strings.TrimSpace(endpoint.Host)
	if host != endpoint.Host || len(host) > 253 || strings.ContainsAny(host, "/ 	\r\n\x00") || endpoint.TCPPort == 0 || endpoint.QUICPort == 0 || endpoint.TCPPort == endpoint.QUICPort {
		return ErrInvalidUsageReport
	}
	return nil
}

func (s *EdgeService) Heartbeat(ctx context.Context, r edgeNodeObservation) error {
	if r.NodeID == "" || r.ProcessEpoch == "" || r.At.IsZero() {
		return ErrInvalidUsageReport
	}
	observation, _ := json.Marshal(map[string]any{"active_streams": r.ActiveStreams})
	_, err := s.store.Queries().HeartbeatControlTunnelNode(ctx, dbsqlc.HeartbeatControlTunnelNodeParams{ID: r.NodeID, ProcessEpoch: r.ProcessEpoch, Ready: r.Ready, Draining: r.Draining, Observation: observation, Now: sql.NullTime{Time: r.At, Valid: true}})
	if err != nil {
		return err
	}
	return nil
}

func (s *EdgeService) Assignment(ctx context.Context, environment, machine, connector string) (dbsqlc.GetControlConnectorAssignmentRow, error) {
	return s.store.Queries().GetControlConnectorAssignment(ctx, dbsqlc.GetControlConnectorAssignmentParams{EnvironmentID: environment, MachineID: machine, ConnectorID: connector})
}

func (s *EdgeService) Routes(ctx context.Context, nodeID string) ([]dbsqlc.ListControlRoutesForNodeRow, error) {
	return s.store.Queries().ListControlRoutesForNode(ctx, sql.NullString{String: nodeID, Valid: nodeID != ""})
}

func (s *EdgeService) Usage(ctx context.Context, r edgeUsageRequest) (UsageReceipt, error) {
	if err := s.verifyUsage(ctx, r); err != nil {
		return UsageReceipt{}, err
	}
	return ReconcileUsageWithBandwidth(ctx, s.store, UsageReport{OperationID: r.OperationID, EdgeNodeID: r.Node, CounterEpoch: r.Epoch, EnvironmentID: r.Environment, RouteID: r.Route, RouteRevision: r.Revision, Direction: r.Direction, Bytes: r.Bytes, IntervalStart: r.Start, IntervalEnd: r.End}, s.clock(), s.bandwidth)
}

func (s *EdgeService) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/nodes/register", s.handleRegister)
	mux.HandleFunc("POST /v1/nodes/heartbeat", s.handleHeartbeat)
	mux.HandleFunc("POST /v1/edge/assignments/current", s.handleAssignment)
	mux.HandleFunc("POST /v1/edge/routes/desired-state", s.handleRoutes)
	mux.HandleFunc("POST /v1/edge/routes/observations", s.handleObservedRoutes)
	mux.HandleFunc("POST /v1/edge/usage-reports", s.handleUsage)
	mux.HandleFunc("GET /v1/trust/revocations", s.handleRevocations)
	if s.certificateDistribution != nil {
		mux.Handle("/v1/edge/certificates/distributions/", s.certificateDistribution)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/connectors/admission" {
			s.handleConnectorAdmission(w, r)
			return
		}
		if subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")), []byte(s.credential)) != 1 || s.credential == "" {
			writeEdgeError(w, r, http.StatusUnauthorized, "unauthenticated", false, 0)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (s *EdgeService) handleObservedRoutes(w http.ResponseWriter, r *http.Request) {
	var input struct {
		NodeID string             `json:"edge_node_id"`
		Routes []RouteObservation `json:"routes"`
	}
	if !s.decode(w, r, &input) || len(input.Routes) > 1000 {
		return
	}
	if err := s.ObserveRoutes(r.Context(), input.NodeID, input.Routes); err != nil {
		slog.ErrorContext(r.Context(), "control route observation failed", "edge_node_id", input.NodeID, "error", err)
		if errors.Is(err, ErrAssignmentConflict) {
			writeEdgeError(w, r, http.StatusConflict, "version_conflict", false, 0)
			return
		}
		writeEdgeError(w, r, http.StatusBadRequest, "invalid_request", false, 0)
		return
	}
	writeEdgeJSON(w, http.StatusNoContent, nil)
}

func (s *EdgeService) handleRevocations(w http.ResponseWriter, r *http.Request) {
	document, err := s.Revocations(r.Context())
	if err != nil {
		writeEdgeError(w, r, http.StatusServiceUnavailable, "provider_unavailable", true, 5)
		return
	}
	writeEdgeJSON(w, http.StatusOK, document)
}

func (s *EdgeService) handleConnectorAdmission(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, maxEdgeDocument+1))
	if err != nil || len(body) > maxEdgeDocument || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		writeEdgeError(w, r, http.StatusBadRequest, "invalid_request", false, 0)
		return
	}
	var input connectorAdmissionRequest
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		writeEdgeError(w, r, http.StatusBadRequest, "invalid_request", false, 0)
		return
	}
	identity := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	proof, err := base64.RawURLEncoding.DecodeString(r.Header.Get("X-Paperboat-Machine-Proof"))
	if err != nil {
		writeEdgeError(w, r, http.StatusUnauthorized, "credential_invalid", false, 0)
		return
	}
	result, err := s.IssueConnectorAdmission(r.Context(), identity, proof, body, input.EdgePool, r.Method, r.URL.Path)
	if err != nil {
		if errors.Is(err, ErrUsageOperationConflict) {
			writeEdgeError(w, r, http.StatusConflict, "operation_conflict", false, 0)
			return
		}
		writeEdgeError(w, r, http.StatusUnauthorized, "credential_invalid", false, 0)
		return
	}
	writeEdgeJSON(w, http.StatusOK, result)
}

func (s *EdgeService) decode(w http.ResponseWriter, r *http.Request, target any) bool {
	defer r.Body.Close()
	data, err := io.ReadAll(io.LimitReader(r.Body, maxEdgeDocument+1))
	if err != nil || len(data) > maxEdgeDocument || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		writeEdgeError(w, r, http.StatusBadRequest, "invalid_request", false, 0)
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		writeEdgeError(w, r, http.StatusBadRequest, "invalid_request", false, 0)
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeEdgeError(w, r, http.StatusBadRequest, "invalid_request", false, 0)
		return false
	}
	return true
}

func (s *EdgeService) handleRegister(w http.ResponseWriter, r *http.Request) {
	var input edgeNodeRegistration
	if !s.decode(w, r, &input) {
		return
	}
	if err := s.RegisterNode(r.Context(), input); err != nil {
		writeEdgeError(w, r, http.StatusBadRequest, "invalid_request", false, 0)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *EdgeService) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	var input edgeNodeObservation
	if !s.decode(w, r, &input) {
		return
	}
	if err := s.Heartbeat(r.Context(), input); err != nil {
		writeEdgeError(w, r, http.StatusConflict, "node_observation_stale", false, 0)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *EdgeService) handleAssignment(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Environment string `json:"environment_id"`
		Machine     string `json:"machine_id"`
		Connector   string `json:"connector_id"`
	}
	if !s.decode(w, r, &input) {
		return
	}
	row, err := s.Assignment(r.Context(), input.Environment, input.Machine, input.Connector)
	if err != nil {
		writeEdgeError(w, r, http.StatusNotFound, "assignment_unavailable", false, 0)
		return
	}
	writeEdgeJSON(w, http.StatusOK, map[string]any{"connector_generation": row.Generation, "edge_pool": row.EdgePool, "edge_node_id": row.EdgeNodeID.String, "revoked": row.Revoked.Bool})
}

func (s *EdgeService) handleRoutes(w http.ResponseWriter, r *http.Request) {
	var input struct {
		NodeID       string `json:"edge_node_id"`
		ProcessEpoch string `json:"process_epoch,omitempty"`
	}
	if !s.decode(w, r, &input) {
		return
	}
	if input.ProcessEpoch != "" {
		rows, err := s.ListTunnelEdgeRouteAssignmentsForNodeV1(r.Context(), input.NodeID, input.ProcessEpoch)
		if err != nil {
			writeEdgeError(w, r, http.StatusServiceUnavailable, "control_unavailable", true, 1000)
			return
		}
		items := make([]map[string]any, 0, len(rows))
		for _, row := range rows {
			items = append(items, tunnelEdgeRouteJSON(row))
		}
		legacyRows, err := s.Routes(r.Context(), input.NodeID)
		if err != nil {
			writeEdgeError(w, r, http.StatusServiceUnavailable, "control_unavailable", true, 1000)
			return
		}
		for _, row := range legacyRows {
			items = append(items, legacyEdgeRouteJSON(row))
		}
		writeEdgeJSON(w, http.StatusOK, map[string]any{"complete": true, "routes": items})
		return
	}
	rows, err := s.Routes(r.Context(), input.NodeID)
	if err != nil {
		writeEdgeError(w, r, http.StatusServiceUnavailable, "control_unavailable", true, 1000)
		return
	}
	// Callers without a process epoch are the legacy control projection. The
	// process-fenced canonical route snapshot above is authoritative for current
	// edge runtimes and deliberately carries an explicit completion marker.
	items := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		items = append(items, legacyEdgeRouteJSON(row))
	}
	writeEdgeJSON(w, http.StatusOK, map[string]any{"routes": items})
}

func legacyEdgeRouteJSON(row dbsqlc.ListControlRoutesForNodeRow) map[string]any {
	return map[string]any{
		"route_id":             row.RouteID,
		"route_revision":       row.RouteRevision,
		"environment_id":       row.EnvironmentID,
		"connector_id":         row.ConnectorID,
		"connector_generation": row.ConnectorGeneration,
		"edge_node_id":         row.EdgeNodeID.String,
		"kind":                 row.Kind,
		"public_host":          row.PublicHost,
		"preview_state":        row.PreviewState,
		"preview_reason":       row.PreviewReason,
		"target": map[string]any{
			"host": row.TargetHost,
			"port": row.TargetPort,
		},
	}
}

func (s *EdgeService) handleUsage(w http.ResponseWriter, r *http.Request) {
	var input edgeUsageRequest
	if !s.decode(w, r, &input) {
		return
	}
	result, err := s.Usage(r.Context(), input)
	if err != nil {
		status, code, retryable, retryAfterMS := usageErrorResponse(err)
		if retryable {
			slog.ErrorContext(r.Context(), "control usage reconciliation failed", "error", err)
		}
		writeEdgeError(w, r, status, code, retryable, retryAfterMS)
		return
	}
	writeEdgeJSON(w, http.StatusOK, map[string]any{"delta": result.DeltaBytes})
}

func usageErrorResponse(err error) (status int, code string, retryable bool, retryAfterMS int) {
	switch {
	case errors.Is(err, ErrUsageOperationConflict):
		return http.StatusConflict, "operation_conflict", false, 0
	case errors.Is(err, ErrUsageSignature):
		return http.StatusBadRequest, "credential_invalid", false, 0
	case errors.Is(err, ErrInvalidUsageReport):
		return http.StatusBadRequest, "invalid_request", false, 0
	default:
		return http.StatusServiceUnavailable, "control_unavailable", true, 1000
	}
}

func writeEdgeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func parseTunnelEdgeConfigHash(value string) ([]byte, error) {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return nil, ErrInvalidUsageReport
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	if err != nil || len(decoded) != sha256.Size {
		return nil, ErrInvalidUsageReport
	}
	return decoded, nil
}

func writeEdgeError(w http.ResponseWriter, r *http.Request, status int, code string, retryable bool, retryAfterMS int) {
	requestID := observability.RequestID(r.Context())
	if requestID == "" {
		requestID = "req_unknown"
	}
	value := map[string]any{"code": code, "message": "control request rejected", "requestId": requestID, "retryable": retryable}
	if retryAfterMS > 0 {
		value["retryAfterMs"] = retryAfterMS
		w.Header().Set("Retry-After", "1")
	}
	writeEdgeJSON(w, status, value)
}
