package peersessions

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/relayselection"
	"github.com/pinksaucepasta/paperboat-server/internal/secrets"
)

type SQLRepository struct {
	store         *db.DB
	audit         *audit.Writer
	nodeFreshness time.Duration
	encryptionKey string
}

// Expire removes expired intents and revokes their signaling/relay grants.
// It is deliberately exposed only through the service worker below.
func (r *SQLRepository) Expire(ctx context.Context, now time.Time) error {
	_, err := r.store.Queries().ExpirePeerSessionIntents(ctx, now)
	return err
}

func NewSQLRepository(store *db.DB, writer *audit.Writer, nodeFreshness time.Duration, encryptionKey string) (*SQLRepository, error) {
	if store == nil || writer == nil || nodeFreshness <= 0 || nodeFreshness > 10*time.Minute || encryptionKey == "" {
		return nil, ErrInvalid
	}
	return &SQLRepository{store: store, audit: writer, nodeFreshness: nodeFreshness, encryptionKey: encryptionKey}, nil
}

func (r *SQLRepository) Reserve(ctx context.Context, request Request, hash [32]byte, proposed reservation) (reservation, error) {
	var result reservation
	err := r.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		authority, err := tx.Queries().ResolvePeerSessionAuthorityForUpdate(ctx, dbsqlc.ResolvePeerSessionAuthorityForUpdateParams{
			ControllingCertificateFingerprint: request.ControllingCertificateFingerprint,
			ControlledCertificateFingerprint:  request.ControlledCertificateFingerprint,
			EnvironmentID:                     request.EnvironmentID,
			CLIClientSessionID:                request.CLIClientSessionID, UserID: request.UserID, Now: proposed.IssuedAt,
			NodeStaleAfter: proposed.IssuedAt.Add(-r.nodeFreshness),
		})
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnavailable
		}
		if err != nil {
			return err
		}
		trustedKeys, err := trustedKeysFromRows(tx.Queries(), ctx, request.UserID)
		if err != nil {
			return err
		}
		proposed.Controlling.EndpointID, proposed.Controlling.PeerEndpointID = authority.ControllingEndpointID, authority.ControlledEndpointID
		proposed.Controlled.EndpointID, proposed.Controlled.PeerEndpointID = authority.ControlledEndpointID, authority.ControllingEndpointID
		proposed.EdgeNodeID, proposed.EdgePool = authority.EdgeNodeID, authority.RelayRegion.String
		proposed.HostGeneration, proposed.AuthorizationGeneration = authority.HostGeneration, authority.AuthorizationGeneration
		proposed.SignalingHost, proposed.STUNHost, proposed.STUNPort = authority.SignalingHost.String, authority.StunHost.String, uint16(authority.StunPort.Int32)
		proposed.ControllingCertificate = append([]byte(nil), authority.ControllingCertificate...)
		proposed.ControlledCertificate = append([]byte(nil), authority.ControlledCertificate...)
		proposed.ControllingCertificateKeyID = authority.ControllingKeyID
		proposed.ControlledCertificateKeyID = authority.ControlledKeyID
		proposed.TrustedKeys = trustedKeys

		existing, err := tx.Queries().GetPeerSessionIntentByOperationForUpdate(ctx, request.OperationKey)
		if err == nil {
			if !bytes.Equal(existing.RequestHash, hash[:]) {
				return ErrConflict
			}
			ready, readyErr := tx.Queries().IsPeerRelayNodeReady(ctx, dbsqlc.IsPeerRelayNodeReadyParams{ID: existing.EdgeNodeID, NodeStaleAfter: proposed.IssuedAt.Add(-r.nodeFreshness)})
			if readyErr != nil {
				return readyErr
			}
			if existing.State != "active" || !existing.ExpiresAt.After(proposed.IssuedAt) || !ready {
				return ErrUnavailable
			}
			grants, listErr := tx.Queries().ListPeerSignalingGrantsForIntent(ctx, existing.ID)
			if listErr != nil {
				return listErr
			}
			relay, relayErr := tx.Queries().GetPeerRelayAllocationForIntent(ctx, existing.ID)
			if relayErr != nil {
				return relayErr
			}
			result, err = r.replayReservation(existing, grants, relay, authority, trustedKeys)
			return err
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if request.RelayLatency != nil && authority.RelayLatencyWorkerGeneration > 0 && authority.RelayLatencyGeneration > 0 && authority.RelayLatencyObservedAt.Valid {
			selected, selectErr := r.selectRelayNode(ctx, tx, request, authority, proposed.IssuedAt)
			if selectErr != nil {
				return selectErr
			}
			proposed.EdgeNodeID, proposed.EdgePool = selected.ID, selected.RelayRegion.String
			proposed.SignalingHost, proposed.STUNHost, proposed.STUNPort = selected.SignalingHost.String, selected.StunHost.String, uint16(selected.StunPort.Int32)
		}
		credentials, err := json.Marshal(struct {
			Ufrag        string           `json:"ufrag"`
			Password     string           `json:"password"`
			Consumer     string           `json:"consumer"`
			AllowedPaths []string         `json:"allowed_paths"`
			Transfer     *TransferBinding `json:"transfer,omitempty"`
		}{proposed.ICEUfrag, proposed.ICEPassword, proposed.Consumer, proposed.AllowedPaths, proposed.Transfer})
		if err != nil {
			return err
		}
		credentialsCiphertext, err := secrets.Encrypt(r.encryptionKey, string(credentials))
		if err != nil {
			return err
		}
		intent, err := tx.Queries().CreatePeerSessionIntent(ctx, dbsqlc.CreatePeerSessionIntentParams{
			ID: proposed.IntentID, OperationKey: request.OperationKey, RequestHash: hash[:],
			UserID: request.UserID, CLIClientSessionID: request.CLIClientSessionID,
			EnvironmentID: request.EnvironmentID, Purpose: request.Purpose, EdgeNodeID: proposed.EdgeNodeID,
			ControllingCertificateFingerprint: request.ControllingCertificateFingerprint,
			ControlledCertificateFingerprint:  request.ControlledCertificateFingerprint,
			AttemptGeneration:                 request.AttemptGeneration, NetworkGeneration: request.NetworkGeneration,
			IceCredentialsCiphertext: credentialsCiphertext,
			EdgePool:                 sql.NullString{String: proposed.EdgePool, Valid: true},
			SignalingHost:            sql.NullString{String: proposed.SignalingHost, Valid: true},
			StunHost:                 sql.NullString{String: proposed.STUNHost, Valid: true},
			StunPort:                 sql.NullInt32{Int32: int32(proposed.STUNPort), Valid: true},
			ExpiresAt:                proposed.ExpiresAt, CreatedAt: proposed.IssuedAt,
		})
		if err != nil {
			return err
		}
		for _, value := range []grant{proposed.Controlling, proposed.Controlled} {
			if _, err := tx.Queries().CreatePeerSignalingGrant(ctx, dbsqlc.CreatePeerSignalingGrantParams{IntentID: intent.ID, Role: value.Role, EndpointID: value.EndpointID, PeerEndpointID: value.PeerEndpointID, Jti: value.JTI, IssuedAt: proposed.IssuedAt, ExpiresAt: proposed.ExpiresAt}); err != nil {
				return err
			}
		}
		routeAllocation, err := base64.RawURLEncoding.Strict().DecodeString(proposed.Relay.RouteAllocation)
		if err != nil || len(routeAllocation) != 16 || base64.RawURLEncoding.EncodeToString(routeAllocation) != proposed.Relay.RouteAllocation {
			return ErrInvalid
		}
		if _, err := tx.Queries().CreatePeerRelayAllocation(ctx, dbsqlc.CreatePeerRelayAllocationParams{IntentID: intent.ID, RouteAllocation: routeAllocation, Jti: proposed.Relay.JTI, RouteGeneration: proposed.Relay.RouteGeneration, ByteLimit: proposed.Relay.ByteLimit, IssuedAt: proposed.IssuedAt, ExpiresAt: proposed.ExpiresAt}); err != nil {
			return err
		}
		if err := r.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: request.UserID, ActorType: audit.ActorUser, EventType: "peer_session.intent_created", ResourceType: "peer_session_intent", ResourceID: intent.ID, IdempotencyKey: request.OperationKey, Metadata: map[string]any{"environment_id": request.EnvironmentID, "edge_node_id": proposed.EdgeNodeID, "attempt_generation": request.AttemptGeneration, "network_generation": request.NetworkGeneration}}); err != nil {
			return err
		}
		result = proposed
		return nil
	})
	return result, err
}

func (r *SQLRepository) selectRelayNode(ctx context.Context, tx *db.Tx, request Request, authority dbsqlc.ResolvePeerSessionAuthorityForUpdateRow, now time.Time) (dbsqlc.ListReadyPeerRelayNodesRow, error) {
	var hostVector RelayLatencyVector
	if json.Unmarshal(authority.RelayLatencyVector, &hostVector) != nil {
		// Vectors written before relay-success metadata were sample arrays.
		if json.Unmarshal(authority.RelayLatencyVector, &hostVector.Samples) != nil {
			return dbsqlc.ListReadyPeerRelayNodesRow{}, ErrUnavailable
		}
		hostVector.Generation = uint64(authority.RelayLatencyGeneration)
		hostVector.ObservedAt = authority.RelayLatencyObservedAt.Time
	}
	nodes, err := tx.Queries().ListReadyPeerRelayNodes(ctx, now.Add(-r.nodeFreshness))
	if err != nil || len(nodes) == 0 {
		return dbsqlc.ListReadyPeerRelayNodesRow{}, ErrUnavailable
	}
	choices := make([]relayselection.Node, 0, len(nodes))
	for index := range nodes {
		choices = append(choices, relayselection.Node{Region: nodes[index].RelayRegion.String, Value: index})
	}
	client := relayVector(request.RelayLatency.Generation, request.RelayLatency.ObservedAt, request.RelayLatency.Samples)
	client.RelaySuccessRegion, client.RelaySuccessAt = request.RelayLatency.RelaySuccessRegion, request.RelayLatency.RelaySuccessAt
	host := relayVector(uint64(authority.RelayLatencyGeneration), authority.RelayLatencyObservedAt.Time, hostVector.Samples)
	host.RelaySuccessRegion, host.RelaySuccessAt = hostVector.RelaySuccessRegion, hostVector.RelaySuccessAt
	key := dbsqlc.EnsurePeerRelaySelectionStateParams{UserID: request.UserID, MachineID: authority.ControlledEndpointID, NetworkGeneration: request.NetworkGeneration, HostWorkerGeneration: authority.RelayLatencyWorkerGeneration, UpdatedAt: now}
	if err := tx.Queries().EnsurePeerRelaySelectionState(ctx, key); err != nil {
		return dbsqlc.ListReadyPeerRelayNodesRow{}, err
	}
	if _, err := tx.Queries().PrunePeerRelaySelectionStates(ctx, dbsqlc.PrunePeerRelaySelectionStatesParams{UserID: key.UserID, MachineID: key.MachineID, StaleBefore: now.Add(-time.Hour)}); err != nil {
		return dbsqlc.ListReadyPeerRelayNodesRow{}, err
	}
	stored, err := tx.Queries().GetPeerRelaySelectionStateForUpdate(ctx, dbsqlc.GetPeerRelaySelectionStateForUpdateParams{UserID: key.UserID, MachineID: key.MachineID, NetworkGeneration: key.NetworkGeneration, HostWorkerGeneration: key.HostWorkerGeneration})
	if err != nil {
		return dbsqlc.ListReadyPeerRelayNodesRow{}, err
	}
	previous := relayselection.State{Current: stored.CurrentRegion.String, ClientGeneration: uint64(stored.ClientGeneration), Candidate: stored.CandidateRegion.String, CandidateSamples: uint8(stored.CandidateSamples)}
	if stored.ClientObservedAt.Valid {
		previous.ClientObservedAt = stored.ClientObservedAt.Time
	}
	if stored.CandidateFirstObservedAt.Valid {
		previous.CandidateFirstObservedAt = stored.CandidateFirstObservedAt.Time
	}
	if stored.CandidateLastObservedAt.Valid {
		previous.CandidateLastObservedAt = stored.CandidateLastObservedAt.Time
	}
	selected, next, err := relayselection.Select(now, previous, client, host, choices)
	if err != nil {
		return dbsqlc.ListReadyPeerRelayNodesRow{}, err
	}
	updated, err := tx.Queries().UpdatePeerRelaySelectionState(ctx, dbsqlc.UpdatePeerRelaySelectionStateParams{
		CurrentRegion: sql.NullString{String: next.Current, Valid: next.Current != ""}, ClientGeneration: int64(next.ClientGeneration), ClientObservedAt: sql.NullTime{Time: next.ClientObservedAt, Valid: !next.ClientObservedAt.IsZero()}, CandidateRegion: sql.NullString{String: next.Candidate, Valid: next.Candidate != ""}, CandidateFirstObservedAt: sql.NullTime{Time: next.CandidateFirstObservedAt, Valid: !next.CandidateFirstObservedAt.IsZero()}, CandidateLastObservedAt: sql.NullTime{Time: next.CandidateLastObservedAt, Valid: !next.CandidateLastObservedAt.IsZero()}, CandidateSamples: int32(next.CandidateSamples), UpdatedAt: now, UserID: key.UserID, MachineID: key.MachineID, NetworkGeneration: key.NetworkGeneration, HostWorkerGeneration: key.HostWorkerGeneration,
	})
	if err != nil || updated != 1 {
		return dbsqlc.ListReadyPeerRelayNodesRow{}, errors.Join(ErrUnavailable, err)
	}
	index, ok := selected.Value.(int)
	if !ok || index < 0 || index >= len(nodes) {
		return dbsqlc.ListReadyPeerRelayNodesRow{}, ErrUnavailable
	}
	return nodes[index], nil
}

func relayVector(generation uint64, observedAt time.Time, samples []RelayLatencySample) relayselection.Vector {
	result := relayselection.Vector{Generation: generation, ObservedAt: observedAt, Samples: make([]relayselection.Sample, 0, len(samples))}
	for _, sample := range samples {
		result.Samples = append(result.Samples, relayselection.Sample{Region: sample.Region, RTT: time.Duration(sample.RTTMS) * time.Millisecond})
	}
	return result
}

func (r *SQLRepository) Revoke(ctx context.Context, actorUserID, operationKey, intentID string, attemptGeneration int64, reason string, now time.Time) error {
	if r == nil || ctx == nil || !bounded(operationKey, 16, 256) || !bounded(intentID, 1, 132) || !bounded(actorUserID, 0, 256) || attemptGeneration <= 0 || !validRevocationReason(reason) || now.IsZero() {
		return ErrInvalid
	}
	now = now.UTC()
	return r.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		_, err := tx.Queries().ReservePeerSessionRevocation(ctx, dbsqlc.ReservePeerSessionRevocationParams{OperationKey: operationKey, IntentID: intentID, ActorUserID: actorUserID, Reason: reason, CreatedAt: now})
		if errors.Is(err, sql.ErrNoRows) {
			existing, getErr := tx.Queries().GetPeerSessionRevocationOperation(ctx, operationKey)
			if getErr != nil || existing.IntentID != intentID || existing.ActorUserID.String != actorUserID || existing.Reason != reason {
				return ErrConflict
			}
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := tx.Queries().RevokePeerSessionIntent(ctx, dbsqlc.RevokePeerSessionIntentParams{ID: intentID, AttemptGeneration: attemptGeneration, ActorUserID: actorUserID, Reason: reason, Now: now}); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrUnavailable
			}
			return err
		}
		actorType := audit.ActorSystem
		if actorUserID != "" {
			actorType = audit.ActorUser
		}
		return r.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: actorUserID, ActorType: actorType, EventType: "peer_session.intent_revoked", ResourceType: "peer_session_intent", ResourceID: intentID, IdempotencyKey: operationKey, Metadata: map[string]any{"reason": reason}})
	})
}

func (r *SQLRepository) Controlled(ctx context.Context, userID, machineID string, hostGeneration int64, now time.Time) (reservation, error) {
	if r == nil || ctx == nil || !bounded(userID, 1, 256) || !bounded(machineID, 1, 128) || hostGeneration <= 0 || now.IsZero() {
		return reservation{}, ErrInvalid
	}
	var row dbsqlc.ResolveControlledPeerSessionForMachineRow
	var trustedKeys []TrustedKey
	err := r.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		var resolveErr error
		row, resolveErr = tx.Queries().ResolveControlledPeerSessionForMachine(ctx, dbsqlc.ResolveControlledPeerSessionForMachineParams{UserID: userID, MachineID: machineID, HostGeneration: hostGeneration, Now: now.UTC(), NodeStaleAfter: now.UTC().Add(-r.nodeFreshness)})
		if resolveErr != nil {
			return resolveErr
		}
		var keyErr error
		trustedKeys, keyErr = trustedKeysFromRows(tx.Queries(), ctx, row.UserID)
		if keyErr != nil {
			return keyErr
		}
		updated, markErr := tx.Queries().MarkControlledPeerSessionDelivered(ctx, dbsqlc.MarkControlledPeerSessionDeliveredParams{ID: row.ID, DeliveredAt: now.UTC()})
		if markErr != nil {
			return markErr
		}
		if updated != 1 {
			return ErrUnavailable
		}
		return nil
	})
	if errors.Is(err, sql.ErrNoRows) {
		return reservation{}, ErrUnavailable
	}
	if err != nil {
		return reservation{}, err
	}
	plaintext, err := secrets.Decrypt(r.encryptionKey, row.IceCredentialsCiphertext)
	if err != nil {
		return reservation{}, ErrUnavailable
	}
	var credentials struct {
		Ufrag        string           `json:"ufrag"`
		Password     string           `json:"password"`
		Consumer     string           `json:"consumer"`
		AllowedPaths []string         `json:"allowed_paths"`
		Transfer     *TransferBinding `json:"transfer,omitempty"`
	}
	if json.Unmarshal([]byte(plaintext), &credentials) != nil || credentials.Ufrag == "" || credentials.Password == "" || !validPurposeConsumer(row.Purpose, credentials.Consumer) || !validAllowedPaths(row.Purpose, credentials.AllowedPaths) || !validTransferBinding(row.Purpose, credentials.Transfer) || !row.EdgePool.Valid || !row.SignalingHost.Valid || !row.StunHost.Valid || !row.StunPort.Valid || row.StunPort.Int32 <= 0 || row.StunPort.Int32 > 65535 || len(row.RouteAllocation) != 16 || row.RouteGeneration <= 0 || row.ByteLimit <= 0 || row.AuthorizationGeneration <= 0 || row.HostGeneration != hostGeneration {
		return reservation{}, ErrUnavailable
	}
	return reservation{UserID: row.UserID, CLIClientSessionID: row.CLIClientSessionID, OperationKey: row.OperationKey, IntentID: row.ID, EnvironmentID: row.EnvironmentID, Purpose: row.Purpose, Consumer: credentials.Consumer, AllowedPaths: append([]string(nil), credentials.AllowedPaths...), EdgeNodeID: row.EdgeNodeID, EdgePool: row.EdgePool.String, SignalingHost: row.SignalingHost.String, STUNHost: row.StunHost.String, STUNPort: uint16(row.StunPort.Int32), ICEUfrag: credentials.Ufrag, ICEPassword: credentials.Password, ControllingCertificate: append([]byte(nil), row.ControllingCertificate...), ControlledCertificate: append([]byte(nil), row.ControlledCertificate...), ControllingCertificateKeyID: row.ControllingKeyID, ControlledCertificateKeyID: row.ControlledKeyID, TrustedKeys: trustedKeys, AttemptGeneration: row.AttemptGeneration, NetworkGeneration: row.NetworkGeneration, HostGeneration: row.HostGeneration, AuthorizationGeneration: row.AuthorizationGeneration, IssuedAt: row.CreatedAt, ExpiresAt: row.ExpiresAt, Controlling: grant{EndpointID: row.ControllingEndpointID, PeerEndpointID: row.ControllingPeerEndpointID, Role: "controlling", JTI: row.ControllingJti}, Controlled: grant{EndpointID: row.ControlledEndpointID, PeerEndpointID: row.ControlledPeerEndpointID, Role: "controlled", JTI: row.ControlledJti}, Relay: relayAllocation{RouteAllocation: base64.RawURLEncoding.EncodeToString(row.RouteAllocation), JTI: row.RelayJti, RouteGeneration: row.RouteGeneration, ByteLimit: row.ByteLimit}, Transfer: cloneTransferBinding(credentials.Transfer)}, nil
}

func validRevocationReason(value string) bool {
	switch value {
	case "client_revoked", "endpoint_revoked", "environment_revoked", "node_reassigned", "superseded":
		return true
	default:
		return false
	}
}

func (r *SQLRepository) replayReservation(intent dbsqlc.PeerSessionIntent, grants []dbsqlc.PeerSignalingGrant, relay dbsqlc.PeerRelayAllocation, authority dbsqlc.ResolvePeerSessionAuthorityForUpdateRow, trustedKeys []TrustedKey) (reservation, error) {
	plaintext, err := secrets.Decrypt(r.encryptionKey, intent.IceCredentialsCiphertext)
	if err != nil {
		return reservation{}, ErrUnavailable
	}
	var credentials struct {
		Ufrag        string           `json:"ufrag"`
		Password     string           `json:"password"`
		Consumer     string           `json:"consumer"`
		AllowedPaths []string         `json:"allowed_paths"`
		Transfer     *TransferBinding `json:"transfer,omitempty"`
	}
	if json.Unmarshal([]byte(plaintext), &credentials) != nil || credentials.Ufrag == "" || credentials.Password == "" || !validPurposeConsumer(intent.Purpose, credentials.Consumer) || !validAllowedPaths(intent.Purpose, credentials.AllowedPaths) || !validTransferBinding(intent.Purpose, credentials.Transfer) {
		return reservation{}, ErrUnavailable
	}
	if !intent.EdgePool.Valid || !intent.SignalingHost.Valid || !intent.StunHost.Valid || !intent.StunPort.Valid || intent.EdgePool.String == "" || intent.SignalingHost.String == "" || intent.StunHost.String == "" || intent.StunPort.Int32 <= 0 || intent.StunPort.Int32 > 65535 {
		return reservation{}, ErrUnavailable
	}
	result := reservation{UserID: intent.UserID, CLIClientSessionID: intent.CLIClientSessionID, OperationKey: intent.OperationKey, IntentID: intent.ID, EnvironmentID: intent.EnvironmentID, Purpose: intent.Purpose, Consumer: credentials.Consumer, AllowedPaths: append([]string(nil), credentials.AllowedPaths...), EdgeNodeID: intent.EdgeNodeID, EdgePool: intent.EdgePool.String, SignalingHost: intent.SignalingHost.String, STUNHost: intent.StunHost.String, STUNPort: uint16(intent.StunPort.Int32), ICEUfrag: credentials.Ufrag, ICEPassword: credentials.Password, ControllingCertificate: append([]byte(nil), authority.ControllingCertificate...), ControlledCertificate: append([]byte(nil), authority.ControlledCertificate...), ControllingCertificateKeyID: authority.ControllingKeyID, ControlledCertificateKeyID: authority.ControlledKeyID, TrustedKeys: trustedKeys, AttemptGeneration: intent.AttemptGeneration, NetworkGeneration: intent.NetworkGeneration, HostGeneration: authority.HostGeneration, AuthorizationGeneration: authority.AuthorizationGeneration, IssuedAt: intent.CreatedAt, ExpiresAt: intent.ExpiresAt, Transfer: cloneTransferBinding(credentials.Transfer)}
	if len(relay.RouteAllocation) != 16 || relay.Jti == "" || relay.RouteGeneration < 1 || relay.ByteLimit < 1 || relay.ByteLimit > 1<<40 || relay.RevokedAt.Valid {
		return reservation{}, fmt.Errorf("peer session intent has invalid relay authority")
	}
	result.Relay = relayAllocation{RouteAllocation: base64.RawURLEncoding.EncodeToString(relay.RouteAllocation), JTI: relay.Jti, RouteGeneration: relay.RouteGeneration, ByteLimit: relay.ByteLimit}
	if len(grants) != 2 {
		return reservation{}, fmt.Errorf("peer session intent has incomplete signaling authority")
	}
	for _, row := range grants {
		value := grant{EndpointID: row.EndpointID, PeerEndpointID: row.PeerEndpointID, Role: row.Role, JTI: row.Jti}
		switch row.Role {
		case "controlling":
			result.Controlling = value
		case "controlled":
			result.Controlled = value
		default:
			return reservation{}, fmt.Errorf("peer session intent has invalid signaling role")
		}
	}
	if result.Controlling.JTI == "" || result.Controlled.JTI == "" {
		return reservation{}, fmt.Errorf("peer session intent has incomplete signaling authority")
	}
	return result, nil
}

func trustedKeysFromRows(queries *dbsqlc.Queries, ctx context.Context, userID string) ([]TrustedKey, error) {
	rows, err := queries.ListActivePeerSessionTrustedKeys(ctx, userID)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, ErrUnavailable
	}
	result := make([]TrustedKey, 0, len(rows))
	for _, row := range rows {
		if row.KeyID == "" || len(row.PublicKey) != sha256.Size || len(row.Fingerprint) != sha256.Size || row.Generation <= 0 {
			return nil, ErrUnavailable
		}
		fingerprint := sha256.Sum256(row.PublicKey)
		if !bytes.Equal(fingerprint[:], row.Fingerprint) || row.KeyID != "aek_"+hex.EncodeToString(fingerprint[:]) {
			return nil, ErrUnavailable
		}
		result = append(result, TrustedKey{KeyID: row.KeyID, PublicKey: append([]byte(nil), row.PublicKey...), Fingerprint: append([]byte(nil), row.Fingerprint...), Generation: row.Generation})
	}
	return result, nil
}
