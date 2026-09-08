package controlplane

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/http"
	"time"
)

const relayNodeLease = 15 * time.Second
const relayRegistryLease = time.Minute

type relayNodeStart struct {
	NodeID             string `json:"node_id"`
	ExpectedGeneration int64  `json:"expected_generation"`
	ProcessEpoch       string `json:"process_epoch"`
}
type relaySubject struct {
	AccountID  string `json:"account_id"`
	EndpointID string `json:"endpoint_id"`
	Generation int64  `json:"generation"`
}
type relayNodeObservation struct {
	NodeID       string         `json:"node_id"`
	Generation   int64          `json:"node_generation"`
	ProcessEpoch string         `json:"process_epoch"`
	Ready        bool           `json:"ready"`
	Draining     bool           `json:"draining"`
	CapacityUsed int64          `json:"capacity_used"`
	Subjects     []relaySubject `json:"subjects"`
}
type relayNodeLeaseDocument struct {
	NodeID        string                `json:"node_id"`
	Generation    int64                 `json:"node_generation"`
	ProcessEpoch  string                `json:"process_epoch"`
	ExpiresAt     int64                 `json:"expires_at"`
	CapacityLimit int64                 `json:"capacity_limit"`
	Revocations   []relaySubject        `json:"revocations"`
	PeerRelay     *relayServiceIdentity `json:"peer_relay,omitempty"`
}
type relayServiceIdentity struct {
	WireGuardPublicKey string `json:"wireguard_public_key"`
	DiscoPublicKey     string `json:"disco_public_key"`
	VirtualAddress     string `json:"virtual_address"`
}

func relayServiceForNode(ctx context.Context, tx *sql.Tx, node string) (*relayServiceIdentity, error) {
	var enabled bool
	var wg, disco []byte
	var address sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT roles @> ARRAY['peer_relay']::text[],peer_relay_wireguard_public_key,peer_relay_disco_public_key,host(peer_relay_virtual_address) FROM paperboat.control_tunnel_nodes WHERE id=$1`, node).Scan(&enabled, &wg, &disco, &address); err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}
	if len(wg) != 32 || len(disco) != 32 || !address.Valid {
		return nil, ErrInvalidUsageReport
	}
	return &relayServiceIdentity{base64.RawURLEncoding.EncodeToString(wg), base64.RawURLEncoding.EncodeToString(disco), address.String}, nil
}

func relayIdentifier(s string) bool { return len(s) > 0 && len(s) <= 256 }

// StartRelayNode activates an existing operator-authorized registry entry. This
// API cannot create nodes or change region, account policy, endpoints or keys.
func (s *EdgeService) StartRelayNode(ctx context.Context, in relayNodeStart) (relayNodeLeaseDocument, error) {
	var out relayNodeLeaseDocument
	if !relayIdentifier(in.NodeID) || !relayIdentifier(in.ProcessEpoch) || in.ExpectedGeneration < 1 || in.ExpectedGeneration == int64(^uint64(0)>>1) {
		return out, ErrInvalidUsageReport
	}
	tx, err := s.store.SQL().BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	var epoch, state string
	var gen, capacity int64
	err = tx.QueryRowContext(ctx, `SELECT node_generation,process_epoch,capacity_limit,state FROM paperboat.control_tunnel_nodes WHERE id=$1 AND roles @> ARRAY['relay']::text[] AND transports @> ARRAY['derp_quic','derp_wss']::text[] AND region IS NOT NULL FOR UPDATE`, in.NodeID).Scan(&gen, &epoch, &capacity, &state)
	if errors.Is(err, sql.ErrNoRows) {
		return out, ErrInvalidUsageReport
	}
	if err != nil {
		return out, err
	}
	if state == "retired" || capacity <= 0 || capacity > 256 {
		return out, ErrInvalidUsageReport
	}
	if epoch == in.ProcessEpoch && gen == in.ExpectedGeneration+1 {
		// A live startup retry preserves the node's existing readiness.
		var expires time.Time
		if err = tx.QueryRowContext(ctx, `SELECT registry_expires_at FROM paperboat.control_tunnel_nodes WHERE id=$1`, in.NodeID).Scan(&expires); err != nil {
			return out, err
		}
		if !expires.After(s.clock()) {
			// An interrupted startup never published readiness. Its persisted
			// pending epoch can safely resume without granting a second process.
			if state != "registered" && state != "offline" {
				return out, ErrInvalidUsageReport
			}
			now := s.clock().UTC()
			expires = now.Add(relayRegistryLease)
			if _, err = tx.ExecContext(ctx, `UPDATE paperboat.control_tunnel_nodes SET registry_expires_at=$2,last_heartbeat_at=$3,capacity_observed_at=$3 WHERE id=$1`, in.NodeID, expires, now); err != nil {
				return out, err
			}
		}
		out = relayNodeLeaseDocument{in.NodeID, gen, epoch, min(expires.Unix(), s.clock().Add(relayNodeLease).Unix()), capacity, []relaySubject{}, nil}
	} else {
		if gen != in.ExpectedGeneration || epoch == in.ProcessEpoch {
			return out, ErrInvalidUsageReport
		}
		now := s.clock().UTC()
		expires := now.Add(relayRegistryLease)
		_, err = tx.ExecContext(ctx, `UPDATE paperboat.control_tunnel_nodes SET node_generation=node_generation+1,process_epoch=$2,state='registered',ready=false,capacity_used=0,capacity_observed_at=$3,last_heartbeat_at=$3,registry_expires_at=$4,drain_deadline=NULL,updated_at=$3,version=version+1 WHERE id=$1`, in.NodeID, in.ProcessEpoch, now, expires)
		if err != nil {
			return out, err
		}
		out = relayNodeLeaseDocument{in.NodeID, gen + 1, in.ProcessEpoch, now.Add(relayNodeLease).Unix(), capacity, []relaySubject{}, nil}
	}
	out.PeerRelay, err = relayServiceForNode(ctx, tx, in.NodeID)
	if err != nil {
		return relayNodeLeaseDocument{}, err
	}
	return out, tx.Commit()
}

func (s *EdgeService) ObserveRelayNode(ctx context.Context, in relayNodeObservation) (relayNodeLeaseDocument, error) {
	var out relayNodeLeaseDocument
	if !relayIdentifier(in.NodeID) || !relayIdentifier(in.ProcessEpoch) || in.Generation < 1 || in.CapacityUsed < 0 || len(in.Subjects) > 256 {
		return out, ErrInvalidUsageReport
	}
	seen := map[string]bool{}
	for _, subject := range in.Subjects {
		k := subject.AccountID + "\x00" + subject.EndpointID
		if !relayIdentifier(subject.AccountID) || !relayIdentifier(subject.EndpointID) || subject.Generation < 1 || subject.Generation == int64(^uint64(0)>>1) || seen[k] {
			return out, ErrInvalidUsageReport
		}
		seen[k] = true
	}
	tx, err := s.store.SQL().BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	now := s.clock().UTC()
	var capacity int64
	var expires time.Time
	var state string
	err = tx.QueryRowContext(ctx, `SELECT capacity_limit,registry_expires_at,state FROM paperboat.control_tunnel_nodes WHERE id=$1 AND node_generation=$2 AND process_epoch=$3 AND roles @> ARRAY['relay']::text[] FOR UPDATE`, in.NodeID, in.Generation, in.ProcessEpoch).Scan(&capacity, &expires, &state)
	if errors.Is(err, sql.ErrNoRows) {
		return out, ErrInvalidUsageReport
	}
	if err != nil {
		return out, err
	}
	if state == "retired" || state == "offline" || !expires.After(now) || in.CapacityUsed > capacity {
		return out, ErrInvalidUsageReport
	}
	if state == "draining" && !in.Draining {
		return out, ErrInvalidUsageReport
	}
	expires = now.Add(relayRegistryLease)
	state = "registered"
	if in.Ready {
		state = "ready"
	}
	if in.Draining {
		state = "draining"
	}
	_, err = tx.ExecContext(ctx, `UPDATE paperboat.control_tunnel_nodes SET state=$4,ready=$5,capacity_used=$6,capacity_observed_at=$7,last_heartbeat_at=$7,registry_expires_at=$8,drain_deadline=CASE WHEN $4='draining' THEN coalesce(drain_deadline,$7) ELSE NULL END,updated_at=$7 WHERE id=$1 AND node_generation=$2 AND process_epoch=$3`, in.NodeID, in.Generation, in.ProcessEpoch, state, in.Ready && !in.Draining, in.CapacityUsed, now, expires)
	if err != nil {
		return out, err
	}
	out = relayNodeLeaseDocument{in.NodeID, in.Generation, in.ProcessEpoch, now.Add(relayNodeLease).Unix(), capacity, []relaySubject{}, nil}
	for _, subject := range in.Subjects {
		var floor int64
		err = tx.QueryRowContext(ctx, `SELECT n.relay_revocation_generation FROM paperboat.peer_network_identities n JOIN paperboat.control_tunnel_nodes r ON r.id=$3 WHERE n.user_id=$1 AND n.endpoint_id=$2 AND (r.allowed_account_ids IS NULL OR n.user_id=ANY(r.allowed_account_ids))`, subject.AccountID, subject.EndpointID, in.NodeID).Scan(&floor)
		if errors.Is(err, sql.ErrNoRows) {
			floor = subject.Generation + 1
		} else if err != nil {
			return relayNodeLeaseDocument{}, err
		}
		if floor > subject.Generation {
			subject.Generation = floor
			out.Revocations = append(out.Revocations, subject)
		}
	}
	out.PeerRelay, err = relayServiceForNode(ctx, tx, in.NodeID)
	if err != nil {
		return relayNodeLeaseDocument{}, err
	}
	return out, tx.Commit()
}
func (s *EdgeService) handleRelayStart(w http.ResponseWriter, r *http.Request) {
	var in relayNodeStart
	if !s.decode(w, r, &in) {
		return
	}
	out, err := s.StartRelayNode(r.Context(), in)
	if err != nil {
		if !errors.Is(err, ErrInvalidUsageReport) {
			writeEdgeError(w, r, http.StatusServiceUnavailable, "control_unavailable", true, 1000)
			return
		}
		writeEdgeError(w, r, http.StatusConflict, "relay_node_fenced", false, 0)
		return
	}
	writeEdgeJSON(w, http.StatusOK, out)
}
func (s *EdgeService) handleRelayObserve(w http.ResponseWriter, r *http.Request) {
	var in relayNodeObservation
	if !s.decode(w, r, &in) {
		return
	}
	out, err := s.ObserveRelayNode(r.Context(), in)
	if err != nil {
		if !errors.Is(err, ErrInvalidUsageReport) {
			writeEdgeError(w, r, http.StatusServiceUnavailable, "control_unavailable", true, 1000)
			return
		}
		writeEdgeError(w, r, http.StatusConflict, "relay_node_fenced", false, 0)
		return
	}
	writeEdgeJSON(w, http.StatusOK, out)
}
