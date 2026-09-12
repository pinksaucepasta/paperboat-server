package peersessions

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/mint"
	"golang.org/x/crypto/curve25519"
)

const networkConfigLimit = 128 << 10

type NetworkRegistration struct {
	OperationID                                                    string
	UserID, EndpointID, Role, MachineID                            string
	EndpointGeneration, MachineGeneration, ExpectedKeyGeneration   int64
	WireGuardPublicKey, DiscoPublicKey, QUICCertificateFingerprint []byte
}
type NetworkRegistrationResult struct {
	KeyGeneration  int64  `json:"key_generation"`
	VirtualAddress string `json:"virtual_address"`
}
type NetworkConfigRequest struct{ OperationID, UserID, EndpointID string }
type NetworkConfigResult struct {
	Configuration string   `json:"configuration"`
	CandidateSet  string   `json:"candidate_set"`
	RelayGrants   []string `json:"relay_grants"`
}

type NetworkService struct {
	store  *db.DB
	signer interface {
		SignNetworkConfiguration(map[string]any) (string, error)
		SignRegionalCandidates(map[string]any) (string, error)
		SignRelayGrant(map[string]any) (string, error)
	}
	issuer string
	now    func() time.Time
}

func NewNetworkService(store *db.DB, signer interface {
	SignNetworkConfiguration(map[string]any) (string, error)
	SignRegionalCandidates(map[string]any) (string, error)
	SignRelayGrant(map[string]any) (string, error)
}, issuer string) (*NetworkService, error) {
	if store == nil || signer == nil || issuer == "" {
		return nil, ErrInvalid
	}
	return &NetworkService{store: store, signer: signer, issuer: issuer, now: time.Now}, nil
}

func (s *NetworkService) Register(ctx context.Context, in NetworkRegistration) (NetworkRegistrationResult, error) {
	if ctx == nil || !bounded(in.OperationID, 8, 128) || !bounded(in.UserID, 1, 256) || !bounded(in.EndpointID, 1, 128) || !validWireGuardPublicKey(in.WireGuardPublicKey) || !validWireGuardPublicKey(in.DiscoPublicKey) || len(in.QUICCertificateFingerprint) != 32 || in.ExpectedKeyGeneration < 0 || (in.Role != "cli" && in.Role != "machine") {
		return NetworkRegistrationResult{}, ErrInvalid
	}
	if in.Role == "cli" && (in.MachineID != "" || in.MachineGeneration != 0) || in.Role == "machine" && (in.MachineID != in.EndpointID || in.MachineGeneration < 1) {
		return NetworkRegistrationResult{}, ErrInvalid
	}
	hash := sha256.Sum256([]byte(in.UserID + "\x00" + in.EndpointID + "\x00" + in.Role + "\x00" + fmt.Sprint(in.EndpointGeneration) + "\x00" + fmt.Sprint(in.MachineGeneration) + "\x00" + fmt.Sprint(in.ExpectedKeyGeneration) + "\x00" + base64.RawURLEncoding.EncodeToString(in.WireGuardPublicKey) + "\x00" + base64.RawURLEncoding.EncodeToString(in.DiscoPublicKey) + "\x00" + hex.EncodeToString(in.QUICCertificateFingerprint)))
	tx, err := s.store.SQL().BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return NetworkRegistrationResult{}, err
	}
	defer tx.Rollback()
	now := s.now().UTC()
	var certRole, certEndpoint string
	var certGeneration int64
	err = tx.QueryRowContext(ctx, `SELECT c.role,c.endpoint_id,c.generation FROM paperboat.peer_endpoint_certificates c JOIN paperboat.account_e2ee_roots r ON r.user_id=c.user_id AND r.revoked_at IS NULL JOIN paperboat.account_e2ee_keys k ON k.key_id=c.key_id AND k.user_id=c.user_id AND k.revoked_at IS NULL WHERE c.user_id=$1 AND c.fingerprint=$2 AND c.revoked_at IS NULL AND c.issued_at<=$3 AND c.expires_at>$3`, in.UserID, in.QUICCertificateFingerprint, now).Scan(&certRole, &certEndpoint, &certGeneration)
	if errors.Is(err, sql.ErrNoRows) || err == nil && (certRole != in.Role || certEndpoint != in.EndpointID || certGeneration != in.EndpointGeneration) {
		return NetworkRegistrationResult{}, ErrDenied
	}
	if err != nil {
		return NetworkRegistrationResult{}, err
	}
	if in.Role == "cli" {
		var active bool
		err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM paperboat.cli_client_sessions c JOIN paperboat.users u ON u.id=c.user_id AND u.status='active' WHERE c.id=$1 AND c.user_id=$2 AND c.state='active' AND c.revoked_at IS NULL)`, in.EndpointID, in.UserID).Scan(&active)
		if err != nil {
			return NetworkRegistrationResult{}, err
		}
		if !active {
			return NetworkRegistrationResult{}, ErrDenied
		}
	} else {
		var generation int64
		err = tx.QueryRowContext(ctx, `SELECT m.installation_generation FROM paperboat.user_machines m JOIN paperboat.users u ON u.id=m.user_id AND u.status='active' JOIN paperboat.control_environments e ON e.id=m.environment_id AND e.owner_user_id=m.user_id AND e.desired_state='active' AND e.revoked_at IS NULL WHERE m.id=$1 AND m.user_id=$2 AND m.state IN ('online','offline') AND ((m.setup_mode='host' AND m.seat_state='occupied') OR (m.setup_mode='client' AND m.seat_state='released')) AND m.revoked_at IS NULL AND m.deleted_at IS NULL`, in.EndpointID, in.UserID).Scan(&generation)
		if errors.Is(err, sql.ErrNoRows) || err == nil && generation != in.MachineGeneration {
			return NetworkRegistrationResult{}, ErrDenied
		}
		if err != nil {
			return NetworkRegistrationResult{}, err
		}
	}
	var oldHash []byte
	var replayGen int64
	err = tx.QueryRowContext(ctx, `SELECT request_hash,key_generation FROM paperboat.peer_network_registration_operations WHERE operation_id=$1`, in.OperationID).Scan(&oldHash, &replayGen)
	if err == nil {
		if !equalBytes(oldHash, hash[:]) {
			return NetworkRegistrationResult{}, ErrConflict
		}
		var address string
		if err = tx.QueryRowContext(ctx, `SELECT host(virtual_address) FROM paperboat.peer_network_identities WHERE user_id=$1 AND endpoint_id=$2 AND revoked_at IS NULL`, in.UserID, in.EndpointID).Scan(&address); err != nil {
			return NetworkRegistrationResult{}, ErrUnavailable
		}
		return NetworkRegistrationResult{replayGen, address}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return NetworkRegistrationResult{}, err
	}
	var currentGen int64
	var address string
	created := false
	err = tx.QueryRowContext(ctx, `SELECT key_generation,host(virtual_address) FROM paperboat.peer_network_identities WHERE user_id=$1 AND endpoint_id=$2 AND role=$3 AND revoked_at IS NULL FOR UPDATE`, in.UserID, in.EndpointID, in.Role).Scan(&currentGen, &address)
	if errors.Is(err, sql.ErrNoRows) {
		if in.ExpectedKeyGeneration != 0 {
			return NetworkRegistrationResult{}, ErrConflict
		}
		created = true
		err = tx.QueryRowContext(ctx, `INSERT INTO paperboat.peer_network_identities(user_id,endpoint_id,role,machine_id,endpoint_generation,machine_generation,key_generation,wireguard_public_key,disco_public_key,quic_certificate_fingerprint,virtual_address,created_at,updated_at) VALUES($1,$2,$3,nullif($4,''),$5,$6,1,$7,$8,$9,('fd7a:115c:a1e0::'::inet + nextval('paperboat.peer_network_virtual_address_seq')), $10,$10) RETURNING key_generation,host(virtual_address)`, in.UserID, in.EndpointID, in.Role, in.MachineID, in.EndpointGeneration, in.MachineGeneration, in.WireGuardPublicKey, in.DiscoPublicKey, in.QUICCertificateFingerprint, now).Scan(&currentGen, &address)
	} else if err == nil {
		if currentGen != in.ExpectedKeyGeneration {
			return NetworkRegistrationResult{}, ErrConflict
		}
		currentGen++
		_, err = tx.ExecContext(ctx, `UPDATE paperboat.peer_network_identities SET endpoint_generation=$1,machine_generation=$2,key_generation=$3,wireguard_public_key=$4,disco_public_key=$5,quic_certificate_fingerprint=$6,revoked_at=NULL,updated_at=$7 WHERE user_id=$8 AND endpoint_id=$9`, in.EndpointGeneration, in.MachineGeneration, currentGen, in.WireGuardPublicKey, in.DiscoPublicKey, in.QUICCertificateFingerprint, now, in.UserID, in.EndpointID)
	}
	if err != nil {
		return NetworkRegistrationResult{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO paperboat.peer_network_registration_operations(operation_id,user_id,endpoint_id,request_hash,key_generation,created_at) VALUES($1,$2,$3,$4,$5,$6)`, in.OperationID, in.UserID, in.EndpointID, hash[:], currentGen, now); err != nil {
		return NetworkRegistrationResult{}, err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM paperboat.peer_network_registration_operations o WHERE o.user_id=$1 AND o.endpoint_id=$2 AND o.operation_id IN (SELECT operation_id FROM paperboat.peer_network_registration_operations WHERE user_id=$1 AND endpoint_id=$2 ORDER BY key_generation DESC,created_at DESC,operation_id DESC OFFSET 64)`, in.UserID, in.EndpointID); err != nil {
		return NetworkRegistrationResult{}, err
	}
	eventType := "peer_network.key_rotated"
	if created {
		eventType = "peer_network.key_registered"
	}
	auditID := "aud_peer_network_" + hex.EncodeToString(hash[:16])
	metadata, _ := json.Marshal(map[string]any{"endpoint_id": in.EndpointID, "role": in.Role, "key_generation": currentGen, "virtual_address": address})
	if _, err = tx.ExecContext(ctx, `INSERT INTO paperboat.audit_events(id,actor_user_id,actor_type,event_type,resource_type,resource_id,idempotency_key,metadata,created_at) VALUES($1,$2,'user',$3,'peer_network_identity',$4,$5,$6::jsonb,$7) ON CONFLICT (event_type,resource_type,resource_id,idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING`, auditID, in.UserID, eventType, in.EndpointID, in.OperationID, metadata, now); err != nil {
		return NetworkRegistrationResult{}, err
	}
	if err = tx.Commit(); err != nil {
		return NetworkRegistrationResult{}, err
	}
	return NetworkRegistrationResult{currentGen, address}, nil
}

type networkBinding struct {
	AccountID                  string `json:"account_id"`
	EndpointID                 string `json:"endpoint_id"`
	Role                       string `json:"role"`
	MachineID                  string `json:"machine_id"`
	EndpointGeneration         int64  `json:"endpoint_generation"`
	MachineGeneration          int64  `json:"machine_generation"`
	KeyGeneration              int64  `json:"key_generation"`
	WireGuardPublicKey         string `json:"wireguard_public_key"`
	DiscoPublicKey             string `json:"disco_public_key"`
	QUICCertificateFingerprint string `json:"quic_certificate_fingerprint"`
	QUICPublicKey              string `json:"quic_public_key"`
	VirtualAddress             string `json:"virtual_address"`
}
type networkScope struct {
	ResourceKind       string `json:"resource_kind"`
	ResourceID         string `json:"resource_id"`
	ResourceGeneration int64  `json:"resource_generation"`
	Capability         string `json:"capability"`
	Direction          string `json:"direction"`
	Port               int    `json:"port"`
	ExpiresAt          int64  `json:"expires_at"`
}
type networkPeer struct {
	Identity networkBinding `json:"identity"`
	Scopes   []networkScope `json:"scopes"`
}

func (s *NetworkService) Configuration(ctx context.Context, in NetworkConfigRequest) (NetworkConfigResult, error) {
	if ctx == nil || !bounded(in.OperationID, 8, 128) || !bounded(in.UserID, 1, 256) || !bounded(in.EndpointID, 1, 128) {
		return NetworkConfigResult{}, ErrInvalid
	}
	now := s.now().UTC()
	tx, err := s.store.SQL().BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return NetworkConfigResult{}, err
	}
	defer tx.Rollback()
	self, certExpiry, err := loadNetworkBinding(ctx, tx, in.UserID, in.EndpointID, now)
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, ErrUnavailable) {
		return NetworkConfigResult{}, ErrDenied
	}
	if err != nil {
		return NetworkConfigResult{}, err
	}
	var generation int64
	err = tx.QueryRowContext(ctx, `UPDATE paperboat.peer_network_identities SET config_generation=config_generation+1,updated_at=$1 WHERE user_id=$2 AND endpoint_id=$3 RETURNING config_generation`, now, in.UserID, in.EndpointID).Scan(&generation)
	if err != nil {
		return NetworkConfigResult{}, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT a.id,a.cli_client_session_id,a.user_machine_id,a.user_id,m.user_id,a.expires_at,array_to_json(a.capabilities),coalesce(a.terminal_session_id,''),coalesce(a.terminal_role,'')
		FROM paperboat.user_machine_access_sessions a
		JOIN paperboat.cli_client_sessions c ON c.id=a.cli_client_session_id AND c.user_id=a.user_id AND c.state='active' AND c.revoked_at IS NULL
		JOIN paperboat.user_machines m ON m.id=a.user_machine_id AND m.environment_id=a.environment_id AND m.revoked_at IS NULL AND m.deleted_at IS NULL
		JOIN paperboat.control_environments e ON e.id=a.environment_id AND e.owner_user_id=m.user_id AND e.desired_state='active' AND e.revoked_at IS NULL
		JOIN paperboat.users actor ON actor.id=a.user_id AND actor.status='active'
		JOIN paperboat.users owner ON owner.id=m.user_id AND owner.status='active'
		WHERE a.state='active' AND a.revoked_at IS NULL AND a.expires_at>$2
		AND ((a.cli_client_session_id=$3 AND a.user_id=$1) OR (a.user_machine_id=$3 AND m.user_id=$1))
		AND ((a.terminal_role IN ('viewer','interactive') AND a.team_id IS NOT NULL AND m.state='online' AND m.online AND m.configured_capabilities @> ARRAY['terminal_host'] AND m.observed_capabilities @> ARRAY['terminal_host']
		 AND paperboat.terminal_session_role(a.user_id,a.terminal_session_id)=a.terminal_role
		 AND EXISTS(SELECT 1 FROM paperboat.teams t JOIN paperboat.team_members tm ON tm.team_id=t.team_id AND tm.account_id=a.user_id JOIN paperboat.team_resource_bindings b ON b.team_id=t.team_id AND b.resource_kind='terminal_session' AND b.resource_id=a.terminal_session_id AND b.active LEFT JOIN paperboat.team_terminal_session_grants sg ON sg.team_id=t.team_id AND sg.terminal_session_id=a.terminal_session_id AND sg.audience='selected_member' AND sg.account_id=a.user_id LEFT JOIN paperboat.team_terminal_session_grants ag ON ag.team_id=t.team_id AND ag.terminal_session_id=a.terminal_session_id AND ag.audience='all_members' WHERE t.team_id=a.team_id AND t.deleted_at IS NULL AND tm.active AND tm.membership_generation=a.terminal_membership_generation AND b.generation=a.terminal_binding_generation AND CASE WHEN sg.account_id IS NOT NULL THEN sg.generation ELSE ag.generation END=a.terminal_grant_generation))
		 OR (coalesce(a.terminal_role,'owner')='owner' AND a.team_id IS NULL AND a.user_id=m.user_id)
		 OR (coalesce(a.terminal_role,'owner')='owner' AND a.team_id IS NOT NULL AND NOT ('private_access'=ANY(a.capabilities)) AND NOT EXISTS(
		  SELECT 1 FROM unnest(a.capabilities) capability
		  WHERE NOT paperboat.team_machine_capability_allowed(a.user_id,a.team_id,a.user_machine_id,capability))))
		ORDER BY a.id LIMIT 129`, in.UserID, now, in.EndpointID)
	if err != nil {
		return NetworkConfigResult{}, err
	}
	type grantRow struct {
		id, cli, machine, cliAccount, machineAccount, kind, terminalSession, terminalRole string
		expiry                                                                            time.Time
		capabilities                                                                      []string
	}
	grants := make([]grantRow, 0, 128)
	for rows.Next() {
		var g grantRow
		var rawCapabilities []byte
		if rows.Scan(&g.id, &g.cli, &g.machine, &g.cliAccount, &g.machineAccount, &g.expiry, &rawCapabilities, &g.terminalSession, &g.terminalRole) != nil {
			rows.Close()
			return NetworkConfigResult{}, ErrUnavailable
		}
		var storedCapabilities []string
		if json.Unmarshal(rawCapabilities, &storedCapabilities) != nil {
			rows.Close()
			return NetworkConfigResult{}, ErrUnavailable
		}
		g.kind = "machine_access"
		if g.terminalRole == "viewer" || g.terminalRole == "interactive" {
			g.capabilities = []string{"terminal"}
			grants = append(grants, g)
			continue
		}
		seenCapabilities := make(map[string]bool, len(storedCapabilities))
		for _, capability := range storedCapabilities {
			projected := capability
			switch capability {
			case "terminal", "exec", "managed_ssh", "private_access":
			case "files":
				projected = "file_transfer"
			case "preview_manage", "tunnel_manage":
				continue
			default:
				rows.Close()
				return NetworkConfigResult{}, ErrUnavailable
			}
			if !seenCapabilities[projected] {
				seenCapabilities[projected] = true
				g.capabilities = append(g.capabilities, projected)
			}
		}
		sort.Strings(g.capabilities)
		grants = append(grants, g)
	}
	rowErr := rows.Err()
	rows.Close()
	if rowErr != nil {
		return NetworkConfigResult{}, rowErr
	}
	if len(grants) > 128 {
		return NetworkConfigResult{}, ErrResourceLimit
	}
	inspectorRows, err := tx.QueryContext(ctx, `SELECT credential_id,native_cli_session_id,native_machine_id,account_id,owner_account_id,expires_at FROM paperboat.inspector_native_admissions WHERE (native_cli_session_id=$1 AND account_id=$2) OR (native_machine_id=$1 AND owner_account_id=$2) ORDER BY credential_id LIMIT 129`, in.EndpointID, in.UserID)
	if err != nil {
		return NetworkConfigResult{}, err
	}
	for inspectorRows.Next() {
		var g grantRow
		if err = inspectorRows.Scan(&g.id, &g.cli, &g.machine, &g.cliAccount, &g.machineAccount, &g.expiry); err != nil {
			inspectorRows.Close()
			return NetworkConfigResult{}, err
		}
		g.kind = "inspector"
		g.capabilities = []string{"inspector"}
		grants = append(grants, g)
	}
	err = inspectorRows.Err()
	inspectorRows.Close()
	if err != nil {
		return NetworkConfigResult{}, err
	}
	if len(grants) > 128 {
		return NetworkConfigResult{}, ErrResourceLimit
	}
	byPeer := map[string]*networkPeer{}
	scopes := 0
	expiry := now.Add(mint.MaxProofTTL)
	if certExpiry.Before(expiry) {
		expiry = certExpiry
	}
	for _, g := range grants {
		if len(g.capabilities) == 0 {
			continue
		}
		peerID, peerAccount, direction := g.machine, g.machineAccount, "dial"
		if in.EndpointID == g.machine {
			peerID, peerAccount, direction = g.cli, g.cliAccount, "accept"
		}
		p := byPeer[peerID]
		if p == nil {
			binding, peerCertExpiry, e := loadNetworkBinding(ctx, tx, peerAccount, peerID, now)
			if errors.Is(e, sql.ErrNoRows) || errors.Is(e, ErrUnavailable) {
				continue
			}
			if e != nil {
				return NetworkConfigResult{}, e
			}
			if len(byPeer) >= 64 {
				return NetworkConfigResult{}, ErrResourceLimit
			}
			if peerCertExpiry.Before(expiry) {
				expiry = peerCertExpiry
			}
			p = &networkPeer{Identity: binding}
			byPeer[peerID] = p
		}
		if g.expiry.Before(expiry) {
			expiry = g.expiry
		}
		for _, capability := range g.capabilities {
			if scopes >= 128 {
				return NetworkConfigResult{}, ErrResourceLimit
			}
			p.Scopes = append(p.Scopes, networkScope{g.kind, g.id, 1, capability, direction, 443, g.expiry.Unix()})
			scopes++
		}
	}
	peerIDs := make([]string, 0, len(byPeer))
	for id := range byPeer {
		peerIDs = append(peerIDs, id)
	}
	sort.Strings(peerIDs)
	peers := make([]networkPeer, 0, len(peerIDs))
	for _, id := range peerIDs {
		p := byPeer[id]
		sort.Slice(p.Scopes, func(i, j int) bool {
			if p.Scopes[i].ResourceID != p.Scopes[j].ResourceID {
				return p.Scopes[i].ResourceID < p.Scopes[j].ResourceID
			}
			return p.Scopes[i].Capability < p.Scopes[j].Capability
		})
		peers = append(peers, *p)
	}
	claims := map[string]any{"version": 1, "iss": s.issuer, "aud": "paperboat-network", "iat": now.Unix(), "exp": expiry.Unix(), "generation": generation, "self": bindingMap(self), "peers": peers}
	relayPairs, err := deviceRelayPairs(ctx, tx, self, now, expiry)
	if err != nil {
		return NetworkConfigResult{}, err
	}
	if len(relayPairs) != 0 {
		claims["relay_pairs"] = relayPairs
	}
	token, err := s.signer.SignNetworkConfiguration(claims)
	if err != nil {
		return NetworkConfigResult{}, err
	}
	if len(token) > networkConfigLimit {
		return NetworkConfigResult{}, ErrUnavailable
	}
	candidates, err := s.regionalCandidates(ctx, tx, in.UserID, in.EndpointID, generation, now, expiry)
	if err != nil {
		return NetworkConfigResult{}, err
	}
	if len(candidates) > networkConfigLimit {
		return NetworkConfigResult{}, ErrUnavailable
	}
	relayPeers := make([]map[string]any, 0, len(peers))
	for _, peer := range peers {
		entry := map[string]any{"wireguard_public_key": peer.Identity.WireGuardPublicKey, "scopes": peer.Scopes}
		if peer.Identity.DiscoPublicKey != "" {
			entry["disco_public_key"] = peer.Identity.DiscoPublicKey
		}
		relayPeers = append(relayPeers, entry)
	}
	relayGrants, err := s.relayGrants(ctx, tx, self, relayPeers, generation, now, expiry)
	if err != nil {
		return NetworkConfigResult{}, err
	}
	if err = tx.Commit(); err != nil {
		return NetworkConfigResult{}, err
	}
	return NetworkConfigResult{Configuration: token, CandidateSet: candidates, RelayGrants: relayGrants}, nil
}

func deviceRelayPairs(ctx context.Context, tx *sql.Tx, self networkBinding, now, authorityExpiry time.Time) ([]map[string]any, error) {
	if self.Role != "machine" {
		return nil, nil
	}
	var enabled bool
	if err := tx.QueryRowContext(ctx, `SELECT configured_capabilities @> ARRAY['peer_relay']::text[] FROM paperboat.user_machines WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL AND deleted_at IS NULL`, self.EndpointID, self.AccountID).Scan(&enabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if !enabled {
		return nil, nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,cli_client_session_id,user_machine_id,expires_at FROM paperboat.user_machine_access_sessions WHERE user_id=$1 AND state='active' AND revoked_at IS NULL AND expires_at>$2 ORDER BY id LIMIT 17`, self.AccountID, now)
	if err != nil {
		return nil, err
	}
	type relayPairRow struct {
		resourceID, firstID, secondID string
		expires                       time.Time
	}
	var pending []relayPairRow
	for rows.Next() {
		if len(pending) == 16 {
			rows.Close()
			return nil, ErrResourceLimit
		}
		var row relayPairRow
		if err := rows.Scan(&row.resourceID, &row.firstID, &row.secondID, &row.expires); err != nil {
			rows.Close()
			return nil, err
		}
		pending = append(pending, row)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	result := make([]map[string]any, 0, len(pending))
	for _, row := range pending {
		if row.firstID == self.EndpointID || row.secondID == self.EndpointID {
			continue
		}
		first, firstExpiry, err := loadNetworkBinding(ctx, tx, self.AccountID, row.firstID, now)
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, ErrUnavailable) {
			continue
		}
		if err != nil {
			return nil, err
		}
		second, secondExpiry, err := loadNetworkBinding(ctx, tx, self.AccountID, row.secondID, now)
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, ErrUnavailable) {
			continue
		}
		if err != nil {
			return nil, err
		}
		pairExpiry := row.expires
		for _, candidate := range []time.Time{authorityExpiry, firstExpiry, secondExpiry} {
			if candidate.Before(pairExpiry) {
				pairExpiry = candidate
			}
		}
		result = append(result, map[string]any{"resource_kind": "machine_access", "resource_id": row.resourceID, "resource_generation": 1, "first": bindingMap(first), "second": bindingMap(second), "expires_at": pairExpiry.Unix()})
	}
	return result, nil
}

func (s *NetworkService) relayGrants(ctx context.Context, tx *sql.Tx, self networkBinding, peers []map[string]any, generation int64, now, authorityExpiry time.Time) ([]string, error) {
	deviceRelay, controlPeers, selfRelay, err := deviceRelayAuthority(ctx, tx, self)
	if err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,node_generation,process_epoch,registry_expires_at FROM paperboat.control_tunnel_nodes WHERE region IS NOT NULL AND (allowed_account_ids IS NULL OR $1=ANY(allowed_account_ids)) AND state='ready' AND ready AND last_heartbeat_at>$2::timestamptz-interval '15 seconds' AND registry_expires_at>$2::timestamptz AND capacity_observed_at>$2::timestamptz-interval '15 seconds' AND capacity_used<capacity_limit-capacity_limit/10 AND drain_deadline IS NULL AND roles @> ARRAY['relay']::text[] AND transports @> ARRAY['derp_quic']::text[] ORDER BY region,id LIMIT 33`, self.AccountID, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	grants := make([]string, 0, 32)
	for rows.Next() {
		if len(grants) == 32 {
			return nil, ErrResourceLimit
		}
		var nodeID, processEpoch string
		var nodeGeneration int64
		var nodeExpiry time.Time
		if err := rows.Scan(&nodeID, &nodeGeneration, &processEpoch, &nodeExpiry); err != nil {
			return nil, err
		}
		expires := now.Add(time.Minute)
		if authorityExpiry.Before(expires) {
			expires = authorityExpiry
		}
		if nodeExpiry.Before(expires) {
			expires = nodeExpiry
		}
		claims := map[string]any{"version": 1, "iss": s.issuer, "aud": "paperboat-relay", "iat": now.Unix(), "exp": expires.Unix(), "generation": generation, "account_id": self.AccountID, "endpoint_id": self.EndpointID, "wireguard_public_key": self.WireGuardPublicKey, "quic_certificate_fingerprint": self.QUICCertificateFingerprint, "quic_public_key": self.QUICPublicKey, "node_id": nodeID, "node_generation": nodeGeneration, "process_epoch": processEpoch, "peers": peers}
		if self.DiscoPublicKey != "" {
			claims["disco_public_key"] = self.DiscoPublicKey
		}
		if len(controlPeers) != 0 {
			claims["relay_control_peers"] = controlPeers
		}
		if !selfRelay && deviceRelay != nil {
			claims["peer_relay"] = deviceRelay
		}
		grant, err := s.signer.SignRelayGrant(claims)
		if err != nil {
			return nil, err
		}
		if len(grant) > networkConfigLimit {
			return nil, ErrUnavailable
		}
		grants = append(grants, grant)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return grants, nil
}

func deviceRelayAuthority(ctx context.Context, tx *sql.Tx, self networkBinding) (map[string]any, []string, bool, error) {
	rows, err := tx.QueryContext(ctx, `SELECT n.endpoint_id,n.wireguard_public_key,n.disco_public_key,host(n.virtual_address),coalesce(n.role='machine' AND m.configured_capabilities @> ARRAY['peer_relay']::text[] AND m.observed_capabilities @> ARRAY['peer_relay']::text[] AND m.online,false)
		FROM paperboat.peer_network_identities n LEFT JOIN paperboat.user_machines m ON m.id=n.machine_id AND m.user_id=n.user_id AND m.installation_generation=n.machine_generation AND m.revoked_at IS NULL AND m.deleted_at IS NULL AND m.state IN ('online','offline')
		WHERE n.user_id=$1 AND n.revoked_at IS NULL AND ((n.role='cli' AND EXISTS(SELECT 1 FROM paperboat.cli_client_sessions c WHERE c.id=n.endpoint_id AND c.user_id=n.user_id AND c.state='active' AND c.revoked_at IS NULL)) OR m.id IS NOT NULL) ORDER BY n.endpoint_id LIMIT 18`, self.AccountID)
	if err != nil {
		return nil, nil, false, err
	}
	defer rows.Close()
	var candidate map[string]any
	var allKeys []string
	selfRelay := false
	for rows.Next() {
		var endpoint, address string
		var wg, disco []byte
		var relay bool
		if err := rows.Scan(&endpoint, &wg, &disco, &address, &relay); err != nil {
			return nil, nil, false, err
		}
		if len(wg) != 32 || len(disco) != 32 {
			continue
		}
		keyValue := base64.RawURLEncoding.EncodeToString(wg)
		if endpoint != self.EndpointID {
			allKeys = append(allKeys, keyValue)
		}
		if endpoint == self.EndpointID {
			selfRelay = relay
			continue
		}
		if relay && candidate == nil {
			candidate = map[string]any{"wireguard_public_key": keyValue, "disco_public_key": base64.RawURLEncoding.EncodeToString(disco), "virtual_address": address}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, false, err
	}
	if len(allKeys) > 16 {
		return nil, nil, false, ErrResourceLimit
	}
	if selfRelay {
		return nil, allKeys, true, nil
	}
	if candidate != nil {
		return candidate, []string{candidate["wireguard_public_key"].(string)}, false, nil
	}
	return nil, nil, false, nil
}

type regionalNode struct {
	NodeID, ProcessEpoch, Region, FailureDomain string
	NodeGeneration                              int64
	Roles, Transports                           []string
	EndpointHost                                string
	EndpointTCPPort, EndpointQUICPort           int
	State                                       string
	ObservedAt, ExpiresAt, CapacityObservedAt   int64
	CapacityLimit, CapacityUsed                 int64
	DrainDeadline                               *int64 `json:",omitempty"`
}

func (s *NetworkService) regionalCandidates(ctx context.Context, tx *sql.Tx, accountID, endpointID string, generation int64, now, authorityExpiry time.Time) (string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id,node_generation,process_epoch,region,failure_domain,array_to_json(roles),array_to_json(transports),coalesce(endpoint_host,''),coalesce(endpoint_tcp_port,0),coalesce(endpoint_quic_port,0),state,last_heartbeat_at,registry_expires_at,capacity_limit,capacity_used,capacity_observed_at,drain_deadline FROM paperboat.control_tunnel_nodes WHERE region IS NOT NULL AND (allowed_account_ids IS NULL OR $1=ANY(allowed_account_ids)) AND state='ready' AND ready AND last_heartbeat_at>$2::timestamptz-interval '15 seconds' AND registry_expires_at>$2::timestamptz AND capacity_observed_at>$2::timestamptz-interval '15 seconds' AND capacity_used<capacity_limit-capacity_limit/10 AND drain_deadline IS NULL ORDER BY region,id LIMIT 33`, accountID, now)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	nodes := make([]map[string]any, 0, 32)
	for rows.Next() {
		var n regionalNode
		var roles, transports []byte
		var observed, expires, capacityAt time.Time
		var drain sql.NullTime
		if err := rows.Scan(&n.NodeID, &n.NodeGeneration, &n.ProcessEpoch, &n.Region, &n.FailureDomain, &roles, &transports, &n.EndpointHost, &n.EndpointTCPPort, &n.EndpointQUICPort, &n.State, &observed, &expires, &n.CapacityLimit, &n.CapacityUsed, &capacityAt, &drain); err != nil {
			return "", err
		}
		if json.Unmarshal(roles, &n.Roles) != nil || json.Unmarshal(transports, &n.Transports) != nil {
			return "", ErrUnavailable
		}
		if len(nodes) == 32 {
			return "", ErrResourceLimit
		}
		n.ObservedAt, n.ExpiresAt, n.CapacityObservedAt = observed.Unix(), expires.Unix(), capacityAt.Unix()
		m := map[string]any{"node_id": n.NodeID, "node_generation": n.NodeGeneration, "process_epoch": n.ProcessEpoch, "region": n.Region, "failure_domain": n.FailureDomain, "roles": n.Roles, "transports": n.Transports, "endpoint_host": n.EndpointHost, "endpoint_tcp_port": n.EndpointTCPPort, "endpoint_quic_port": n.EndpointQUICPort, "state": n.State, "observed_at": n.ObservedAt, "expires_at": n.ExpiresAt, "capacity_limit": n.CapacityLimit, "capacity_used": n.CapacityUsed, "capacity_observed_at": n.CapacityObservedAt}
		if drain.Valid {
			m["drain_deadline"] = drain.Time.Unix()
		}
		nodes = append(nodes, m)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	expires := now.Add(time.Minute)
	if authorityExpiry.Before(expires) {
		expires = authorityExpiry
	}
	return s.signer.SignRegionalCandidates(map[string]any{"schema": "paperboat.regional-candidates.v1", "iss": s.issuer, "aud": "paperboat-regional-candidates", "account_id": accountID, "endpoint_id": endpointID, "authorization_generation": generation, "generation": generation, "iat": now.Unix(), "exp": expires.Unix(), "nodes": nodes})
}

func loadNetworkBinding(ctx context.Context, tx *sql.Tx, userID, endpointID string, now time.Time) (networkBinding, time.Time, error) {
	var b networkBinding
	var key, disco, fingerprint, quicPublic []byte
	var expiry time.Time
	err := tx.QueryRowContext(ctx, `SELECT n.user_id,n.endpoint_id,n.role,coalesce(n.machine_id,''),n.endpoint_generation,n.machine_generation,n.key_generation,n.wireguard_public_key,n.disco_public_key,n.quic_certificate_fingerprint,c.quic_public_key,host(n.virtual_address),c.expires_at FROM paperboat.peer_network_identities n JOIN paperboat.users u ON u.id=n.user_id AND u.status='active' JOIN paperboat.peer_endpoint_certificates c ON c.fingerprint=n.quic_certificate_fingerprint AND c.user_id=n.user_id AND c.endpoint_id=n.endpoint_id AND c.generation=n.endpoint_generation AND c.role=n.role AND c.revoked_at IS NULL AND c.issued_at<=$3 AND c.expires_at>$3 JOIN paperboat.account_e2ee_roots r ON r.user_id=c.user_id AND r.revoked_at IS NULL JOIN paperboat.account_e2ee_keys k ON k.key_id=c.key_id AND k.user_id=c.user_id AND k.revoked_at IS NULL WHERE n.user_id=$1 AND n.endpoint_id=$2 AND n.revoked_at IS NULL`, userID, endpointID, now).Scan(&b.AccountID, &b.EndpointID, &b.Role, &b.MachineID, &b.EndpointGeneration, &b.MachineGeneration, &b.KeyGeneration, &key, &disco, &fingerprint, &quicPublic, &b.VirtualAddress, &expiry)
	if err != nil {
		return b, time.Time{}, err
	}
	if b.Role == "cli" {
		var active bool
		err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM paperboat.cli_client_sessions WHERE id=$1 AND user_id=$2 AND state='active' AND revoked_at IS NULL)`, endpointID, userID).Scan(&active)
		if err != nil {
			return b, time.Time{}, err
		}
		if !active {
			return b, time.Time{}, ErrUnavailable
		}
	} else {
		var gen int64
		err = tx.QueryRowContext(ctx, `SELECT m.installation_generation FROM paperboat.user_machines m JOIN paperboat.control_environments e ON e.id=m.environment_id AND e.owner_user_id=m.user_id AND e.desired_state='active' AND e.revoked_at IS NULL WHERE m.id=$1 AND m.user_id=$2 AND m.state IN ('online','offline') AND ((m.setup_mode='host' AND m.seat_state='occupied') OR (m.setup_mode='client' AND m.seat_state='released')) AND m.revoked_at IS NULL AND m.deleted_at IS NULL`, endpointID, userID).Scan(&gen)
		if errors.Is(err, sql.ErrNoRows) || err == nil && gen != b.MachineGeneration {
			return b, time.Time{}, ErrUnavailable
		}
		if err != nil {
			return b, time.Time{}, err
		}
	}
	b.WireGuardPublicKey = base64.RawURLEncoding.EncodeToString(key)
	if len(disco) == 32 {
		b.DiscoPublicKey = base64.RawURLEncoding.EncodeToString(disco)
	}
	b.QUICCertificateFingerprint = hex.EncodeToString(fingerprint)
	if len(quicPublic) != 32 {
		return b, time.Time{}, ErrUnavailable
	}
	b.QUICPublicKey = base64.RawURLEncoding.EncodeToString(quicPublic)
	if _, err = netip.ParseAddr(b.VirtualAddress); err != nil {
		return b, time.Time{}, ErrUnavailable
	}
	return b, expiry, nil
}
func bindingMap(b networkBinding) map[string]any {
	raw, _ := json.Marshal(b)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out
}

func validWireGuardPublicKey(key []byte) bool {
	if len(key) != curve25519.PointSize {
		return false
	}
	// X25519 rejects the low-order inputs that would produce an all-zero
	// shared secret. The scalar is validation-only and carries no identity.
	var scalar [curve25519.ScalarSize]byte
	for i := range scalar {
		scalar[i] = byte(i + 1)
	}
	_, err := curve25519.X25519(scalar[:], key)
	return err == nil
}
