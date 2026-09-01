package environment

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"errors"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/peeridentity"
)

type scopeRow struct {
	ID, AccountID, Scope, MachineID, State, AuthorityID, ManifestID string
	Version, KeyEpoch, AuthorityGeneration                          int64
	UpdatedAt                                                       time.Time
	Names                                                           []string
}
type authorityHeadRow struct {
	Generation int64
	ID         string
	Raw        []byte
}
type transitionRow struct {
	ID, AccountID, OperationID, BaseID, ProposedID, State string
	Generation                                            int64
	Raw                                                   []byte
	RequiredScopes                                        []string
}
type enrollmentRow struct {
	ID, State, SafetyCode, RequesterKind, RequesterID, SubjectKind, SubjectID, OperationID, RecipientKeyID string
	ExpiresAt                                                                                              time.Time
	Canonical, SigningProof, Challenge, RequestDigest, ExpectedProof, RecipientPublic                      []byte
	SubjectGeneration, KeyGeneration                                                                       int64
}
type rowScanner interface{ Scan(...any) error }

func lockAccountTx(ctx context.Context, tx *db.Tx, accountID string) error {
	var id string
	err := tx.QueryRow(ctx, `SELECT id FROM users WHERE id=$1 FOR UPDATE`, accountID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}
func pendingTransitionTx(ctx context.Context, tx *db.Tx, accountID string) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `SELECT transition_id FROM environment_authority_transitions WHERE account_id=$1 AND state IN ('staged','ready')`, accountID).Scan(&id)
	return id, normalizeNoRows(err)
}

func readScopeTx(ctx context.Context, tx *db.Tx, accountID, scope, machineID string, lock bool) (scopeRow, error) {
	query := `SELECT id,account_id,scope,COALESCE(machine_id,''),scope_state,version,key_epoch,authority_generation,authority_id,manifest_id,updated_at FROM environment_scopes WHERE account_id=$1 AND scope=$2 AND (($3='' AND machine_id IS NULL) OR machine_id=$3)`
	if lock {
		query += ` FOR UPDATE`
	}
	var r scopeRow
	err := tx.QueryRow(ctx, query, accountID, scope, machineID).Scan(&r.ID, &r.AccountID, &r.Scope, &r.MachineID, &r.State, &r.Version, &r.KeyEpoch, &r.AuthorityGeneration, &r.AuthorityID, &r.ManifestID, &r.UpdatedAt)
	if err != nil {
		return r, normalizeNoRows(err)
	}
	rows, err := tx.Query(ctx, `SELECT name FROM environment_scope_names WHERE scope_id=$1 ORDER BY name`, r.ID)
	if err != nil {
		return r, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return r, err
		}
		r.Names = append(r.Names, name)
	}
	return r, rows.Err()
}

func readAuthorityHeadTx(ctx context.Context, tx *db.Tx, accountID string, lock bool) (authorityHeadRow, error) {
	query := `SELECT h.generation,h.authority_id,a.envelope FROM environment_authority_heads h JOIN environment_authorities a ON a.account_id=h.account_id AND a.generation=h.generation WHERE h.account_id=$1`
	if lock {
		query += ` FOR UPDATE OF h`
	}
	var r authorityHeadRow
	err := tx.QueryRow(ctx, query, accountID).Scan(&r.Generation, &r.ID, &r.Raw)
	return r, normalizeNoRows(err)
}

func authorityPageTx(ctx context.Context, tx *db.Tx, accountID string, afterGeneration int64, afterID string) (AuthorityPage, error) {
	head, err := readAuthorityHeadTx(ctx, tx, accountID, false)
	if err != nil {
		return AuthorityPage{}, err
	}
	if afterGeneration > 0 {
		var retainedID string
		if err := tx.QueryRow(ctx, `SELECT authority_id FROM environment_authorities WHERE account_id=$1 AND generation=$2`, accountID, afterGeneration).Scan(&retainedID); err != nil || retainedID != afterID {
			return AuthorityPage{}, ErrAuthorityFork
		}
	}
	page := AuthorityPage{Schema: "paperboat.environment-authority-page/v1", AuthorityHead: AuthorityRef{Generation: head.Generation, AuthorityID: head.ID}, AuthorityDocuments: []string{}}
	rows, err := tx.Query(ctx, `SELECT generation,envelope FROM environment_authorities WHERE account_id=$1 AND generation>$2 ORDER BY generation LIMIT 5`, accountID, afterGeneration)
	if err != nil {
		return AuthorityPage{}, err
	}
	defer rows.Close()
	decoded := 0
	nextGeneration := afterGeneration + 1
	for rows.Next() {
		var generation int64
		var raw []byte
		if err := rows.Scan(&generation, &raw); err != nil {
			return AuthorityPage{}, err
		}
		if generation != nextGeneration {
			return AuthorityPage{}, ErrAuthorityFork
		}
		nextGeneration++
		if len(page.AuthorityDocuments) == 4 || decoded+len(raw) > 4<<20 {
			page.HasMore = true
			break
		}
		decoded += len(raw)
		page.AuthorityDocuments = append(page.AuthorityDocuments, base64.RawURLEncoding.EncodeToString(raw))
	}
	return page, rows.Err()
}
func (s *Service) parseActiveAuthorityTx(ctx context.Context, tx *db.Tx, accountID string) (Authority, error) {
	head, err := readAuthorityHeadTx(ctx, tx, accountID, false)
	if err != nil {
		return Authority{}, err
	}
	roots, err := s.verificationRootsTx(ctx, tx, accountID)
	if err != nil {
		return Authority{}, err
	}
	authority, err := ParseAuthority(head.Raw, roots.Environment, roots.Endpoint)
	if err != nil {
		return Authority{}, err
	}
	if int64(authority.Generation) != head.Generation || authority.ID != head.ID {
		return Authority{}, ErrAuthorityFork
	}
	return authority, nil
}

func loadManifestStateTx(ctx context.Context, tx *db.Tx, row scopeRow, out *ManifestState) error {
	var raw []byte
	if err := tx.QueryRow(ctx, `SELECT envelope FROM environment_scope_manifests WHERE scope_id=$1 AND version=$2`, row.ID, row.Version).Scan(&raw); err != nil {
		return normalizeNoRows(err)
	}
	*out = ManifestState{Schema: "paperboat.environment-manifest-state/v1", Scope: row.Scope, MachineID: row.MachineID, Version: row.Version, KeyEpoch: row.KeyEpoch, ManifestID: row.ManifestID, Envelope: base64.RawURLEncoding.EncodeToString(raw)}
	return nil
}
func manifestOperationTx(ctx context.Context, tx *db.Tx, scopeID, operationID string) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `SELECT manifest_id FROM environment_scope_manifests WHERE scope_id=$1 AND operation_id=$2`, scopeID, operationID).Scan(&id)
	return id, normalizeNoRows(err)
}
func manifestOperationStateTx(ctx context.Context, tx *db.Tx, scope scopeRow, operationID string) (ManifestState, bool, error) {
	var version, epoch int64
	var id string
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT version,key_epoch,manifest_id,envelope FROM environment_scope_manifests WHERE scope_id=$1 AND operation_id=$2`, scope.ID, operationID).Scan(&version, &epoch, &id, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return ManifestState{}, false, nil
	}
	if err != nil {
		return ManifestState{}, false, err
	}
	return ManifestState{Schema: "paperboat.environment-manifest-state/v1", Scope: scope.Scope, MachineID: scope.MachineID, Version: version, KeyEpoch: epoch, ManifestID: id, Envelope: base64.RawURLEncoding.EncodeToString(raw)}, true, nil
}

func activateManifestTx(ctx context.Context, tx *db.Tx, current scopeRow, m Manifest) error {
	if _, err := tx.Exec(ctx, `INSERT INTO environment_scope_manifests(scope_id,version,key_epoch,authority_generation,authority_id,operation_id,manifest_id,envelope) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, current.ID, int64(m.Version), int64(m.KeyEpoch), int64(m.AuthorityGeneration), m.AuthorityID, m.OperationID, m.ID, m.Raw); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE environment_scopes SET scope_state=$2,version=$3,key_epoch=$4,authority_generation=$5,authority_id=$6,manifest_id=$7,updated_at=now() WHERE id=$1 AND version=$8`, current.ID, m.ScopeState, int64(m.Version), int64(m.KeyEpoch), int64(m.AuthorityGeneration), m.AuthorityID, m.ID, current.Version)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return &VersionConflictError{CurrentVersion: current.Version}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM environment_scope_names WHERE scope_id=$1`, current.ID); err != nil {
		return err
	}
	for _, name := range m.Names {
		if _, err := tx.Exec(ctx, `INSERT INTO environment_scope_names(scope_id,name) VALUES($1,$2)`, current.ID, name); err != nil {
			return err
		}
	}
	return nil
}

func validateNormalMutation(m Manifest, current scopeRow) error {
	if m.AuthorityID != current.AuthorityID || m.ScopeState != current.State || m.PreviousVersion != uint64(current.Version) || m.Version != uint64(current.Version+1) {
		return ErrPrecondition
	}
	old := current.Names
	switch m.MutationKind {
	case 1:
		if len(m.ChangedNames) != 1 || !containsExact(m.Names, m.ChangedNames[0]) || (!sameStrings(old, m.Names) && !sameStrings(insertName(old, m.ChangedNames[0]), m.Names)) || m.KeyEpoch != uint64(current.KeyEpoch) {
			return ErrPrecondition
		}
	case 2:
		if len(m.ChangedNames) != 1 || !containsExact(old, m.ChangedNames[0]) || containsExact(m.Names, m.ChangedNames[0]) || !sameStrings(removeName(old, m.ChangedNames[0]), m.Names) || m.KeyEpoch != uint64(current.KeyEpoch) {
			return ErrPrecondition
		}
	case 4:
		if len(m.ChangedNames) != 0 || !sameStrings(old, m.Names) || m.KeyEpoch != uint64(current.KeyEpoch+1) {
			return ErrPrecondition
		}
	default:
		return ErrPrecondition
	}
	return nil
}

func validateScopeNameCompatibilityTx(ctx context.Context, tx *db.Tx, accountID, scope, machineID string, names []string) error {
	query := `SELECT n.name FROM environment_scope_names n JOIN environment_scopes s ON s.id=n.scope_id WHERE s.account_id=$1 AND s.scope<>$2`
	if scope == ScopeMachine {
		query += ` AND s.scope='global'`
	}
	rows, err := tx.Query(ctx, query, accountID, scope)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var other string
		if err := rows.Scan(&other); err != nil {
			return err
		}
		for _, name := range names {
			if strings.EqualFold(name, other) && name != other {
				return ErrInvalidName
			}
		}
	}
	_ = machineID
	return rows.Err()
}

func validateTransitionMutation(m Manifest, current scopeRow, t transitionRow, previous, proposed Authority) error {
	if m.AuthorityID != t.ProposedID || m.PreviousVersion != uint64(current.Version) || m.Version != uint64(current.Version+1) || !sameStrings(current.Names, m.Names) && m.MutationKind != 5 {
		return ErrPrecondition
	}
	reset := false
	targetScope := (ScopeRef{Scope: m.Scope, MachineID: m.MachineID}).Key()
	for _, scope := range proposed.ResetScopes {
		if scope.Key() == targetScope {
			reset = true
		}
	}
	removedExposure := scopeRequiresRotation(previous, proposed, m.Scope, m.MachineID)
	if m.MutationKind == 5 {
		if !reset || len(m.Names) != 0 || !sameStrings(m.ChangedNames, current.Names) || m.KeyEpoch != uint64(current.KeyEpoch+1) {
			return ErrPrecondition
		}
	} else {
		if reset {
			return ErrPrecondition
		}
		if removedExposure && m.MutationKind != 4 {
			return ErrPrecondition
		}
		if m.MutationKind == 4 {
			if len(m.ChangedNames) != 0 || m.KeyEpoch != uint64(current.KeyEpoch+1) {
				return ErrPrecondition
			}
		} else if m.MutationKind == 3 {
			if len(m.ChangedNames) != 0 || m.KeyEpoch != uint64(current.KeyEpoch) {
				return ErrPrecondition
			}
		} else {
			return ErrPrecondition
		}
	}
	if m.Scope == ScopeMachine {
		hostPresent := false
		for _, b := range proposed.Bindings {
			if b.SubjectKind == 3 && b.SubjectID == m.MachineID {
				hostPresent = true
			}
		}
		expected := "retired"
		if hostPresent {
			expected = "active"
		}
		if m.ScopeState != expected {
			return ErrPrecondition
		}
	} else if m.ScopeState != "active" {
		return ErrPrecondition
	}
	return nil
}

func scopeRequiresRotation(previous, proposed Authority, scope, machineID string) bool {
	proposedRecipients := make(map[string]bool, len(proposed.Bindings))
	for _, binding := range proposed.Bindings {
		proposedRecipients[binding.RecipientKeyID] = true
	}
	for _, binding := range previous.Bindings {
		if proposedRecipients[binding.RecipientKeyID] {
			continue
		}
		switch binding.SubjectKind {
		case 1, 2, 4:
			return true
		case 3:
			if scope == ScopeGlobal || (scope == ScopeMachine && binding.SubjectID == machineID) {
				return true
			}
		}
	}
	return false
}

func (s *Service) beginTransitionTx(ctx context.Context, tx *db.Tx, accountID, expectedID, operationID string, authority Authority) (TransitionState, error) {
	if authority.AccountID != accountID || authority.OperationID != operationID || !operationExpression.MatchString(operationID) {
		return TransitionState{}, ErrPrecondition
	}
	var recordedID string
	if err := tx.QueryRow(ctx, `SELECT transition_id FROM environment_authority_transitions WHERE account_id=$1 AND operation_id=$2`, accountID, operationID).Scan(&recordedID); err == nil {
		if recordedID != authority.ID {
			return TransitionState{}, ErrOperationConflict
		}
		return transitionStateTx(ctx, tx, accountID, recordedID)
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return TransitionState{}, err
	}
	if pending, err := pendingTransitionTx(ctx, tx, accountID); err == nil && pending != "" {
		return TransitionState{}, ErrTransitionInProgress
	} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return TransitionState{}, err
	}
	head, headErr := readAuthorityHeadTx(ctx, tx, accountID, true)
	genesis := errors.Is(headErr, sql.ErrNoRows)
	if headErr != nil && !genesis {
		return TransitionState{}, headErr
	}
	if genesis {
		if expectedID != "" || authority.Generation != 1 || authority.PreviousID != "" {
			return TransitionState{}, ErrPrecondition
		}
	} else if expectedID != head.ID || authority.Generation != uint64(head.Generation+1) || authority.PreviousID != head.ID {
		return TransitionState{}, &AuthorityConflictError{CurrentID: head.ID}
	}
	required, err := requiredScopeInventoryTx(ctx, tx, accountID, authority)
	if err != nil {
		return TransitionState{}, err
	}
	id := authority.ID
	base := ""
	if !genesis {
		base = head.ID
	}
	if _, err := tx.Exec(ctx, `INSERT INTO environment_authority_transitions(transition_id,account_id,operation_id,base_authority_id,proposed_generation,proposed_authority_id,proposed_authority,state,required_scopes) VALUES($1,$2,$3,NULLIF($4,''),$5,$6,$7,'staged',$8)`, id, accountID, operationID, base, int64(authority.Generation), authority.ID, authority.Raw, required); err != nil {
		return TransitionState{}, err
	}
	return transitionStateTx(ctx, tx, accountID, id)
}

func requiredScopeInventoryTx(ctx context.Context, tx *db.Tx, accountID string, authority Authority) ([]string, error) {
	set := map[string]bool{(ScopeRef{Scope: ScopeGlobal}).Key(): true}
	rows, err := tx.Query(ctx, `SELECT scope,COALESCE(machine_id,'') FROM environment_scopes WHERE account_id=$1`, accountID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var scope, machine string
		if err := rows.Scan(&scope, &machine); err != nil {
			rows.Close()
			return nil, err
		}
		if err := validateScope(scope, machine); err != nil {
			rows.Close()
			return nil, ErrPrecondition
		}
		set[ScopeRef{Scope: scope, MachineID: machine}.Key()] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, binding := range authority.Bindings {
		if binding.SubjectKind == 3 {
			var setupMode string
			var setupRoles []string
			var installationGeneration int64
			if err := tx.QueryRow(ctx, `SELECT installation_generation,setup_mode,setup_roles FROM user_machines WHERE id=$1 AND user_id=$2 AND deleted_at IS NULL`, binding.SubjectID, accountID).Scan(&installationGeneration, &setupMode, &setupRoles); errors.Is(err, pgx.ErrNoRows) {
				return nil, ErrMachineNotFound
			} else if err != nil {
				return nil, err
			}
			if !hostCapable(setupMode, setupRoles) {
				return nil, ErrMachineNotHost
			}
			if installationGeneration <= 0 || binding.SubjectGeneration != uint64(installationGeneration) {
				return nil, ErrPrecondition
			}
			set[ScopeRef{Scope: ScopeMachine, MachineID: binding.SubjectID}.Key()] = true
		}
	}
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out, nil
}

func readTransitionTx(ctx context.Context, tx *db.Tx, accountID, id string, lock bool) (transitionRow, error) {
	query := `SELECT transition_id,account_id,operation_id,COALESCE(base_authority_id,''),proposed_generation,proposed_authority_id,proposed_authority,state,required_scopes FROM environment_authority_transitions WHERE account_id=$1 AND transition_id=$2`
	if lock {
		query += ` FOR UPDATE`
	}
	var r transitionRow
	err := tx.QueryRow(ctx, query, accountID, id).Scan(&r.ID, &r.AccountID, &r.OperationID, &r.BaseID, &r.Generation, &r.ProposedID, &r.Raw, &r.State, &r.RequiredScopes)
	return r, normalizeNoRows(err)
}
func transitionStateTx(ctx context.Context, tx *db.Tx, accountID, id string) (TransitionState, error) {
	r, err := readTransitionTx(ctx, tx, accountID, id, false)
	if err != nil {
		return TransitionState{}, err
	}
	rows, err := tx.Query(ctx, `SELECT scope_ref FROM environment_transition_manifests WHERE transition_id=$1 ORDER BY scope_ref`, id)
	if err != nil {
		return TransitionState{}, err
	}
	defer rows.Close()
	staged := []string{}
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return TransitionState{}, err
		}
		if scope, machine := parseScopeKey(key); validateScope(scope, machine) != nil {
			return TransitionState{}, ErrPrecondition
		}
		staged = append(staged, key)
	}
	return TransitionState{Schema: "paperboat.environment-authority-transition-state/v1", TransitionID: r.ID, State: r.State, ProposedGeneration: r.Generation, ProposedAuthorityID: r.ProposedID, RequiredScopes: r.RequiredScopes, StagedScopes: staged}, rows.Err()
}

func (s *Service) activateTransitionTx(ctx context.Context, tx *db.Tx, t transitionRow, authority Authority) error {
	if authority.ID != t.ProposedID {
		return ErrPrecondition
	}
	rows, err := tx.Query(ctx, `SELECT scope_ref,expected_version,version,key_epoch,operation_id,manifest_id,envelope,names FROM environment_transition_manifests WHERE transition_id=$1 ORDER BY scope_ref`, t.ID)
	if err != nil {
		return err
	}
	type staged struct {
		key, operation, id       string
		expected, version, epoch int64
		raw                      []byte
		names                    []string
	}
	var all []staged
	for rows.Next() {
		var v staged
		if err := rows.Scan(&v.key, &v.expected, &v.version, &v.epoch, &v.operation, &v.id, &v.raw, &v.names); err != nil {
			rows.Close()
			return err
		}
		all = append(all, v)
	}
	rows.Close()
	if len(all) != len(t.RequiredScopes) {
		return ErrPrecondition
	}
	if _, err := tx.Exec(ctx, `INSERT INTO environment_authorities(account_id,generation,authority_id,previous_authority_id,operation_id,envelope) VALUES($1,$2,$3,NULLIF($4,''),$5,$6)`, t.AccountID, t.Generation, t.ProposedID, t.BaseID, t.OperationID, t.Raw); err != nil {
		return err
	}
	if t.Generation == 1 {
		live, err := s.roots.Root(ctx, t.AccountID)
		if err != nil {
			return err
		}
		root, err := selectAuthoritySignerRoot(live, authority)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO environment_authority_roots(account_id,key_id,public_key) VALUES($1,$2,$3)`, t.AccountID, root.KeyID, []byte(root.PublicKey)); err != nil {
			return err
		}
	}
	for _, binding := range authority.Bindings {
		if _, err := tx.Exec(ctx, `INSERT INTO environment_key_bindings(binding_id,account_id,subject_kind,subject_id,subject_generation,key_generation,signing_key_id,signing_public_key,recipient_key_id,recipient_public_key,envelope) VALUES($1,$2,$3,$4,$5,$6,NULLIF($7,''),$8,$9,$10,$11) ON CONFLICT(binding_id) DO NOTHING`, binding.ID, t.AccountID, binding.SubjectKindName(), binding.SubjectID, int64(binding.SubjectGeneration), int64(binding.KeyGeneration), binding.SigningKeyID, nullableBytesSQL(binding.SigningPublicKey), binding.RecipientKeyID, binding.RecipientPublicKey[:], binding.Raw); err != nil {
			return err
		}
	}
	for _, v := range all {
		scope, machine := parseScopeKey(v.key)
		if err := validateScope(scope, machine); err != nil {
			return ErrPrecondition
		}
		current, err := readScopeTx(ctx, tx, t.AccountID, scope, machine, true)
		if v.expected == 0 {
			if !errors.Is(err, sql.ErrNoRows) {
				return ErrPrecondition
			}
			id, idErr := randomID("envscope_")
			if idErr != nil {
				return idErr
			}
			state := "active"
			manifest, parseErr := ParseManifest(v.raw, authority)
			if parseErr != nil {
				return parseErr
			}
			state = manifest.ScopeState
			if _, err := tx.Exec(ctx, `INSERT INTO environment_scopes(id,account_id,scope,machine_id,scope_state,version,key_epoch,authority_generation,authority_id,manifest_id) VALUES($1,$2,$3,NULLIF($4,''),$5,$6,$7,$8,$9,$10)`, id, t.AccountID, scope, machine, state, v.version, v.epoch, t.Generation, t.ProposedID, v.id); err != nil {
				return err
			}
			current = scopeRow{ID: id, AccountID: t.AccountID, Scope: scope, MachineID: machine, State: state, Version: 0}
		} else {
			if err != nil || current.Version != v.expected {
				return ErrPrecondition
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO environment_scope_manifests(scope_id,version,key_epoch,authority_generation,authority_id,operation_id,manifest_id,envelope) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, current.ID, v.version, v.epoch, t.Generation, t.ProposedID, v.operation, v.id, v.raw); err != nil {
			return err
		}
		manifest, err := ParseManifest(v.raw, authority)
		if err != nil {
			return err
		}
		if v.expected > 0 {
			if _, err := tx.Exec(ctx, `UPDATE environment_scopes SET scope_state=$2,version=$3,key_epoch=$4,authority_generation=$5,authority_id=$6,manifest_id=$7,updated_at=now() WHERE id=$1`, current.ID, manifest.ScopeState, v.version, v.epoch, t.Generation, t.ProposedID, v.id); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `DELETE FROM environment_scope_names WHERE scope_id=$1`, current.ID); err != nil {
			return err
		}
		for _, name := range v.names {
			if _, err := tx.Exec(ctx, `INSERT INTO environment_scope_names(scope_id,name) VALUES($1,$2)`, current.ID, name); err != nil {
				return err
			}
		}
		if err := s.auditManifestTx(ctx, tx, t.AccountID, manifest); err != nil {
			return err
		}
	}
	stagedByScope := make(map[string]staged, len(all))
	for _, value := range all {
		stagedByScope[value.key] = value
	}
	activeHostRecipients := make(map[string]struct{})
	for _, binding := range authority.Bindings {
		if binding.SubjectKind != 3 {
			continue
		}
		activeHostRecipients[binding.RecipientKeyID] = struct{}{}
		global, globalOK := stagedByScope[(ScopeRef{Scope: ScopeGlobal}).Key()]
		machine, machineOK := stagedByScope[(ScopeRef{Scope: ScopeMachine, MachineID: binding.SubjectID}).Key()]
		if !globalOK || !machineOK {
			return ErrPrecondition
		}
		if _, err := tx.Exec(ctx, `INSERT INTO environment_host_bootstraps(account_id,machine_id,subject_generation,key_generation,recipient_key_id,authority_generation,authority_id,global_version,global_key_epoch,global_manifest_id,global_envelope,machine_version,machine_key_epoch,machine_manifest_id,machine_envelope) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) ON CONFLICT(account_id,machine_id,recipient_key_id) DO NOTHING`, t.AccountID, binding.SubjectID, int64(binding.SubjectGeneration), int64(binding.KeyGeneration), binding.RecipientKeyID, t.Generation, t.ProposedID, global.version, global.epoch, global.id, global.raw, machine.version, machine.epoch, machine.id, machine.raw); err != nil {
			return err
		}
	}
	rows, err = tx.Query(ctx, `SELECT machine_id,recipient_key_id FROM environment_host_bootstraps WHERE account_id=$1`, t.AccountID)
	if err != nil {
		return err
	}
	var retired [][2]string
	for rows.Next() {
		var machineID, recipientID string
		if err := rows.Scan(&machineID, &recipientID); err != nil {
			rows.Close()
			return err
		}
		if _, active := activeHostRecipients[recipientID]; !active {
			retired = append(retired, [2]string{machineID, recipientID})
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, key := range retired {
		if _, err := tx.Exec(ctx, `DELETE FROM environment_host_bootstraps WHERE account_id=$1 AND machine_id=$2 AND recipient_key_id=$3`, t.AccountID, key[0], key[1]); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO environment_authority_heads(account_id,generation,authority_id) VALUES($1,$2,$3) ON CONFLICT(account_id) DO UPDATE SET generation=excluded.generation,authority_id=excluded.authority_id,updated_at=now()`, t.AccountID, t.Generation, t.ProposedID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE environment_authority_transitions SET state='active',activated_at=now() WHERE transition_id=$1 AND state='ready'`, t.ID); err != nil {
		return err
	}
	_, _ = tx.Exec(ctx, `UPDATE environment_key_enrollment_requests SET state='approved',approved_at=now() WHERE transition_id=$1 AND state='pending' AND expires_at>now()`, t.ID)
	return nil
}

// selectAuthoritySignerRoot returns the one account root that signed the
// authority document.  Account E2EE intentionally has an append-only live
// root set, but ENV's initial authority is its trust ceremony: accepting all
// live roots here would silently authorize every later account device to
// issue ENV authorities.  The persisted ENV verifier set is therefore the
// exact signer key, not the current account-root set.
func selectAuthoritySignerRoot(live peeridentity.AccountRoot, authority Authority) (peeridentity.AccountKey, error) {
	if authority.SignerKeyID == "" {
		return peeridentity.AccountKey{}, ErrRootSetChanged
	}
	var selected peeridentity.AccountKey
	for _, key := range live.Keys {
		if !validRootKeyID(key.KeyID, key.PublicKey) {
			return peeridentity.AccountKey{}, ErrRootSetChanged
		}
		if key.KeyID != authority.SignerKeyID {
			continue
		}
		if selected.KeyID != "" {
			return peeridentity.AccountKey{}, ErrRootSetChanged
		}
		selected = peeridentity.AccountKey{KeyID: key.KeyID, PublicKey: slices.Clone(key.PublicKey), Fingerprint: key.Fingerprint, Generation: key.Generation}
	}
	if selected.KeyID == "" {
		return peeridentity.AccountKey{}, ErrRootSetChanged
	}
	return selected, nil
}

func (s *Service) verificationRootsTx(ctx context.Context, tx *db.Tx, accountID string) (VerificationRoots, error) {
	rows, err := tx.Query(ctx, `SELECT key_id,public_key FROM environment_authority_roots WHERE account_id=$1 ORDER BY key_id`, accountID)
	if err != nil {
		return VerificationRoots{}, err
	}
	defer rows.Close()
	var pinned peeridentity.AccountRoot
	for rows.Next() {
		var key peeridentity.AccountKey
		var raw []byte
		if err := rows.Scan(&key.KeyID, &raw); err != nil {
			return VerificationRoots{}, err
		}
		key.PublicKey = ed25519.PublicKey(raw)
		pinned.Keys = append(pinned.Keys, key)
	}
	if len(pinned.Keys) == 0 {
		live, err := s.roots.Root(ctx, accountID)
		if err != nil {
			return VerificationRoots{}, err
		}
		return VerificationRoots{Environment: live, Endpoint: live}, nil
	}
	live, err := s.roots.Root(ctx, accountID)
	if err != nil {
		if errors.Is(err, peeridentity.ErrUnavailable) {
			return VerificationRoots{}, ErrRootSetChanged
		}
		return VerificationRoots{}, err
	}
	environment, err := selectVerificationRoots(live, pinned)
	if err != nil {
		return VerificationRoots{}, err
	}
	return VerificationRoots{Environment: environment, Endpoint: live}, nil
}

// selectVerificationRoots keeps the genesis-pinned roots as the only ENV
// verification keys. Account E2EE may add live keys for other purposes, so
// those keys are allowed as a live-set superset but never become ENV trust.
func selectVerificationRoots(live, pinned peeridentity.AccountRoot) (peeridentity.AccountRoot, error) {
	if len(pinned.Keys) == 0 {
		return live, nil
	}
	liveByID := make(map[string]ed25519.PublicKey, len(live.Keys))
	for _, key := range live.Keys {
		if previous, ok := liveByID[key.KeyID]; ok && !bytesEqual(previous, key.PublicKey) {
			return peeridentity.AccountRoot{}, ErrRootSetChanged
		}
		liveByID[key.KeyID] = key.PublicKey
	}
	for _, key := range pinned.Keys {
		public, ok := liveByID[key.KeyID]
		if !ok || !bytesEqual(public, key.PublicKey) {
			return peeridentity.AccountRoot{}, ErrRootSetChanged
		}
	}
	return pinned, nil
}

func (s *Service) validateEnrollmentIdentity(ctx context.Context, input EnrollmentRequest, kind int, now time.Time) error {
	roots, err := s.roots.Root(ctx, input.AccountID)
	if err != nil {
		return err
	}
	if kind == 2 {
		if len(input.EndpointCertificate) != 0 {
			return ErrProtocolInvalid
		}
		return nil
	}
	if kind == 3 {
		var installationGeneration int64
		var setupMode string
		var setupRoles []string
		err := s.db.Pool().QueryRow(ctx, `SELECT installation_generation,setup_mode,setup_roles FROM paperboat.user_machines WHERE id=$1 AND user_id=$2 AND deleted_at IS NULL`, input.SubjectID, input.AccountID).Scan(&installationGeneration, &setupMode, &setupRoles)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrMachineNotFound
		}
		if err != nil {
			return err
		}
		if !hostCapable(setupMode, setupRoles) {
			return ErrMachineNotHost
		}
		if installationGeneration != input.SubjectGeneration {
			return ErrPrecondition
		}
	}
	role := peeridentity.RoleCLI
	if kind == 3 {
		role = peeridentity.RoleMachine
	}
	for _, root := range roots.Keys {
		if _, err := peeridentity.Verify(input.EndpointCertificate, root.PublicKey, peeridentity.Expected{AccountID: input.AccountID, Role: role, EndpointID: input.SubjectID, Generation: uint64(input.SubjectGeneration)}, now); err == nil {
			return nil
		}
	}
	return ErrProtocolInvalid
}

func readEnrollmentByOperationTx(ctx context.Context, tx *db.Tx, accountID, operationID string, out *enrollmentRow) error {
	return scanEnrollment(tx.QueryRow(ctx, `SELECT id,state,expires_at,safety_code,canonical_request,signing_proof,challenge_envelope,request_digest,expected_proof,requester_kind,requester_id,subject_kind,subject_id,subject_generation,key_generation,operation_id,recipient_key_id,recipient_public_key FROM environment_key_enrollment_requests WHERE account_id=$1 AND operation_id=$2`, accountID, operationID), out)
}
func readEnrollmentForUpdateTx(ctx context.Context, tx *db.Tx, accountID, id string, out *enrollmentRow) error {
	return scanEnrollment(tx.QueryRow(ctx, `SELECT id,state,expires_at,safety_code,canonical_request,signing_proof,challenge_envelope,request_digest,expected_proof,requester_kind,requester_id,subject_kind,subject_id,subject_generation,key_generation,operation_id,recipient_key_id,recipient_public_key FROM environment_key_enrollment_requests WHERE account_id=$1 AND id=$2 FOR UPDATE`, accountID, id), out)
}
func scanEnrollment(row rowScanner, out *enrollmentRow) error {
	var signing []byte
	err := row.Scan(&out.ID, &out.State, &out.ExpiresAt, &out.SafetyCode, &out.Canonical, &signing, &out.Challenge, &out.RequestDigest, &out.ExpectedProof, &out.RequesterKind, &out.RequesterID, &out.SubjectKind, &out.SubjectID, &out.SubjectGeneration, &out.KeyGeneration, &out.OperationID, &out.RecipientKeyID, &out.RecipientPublic)
	if err != nil {
		return normalizeNoRows(err)
	}
	out.SigningProof = signing
	return nil
}
func enrollmentState(r enrollmentRow, challenge bool) EnrollmentState {
	out := EnrollmentState{Schema: "paperboat.environment-key-enrollment-state/v1", RequestID: r.ID, State: r.State, ExpiresAt: r.ExpiresAt.UTC(), SafetyCode: r.SafetyCode, EnrollmentRequest: base64.RawURLEncoding.EncodeToString(r.Canonical)}
	if len(r.SigningProof) > 0 {
		v := base64.RawURLEncoding.EncodeToString(r.SigningProof)
		out.SigningProof = &v
	}
	if challenge && r.State == "challenge" {
		out.Challenge = base64.RawURLEncoding.EncodeToString(r.Challenge)
	}
	return out
}

func (s *Service) validateMachineOwner(ctx context.Context, accountID, machineID string) error {
	machine, err := s.db.Queries().GetUserMachineForUser(ctx, dbsqlc.GetUserMachineForUserParams{ID: machineID, UserID: accountID})
	if errors.Is(err, sql.ErrNoRows) {
		return ErrMachineNotFound
	}
	if err != nil {
		return err
	}
	if !hostCapable(machine.SetupMode, machine.SetupRoles) {
		return ErrMachineNotHost
	}
	return nil
}

// markMachineScopeAuthorizationRequired replaces any initialized scope metadata
// when the machine no longer has an active host binding. The authorization-
// required shape is intentionally uninitialized so callers cannot treat stale
// retired or revoked-host metadata as deliverable state.
func markMachineScopeAuthorizationRequired(view *ScopeView) {
	scope, machineID := view.Scope, view.MachineID
	*view = ScopeView{
		Scope:     scope,
		MachineID: machineID,
		KeyState:  "key_authorization_required",
		Variables: []VariableMetadata{},
	}
}

func (s *Service) populateMachineStatusTx(ctx context.Context, tx *db.Tx, accountID, machineID string, view *ScopeView) error {
	machine, err := tx.Queries().GetUserMachineForUser(ctx, dbsqlc.GetUserMachineForUserParams{ID: machineID, UserID: accountID})
	if errors.Is(err, sql.ErrNoRows) {
		return ErrMachineNotFound
	}
	if err != nil {
		return err
	}
	if !hostCapable(machine.SetupMode, machine.SetupRoles) {
		return ErrMachineNotHost
	}
	authority, authorityErr := s.parseActiveAuthorityTx(ctx, tx, accountID)
	if authorityErr != nil && !errors.Is(authorityErr, sql.ErrNoRows) {
		return authorityErr
	}
	activeBinding, bindingReady := activeHostBindingForInstallation(authority, machineID, machine.InstallationGeneration, "")
	if !bindingReady {
		markMachineScopeAuthorizationRequired(view)
		if !machine.Online || machine.State != "online" {
			view.Status = "offline"
		} else {
			view.Status = "pending"
		}
		return nil
	}
	if !machine.Online || machine.State != "online" {
		view.Status = "offline"
		return nil
	}
	var g, m sql.NullInt64
	var globalManifestID, machineManifestID sql.NullString
	var observedRecipientKeyID, state string
	var code sql.NullString
	var observed time.Time
	err = tx.QueryRow(ctx, `SELECT host_recipient_key_id,global_version,global_manifest_id,machine_version,machine_manifest_id,state,error_code,observed_at FROM environment_observations WHERE account_id=$1 AND machine_id=$2`, accountID, machineID).Scan(&observedRecipientKeyID, &g, &globalManifestID, &m, &machineManifestID, &state, &code, &observed)
	if errors.Is(err, pgx.ErrNoRows) {
		view.Status = "pending"
		return nil
	}
	if err != nil {
		return err
	}
	if observedRecipientKeyID != activeBinding.RecipientKeyID {
		view.Status = "pending"
		return nil
	}
	view.AppliedGlobalVersion = g.Int64
	view.AppliedMachineVersion = m.Int64
	view.AppliedState = state
	view.ErrorCode = code.String
	view.ObservedAt = &observed
	if state != "applied" {
		view.Status = state
		return nil
	}
	global, _ := readScopeTx(ctx, tx, accountID, ScopeGlobal, "", false)
	if g.Int64 == global.Version && globalManifestID.String == global.ManifestID && m.Int64 == view.Version && machineManifestID.String == view.ManifestID {
		view.Status = "applied"
	} else {
		view.Status = "pending"
	}
	return nil
}

func (s *Service) auditManifestTx(ctx context.Context, tx *db.Tx, accountID string, m Manifest) error {
	if s.audit == nil {
		return nil
	}
	action := map[int]string{1: "set", 2: "unset", 3: "reauthorize", 4: "rotate", 5: "reset"}[m.MutationKind]
	return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: accountID, ActorType: audit.ActorUser, EventType: "environment_manifest." + action, ResourceType: "environment_manifest", ResourceID: m.ID, IdempotencyKey: "environment-manifest:" + m.OperationID, Metadata: map[string]any{"scope": m.Scope, "machine_id": m.MachineID, "changed_names": m.ChangedNames, "version": m.Version, "key_epoch": m.KeyEpoch, "signer": m.SignerKeyID, "manifest_id": m.ID}})
}

func normalizeNoRows(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return sql.ErrNoRows
	}
	return err
}
func sameStrings(a, b []string) bool             { return slices.Equal(a, b) }
func containsExact(v []string, name string) bool { return slices.Contains(v, name) }
func insertName(values []string, name string) []string {
	out := append([]string(nil), values...)
	if !slices.Contains(out, name) {
		out = append(out, name)
		sort.Strings(out)
	}
	return out
}
func removeName(values []string, name string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v != name {
			out = append(out, v)
		}
	}
	return out
}
func parseScopeKey(key string) (string, string) {
	if key == scopeRefGlobalKey {
		return ScopeGlobal, ""
	}
	if machine, ok := strings.CutPrefix(key, scopeRefMachineKey); ok && validIdentifier(machine) {
		return ScopeMachine, machine
	}
	return "", ""
}

func (s *Service) recordObservationTx(ctx context.Context, tx *db.Tx, accountID, machineID string, o Observation, received time.Time) error {
	var ag, gv, gk, mv, mk any
	var aid, gid, mid any
	if o.Authority != nil {
		ag, aid = o.Authority.Generation, o.Authority.AuthorityID
	}
	if o.Global != nil {
		gv, gk, gid = o.Global.Version, o.Global.KeyEpoch, o.Global.ManifestID
	}
	if o.Machine != nil {
		mv, mk, mid = o.Machine.Version, o.Machine.KeyEpoch, o.Machine.ManifestID
	}
	var code any
	if o.ErrorCode != nil {
		code = *o.ErrorCode
	}
	_, err := tx.Exec(ctx, `INSERT INTO environment_observations(machine_id,account_id,host_recipient_key_id,observation_seq,authority_generation,authority_id,global_version,global_key_epoch,global_manifest_id,machine_version,machine_key_epoch,machine_manifest_id,state,error_code,observed_at,received_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) ON CONFLICT(machine_id) DO UPDATE SET account_id=excluded.account_id,host_recipient_key_id=excluded.host_recipient_key_id,observation_seq=excluded.observation_seq,authority_generation=excluded.authority_generation,authority_id=excluded.authority_id,global_version=excluded.global_version,global_key_epoch=excluded.global_key_epoch,global_manifest_id=excluded.global_manifest_id,machine_version=excluded.machine_version,machine_key_epoch=excluded.machine_key_epoch,machine_manifest_id=excluded.machine_manifest_id,state=excluded.state,error_code=excluded.error_code,observed_at=excluded.observed_at,received_at=excluded.received_at WHERE environment_observations.account_id=excluded.account_id AND (excluded.host_recipient_key_id<>environment_observations.host_recipient_key_id OR excluded.observation_seq>environment_observations.observation_seq)`, machineID, accountID, o.HostRecipientKeyID, o.ObservationSeq, ag, aid, gv, gk, gid, mv, mk, mid, o.State, code, o.ObservedAt.UTC(), received)
	return err
}

func (s *Service) runtimeBundleTx(ctx context.Context, tx *db.Tx, accountID, machineID string, installationGeneration int64, o Observation) (*Bundle, error) {
	head, err := readAuthorityHeadTx(ctx, tx, accountID, false)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	bundle := &Bundle{Schema: BundleSchema, AuthorityHead: AuthorityRef{Generation: head.Generation, AuthorityID: head.ID}, AuthorityDocuments: []string{}}
	authority, err := s.parseActiveAuthorityTx(ctx, tx, accountID)
	if err != nil {
		return nil, err
	}
	authorized := false
	recipientListed := false
	var activeBinding Binding
	for _, b := range authority.Bindings {
		if b.SubjectKind == 3 && b.SubjectID == machineID && b.RecipientKeyID == o.HostRecipientKeyID {
			recipientListed = true
			break
		}
	}
	if binding, ok := activeHostBindingForInstallation(authority, machineID, installationGeneration, o.HostRecipientKeyID); ok {
		authorized = true
		activeBinding = binding
	}
	// A never-authorized host is waiting for key authorization. Only a host
	// with an accepted authority cursor needs an exclusion chain marked as a
	// revocation-only delivery.
	bundle.RevocationOnly = o.Authority != nil && !authorized && !recipientListed
	if authorized {
		if transitionID, pendingErr := pendingTransitionTx(ctx, tx, accountID); pendingErr == nil {
			transition, readErr := readTransitionTx(ctx, tx, accountID, transitionID, false)
			if readErr != nil {
				return nil, readErr
			}
			roots, rootErr := s.verificationRootsTx(ctx, tx, accountID)
			if rootErr != nil {
				return nil, rootErr
			}
			proposed, parseErr := ParseAuthority(transition.Raw, roots.Environment, roots.Endpoint)
			if parseErr != nil {
				return nil, parseErr
			}
			proposedBinding, stillAuthorized := activeHostBindingForInstallation(proposed, machineID, installationGeneration, o.HostRecipientKeyID)
			stillAuthorized = stillAuthorized && proposedBinding.KeyGeneration == activeBinding.KeyGeneration
			if !stillAuthorized {
				// Staging a removal immediately suspends new ENV delivery. The
				// exclusion chain becomes revocation-only only after activation.
				return bundle, nil
			}
		} else if !errors.Is(pendingErr, sql.ErrNoRows) {
			return nil, pendingErr
		}
	}
	start := int64(0)
	if o.Authority != nil {
		start = o.Authority.Generation
		if start > head.Generation {
			return nil, ErrAuthorityFork
		}
		var id string
		if err := tx.QueryRow(ctx, `SELECT authority_id FROM environment_authorities WHERE account_id=$1 AND generation=$2`, accountID, start).Scan(&id); err != nil || id != o.Authority.AuthorityID {
			return nil, ErrAuthorityFork
		}
	}
	if start < head.Generation {
		rows, err := tx.Query(ctx, `SELECT generation,envelope FROM environment_authorities WHERE account_id=$1 AND generation>$2 ORDER BY generation LIMIT 5`, accountID, start)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		decoded := 0
		nextGeneration := start + 1
		for rows.Next() {
			var generation int64
			var raw []byte
			if err := rows.Scan(&generation, &raw); err != nil {
				return nil, err
			}
			if generation != nextGeneration {
				return nil, ErrAuthorityFork
			}
			nextGeneration++
			if len(bundle.AuthorityDocuments) == 4 || decoded+len(raw) > 4<<20 {
				bundle.AuthorityHasMore = true
				break
			}
			decoded += len(raw)
			bundle.AuthorityDocuments = append(bundle.AuthorityDocuments, base64.RawURLEncoding.EncodeToString(raw))
		}
		if len(bundle.AuthorityDocuments) > 0 || bundle.AuthorityHasMore {
			return bundle, rows.Err()
		}
	}
	if !authorized {
		return bundle, nil
	}
	if o.Global == nil || o.Machine == nil {
		var bootstrap Bootstrap
		var globalEnvelope, machineEnvelope []byte
		err := tx.QueryRow(ctx, `SELECT authority_generation,authority_id,global_version,global_key_epoch,global_manifest_id,global_envelope,machine_version,machine_key_epoch,machine_manifest_id,machine_envelope FROM environment_host_bootstraps WHERE account_id=$1 AND machine_id=$2 AND recipient_key_id=$3 AND subject_generation=$4 AND key_generation=$5`, accountID, machineID, o.HostRecipientKeyID, installationGeneration, int64(activeBinding.KeyGeneration)).Scan(
			&bootstrap.Authority.Generation, &bootstrap.Authority.AuthorityID,
			&bootstrap.GlobalManifest.Version, &bootstrap.GlobalManifest.KeyEpoch, &bootstrap.GlobalManifest.ManifestID, &globalEnvelope,
			&bootstrap.MachineManifest.Version, &bootstrap.MachineManifest.KeyEpoch, &bootstrap.MachineManifest.ManifestID, &machineEnvelope,
		)
		if errors.Is(err, pgx.ErrNoRows) {
			return bundle, nil
		}
		if err != nil {
			return nil, err
		}
		bootstrap.GlobalManifest.Envelope = base64.RawURLEncoding.EncodeToString(globalEnvelope)
		bootstrap.MachineManifest.Envelope = base64.RawURLEncoding.EncodeToString(machineEnvelope)
		bundle.AuthorizationBootstrap = &bootstrap
	}
	global, err := readScopeTx(ctx, tx, accountID, ScopeGlobal, "", false)
	if err != nil {
		return nil, err
	}
	machine, err := readScopeTx(ctx, tx, accountID, ScopeMachine, machineID, false)
	if err != nil {
		return nil, err
	}
	sameGlobal := o.Global != nil && o.Global.Version == global.Version && o.Global.KeyEpoch == global.KeyEpoch && o.Global.ManifestID == global.ManifestID
	sameMachine := o.Machine != nil && o.Machine.Version == machine.Version && o.Machine.KeyEpoch == machine.KeyEpoch && o.Machine.ManifestID == machine.ManifestID
	if sameGlobal && sameMachine {
		return nil, nil
	}
	bundle.GlobalManifest, err = bundleManifestTx(ctx, tx, global)
	if err != nil {
		return nil, err
	}
	bundle.MachineManifest, err = bundleManifestTx(ctx, tx, machine)
	if err != nil {
		return nil, err
	}
	return bundle, nil
}
func bundleManifestTx(ctx context.Context, tx *db.Tx, row scopeRow) (*BundleManifest, error) {
	var raw []byte
	if err := tx.QueryRow(ctx, `SELECT envelope FROM environment_scope_manifests WHERE scope_id=$1 AND version=$2`, row.ID, row.Version).Scan(&raw); err != nil {
		return nil, err
	}
	return &BundleManifest{Version: row.Version, KeyEpoch: row.KeyEpoch, ManifestID: row.ManifestID, Envelope: base64.RawURLEncoding.EncodeToString(raw)}, nil
}
