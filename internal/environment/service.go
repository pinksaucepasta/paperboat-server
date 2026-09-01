// Package environment owns the opaque control-plane half of ENV Injection
// E2EE. It validates signed public structure and routes ciphertext. It has no
// decrypt API and accepts no plaintext value.
package environment

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/peeridentity"
)

const (
	ScopeGlobal       = "global"
	ScopeMachine      = "machine"
	ObservationSchema = "paperboat.environment-observation/v2"
	BundleSchema      = "paperboat.environment-bundle/v2"
	MaxVariables      = 128
	MaxNameBytes      = 128
	MaxErrorCodeBytes = 64
)

var (
	ErrInvalidScope             = errors.New("environment scope is invalid")
	ErrInvalidName              = errors.New("environment variable name is invalid")
	ErrLimitExceeded            = errors.New("environment E2EE document exceeds a bound")
	ErrVersionConflict          = errors.New("environment scope version conflicts")
	ErrAuthorityConflict        = errors.New("environment authority conflicts")
	ErrTransitionInProgress     = errors.New("environment authority transition is in progress")
	ErrOperationConflict        = errors.New("environment operation conflicts")
	ErrPrecondition             = errors.New("environment precondition failed")
	ErrNotFound                 = errors.New("environment resource not found")
	ErrMachineNotFound          = errors.New("environment machine not found")
	ErrMachineNotHost           = errors.New("environment machine is not host-capable")
	ErrKeyAuthorizationRequired = errors.New("environment key authorization is required")
	ErrObservationInvalid       = errors.New("environment observation is invalid")
	ErrAuthorityFork            = errors.New("environment authority cursor is missing or forked")
	ErrRequesterMismatch        = errors.New("environment enrollment requester does not match")
	ErrEnrollmentExpired        = errors.New("environment enrollment expired")
	ErrRootSetChanged           = errors.New("environment root set changed")
	portableName                = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	safeErrorCode               = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
	digestExpression            = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type VersionConflictError struct{ CurrentVersion int64 }

func (e *VersionConflictError) Error() string {
	return fmt.Sprintf("environment scope version is %d", e.CurrentVersion)
}
func (e *VersionConflictError) Is(target error) bool { return target == ErrVersionConflict }

type AuthorityConflictError struct{ CurrentID string }

func (e *AuthorityConflictError) Error() string        { return "environment authority changed" }
func (e *AuthorityConflictError) Is(target error) bool { return target == ErrAuthorityConflict }

type VariableMetadata struct {
	Scope      string    `json:"scope"`
	MachineID  string    `json:"machine_id,omitempty"`
	Name       string    `json:"name"`
	Configured bool      `json:"configured"`
	Version    int64     `json:"version"`
	UpdatedAt  time.Time `json:"updated_at"`
}
type ScopeView struct {
	Scope                 string             `json:"scope"`
	MachineID             string             `json:"machine_id,omitempty"`
	ScopeState            string             `json:"scope_state,omitempty"`
	KeyState              string             `json:"key_state,omitempty"`
	Version               int64              `json:"version"`
	KeyEpoch              int64              `json:"key_epoch,omitempty"`
	ManifestID            string             `json:"manifest_id,omitempty"`
	Variables             []VariableMetadata `json:"variables"`
	Status                string             `json:"status,omitempty"`
	AppliedGlobalVersion  int64              `json:"applied_global_version,omitempty"`
	AppliedMachineVersion int64              `json:"applied_machine_version,omitempty"`
	AppliedState          string             `json:"applied_state,omitempty"`
	ErrorCode             string             `json:"error_code,omitempty"`
	ObservedAt            *time.Time         `json:"observed_at,omitempty"`
}
type ScopeInventoryItem struct {
	Scope      string   `json:"scope"`
	MachineID  string   `json:"machine_id,omitempty"`
	ScopeState string   `json:"scope_state"`
	Version    int64    `json:"version"`
	KeyEpoch   int64    `json:"key_epoch"`
	ManifestID string   `json:"manifest_id"`
	Names      []string `json:"names"`
}
type ScopeInventory struct {
	Schema string               `json:"schema"`
	Scopes []ScopeInventoryItem `json:"scopes"`
}
type ManifestState struct {
	Schema     string `json:"schema"`
	Scope      string `json:"scope"`
	MachineID  string `json:"machine_id,omitempty"`
	Version    int64  `json:"version"`
	KeyEpoch   int64  `json:"key_epoch"`
	ManifestID string `json:"manifest_id"`
	Envelope   string `json:"envelope"`
}
type ManifestMutation struct {
	AccountID, Scope, MachineID, OperationID string
	ExpectedVersion                          int64
	Envelope                                 []byte
}
type AuthorityState struct {
	Schema      string `json:"schema"`
	Generation  int64  `json:"generation"`
	AuthorityID string `json:"authority_id"`
	Authority   string `json:"authority"`
}
type AuthorityPage struct {
	Schema             string       `json:"schema"`
	AuthorityHead      AuthorityRef `json:"authority_head"`
	AuthorityDocuments []string     `json:"authority_documents"`
	HasMore            bool         `json:"has_more"`
}

type EnrollmentRequest struct {
	AccountID, RequesterKind, RequesterID, OperationID, SubjectKind, SubjectID string
	SubjectGeneration, KeyGeneration                                           int64
	EndpointCertificate, SigningPublicKey, SigningProof, RecipientPublicKey    []byte
	SigningKeyID, RecipientKeyID                                               string
	RequestExpiresAt                                                           time.Time
}
type EnrollmentState struct {
	Schema            string    `json:"schema"`
	RequestID         string    `json:"request_id"`
	State             string    `json:"state"`
	ExpiresAt         time.Time `json:"expires_at"`
	SafetyCode        string    `json:"safety_code"`
	EnrollmentRequest string    `json:"enrollment_request"`
	SigningProof      *string   `json:"signing_proof"`
	Challenge         string    `json:"challenge,omitempty"`
}
type ApprovalRequest struct {
	AccountID, RequestID, ExpectedAuthorityID, OperationID string
	Binding, Authority                                     []byte
}
type TransitionRequest struct {
	AccountID, ExpectedAuthorityID, OperationID string
	Authority                                   []byte
}
type TransitionManifestRequest struct {
	AccountID, TransitionID, Scope, MachineID, OperationID string
	ExpectedVersion                                        int64
	Envelope                                               []byte
}
type AbortRequest struct {
	AccountID, TransitionID, ExpectedTransitionID, OperationID string
	ExpectedAuthorityID                                        string
	Authorization                                              []byte
}
type TransitionState struct {
	Schema              string   `json:"schema"`
	TransitionID        string   `json:"transition_id"`
	State               string   `json:"state"`
	ProposedGeneration  int64    `json:"proposed_generation"`
	ProposedAuthorityID string   `json:"proposed_authority_id"`
	RequiredScopes      []string `json:"required_scopes"`
	StagedScopes        []string `json:"staged_scopes"`
}

type ObservationRef struct {
	Version    int64  `json:"version"`
	KeyEpoch   int64  `json:"key_epoch"`
	ManifestID string `json:"manifest_id"`
}
type AuthorityRef struct {
	Generation  int64  `json:"generation"`
	AuthorityID string `json:"authority_id"`
}
type Observation struct {
	Schema             string          `json:"schema"`
	ObservationSeq     int64           `json:"observation_seq"`
	HostRecipientKeyID string          `json:"host_recipient_key_id"`
	Authority          *AuthorityRef   `json:"authority"`
	Global             *ObservationRef `json:"global"`
	Machine            *ObservationRef `json:"machine"`
	State              string          `json:"state"`
	ErrorCode          *string         `json:"error_code"`
	ObservedAt         time.Time       `json:"observed_at"`
}
type BundleManifest struct {
	Version    int64  `json:"version"`
	KeyEpoch   int64  `json:"key_epoch"`
	ManifestID string `json:"manifest_id"`
	Envelope   string `json:"envelope"`
}
type Bootstrap struct {
	Authority       AuthorityRef   `json:"authority"`
	GlobalManifest  BundleManifest `json:"global_manifest"`
	MachineManifest BundleManifest `json:"machine_manifest"`
}
type Bundle struct {
	Schema                 string          `json:"schema"`
	AuthorityHead          AuthorityRef    `json:"authority_head"`
	AuthorityDocuments     []string        `json:"authority_documents"`
	AuthorityHasMore       bool            `json:"authority_has_more"`
	RevocationOnly         bool            `json:"revocation_only"`
	AuthorizationBootstrap *Bootstrap      `json:"authorization_bootstrap"`
	GlobalManifest         *BundleManifest `json:"global_manifest"`
	MachineManifest        *BundleManifest `json:"machine_manifest"`
}
type RuntimeResult struct{ Bundle *Bundle }

type RootResolver interface {
	Root(context.Context, string) (peeridentity.AccountRoot, error)
}
type Service struct {
	db    *db.DB
	audit *audit.Writer
	roots RootResolver
	now   func() time.Time
}

func NewService(store *db.DB, writer *audit.Writer, roots RootResolver) *Service {
	return &Service{db: store, audit: writer, roots: roots, now: func() time.Time { return time.Now().UTC() }}
}
func (s *Service) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

func (s *Service) AuthorizeManager(ctx context.Context, accountID, subjectKind, subjectID string) error {
	if (subjectKind != "manager_cli" && subjectKind != "manager_browser") || !validIdentifier(subjectID) {
		return ErrKeyAuthorizationRequired
	}
	return s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		authority, err := s.parseActiveAuthorityTx(ctx, tx, accountID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrKeyAuthorizationRequired
			}
			return err
		}
		active := false
		for _, binding := range authority.Bindings {
			if binding.SubjectKindName() == subjectKind && binding.SubjectID == subjectID {
				active = true
				break
			}
		}
		if !active {
			return ErrKeyAuthorizationRequired
		}
		transitionID, err := pendingTransitionTx(ctx, tx, accountID)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		transition, err := readTransitionTx(ctx, tx, accountID, transitionID, false)
		if err != nil {
			return err
		}
		roots, err := s.verificationRootsTx(ctx, tx, accountID)
		if err != nil {
			return err
		}
		proposed, err := ParseAuthority(transition.Raw, roots.Environment, roots.Endpoint)
		if err != nil {
			return err
		}
		for _, binding := range proposed.Bindings {
			if binding.SubjectKindName() == subjectKind && binding.SubjectID == subjectID {
				return nil
			}
		}
		return ErrKeyAuthorizationRequired
	})
}

func ValidateName(name string) error {
	if len(name) == 0 || len([]byte(name)) > MaxNameBytes || !portableName.MatchString(name) {
		return ErrInvalidName
	}
	upper := strings.ToUpper(name)
	if strings.HasPrefix(upper, "PAPERBOAT_") || strings.HasPrefix(upper, "LD_") || strings.HasPrefix(upper, "DYLD_") {
		return ErrInvalidName
	}
	switch upper {
	case "NODE_OPTIONS", "PYTHONPATH", "PYTHONHOME", "GOTRACEBACK":
		return ErrInvalidName
	}
	return nil
}
func ValidateObservation(o Observation) error {
	if o.Schema != ObservationSchema || o.ObservationSeq <= 0 || !strings.HasPrefix(o.HostRecipientKeyID, "envk_") || !keyIDExpression.MatchString(o.HostRecipientKeyID) || o.ObservedAt.IsZero() {
		return ErrObservationInvalid
	}
	if o.State != "pending" && o.State != "applied" && o.State != "failed" {
		return ErrObservationInvalid
	}
	if (o.State == "failed") != (o.ErrorCode != nil) || (o.ErrorCode != nil && !safeErrorCode.MatchString(*o.ErrorCode)) {
		return ErrObservationInvalid
	}
	if o.Authority != nil && (o.Authority.Generation <= 0 || o.Authority.Generation > int64(MaxBrowserInteger) || !digestExpression.MatchString(o.Authority.AuthorityID)) {
		return ErrObservationInvalid
	}
	for _, r := range []*ObservationRef{o.Global, o.Machine} {
		if r != nil && (r.Version <= 0 || r.KeyEpoch <= 0 || r.Version > int64(MaxBrowserInteger) || r.KeyEpoch > int64(MaxBrowserInteger) || !digestExpression.MatchString(r.ManifestID)) {
			return ErrObservationInvalid
		}
	}
	return nil
}

func (s *Service) List(ctx context.Context, accountID string) (ScopeView, error) {
	return s.list(ctx, accountID, ScopeGlobal, "")
}
func (s *Service) ListMachine(ctx context.Context, accountID, machineID string) (ScopeView, error) {
	if err := s.validateMachineOwner(ctx, accountID, machineID); err != nil {
		return ScopeView{}, err
	}
	return s.list(ctx, accountID, ScopeMachine, machineID)
}
func (s *Service) ListScopes(ctx context.Context, accountID string) (ScopeInventory, error) {
	out := ScopeInventory{Schema: "paperboat.environment-scope-inventory/v1", Scopes: []ScopeInventoryItem{}}
	rows, err := s.db.Pool().Query(ctx, `SELECT s.scope,COALESCE(s.machine_id,''),s.scope_state,s.version,s.key_epoch,s.manifest_id,n.name FROM paperboat.environment_scopes s LEFT JOIN paperboat.environment_scope_names n ON n.scope_id=s.id WHERE s.account_id=$1 ORDER BY CASE WHEN s.scope='global' THEN 0 ELSE 1 END,s.machine_id NULLS FIRST,n.name`, accountID)
	if err != nil {
		return ScopeInventory{}, err
	}
	defer rows.Close()
	indexes := make(map[[2]string]int)
	for rows.Next() {
		var scope, machineID, scopeState, manifestID string
		var version, keyEpoch int64
		var name sql.NullString
		if err := rows.Scan(&scope, &machineID, &scopeState, &version, &keyEpoch, &manifestID, &name); err != nil {
			return ScopeInventory{}, err
		}
		key := [2]string{scope, machineID}
		index, ok := indexes[key]
		if !ok {
			index = len(out.Scopes)
			indexes[key] = index
			out.Scopes = append(out.Scopes, ScopeInventoryItem{Scope: scope, MachineID: machineID, ScopeState: scopeState, Version: version, KeyEpoch: keyEpoch, ManifestID: manifestID, Names: []string{}})
		}
		if name.Valid {
			out.Scopes[index].Names = append(out.Scopes[index].Names, name.String)
		}
	}
	if err := rows.Err(); err != nil {
		return ScopeInventory{}, err
	}
	// PostgreSQL text ordering follows the database collation. Sort in Go so
	// the public inventory is stable bytewise regardless of cluster locale.
	sort.Slice(out.Scopes, func(i, j int) bool {
		left, right := out.Scopes[i], out.Scopes[j]
		if left.Scope != right.Scope {
			if left.Scope == ScopeGlobal {
				return true
			}
			if right.Scope == ScopeGlobal {
				return false
			}
			return left.Scope < right.Scope
		}
		return left.MachineID < right.MachineID
	})
	for i := range out.Scopes {
		sort.Strings(out.Scopes[i].Names)
	}
	return out, nil
}
func (s *Service) Get(ctx context.Context, accountID, scope, machineID, name string) (VariableMetadata, error) {
	if ValidateName(name) != nil {
		return VariableMetadata{}, ErrInvalidName
	}
	v, err := s.list(ctx, accountID, scope, machineID)
	if err != nil {
		return VariableMetadata{}, err
	}
	for _, item := range v.Variables {
		if item.Name == name {
			return item, nil
		}
	}
	return VariableMetadata{}, ErrNotFound
}
func (s *Service) list(ctx context.Context, accountID, scope, machineID string) (ScopeView, error) {
	if err := validateScope(scope, machineID); err != nil {
		return ScopeView{}, err
	}
	view := ScopeView{Scope: scope, MachineID: machineID, Variables: []VariableMetadata{}, KeyState: "key_authorization_required"}
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		row, err := readScopeTx(ctx, tx, accountID, scope, machineID, false)
		if errors.Is(normalizeNoRows(err), sql.ErrNoRows) {
			if scope == ScopeMachine {
				return s.populateMachineStatusTx(ctx, tx, accountID, machineID, &view)
			}
			return nil
		}
		if err != nil {
			return err
		}
		view.Version, view.KeyEpoch, view.ManifestID, view.ScopeState = row.Version, row.KeyEpoch, row.ManifestID, row.State
		view.KeyState = "ready"
		if transitionID, pendingErr := pendingTransitionTx(ctx, tx, accountID); pendingErr == nil {
			transition, transitionErr := readTransitionTx(ctx, tx, accountID, transitionID, false)
			if transitionErr != nil {
				return transitionErr
			}
			roots, rootErr := s.verificationRootsTx(ctx, tx, accountID)
			if rootErr != nil {
				return rootErr
			}
			previous, previousErr := s.parseActiveAuthorityTx(ctx, tx, accountID)
			if previousErr != nil {
				return previousErr
			}
			proposed, proposedErr := ParseAuthority(transition.Raw, roots.Environment, roots.Endpoint)
			if proposedErr != nil {
				return proposedErr
			}
			if scopeRequiresRotation(previous, proposed, scope, machineID) {
				view.KeyState = "rotation_required"
			}
		} else if !errors.Is(pendingErr, sql.ErrNoRows) {
			return pendingErr
		}
		rows, err := tx.Query(ctx, `SELECT name,updated_at FROM environment_scope_names WHERE scope_id=$1 ORDER BY name`, row.ID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var name string
			var updated time.Time
			if err := rows.Scan(&name, &updated); err != nil {
				return err
			}
			view.Variables = append(view.Variables, VariableMetadata{Scope: scope, MachineID: machineID, Name: name, Configured: true, Version: row.Version, UpdatedAt: updated})
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if scope == ScopeMachine {
			return s.populateMachineStatusTx(ctx, tx, accountID, machineID, &view)
		}
		return nil
	})
	return view, err
}

func (s *Service) GetAuthority(ctx context.Context, accountID string) (AuthorityState, error) {
	var out AuthorityState
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		head, err := readAuthorityHeadTx(ctx, tx, accountID, false)
		if err != nil {
			return err
		}
		out = AuthorityState{Schema: "paperboat.environment-authority-state/v1", Generation: head.Generation, AuthorityID: head.ID, Authority: base64.RawURLEncoding.EncodeToString(head.Raw)}
		return nil
	})
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return out, err
}
func (s *Service) GetAuthorityDocuments(ctx context.Context, accountID string, afterGeneration int64, afterID string) (AuthorityPage, error) {
	if afterGeneration < 0 || afterGeneration > int64(MaxBrowserInteger) || (afterGeneration == 0) != (afterID == "") || (afterGeneration > 0 && !digestExpression.MatchString(afterID)) {
		return AuthorityPage{}, ErrPrecondition
	}
	var out AuthorityPage
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		var err error
		out, err = authorityPageTx(ctx, tx, accountID, afterGeneration, afterID)
		return err
	})
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return out, err
}
func (s *Service) GetManifest(ctx context.Context, accountID, scope, machineID string) (ManifestState, error) {
	if err := validateScope(scope, machineID); err != nil {
		return ManifestState{}, err
	}
	if scope == ScopeMachine {
		if err := s.validateMachineOwner(ctx, accountID, machineID); err != nil {
			return ManifestState{}, err
		}
	}
	var out ManifestState
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		row, err := readScopeTx(ctx, tx, accountID, scope, machineID, false)
		if err != nil {
			return err
		}
		return loadManifestStateTx(ctx, tx, row, &out)
	})
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return out, err
}

func (s *Service) PutManifest(ctx context.Context, input ManifestMutation) (ManifestState, error) {
	if err := validateScope(input.Scope, input.MachineID); err != nil {
		return ManifestState{}, err
	}
	if input.ExpectedVersion <= 0 || !operationExpression.MatchString(input.OperationID) {
		return ManifestState{}, ErrPrecondition
	}
	if input.Scope == ScopeMachine {
		if err := s.validateMachineOwner(ctx, input.AccountID, input.MachineID); err != nil {
			return ManifestState{}, err
		}
	}
	var out ManifestState
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := lockAccountTx(ctx, tx, input.AccountID); err != nil {
			return err
		}
		if id, err := pendingTransitionTx(ctx, tx, input.AccountID); err == nil && id != "" {
			return ErrTransitionInProgress
		} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		authority, err := s.parseActiveAuthorityTx(ctx, tx, input.AccountID)
		if err != nil {
			return err
		}
		current, err := readScopeTx(ctx, tx, input.AccountID, input.Scope, input.MachineID, true)
		if err != nil {
			return err
		}
		if existing, found, loadErr := manifestOperationStateTx(ctx, tx, current, input.OperationID); loadErr != nil {
			return loadErr
		} else if found {
			if existing.ManifestID != DocumentID(input.Envelope) || existing.Envelope != base64.RawURLEncoding.EncodeToString(input.Envelope) {
				return ErrOperationConflict
			}
			out = existing
			return nil
		}
		if current.Version != input.ExpectedVersion {
			return &VersionConflictError{CurrentVersion: current.Version}
		}
		manifest, err := ParseManifest(input.Envelope, authority)
		if err != nil {
			return err
		}
		if manifest.Scope != input.Scope || manifest.MachineID != input.MachineID || manifest.PreviousVersion != uint64(current.Version) || manifest.OperationID != input.OperationID {
			return ErrPrecondition
		}
		if err := validateNormalMutation(manifest, current); err != nil {
			return err
		}
		if err := validateScopeNameCompatibilityTx(ctx, tx, input.AccountID, input.Scope, input.MachineID, manifest.Names); err != nil {
			return err
		}
		if id, err := manifestOperationTx(ctx, tx, current.ID, input.OperationID); err == nil {
			if id != manifest.ID {
				return ErrOperationConflict
			}
			return loadManifestStateTx(ctx, tx, current, &out)
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err := activateManifestTx(ctx, tx, current, manifest); err != nil {
			return err
		}
		current.Version, current.KeyEpoch, current.ManifestID, current.State = int64(manifest.Version), int64(manifest.KeyEpoch), manifest.ID, manifest.ScopeState
		if err := loadManifestStateTx(ctx, tx, current, &out); err != nil {
			return err
		}
		return s.auditManifestTx(ctx, tx, input.AccountID, manifest)
	})
	return out, err
}

func (s *Service) RequestEnrollment(ctx context.Context, input EnrollmentRequest) (EnrollmentState, error) {
	now := s.now().UTC()
	kind := map[string]int{"manager_cli": 1, "manager_browser": 2, "host": 3}[input.SubjectKind]
	if kind == 0 || !validRequester(input) || !input.RequestExpiresAt.After(now) || input.RequestExpiresAt.After(now.Add(5*time.Minute)) {
		return EnrollmentState{}, ErrProtocolInvalid
	}
	canonical, digest, safety, err := CanonicalEnrollment(EnrollmentCanonicalInput{AccountID: input.AccountID, OperationID: input.OperationID, SubjectKind: kind, SubjectID: input.SubjectID, SubjectGeneration: uint64(input.SubjectGeneration), KeyGeneration: uint64(input.KeyGeneration), EndpointCertificate: input.EndpointCertificate, SigningPublic: input.SigningPublicKey, SigningKeyID: input.SigningKeyID, RecipientPublic: input.RecipientPublicKey, RecipientKeyID: input.RecipientKeyID, ExpiresAt: input.RequestExpiresAt})
	if err != nil {
		return EnrollmentState{}, err
	}
	manager := kind < 3
	if manager {
		if len(input.SigningPublicKey) != 32 || len(input.SigningProof) != 64 || !ed25519.Verify(input.SigningPublicKey, EnrollmentSigningBytes(canonical), input.SigningProof) {
			return EnrollmentState{}, ErrProtocolSignature
		}
	} else if len(input.SigningPublicKey) != 0 || len(input.SigningProof) != 0 || input.SigningKeyID != "" {
		return EnrollmentState{}, ErrProtocolInvalid
	}
	if err := s.validateEnrollmentIdentity(ctx, input, kind, now); err != nil {
		return EnrollmentState{}, err
	}
	requestID, err := randomID("envreq_")
	if err != nil {
		return EnrollmentState{}, err
	}
	challenge, proof, err := SealEnrollmentChallenge(input.AccountID, requestID, input.OperationID, input.RecipientKeyID, input.RecipientPublicKey, digest[:])
	if err != nil {
		return EnrollmentState{}, err
	}
	row := enrollmentRow{ID: requestID, State: "challenge", ExpiresAt: input.RequestExpiresAt.UTC(), SafetyCode: safety, Canonical: canonical, SigningProof: input.SigningProof, Challenge: challenge, RequestDigest: digest[:], ExpectedProof: proof, RequesterKind: input.RequesterKind, RequesterID: input.RequesterID, SubjectKind: input.SubjectKind, SubjectID: input.SubjectID, SubjectGeneration: input.SubjectGeneration, KeyGeneration: input.KeyGeneration, RecipientKeyID: input.RecipientKeyID, RecipientPublic: input.RecipientPublicKey}
	err = s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := lockAccountTx(ctx, tx, input.AccountID); err != nil {
			return err
		}
		var existing enrollmentRow
		if err := readEnrollmentByOperationTx(ctx, tx, input.AccountID, input.OperationID, &existing); err == nil {
			if existing.RequesterKind != input.RequesterKind || existing.RequesterID != input.RequesterID {
				return ErrRequesterMismatch
			}
			if !bytesEqual(existing.RequestDigest, digest[:]) {
				return ErrOperationConflict
			}
			row = existing
			return nil
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO environment_key_enrollment_requests(id,account_id,requester_kind,requester_id,subject_kind,subject_id,subject_generation,key_generation,operation_id,request_digest,canonical_request,signing_proof,recipient_key_id,recipient_public_key,safety_code,challenge_envelope,expected_proof,state,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,'challenge',$18)`, row.ID, input.AccountID, row.RequesterKind, row.RequesterID, row.SubjectKind, row.SubjectID, row.SubjectGeneration, row.KeyGeneration, input.OperationID, row.RequestDigest, row.Canonical, nullableBytesSQL(row.SigningProof), row.RecipientKeyID, row.RecipientPublic, row.SafetyCode, row.Challenge, row.ExpectedProof, row.ExpiresAt)
		return err
	})
	return enrollmentState(row, true), err
}

func (s *Service) ProveEnrollment(ctx context.Context, accountID, requestID, requesterKind, requesterID string, proof []byte) (EnrollmentState, error) {
	if len(proof) != 32 {
		return EnrollmentState{}, ErrProtocolInvalid
	}
	var row enrollmentRow
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := readEnrollmentForUpdateTx(ctx, tx, accountID, requestID, &row); err != nil {
			return err
		}
		if row.RequesterKind != requesterKind || row.RequesterID != requesterID {
			return ErrRequesterMismatch
		}
		if !s.now().UTC().Before(row.ExpiresAt) {
			_, _ = tx.Exec(ctx, `UPDATE environment_key_enrollment_requests SET state='expired' WHERE id=$1`, requestID)
			return ErrEnrollmentExpired
		}
		if row.State == "pending" && subtle.ConstantTimeCompare(row.ExpectedProof, proof) == 1 {
			return nil
		}
		if row.State != "challenge" || subtle.ConstantTimeCompare(row.ExpectedProof, proof) != 1 {
			return ErrProtocolInvalid
		}
		if _, err := tx.Exec(ctx, `UPDATE environment_key_enrollment_requests SET state='pending',proved_at=$2 WHERE id=$1`, requestID, s.now().UTC()); err != nil {
			return err
		}
		row.State = "pending"
		return nil
	})
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return enrollmentState(row, false), err
}
func (s *Service) PendingEnrollments(ctx context.Context, accountID string) ([]EnrollmentState, error) {
	rows, err := s.db.Pool().Query(ctx, `SELECT id,state,expires_at,safety_code,canonical_request,signing_proof,challenge_envelope,request_digest,expected_proof,requester_kind,requester_id,subject_kind,subject_id,subject_generation,key_generation,operation_id,recipient_key_id,recipient_public_key FROM paperboat.environment_key_enrollment_requests WHERE account_id=$1 AND state='pending' AND expires_at>$2 ORDER BY created_at,id LIMIT 100`, accountID, s.now().UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []EnrollmentState{}
	for rows.Next() {
		var row enrollmentRow
		if err := scanEnrollment(rows, &row); err != nil {
			return nil, err
		}
		items = append(items, enrollmentState(row, false))
	}
	return items, rows.Err()
}

func (s *Service) ApproveEnrollment(ctx context.Context, input ApprovalRequest) (TransitionState, error) {
	var out TransitionState
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := lockAccountTx(ctx, tx, input.AccountID); err != nil {
			return err
		}
		var enrollment enrollmentRow
		if err := readEnrollmentForUpdateTx(ctx, tx, input.AccountID, input.RequestID, &enrollment); err != nil {
			return err
		}
		if enrollment.OperationID != input.OperationID {
			return ErrOperationConflict
		}
		if enrollment.State == "approved" {
			roots, rootErr := s.verificationRootsTx(ctx, tx, input.AccountID)
			if rootErr != nil {
				return rootErr
			}
			binding, bindingErr := ParseBinding(input.Binding, roots.Environment, roots.Endpoint)
			authority, authorityErr := ParseAuthority(input.Authority, roots.Environment, roots.Endpoint)
			if bindingErr != nil || authorityErr != nil || !bindingMatchesEnrollment(binding, enrollment) {
				return ErrOperationConflict
			}
			var transitionID, baseID string
			if err := tx.QueryRow(ctx, `SELECT e.transition_id,COALESCE(t.base_authority_id,'') FROM environment_key_enrollment_requests e JOIN environment_authority_transitions t ON t.transition_id=e.transition_id WHERE e.id=$1`, enrollment.ID).Scan(&transitionID, &baseID); err != nil || transitionID != authority.ID || authority.OperationID != input.OperationID || baseID != input.ExpectedAuthorityID {
				return ErrOperationConflict
			}
			state, stateErr := transitionStateTx(ctx, tx, input.AccountID, transitionID)
			out = state
			return stateErr
		}
		if enrollment.State != "pending" || !s.now().UTC().Before(enrollment.ExpiresAt) {
			return ErrEnrollmentExpired
		}
		roots, err := s.verificationRootsTx(ctx, tx, input.AccountID)
		if err != nil {
			return err
		}
		binding, err := ParseBinding(input.Binding, roots.Environment, roots.Endpoint)
		if err != nil {
			return err
		}
		if !bindingMatchesEnrollment(binding, enrollment) {
			return ErrProtocolInvalid
		}
		authority, err := ParseAuthority(input.Authority, roots.Environment, roots.Endpoint)
		if err != nil {
			return err
		}
		bindingOccurrences := 0
		for _, candidate := range authority.Bindings {
			if candidate.ID == binding.ID {
				bindingOccurrences++
			}
		}
		if bindingOccurrences != 1 {
			return ErrProtocolInvalid
		}
		out, err = s.beginTransitionTx(ctx, tx, input.AccountID, input.ExpectedAuthorityID, input.OperationID, authority)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE environment_key_enrollment_requests SET transition_id=$2 WHERE id=$1 AND state='pending'`, enrollment.ID, out.TransitionID); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO environment_key_bindings(binding_id,account_id,subject_kind,subject_id,subject_generation,key_generation,signing_key_id,signing_public_key,recipient_key_id,recipient_public_key,envelope) VALUES($1,$2,$3,$4,$5,$6,NULLIF($7,''),$8,$9,$10,$11) ON CONFLICT(binding_id) DO NOTHING`, binding.ID, input.AccountID, binding.SubjectKindName(), binding.SubjectID, int64(binding.SubjectGeneration), int64(binding.KeyGeneration), binding.SigningKeyID, nullableBytesSQL(binding.SigningPublicKey), binding.RecipientKeyID, binding.RecipientPublicKey[:], binding.Raw)
		return err
	})
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return out, err
}
func bindingMatchesEnrollment(binding Binding, enrollment enrollmentRow) bool {
	requested, err := ParseCanonicalEnrollment(enrollment.Canonical)
	if err != nil {
		return false
	}
	if binding.AccountID != requested.AccountID ||
		binding.SubjectKind != requested.SubjectKind ||
		binding.SubjectID != requested.SubjectID ||
		binding.SubjectGeneration != requested.SubjectGeneration ||
		binding.KeyGeneration != requested.KeyGeneration ||
		!exactNullableBytes(binding.EndpointCertificate, requested.EndpointCertificate) ||
		!exactNullableBytes(binding.SigningPublicKey, requested.SigningPublic) ||
		binding.RecipientKeyID != requested.RecipientKeyID ||
		!bytesEqual(binding.RecipientPublicKey[:], requested.RecipientPublic) ||
		binding.NotAfter != nil {
		return false
	}
	if binding.SigningKeyID != requested.SigningKeyID {
		return false
	}
	// Binding.SigningKeyID is a string, so retain whether the signed CBOR
	// field was null. This prevents an empty text value from standing in for
	// the null signer fields required by non-manager enrollments.
	return requested.SigningKeyID != "" || !binding.signingKeyIDPresent
}
func (s *Service) BeginTransition(ctx context.Context, input TransitionRequest) (TransitionState, error) {
	// Authority genesis is created only by approving the first proven manager
	// enrollment. Generic transitions always replace an existing authority.
	if !digestExpression.MatchString(input.ExpectedAuthorityID) {
		return TransitionState{}, ErrPrecondition
	}
	var out TransitionState
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := lockAccountTx(ctx, tx, input.AccountID); err != nil {
			return err
		}
		roots, err := s.verificationRootsTx(ctx, tx, input.AccountID)
		if err != nil {
			return err
		}
		authority, err := ParseAuthority(input.Authority, roots.Environment, roots.Endpoint)
		if err != nil {
			return err
		}
		out, err = s.beginTransitionTx(ctx, tx, input.AccountID, input.ExpectedAuthorityID, input.OperationID, authority)
		return err
	})
	return out, err
}
func (s *Service) GetTransition(ctx context.Context, accountID, transitionID string) (TransitionState, error) {
	var out TransitionState
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		var err error
		out, err = transitionStateTx(ctx, tx, accountID, transitionID)
		return err
	})
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return out, err
}
func (s *Service) StageTransitionManifest(ctx context.Context, input TransitionManifestRequest) (TransitionState, error) {
	if validateScope(input.Scope, input.MachineID) != nil || !operationExpression.MatchString(input.OperationID) {
		return TransitionState{}, ErrPrecondition
	}
	var out TransitionState
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := lockAccountTx(ctx, tx, input.AccountID); err != nil {
			return err
		}
		transition, err := readTransitionTx(ctx, tx, input.AccountID, input.TransitionID, true)
		if err != nil {
			return err
		}
		scopeKey := ScopeRef{Scope: input.Scope, MachineID: input.MachineID}.Key()
		if transition.State == "active" {
			var recordedOperation string
			var recordedEnvelope []byte
			if err := tx.QueryRow(ctx, `SELECT operation_id,envelope FROM environment_transition_manifests WHERE transition_id=$1 AND scope_ref=$2`, input.TransitionID, scopeKey).Scan(&recordedOperation, &recordedEnvelope); err != nil {
				return ErrPrecondition
			}
			if recordedOperation != input.OperationID || !bytesEqual(recordedEnvelope, input.Envelope) {
				return ErrOperationConflict
			}
			out, err = transitionStateTx(ctx, tx, input.AccountID, input.TransitionID)
			return err
		}
		if transition.State != "staged" && transition.State != "ready" {
			return ErrPrecondition
		}
		if input.OperationID != transition.OperationID {
			return ErrOperationConflict
		}
		roots, err := s.verificationRootsTx(ctx, tx, input.AccountID)
		if err != nil {
			return err
		}
		authority, err := ParseAuthority(transition.Raw, roots.Environment, roots.Endpoint)
		if err != nil {
			return err
		}
		manifest, err := ParseManifest(input.Envelope, authority)
		if err != nil {
			return err
		}
		if manifest.Scope != input.Scope || manifest.MachineID != input.MachineID || manifest.OperationID != input.OperationID || manifest.PreviousVersion != uint64(input.ExpectedVersion) || !slices.Contains(transition.RequiredScopes, scopeKey) {
			return ErrPrecondition
		}
		current, currentErr := readScopeTx(ctx, tx, input.AccountID, input.Scope, input.MachineID, true)
		if input.ExpectedVersion == 0 {
			resetAuthorized := false
			for _, reset := range authority.ResetScopes {
				if reset.Key() == scopeKey {
					resetAuthorized = true
					break
				}
			}
			validMutation := (manifest.MutationKind == 0 && !resetAuthorized) || (manifest.MutationKind == 5 && resetAuthorized)
			if !errors.Is(currentErr, sql.ErrNoRows) || !validMutation || manifest.PreviousVersion != 0 || manifest.Version != 1 || manifest.KeyEpoch != 1 || len(manifest.Names) != 0 || len(manifest.ChangedNames) != 0 {
				return ErrPrecondition
			}
		} else {
			if currentErr != nil {
				return currentErr
			}
			if current.Version != input.ExpectedVersion {
				return &VersionConflictError{CurrentVersion: current.Version}
			}
			previous, previousErr := s.parseActiveAuthorityTx(ctx, tx, input.AccountID)
			if previousErr != nil {
				return previousErr
			}
			if err := validateTransitionMutation(manifest, current, transition, previous, authority); err != nil {
				return err
			}
		}
		if err := validateScopeNameCompatibilityTx(ctx, tx, input.AccountID, input.Scope, input.MachineID, manifest.Names); err != nil {
			return err
		}
		var existing string
		var recordedOperation string
		var recordedEnvelope []byte
		if err := tx.QueryRow(ctx, `SELECT operation_id,manifest_id,envelope FROM environment_transition_manifests WHERE transition_id=$1 AND scope_ref=$2`, input.TransitionID, scopeKey).Scan(&recordedOperation, &existing, &recordedEnvelope); err == nil {
			if recordedOperation != input.OperationID || existing != manifest.ID || !bytesEqual(recordedEnvelope, input.Envelope) {
				return ErrOperationConflict
			}
		} else if errors.Is(err, sql.ErrNoRows) {
			if _, err = tx.Exec(ctx, `INSERT INTO environment_transition_manifests(transition_id,scope_ref,expected_version,version,key_epoch,operation_id,manifest_id,envelope,names) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, input.TransitionID, scopeKey, input.ExpectedVersion, int64(manifest.Version), int64(manifest.KeyEpoch), manifest.OperationID, manifest.ID, manifest.Raw, manifest.Names); err != nil {
				return err
			}
		} else {
			return err
		}
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM environment_transition_manifests WHERE transition_id=$1`, input.TransitionID).Scan(&count); err != nil {
			return err
		}
		if count == len(transition.RequiredScopes) {
			if _, err := tx.Exec(ctx, `UPDATE environment_authority_transitions SET state='ready' WHERE transition_id=$1 AND state='staged'`, input.TransitionID); err != nil {
				return err
			}
			if err := s.activateTransitionTx(ctx, tx, transition, authority); err != nil {
				return err
			}
		}
		out, err = transitionStateTx(ctx, tx, input.AccountID, input.TransitionID)
		return err
	})
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return out, err
}
func (s *Service) AbortTransition(ctx context.Context, input AbortRequest) (TransitionState, error) {
	var out TransitionState
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := lockAccountTx(ctx, tx, input.AccountID); err != nil {
			return err
		}
		transition, err := readTransitionTx(ctx, tx, input.AccountID, input.TransitionID, true)
		if err != nil {
			return err
		}
		if transition.ID != input.ExpectedTransitionID || transition.State == "active" {
			return ErrPrecondition
		}
		if transition.State == "aborted" {
			var operationID string
			var authorization []byte
			if err := tx.QueryRow(ctx, `SELECT abort_operation_id,abort_authorization FROM environment_authority_transitions WHERE transition_id=$1`, input.TransitionID).Scan(&operationID, &authorization); err != nil || operationID != input.OperationID || !bytesEqual(authorization, input.Authorization) {
				return ErrOperationConflict
			}
			head, headErr := readAuthorityHeadTx(ctx, tx, input.AccountID, false)
			if headErr != nil || head.ID != input.ExpectedAuthorityID {
				return ErrPrecondition
			}
			out, err = transitionStateTx(ctx, tx, input.AccountID, input.TransitionID)
			return err
		}
		roots, err := s.verificationRootsTx(ctx, tx, input.AccountID)
		if err != nil {
			return err
		}
		authorization, err := ParseAbort(input.Authorization, roots.Environment)
		if err != nil {
			return err
		}
		head, err := readAuthorityHeadTx(ctx, tx, input.AccountID, false)
		if err != nil {
			return err
		}
		if input.ExpectedAuthorityID != head.ID || authorization.AccountID != input.AccountID || authorization.ActiveAuthorityID != head.ID || authorization.TransitionID != input.TransitionID || authorization.OperationID != input.OperationID {
			return ErrPrecondition
		}
		_, err = tx.Exec(ctx, `UPDATE environment_authority_transitions SET state='aborted',abort_operation_id=$2,abort_authorization=$3,aborted_at=$4 WHERE transition_id=$1`, input.TransitionID, input.OperationID, input.Authorization, s.now().UTC())
		if err != nil {
			return err
		}
		out, err = transitionStateTx(ctx, tx, input.AccountID, input.TransitionID)
		return err
	})
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return out, err
}

func (s *Service) RecordEnvironmentObservation(ctx context.Context, environmentID, machineID string, observation *Observation) (RuntimeResult, error) {
	if observation == nil {
		return RuntimeResult{}, nil
	}
	if err := ValidateObservation(*observation); err != nil {
		return RuntimeResult{}, err
	}
	var result RuntimeResult
	received := s.now().UTC()
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		var canonicalID, accountID, setupMode string
		var installationGeneration int64
		var setupRoles []string
		err := tx.QueryRow(ctx, `SELECT m.id,m.user_id,m.setup_mode,m.setup_roles,m.installation_generation FROM user_machines m LEFT JOIN fly_machines fm ON fm.user_machine_id=m.id AND fm.project_id=m.environment_id WHERE m.environment_id=$1 AND (m.id=$2 OR fm.fly_machine_id=$2) AND m.deleted_at IS NULL ORDER BY CASE WHEN m.id=$2 THEN 0 ELSE 1 END,m.created_at DESC LIMIT 1`, environmentID, machineID).Scan(&canonicalID, &accountID, &setupMode, &setupRoles, &installationGeneration)
		if errors.Is(normalizeNoRows(err), sql.ErrNoRows) {
			return ErrMachineNotFound
		}
		if err != nil {
			return err
		}
		if !hostCapable(setupMode, setupRoles) {
			return ErrMachineNotHost
		}
		authority, authorityErr := s.parseActiveAuthorityTx(ctx, tx, accountID)
		if authorityErr != nil && !errors.Is(authorityErr, sql.ErrNoRows) {
			return authorityErr
		}
		_, recipientActive := activeHostBindingForInstallation(authority, canonicalID, installationGeneration, observation.HostRecipientKeyID)
		if recipientActive {
			if err := s.recordObservationTx(ctx, tx, accountID, canonicalID, *observation, received); err != nil {
				return err
			}
		}
		bundle, err := s.runtimeBundleTx(ctx, tx, accountID, canonicalID, installationGeneration, *observation)
		if err != nil {
			return err
		}
		result.Bundle = bundle
		return nil
	})
	return result, err
}

func validateScope(scope, machine string) error {
	if scope == ScopeGlobal && machine == "" {
		return nil
	}
	if scope == ScopeMachine && validIdentifier(machine) {
		return nil
	}
	return ErrInvalidScope
}
func randomID(prefix string) (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(raw[:]), nil
}
func bytesEqual(a, b []byte) bool { return len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1 }
func exactNullableBytes(a, b []byte) bool {
	return (a == nil) == (b == nil) && bytesEqual(a, b)
}
func nullableBytesSQL(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}
func hostCapable(mode string, roles []string) bool {
	if mode == "host" {
		return true
	}
	return slices.Contains(roles, "host")
}

func activeHostBindingForInstallation(authority Authority, machineID string, installationGeneration int64, recipientKeyID string) (Binding, bool) {
	if installationGeneration <= 0 || (recipientKeyID != "" && (!strings.HasPrefix(recipientKeyID, "envk_") || !keyIDExpression.MatchString(recipientKeyID))) {
		return Binding{}, false
	}
	for _, binding := range authority.Bindings {
		if binding.SubjectKind == 3 && binding.SubjectID == machineID && binding.SubjectGeneration == uint64(installationGeneration) && (recipientKeyID == "" || binding.RecipientKeyID == recipientKeyID) {
			return binding, true
		}
	}
	return Binding{}, false
}
func validRequester(i EnrollmentRequest) bool {
	if !validIdentifier(i.AccountID) || !validIdentifier(i.RequesterID) || !validIdentifier(i.SubjectID) || !operationExpression.MatchString(i.OperationID) || i.SubjectGeneration <= 0 || i.KeyGeneration <= 0 {
		return false
	}
	switch i.RequesterKind {
	case "human_session", "cli_session", "machine":
	default:
		return false
	}
	switch i.SubjectKind {
	case "manager_cli":
		return i.RequesterKind == "cli_session" && i.SubjectID == i.RequesterID
	case "manager_browser":
		return i.RequesterKind == "human_session" && i.SubjectID == i.RequesterID
	case "host":
		return i.RequesterKind == "machine" && i.SubjectID == i.RequesterID
	}
	return false
}
