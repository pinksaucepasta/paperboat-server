package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/environment"
)

type environmentMachinePrincipalKey struct{}

type environmentMachinePrincipal struct {
	AccountID   string
	MachineID   string
	OperationID string
}

// environmentEnrollmentMachineOrHuman accepts the existing human/device
// authentication path or an existing signed machine-control proof. The raw
// body is restored after proof verification so both paths parse identical JSON.
func environmentEnrollmentMachineOrHuman(verifier machineEndpointProofVerifier, human, machine http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.TrimSpace(r.Header.Get("X-Paperboat-Machine-Proof")) == "" {
			human.ServeHTTP(w, r)
			return
		}
		if verifier == nil {
			writeError(w, r, http.StatusUnauthorized, "machine_identity_invalid", "Machine identity proof was rejected.")
			return
		}
		maxBody := int64(32 << 10)
		if strings.HasSuffix(r.URL.Path, "/proof") {
			maxBody = 1 << 10
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		proof, proofErr := base64.RawURLEncoding.Strict().DecodeString(strings.TrimSpace(r.Header.Get("X-Paperboat-Machine-Proof")))
		scheme, credential, found := strings.Cut(strings.TrimSpace(r.Header.Get("Authorization")), " ")
		if err != nil || int64(len(body)) > maxBody || proofErr != nil || len(proof) == 0 || !found || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(credential) == "" {
			writeError(w, r, http.StatusUnauthorized, "machine_identity_invalid", "Machine identity proof was rejected.")
			return
		}
		claims, err := verifier.VerifyMachineRequest(r.Context(), strings.TrimSpace(credential), proof, r.Method, r.URL.Path, body)
		if err != nil || claims.UserID == "" || claims.MachineID == "" {
			writeError(w, r, http.StatusUnauthorized, "machine_identity_invalid", "Machine identity proof was rejected.")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		ctx := context.WithValue(r.Context(), environmentMachinePrincipalKey{}, environmentMachinePrincipal{AccountID: claims.UserID, MachineID: claims.MachineID, OperationID: claims.OperationID})
		machine.ServeHTTP(w, r.WithContext(ctx))
	})
}

type environmentVariableAPI interface {
	AuthorizeManager(context.Context, string, string, string) error
	ListScopes(context.Context, string) (environment.ScopeInventory, error)
	List(context.Context, string) (environment.ScopeView, error)
	ListMachine(context.Context, string, string) (environment.ScopeView, error)
	Get(context.Context, string, string, string, string) (environment.VariableMetadata, error)
	GetAuthority(context.Context, string) (environment.AuthorityState, error)
	GetAuthorityDocuments(context.Context, string, int64, string) (environment.AuthorityPage, error)
	GetManifest(context.Context, string, string, string) (environment.ManifestState, error)
	PutManifest(context.Context, environment.ManifestMutation) (environment.ManifestState, error)
	RequestEnrollment(context.Context, environment.EnrollmentRequest) (environment.EnrollmentState, error)
	ProveEnrollment(context.Context, string, string, string, string, []byte) (environment.EnrollmentState, error)
	PendingEnrollments(context.Context, string) ([]environment.EnrollmentState, error)
	ApproveEnrollment(context.Context, environment.ApprovalRequest) (environment.TransitionState, error)
	BeginTransition(context.Context, environment.TransitionRequest) (environment.TransitionState, error)
	GetTransition(context.Context, string, string) (environment.TransitionState, error)
	StageTransitionManifest(context.Context, environment.TransitionManifestRequest) (environment.TransitionState, error)
	AbortTransition(context.Context, environment.AbortRequest) (environment.TransitionState, error)
}

func environmentScopesList(service environmentVariableAPI) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		noStore(w)
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		inventory, err := service.ListScopes(r.Context(), p.User.ID)
		if err != nil {
			writeEnvironmentError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: inventory})
	}
}

func environmentManagerAuthorized(service environmentVariableAPI, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		kind, id := "manager_browser", p.Session.ID
		if p.Client != nil {
			kind, id = "manager_cli", p.Client.SessionID
		}
		if err := service.AuthorizeManager(r.Context(), p.User.ID, kind, id); err != nil {
			writeEnvironmentError(w, r, err)
			return
		}
		next.ServeHTTP(w, r)
	})
}

const maxEnvironmentManifestJSON = (14 * 1024 * 1024) / 10

func limitEnvironmentJSON(w http.ResponseWriter, r *http.Request, max int64) {
	r.Body = http.MaxBytesReader(w, r.Body, max)
}

func environmentVariablesList(service environmentVariableAPI, machine bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		noStore(w)
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, 401, "unauthenticated", "Authentication is required.")
			return
		}
		var view environment.ScopeView
		var err error
		if machine {
			view, err = service.ListMachine(r.Context(), p.User.ID, r.PathValue("machine_id"))
		} else {
			view, err = service.List(r.Context(), p.User.ID)
		}
		if err != nil {
			writeEnvironmentError(w, r, err)
			return
		}
		w.Header().Set("ETag", environmentETag(view.Scope, view.MachineID, view.Version))
		writeJSON(w, 200, SuccessResponse{Data: view})
	}
}
func environmentVariableGet(service environmentVariableAPI, machine bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		noStore(w)
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, 401, "unauthenticated", "Authentication is required.")
			return
		}
		scope, id := environment.ScopeGlobal, ""
		if machine {
			scope, id = environment.ScopeMachine, r.PathValue("machine_id")
		}
		item, err := service.Get(r.Context(), p.User.ID, scope, id, r.PathValue("name"))
		if err != nil {
			writeEnvironmentError(w, r, err)
			return
		}
		w.Header().Set("ETag", environmentETag(scope, id, item.Version))
		writeJSON(w, 200, SuccessResponse{Data: item})
	}
}

func environmentManifestGet(service environmentVariableAPI, machine bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		noStore(w)
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, 401, "unauthenticated", "Authentication is required.")
			return
		}
		scope, id := environment.ScopeGlobal, ""
		if machine {
			scope, id = environment.ScopeMachine, r.PathValue("machine_id")
		}
		state, err := service.GetManifest(r.Context(), p.User.ID, scope, id)
		if err != nil {
			writeEnvironmentError(w, r, err)
			return
		}
		w.Header().Set("ETag", environmentETag(scope, id, state.Version))
		writeJSON(w, 200, SuccessResponse{Data: state})
	}
}
func environmentManifestPut(service environmentVariableAPI, machine bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		noStore(w)
		limitEnvironmentJSON(w, r, maxEnvironmentManifestJSON)
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, 401, "unauthenticated", "Authentication is required.")
			return
		}
		var body struct {
			Schema          string `json:"schema"`
			ExpectedVersion int64  `json:"expected_version"`
			OperationID     string `json:"operation_id"`
			Envelope        string `json:"envelope"`
		}
		if !decodeStrictJSON(w, r, &body) {
			return
		}
		if body.Schema != "paperboat.environment-manifest-mutation/v1" || !validEnvironmentOperation(r, body.OperationID) {
			writeEnvironmentError(w, r, environment.ErrPrecondition)
			return
		}
		raw, err := environment.DecodeCanonicalBase64URL(body.Envelope, environment.MaxManifestBytes)
		if err != nil {
			writeEnvironmentError(w, r, err)
			return
		}
		scope, id := environment.ScopeGlobal, ""
		if machine {
			scope, id = environment.ScopeMachine, r.PathValue("machine_id")
		}
		expected, err := parseEnvironmentIfMatch(r.Header.Values("If-Match"), scope, id)
		if err != nil || expected != body.ExpectedVersion {
			writeError(w, r, http.StatusPreconditionRequired, "if_match_required", "If-Match must contain the current scope ETag.")
			return
		}
		state, err := service.PutManifest(r.Context(), environment.ManifestMutation{AccountID: p.User.ID, Scope: scope, MachineID: id, ExpectedVersion: body.ExpectedVersion, OperationID: body.OperationID, Envelope: raw})
		if err != nil {
			writeEnvironmentError(w, r, err)
			return
		}
		w.Header().Set("ETag", environmentETag(scope, id, state.Version))
		writeJSON(w, 200, SuccessResponse{Data: state})
	}
}

func environmentAuthorityGet(service environmentVariableAPI) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		noStore(w)
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, 401, "unauthenticated", "Authentication is required.")
			return
		}
		state, err := service.GetAuthority(r.Context(), p.User.ID)
		if err != nil {
			if errors.Is(err, environment.ErrNotFound) {
				writeError(w, r, http.StatusNotFound, "authority_not_initialized", "ENV authority has not been initialized for this account.")
				return
			}
			writeEnvironmentError(w, r, err)
			return
		}
		w.Header().Set("ETag", environmentAuthorityETag(state.Generation, state.AuthorityID))
		writeJSON(w, 200, SuccessResponse{Data: state})
	}
}
func environmentAuthorityDocuments(service environmentVariableAPI) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		noStore(w)
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, 401, "unauthenticated", "Authentication is required.")
			return
		}
		generation, err := strconv.ParseInt(r.URL.Query().Get("after_generation"), 10, 64)
		if err != nil {
			writeEnvironmentError(w, r, environment.ErrPrecondition)
			return
		}
		page, err := service.GetAuthorityDocuments(r.Context(), p.User.ID, generation, r.URL.Query().Get("after_id"))
		if err != nil {
			writeEnvironmentError(w, r, err)
			return
		}
		w.Header().Set("ETag", environmentAuthorityETag(page.AuthorityHead.Generation, page.AuthorityHead.AuthorityID))
		writeJSON(w, 200, SuccessResponse{Data: page})
	}
}

type enrollmentJSON struct {
	Schema              string          `json:"schema"`
	OperationID         string          `json:"operation_id"`
	SubjectKind         string          `json:"subject_kind"`
	SubjectID           string          `json:"subject_id"`
	SubjectGeneration   int64           `json:"subject_generation"`
	KeyGeneration       int64           `json:"key_generation"`
	EndpointCertificate *string         `json:"endpoint_certificate"`
	SigningPublicKey    *string         `json:"signing_public_key"`
	SigningKeyID        *string         `json:"signing_key_id"`
	SigningProof        *string         `json:"signing_proof"`
	RecipientPublicKey  string          `json:"recipient_public_key"`
	RecipientKeyID      string          `json:"recipient_key_id"`
	BindingNotAfter     json.RawMessage `json:"binding_not_after"`
	RequestExpiresAt    time.Time       `json:"request_expires_at"`
}

func environmentEnrollmentPost(service environmentVariableAPI) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		noStore(w)
		limitEnvironmentJSON(w, r, 32<<10)
		p, ok := principalFromContext(r.Context())
		machine, machineOK := r.Context().Value(environmentMachinePrincipalKey{}).(environmentMachinePrincipal)
		if !ok && !machineOK {
			writeError(w, r, 401, "unauthenticated", "Authentication is required.")
			return
		}
		var body enrollmentJSON
		if !decodeStrictJSON(w, r, &body) {
			return
		}
		if body.Schema != "paperboat.environment-key-enrollment/v1" || !validEnvironmentOperation(r, body.OperationID) || !bytes.Equal(bytes.TrimSpace(body.BindingNotAfter), []byte("null")) {
			writeEnvironmentError(w, r, environment.ErrPrecondition)
			return
		}
		decode := func(v *string, max int) ([]byte, error) {
			if v == nil {
				return nil, nil
			}
			return environment.DecodeCanonicalBase64URL(*v, max)
		}
		certificate, e1 := decode(body.EndpointCertificate, 8192)
		signing, e2 := decode(body.SigningPublicKey, 32)
		proof, e3 := decode(body.SigningProof, 64)
		recipient, e4 := environment.DecodeCanonicalBase64URL(body.RecipientPublicKey, 32)
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
			writeEnvironmentError(w, r, environment.ErrProtocolInvalid)
			return
		}
		var accountID, requesterKind, requesterID string
		if machineOK {
			accountID, requesterKind, requesterID = machine.AccountID, "machine", machine.MachineID
			if body.SubjectKind != "host" || body.SubjectID != machine.MachineID || machine.OperationID != body.OperationID {
				writeEnvironmentError(w, r, environment.ErrPrecondition)
				return
			}
		} else {
			accountID, requesterKind, requesterID = p.User.ID, "human_session", p.Session.ID
			if p.Client != nil {
				requesterKind, requesterID = "cli_session", p.Client.SessionID
			}
		}
		state, err := service.RequestEnrollment(r.Context(), environment.EnrollmentRequest{AccountID: accountID, RequesterKind: requesterKind, RequesterID: requesterID, OperationID: body.OperationID, SubjectKind: body.SubjectKind, SubjectID: body.SubjectID, SubjectGeneration: body.SubjectGeneration, KeyGeneration: body.KeyGeneration, EndpointCertificate: certificate, SigningPublicKey: signing, SigningKeyID: valueOrEmpty(body.SigningKeyID), SigningProof: proof, RecipientPublicKey: recipient, RecipientKeyID: body.RecipientKeyID, RequestExpiresAt: body.RequestExpiresAt})
		if err != nil {
			writeEnvironmentError(w, r, err)
			return
		}
		writeJSON(w, 201, SuccessResponse{Data: state})
	}
}
func environmentEnrollmentProof(service environmentVariableAPI) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		noStore(w)
		limitEnvironmentJSON(w, r, 1<<10)
		p, ok := principalFromContext(r.Context())
		machine, machineOK := r.Context().Value(environmentMachinePrincipalKey{}).(environmentMachinePrincipal)
		if !ok && !machineOK {
			writeError(w, r, 401, "unauthenticated", "Authentication is required.")
			return
		}
		var body struct {
			Schema string `json:"schema"`
			Proof  string `json:"proof"`
		}
		if !decodeStrictJSON(w, r, &body) {
			return
		}
		proof, err := environment.DecodeCanonicalBase64URL(body.Proof, 32)
		if err != nil || body.Schema != "paperboat.environment-key-enrollment-proof/v1" {
			writeEnvironmentError(w, r, environment.ErrPrecondition)
			return
		}
		var accountID, kind, id string
		if machineOK {
			accountID, kind, id = machine.AccountID, "machine", machine.MachineID
		} else {
			accountID, kind, id = p.User.ID, "human_session", p.Session.ID
			if p.Client != nil {
				kind, id = "cli_session", p.Client.SessionID
			}
		}
		state, err := service.ProveEnrollment(r.Context(), accountID, r.PathValue("request_id"), kind, id, proof)
		if err != nil {
			writeEnvironmentError(w, r, err)
			return
		}
		writeJSON(w, 200, SuccessResponse{Data: state})
	}
}
func environmentEnrollmentPending(service environmentVariableAPI) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		noStore(w)
		p, ok := principalFromContext(r.Context())
		if !ok || p.Client == nil {
			writeError(w, r, 401, "unauthenticated", "CLI authentication is required.")
			return
		}
		items, err := service.PendingEnrollments(r.Context(), p.User.ID)
		if err != nil {
			writeEnvironmentError(w, r, err)
			return
		}
		writeJSON(w, 200, SuccessResponse{Data: map[string]any{"items": items}})
	}
}
func environmentEnrollmentApprove(service environmentVariableAPI) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		noStore(w)
		limitEnvironmentJSON(w, r, 3<<20)
		p, ok := principalFromContext(r.Context())
		if !ok || p.Client == nil {
			writeError(w, r, 401, "unauthenticated", "CLI authentication is required.")
			return
		}
		var body struct {
			Schema              string  `json:"schema"`
			ExpectedAuthorityID *string `json:"expected_authority_id"`
			OperationID         string  `json:"operation_id"`
			Binding             string  `json:"binding"`
			Authority           string  `json:"authority"`
		}
		if !decodeStrictJSON(w, r, &body) {
			return
		}
		binding, e1 := environment.DecodeCanonicalBase64URL(body.Binding, environment.MaxBindingBytes)
		authority, e2 := environment.DecodeCanonicalBase64URL(body.Authority, environment.MaxAuthorityBytes)
		if e1 != nil || e2 != nil || body.Schema != "paperboat.environment-key-approval/v1" || !validEnvironmentOperation(r, body.OperationID) {
			writeEnvironmentError(w, r, environment.ErrPrecondition)
			return
		}
		expected := valueOrEmpty(body.ExpectedAuthorityID)
		if !validAuthorityPrecondition(r, expected) {
			writeError(w, r, 428, "if_match_required", "Authority precondition is required.")
			return
		}
		state, err := service.ApproveEnrollment(r.Context(), environment.ApprovalRequest{AccountID: p.User.ID, RequestID: r.PathValue("request_id"), ExpectedAuthorityID: expected, OperationID: body.OperationID, Binding: binding, Authority: authority})
		if err != nil {
			writeEnvironmentError(w, r, err)
			return
		}
		w.Header().Set("ETag", environmentAuthorityETag(state.ProposedGeneration, state.ProposedAuthorityID))
		writeJSON(w, 202, SuccessResponse{Data: state})
	}
}

func environmentTransitionPost(service environmentVariableAPI) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		noStore(w)
		limitEnvironmentJSON(w, r, 3<<20)
		p, ok := principalFromContext(r.Context())
		if !ok || p.Client == nil {
			writeError(w, r, 401, "unauthenticated", "CLI authentication is required.")
			return
		}
		var body struct {
			Schema              string `json:"schema"`
			ExpectedAuthorityID string `json:"expected_authority_id"`
			OperationID         string `json:"operation_id"`
			Authority           string `json:"authority"`
		}
		if !decodeStrictJSON(w, r, &body) {
			return
		}
		raw, err := environment.DecodeCanonicalBase64URL(body.Authority, environment.MaxAuthorityBytes)
		if err != nil || body.Schema != "paperboat.environment-authority-transition/v1" || body.ExpectedAuthorityID == "" || !validEnvironmentOperation(r, body.OperationID) || !validAuthorityPrecondition(r, body.ExpectedAuthorityID) {
			writeEnvironmentError(w, r, environment.ErrPrecondition)
			return
		}
		state, err := service.BeginTransition(r.Context(), environment.TransitionRequest{AccountID: p.User.ID, ExpectedAuthorityID: body.ExpectedAuthorityID, OperationID: body.OperationID, Authority: raw})
		if err != nil {
			writeEnvironmentError(w, r, err)
			return
		}
		w.Header().Set("ETag", environmentAuthorityETag(state.ProposedGeneration, state.ProposedAuthorityID))
		writeJSON(w, 202, SuccessResponse{Data: state})
	}
}
func environmentTransitionGet(service environmentVariableAPI) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		noStore(w)
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, 401, "unauthenticated", "Authentication is required.")
			return
		}
		state, err := service.GetTransition(r.Context(), p.User.ID, r.PathValue("transition_id"))
		if err != nil {
			writeEnvironmentError(w, r, err)
			return
		}
		writeJSON(w, 200, SuccessResponse{Data: state})
	}
}
func environmentTransitionStage(service environmentVariableAPI, machine bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		noStore(w)
		limitEnvironmentJSON(w, r, maxEnvironmentManifestJSON)
		p, ok := principalFromContext(r.Context())
		if !ok || p.Client == nil {
			writeError(w, r, 401, "unauthenticated", "CLI authentication is required.")
			return
		}
		var body struct {
			Schema          string `json:"schema"`
			ExpectedVersion int64  `json:"expected_version"`
			OperationID     string `json:"operation_id"`
			Envelope        string `json:"envelope"`
		}
		if !decodeStrictJSON(w, r, &body) {
			return
		}
		raw, err := environment.DecodeCanonicalBase64URL(body.Envelope, environment.MaxManifestBytes)
		if err != nil || body.Schema != "paperboat.environment-transition-manifest/v1" || !validEnvironmentOperation(r, body.OperationID) {
			writeEnvironmentError(w, r, environment.ErrPrecondition)
			return
		}
		scope, id := environment.ScopeGlobal, ""
		if machine {
			scope, id = environment.ScopeMachine, r.PathValue("machine_id")
		}
		if body.ExpectedVersion == 0 {
			if r.Header.Get("If-None-Match") != "*" {
				writeError(w, r, 428, "if_match_required", "If-None-Match is required for initialization.")
				return
			}
		} else if expected, err := parseEnvironmentIfMatch(r.Header.Values("If-Match"), scope, id); err != nil || expected != body.ExpectedVersion {
			writeError(w, r, 428, "if_match_required", "If-Match must contain the current scope ETag.")
			return
		}
		state, err := service.StageTransitionManifest(r.Context(), environment.TransitionManifestRequest{AccountID: p.User.ID, TransitionID: r.PathValue("transition_id"), Scope: scope, MachineID: id, ExpectedVersion: body.ExpectedVersion, OperationID: body.OperationID, Envelope: raw})
		if err != nil {
			writeEnvironmentError(w, r, err)
			return
		}
		status := 202
		if state.State == "active" {
			status = 200
		}
		w.Header().Set("ETag", environmentETag(scope, id, body.ExpectedVersion+1))
		writeJSON(w, status, SuccessResponse{Data: state})
	}
}
func environmentTransitionAbort(service environmentVariableAPI) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		noStore(w)
		limitEnvironmentJSON(w, r, 8<<10)
		p, ok := principalFromContext(r.Context())
		if !ok || p.Client == nil {
			writeError(w, r, 401, "unauthenticated", "CLI authentication is required.")
			return
		}
		var body struct {
			Schema               string `json:"schema"`
			ExpectedTransitionID string `json:"expected_transition_id"`
			OperationID          string `json:"operation_id"`
			Authorization        string `json:"authorization"`
		}
		if !decodeStrictJSON(w, r, &body) {
			return
		}
		raw, err := environment.DecodeCanonicalBase64URL(body.Authorization, environment.MaxBindingBytes)
		expectedAuthorityID, preconditionOK := authorityIDFromIfMatch(r.Header.Values("If-Match"))
		if err != nil || body.Schema != "paperboat.environment-authority-transition-abort/v1" || !validEnvironmentOperation(r, body.OperationID) || !preconditionOK {
			writeEnvironmentError(w, r, environment.ErrPrecondition)
			return
		}
		state, err := service.AbortTransition(r.Context(), environment.AbortRequest{AccountID: p.User.ID, TransitionID: r.PathValue("transition_id"), ExpectedTransitionID: body.ExpectedTransitionID, ExpectedAuthorityID: expectedAuthorityID, OperationID: body.OperationID, Authorization: raw})
		if err != nil {
			writeEnvironmentError(w, r, err)
			return
		}
		w.Header().Set("ETag", strings.TrimSpace(r.Header.Get("If-Match")))
		writeJSON(w, 200, SuccessResponse{Data: state})
	}
}

func environmentETag(scope, machineID string, version int64) string {
	if scope == environment.ScopeMachine {
		return `"environment-machine-` + machineID + `-` + strconv.FormatInt(version, 10) + `"`
	}
	return `"environment-global-` + strconv.FormatInt(version, 10) + `"`
}
func environmentAuthorityETag(generation int64, id string) string {
	return `"environment-authority-` + strconv.FormatInt(generation, 10) + `-` + strings.TrimPrefix(id, "sha256:") + `"`
}
func parseEnvironmentIfMatch(values []string, scope, machineID string) (int64, error) {
	if len(values) != 1 {
		return 0, errors.New("missing")
	}
	raw := strings.TrimSpace(values[0])
	if raw == "" || strings.Contains(raw, ",") || strings.HasPrefix(raw, "W/") {
		return 0, errors.New("invalid")
	}
	prefix := `"environment-global-`
	if scope == environment.ScopeMachine {
		prefix = `"environment-machine-` + machineID + `-`
	}
	if !strings.HasPrefix(raw, prefix) || !strings.HasSuffix(raw, `"`) {
		return 0, errors.New("invalid")
	}
	v, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(raw, prefix), `"`), 10, 64)
	if err != nil || v < 0 || environmentETag(scope, machineID, v) != raw {
		return 0, errors.New("invalid")
	}
	return v, nil
}
func validAuthorityPrecondition(r *http.Request, expected string) bool {
	if expected == "" {
		return r.Header.Get("If-None-Match") == "*"
	}
	values := r.Header.Values("If-Match")
	if len(values) != 1 || !strings.HasPrefix(expected, "sha256:") {
		return false
	}
	raw := strings.TrimSpace(values[0])
	digest := strings.TrimPrefix(expected, "sha256:")
	prefix, suffix := `"environment-authority-`, `-`+digest+`"`
	if strings.HasPrefix(raw, "W/") || strings.Contains(raw, ",") || !strings.HasPrefix(raw, prefix) || !strings.HasSuffix(raw, suffix) {
		return false
	}
	generationText := strings.TrimSuffix(strings.TrimPrefix(raw, prefix), suffix)
	generation, err := strconv.ParseInt(generationText, 10, 64)
	return err == nil && generation > 0 && environmentAuthorityETag(generation, expected) == raw
}
func authorityIDFromIfMatch(values []string) (string, bool) {
	if len(values) != 1 {
		return "", false
	}
	raw := strings.TrimSpace(values[0])
	prefix := `"environment-authority-`
	if strings.HasPrefix(raw, "W/") || strings.Contains(raw, ",") || !strings.HasPrefix(raw, prefix) || !strings.HasSuffix(raw, `"`) {
		return "", false
	}
	body := strings.TrimSuffix(strings.TrimPrefix(raw, prefix), `"`)
	split := strings.LastIndexByte(body, '-')
	if split <= 0 || len(body)-split-1 != 64 {
		return "", false
	}
	generation, err := strconv.ParseInt(body[:split], 10, 64)
	digest := body[split+1:]
	if err != nil || generation <= 0 || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(digest) {
		return "", false
	}
	id := "sha256:" + digest
	return id, environmentAuthorityETag(generation, id) == raw
}
func valueOrEmpty(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}
func validEnvironmentOperation(r *http.Request, operationID string) bool {
	values := r.Header.Values("Idempotency-Key")
	return len(values) == 1 && values[0] == operationID
}
func writeEnvironmentError(w http.ResponseWriter, r *http.Request, err error) {
	status, code, message := 500, "internal_error", "ENV Injection operation failed."
	details := map[string]any{}
	switch {
	case errors.Is(err, environment.ErrProtocolInvalid), errors.Is(err, environment.ErrProtocolSignature), errors.Is(err, environment.ErrInvalidScope), errors.Is(err, environment.ErrInvalidName), errors.Is(err, environment.ErrLimitExceeded), errors.Is(err, environment.ErrObservationInvalid):
		status, code, message = 400, "validation_failed", "ENV Injection request is invalid."
	case errors.Is(err, environment.ErrPrecondition):
		status, code, message = 412, "precondition_failed", "ENV Injection precondition failed."
	case errors.Is(err, environment.ErrNotFound), errors.Is(err, environment.ErrMachineNotFound):
		status, code, message = 404, "not_found_or_forbidden", "ENV Injection resource was not found."
	case errors.Is(err, environment.ErrMachineNotHost):
		status, code, message = 422, "machine_not_host", "ENV Injection is available only for host machines."
	case errors.Is(err, environment.ErrVersionConflict):
		status, code, message = 409, "version_conflict", "ENV scope changed; fetch it and retry."
		var c *environment.VersionConflictError
		if errors.As(err, &c) {
			details["current_version"] = c.CurrentVersion
		}
	case errors.Is(err, environment.ErrAuthorityConflict):
		status, code, message = 409, "authority_conflict", "ENV authority changed; fetch it and retry."
	case errors.Is(err, environment.ErrTransitionInProgress):
		status, code, message = 409, "transition_in_progress", "An ENV authority transition is already in progress."
	case errors.Is(err, environment.ErrOperationConflict):
		status, code, message = 409, "operation_conflict", "The ENV operation ID is already bound to different bytes."
	case errors.Is(err, environment.ErrKeyAuthorizationRequired):
		status, code, message = 409, "key_authorization_required", "A trusted ENV manager must authorize this key."
	case errors.Is(err, environment.ErrAuthorityFork), errors.Is(err, environment.ErrRootSetChanged):
		status, code, message = 409, "authority_fork", "ENV authority continuity could not be verified."
	case errors.Is(err, environment.ErrEnrollmentExpired):
		status, code, message = 409, "enrollment_expired", "ENV key enrollment expired."
	case errors.Is(err, environment.ErrRequesterMismatch):
		status, code, message = 403, "forbidden", "Only the enrollment requester may complete proof."
	}
	writeErrorDetails(w, r, status, code, message, details)
}
