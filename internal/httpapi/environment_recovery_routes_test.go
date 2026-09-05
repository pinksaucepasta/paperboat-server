package httpapi

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/pinksaucepasta/paperboat-server/internal/auth"
	"github.com/pinksaucepasta/paperboat-server/internal/environment"
	"github.com/pinksaucepasta/paperboat-server/internal/peeridentity"
)

type environmentRecoveryRouteAPI struct {
	environmentVariableAPI
	roots          peeridentity.AccountRoot
	proposed       environment.Authority
	authorizeCalls int
	staged         bool
}

func (a *environmentRecoveryRouteAPI) AuthorizeManager(context.Context, string, string, string) error {
	a.authorizeCalls++
	return environment.ErrKeyAuthorizationRequired
}

func (a *environmentRecoveryRouteAPI) BeginTransition(_ context.Context, input environment.TransitionRequest) (environment.TransitionState, error) {
	proposed, err := environment.ParseAuthority(input.Authority, a.roots)
	if err != nil {
		return environment.TransitionState{}, err
	}
	if input.ExpectedAuthorityID != proposed.ID || proposed.AccountID != input.AccountID || proposed.OperationID != input.OperationID {
		return environment.TransitionState{}, environment.ErrPrecondition
	}
	a.proposed = proposed
	return environment.TransitionState{
		Schema:              "paperboat.environment-authority-transition-state/v1",
		TransitionID:        proposed.ID,
		State:               "staged",
		ProposedGeneration:  int64(proposed.Generation),
		ProposedAuthorityID: proposed.ID,
		RequiredScopes:      []string{environment.ScopeGlobal},
		StagedScopes:        []string{},
	}, nil
}

func (a *environmentRecoveryRouteAPI) StageTransitionManifest(_ context.Context, input environment.TransitionManifestRequest) (environment.TransitionState, error) {
	if a.proposed.ID == "" || input.TransitionID != a.proposed.ID {
		return environment.TransitionState{}, environment.ErrPrecondition
	}
	manifest, err := environment.ParseManifest(input.Envelope, a.proposed)
	if err != nil {
		return environment.TransitionState{}, err
	}
	if manifest.AccountID != input.AccountID || manifest.Scope != input.Scope || manifest.MachineID != input.MachineID || manifest.OperationID != input.OperationID || int64(manifest.PreviousVersion) != input.ExpectedVersion {
		return environment.TransitionState{}, environment.ErrPrecondition
	}
	a.staged = true
	return environment.TransitionState{
		Schema:              "paperboat.environment-authority-transition-state/v1",
		TransitionID:        a.proposed.ID,
		State:               "active",
		ProposedGeneration:  int64(a.proposed.Generation),
		ProposedAuthorityID: a.proposed.ID,
		RequiredScopes:      []string{environment.ScopeGlobal},
		StagedScopes:        []string{environment.ScopeGlobal},
	}, nil
}

func TestEnvironmentRecoveryRoutesAllowProposedManagerAndRequireCryptographicDocuments(t *testing.T) {
	vectorRaw, err := os.ReadFile("../../testdata/contracts/environment-e2ee-v1/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		RootPublic  string `json:"root_public"`
		Authority   string `json:"authority"`
		SetManifest string `json:"set_manifest"`
	}
	if err := json.Unmarshal(vectorRaw, &vector); err != nil {
		t.Fatal(err)
	}
	rootPublic, err := base64.RawURLEncoding.DecodeString(vector.RootPublic)
	if err != nil {
		t.Fatal(err)
	}
	rootID, err := peeridentity.RootFingerprint(ed25519.PublicKey(rootPublic))
	if err != nil {
		t.Fatal(err)
	}
	roots := peeridentity.AccountRoot{Keys: []peeridentity.AccountKey{{KeyID: "aek_" + rootID, PublicKey: ed25519.PublicKey(rootPublic)}}}
	authorityRaw, err := base64.RawURLEncoding.DecodeString(vector.Authority)
	if err != nil {
		t.Fatal(err)
	}
	proposed, err := environment.ParseAuthority(authorityRaw, roots)
	if err != nil {
		t.Fatal(err)
	}
	manifestRaw, err := base64.RawURLEncoding.DecodeString(vector.SetManifest)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := environment.ParseManifest(manifestRaw, proposed)
	if err != nil {
		t.Fatal(err)
	}
	freshManager := ""
	for _, binding := range proposed.Bindings {
		if binding.SubjectKindName() == "manager_cli" {
			freshManager = binding.SubjectID
			break
		}
	}
	if freshManager == "" {
		t.Fatal("shared authority has no CLI manager")
	}

	api := &environmentRecoveryRouteAPI{roots: roots}
	mux := http.NewServeMux()
	identity := func(next http.Handler) http.Handler { return next }
	registerEnvironmentTransitionRoutes(mux, api, identity, identity)
	principalContext := func(request *http.Request) *http.Request {
		client := auth.ClientPrincipal{SessionID: freshManager}
		return request.WithContext(context.WithValue(request.Context(), authContextKey{}, principal{User: auth.User{ID: proposed.AccountID}, Client: &client}))
	}

	invalidBody, _ := json.Marshal(map[string]any{
		"schema": "paperboat.environment-authority-transition/v1", "expected_authority_id": proposed.ID, "operation_id": proposed.OperationID,
		"authority": base64.RawURLEncoding.EncodeToString([]byte{0}),
	})
	invalid := principalContext(httptest.NewRequest(http.MethodPost, "/v1/environment-authority/transitions", strings.NewReader(string(invalidBody))))
	invalid.Header.Set("If-Match", environmentAuthorityETag(int64(proposed.Generation), proposed.ID))
	invalid.Header.Set("Idempotency-Key", proposed.OperationID)
	invalidResult := httptest.NewRecorder()
	mux.ServeHTTP(invalidResult, invalid)
	if invalidResult.Code < 400 || api.proposed.ID != "" {
		t.Fatalf("unsigned authority status=%d body=%s", invalidResult.Code, invalidResult.Body.String())
	}

	startBody, _ := json.Marshal(map[string]any{
		"schema": "paperboat.environment-authority-transition/v1", "expected_authority_id": proposed.ID, "operation_id": proposed.OperationID, "authority": vector.Authority,
	})
	start := principalContext(httptest.NewRequest(http.MethodPost, "/v1/environment-authority/transitions", strings.NewReader(string(startBody))))
	start.Header.Set("If-Match", environmentAuthorityETag(int64(proposed.Generation), proposed.ID))
	start.Header.Set("Idempotency-Key", proposed.OperationID)
	startResult := httptest.NewRecorder()
	mux.ServeHTTP(startResult, start)
	if startResult.Code != http.StatusAccepted {
		t.Fatalf("start status=%d body=%s", startResult.Code, startResult.Body.String())
	}

	stageBody, _ := json.Marshal(map[string]any{
		"schema": "paperboat.environment-transition-manifest/v1", "expected_version": manifest.PreviousVersion, "operation_id": manifest.OperationID, "envelope": vector.SetManifest,
	})
	stage := principalContext(httptest.NewRequest(http.MethodPut, "/v1/environment-authority/transitions/"+proposed.ID+"/scopes/global", strings.NewReader(string(stageBody))))
	stage.Header.Set("If-Match", environmentETag(environment.ScopeGlobal, "", int64(manifest.PreviousVersion)))
	stage.Header.Set("Idempotency-Key", manifest.OperationID)
	stageResult := httptest.NewRecorder()
	mux.ServeHTTP(stageResult, stage)
	if stageResult.Code != http.StatusOK || !api.staged {
		t.Fatalf("stage status=%d body=%s", stageResult.Code, stageResult.Body.String())
	}
	if api.authorizeCalls != 0 {
		t.Fatalf("active-manager middleware ran %d times before root/proposed signature verification", api.authorizeCalls)
	}
}
