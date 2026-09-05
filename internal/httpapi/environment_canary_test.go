package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/auth"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/environment"
	"github.com/pinksaucepasta/paperboat-server/internal/peeridentity"
)

type environmentCanaryAPI struct {
	environmentVariableAPI
	raw []byte
}

func (a *environmentCanaryAPI) PutManifest(_ context.Context, mutation environment.ManifestMutation) (environment.ManifestState, error) {
	a.raw = append([]byte(nil), mutation.Envelope...)
	return environment.ManifestState{Schema: "paperboat.environment-manifest-state/v1", Scope: mutation.Scope, Version: mutation.ExpectedVersion + 1, KeyEpoch: 1, ManifestID: environment.DocumentID(mutation.Envelope), Envelope: base64.RawURLEncoding.EncodeToString(mutation.Envelope)}, nil
}

func TestEnvironmentManifestHTTPHandlerNeverReceivesPlaintextCanary(t *testing.T) {
	vectorRaw, err := os.ReadFile("../../testdata/contracts/environment-e2ee-v1/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		RootPublic  string            `json:"root_public"`
		Authority   string            `json:"authority"`
		SetManifest string            `json:"set_manifest"`
		Expected    map[string]string `json:"expected_values"`
	}
	if json.Unmarshal(vectorRaw, &vector) != nil {
		t.Fatal("invalid shared vector")
	}
	rootRaw, _ := base64.RawURLEncoding.DecodeString(vector.RootPublic)
	authorityRaw, _ := base64.RawURLEncoding.DecodeString(vector.Authority)
	manifestRaw, _ := base64.RawURLEncoding.DecodeString(vector.SetManifest)
	rootID, _ := peeridentity.RootFingerprint(ed25519.PublicKey(rootRaw))
	authority, err := environment.ParseAuthority(authorityRaw, peeridentity.AccountRoot{Keys: []peeridentity.AccountKey{{KeyID: "aek_" + rootID, PublicKey: ed25519.PublicKey(rootRaw)}}})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := environment.ParseManifest(manifestRaw, authority)
	if err != nil {
		t.Fatal(err)
	}
	canary := []byte(vector.Expected["APP_TOKEN"])
	body, _ := json.Marshal(map[string]any{"schema": "paperboat.environment-manifest-mutation/v1", "expected_version": manifest.PreviousVersion, "operation_id": manifest.OperationID, "envelope": vector.SetManifest})
	if len(canary) == 0 || bytes.Contains(body, canary) {
		t.Fatal("test request was not end-to-end encrypted")
	}

	var logs bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })

	request := httptest.NewRequest(http.MethodPut, "/v1/environment-manifests/global", bytes.NewReader(body))
	request.Header.Set("If-Match", environmentETag(environment.ScopeGlobal, "", int64(manifest.PreviousVersion)))
	request.Header.Set("Idempotency-Key", manifest.OperationID)
	request = request.WithContext(context.WithValue(request.Context(), authContextKey{}, principal{User: auth.User{ID: authority.AccountID}, Session: auth.Session{ID: "session_canary"}}))
	recorder := httptest.NewRecorder()
	api := &environmentCanaryAPI{}
	environmentManifestPut(api, false).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	for _, surface := range [][]byte{api.raw, recorder.Body.Bytes(), logs.Bytes()} {
		if bytes.Contains(surface, canary) {
			t.Fatal("plaintext ENV canary crossed handler, response, or log capture")
		}
	}
}

type environmentCanaryRoots struct{ root peeridentity.AccountRoot }

func (r environmentCanaryRoots) Root(context.Context, string) (peeridentity.AccountRoot, error) {
	return r.root, nil
}

func TestPostgresEnvironmentManifestHTTPFlowNeverPersistsOrLogsPlaintextCanary(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_DATABASE_DSN"))
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run the HTTP-to-Postgres ENV E2EE canary proof")
	}
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(dsn), "_test") {
		t.Fatal("PAPERBOAT_TEST_DATABASE_DSN must name an isolated *_test database")
	}
	vectorRaw, err := os.ReadFile("../../testdata/contracts/environment-e2ee-v1/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		RootPublic  string            `json:"root_public"`
		Authority   string            `json:"authority"`
		Manifest    string            `json:"manifest"`
		SetManifest string            `json:"set_manifest"`
		Expected    map[string]string `json:"expected_values"`
	}
	if err := json.Unmarshal(vectorRaw, &vector); err != nil {
		t.Fatal(err)
	}
	rootRaw, err := base64.RawURLEncoding.DecodeString(vector.RootPublic)
	if err != nil {
		t.Fatal(err)
	}
	authorityRaw, err := base64.RawURLEncoding.DecodeString(vector.Authority)
	if err != nil {
		t.Fatal(err)
	}
	initialRaw, err := base64.RawURLEncoding.DecodeString(vector.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	setRaw, err := base64.RawURLEncoding.DecodeString(vector.SetManifest)
	if err != nil {
		t.Fatal(err)
	}
	rootID, err := peeridentity.RootFingerprint(ed25519.PublicKey(rootRaw))
	if err != nil {
		t.Fatal(err)
	}
	roots := peeridentity.AccountRoot{Keys: []peeridentity.AccountKey{{KeyID: "aek_" + rootID, PublicKey: ed25519.PublicKey(rootRaw)}}}
	authorityDocument, err := environment.ParseAuthority(authorityRaw, roots)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := environment.ParseManifest(initialRaw, authorityDocument)
	if err != nil {
		t.Fatal(err)
	}
	setManifest, err := environment.ParseManifest(setRaw, authorityDocument)
	if err != nil {
		t.Fatal(err)
	}
	canary := []byte(vector.Expected["APP_TOKEN"])
	if len(canary) == 0 || bytes.Contains(setRaw, canary) {
		t.Fatal("shared vector does not provide an encrypted canary")
	}

	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if err := db.Migrate(ctx, store); err != nil {
		t.Fatal(err)
	}
	accountID, scopeID := authorityDocument.AccountID, "envscope_http_canary"
	_, _ = store.SQL().ExecContext(ctx, `DELETE FROM paperboat.users WHERE id=$1`, accountID)
	t.Cleanup(func() { _, _ = store.SQL().ExecContext(ctx, `DELETE FROM paperboat.users WHERE id=$1`, accountID) })
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users(id,workos_subject,primary_email,status) VALUES($1,$2,$3,'active')`, accountID, "workos_env_http_canary", "env-http-canary@canary.invalid"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.environment_authority_roots(account_id,key_id,public_key) VALUES($1,$2,$3)`, accountID, roots.Keys[0].KeyID, []byte(roots.Keys[0].PublicKey)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.environment_authorities(account_id,generation,authority_id,operation_id,envelope) VALUES($1,$2,$3,$4,$5)`, accountID, int64(authorityDocument.Generation), authorityDocument.ID, authorityDocument.OperationID, authorityRaw); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.environment_authority_heads(account_id,generation,authority_id) VALUES($1,$2,$3)`, accountID, int64(authorityDocument.Generation), authorityDocument.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.environment_scopes(id,account_id,scope,scope_state,version,key_epoch,authority_generation,authority_id,manifest_id) VALUES($1,$2,'global','active',$3,$4,$5,$6,$7)`, scopeID, accountID, int64(initial.Version), int64(initial.KeyEpoch), int64(initial.AuthorityGeneration), initial.AuthorityID, initial.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.environment_scope_manifests(scope_id,version,key_epoch,authority_generation,authority_id,operation_id,manifest_id,envelope) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, scopeID, int64(initial.Version), int64(initial.KeyEpoch), int64(initial.AuthorityGeneration), initial.AuthorityID, initial.OperationID, initial.ID, initialRaw); err != nil {
		t.Fatal(err)
	}

	service := environment.NewService(store, audit.NewWriter(store), environmentCanaryRoots{root: roots})
	body, _ := json.Marshal(map[string]any{
		"schema": "paperboat.environment-manifest-mutation/v1", "expected_version": setManifest.PreviousVersion, "operation_id": setManifest.OperationID, "envelope": vector.SetManifest,
	})
	if bytes.Contains(body, canary) {
		t.Fatal("HTTP request body exposed plaintext canary")
	}
	var logs bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })
	request := httptest.NewRequest(http.MethodPut, "/v1/environment-manifests/global", bytes.NewReader(body))
	request.Header.Set("If-Match", environmentETag(environment.ScopeGlobal, "", int64(setManifest.PreviousVersion)))
	request.Header.Set("Idempotency-Key", setManifest.OperationID)
	request = request.WithContext(context.WithValue(request.Context(), authContextKey{}, principal{User: auth.User{ID: accountID}, Client: &auth.ClientPrincipal{SessionID: "cli_01"}}))
	response := httptest.NewRecorder()
	environmentManifestPut(service, false).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}

	var stored, audited string
	for _, surface := range []struct {
		query string
		arg   string
	}{
		{`SELECT COALESCE(jsonb_agg(to_jsonb(t))::text,'') FROM paperboat.environment_authorities t WHERE account_id=$1`, accountID},
		{`SELECT COALESCE(jsonb_agg(to_jsonb(t))::text,'') FROM paperboat.environment_authority_heads t WHERE account_id=$1`, accountID},
		{`SELECT COALESCE(jsonb_agg(to_jsonb(t))::text,'') FROM paperboat.environment_scopes t WHERE account_id=$1`, accountID},
		{`SELECT COALESCE(jsonb_agg(to_jsonb(t))::text,'') FROM paperboat.environment_scope_manifests t WHERE scope_id=$1`, scopeID},
		{`SELECT COALESCE(jsonb_agg(to_jsonb(t))::text,'') FROM paperboat.environment_scope_names t WHERE scope_id=$1`, scopeID},
	} {
		var part string
		if err := store.SQL().QueryRowContext(ctx, surface.query, surface.arg).Scan(&part); err != nil {
			t.Fatal(err)
		}
		stored += part
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(t))::text,'') FROM paperboat.audit_events t WHERE resource_id=$1`, setManifest.ID).Scan(&audited); err != nil {
		t.Fatal(err)
	}
	if audited == "" || audited == "[]" {
		t.Fatal("manifest audit event was not persisted")
	}
	for _, surface := range [][]byte{body, response.Body.Bytes(), logs.Bytes(), []byte(stored), []byte(audited)} {
		if bytes.Contains(surface, canary) {
			t.Fatal("plaintext ENV canary crossed the HTTP, service, database, audit, or log boundary")
		}
	}
}

func TestPostgresEnrollmentCreateReplayAfterLostProofResponseReturnsPendingWithoutChallenge(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_DATABASE_DSN"))
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run the enrollment replay proof")
	}
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(dsn), "_test") {
		t.Fatal("PAPERBOAT_TEST_DATABASE_DSN must name an isolated *_test database")
	}
	vectorRaw, err := os.ReadFile("../../testdata/contracts/environment-e2ee-v1/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		RootPublic         string `json:"root_public"`
		Authority          string `json:"authority"`
		ManagerSigningSeed string `json:"manager_signing_seed"`
	}
	if err := json.Unmarshal(vectorRaw, &vector); err != nil {
		t.Fatal(err)
	}
	rootRaw, _ := base64.RawURLEncoding.DecodeString(vector.RootPublic)
	authorityRaw, _ := base64.RawURLEncoding.DecodeString(vector.Authority)
	managerSeed, _ := base64.RawURLEncoding.DecodeString(vector.ManagerSigningSeed)
	rootID, err := peeridentity.RootFingerprint(ed25519.PublicKey(rootRaw))
	if err != nil {
		t.Fatal(err)
	}
	roots := peeridentity.AccountRoot{Keys: []peeridentity.AccountKey{{KeyID: "aek_" + rootID, PublicKey: ed25519.PublicKey(rootRaw)}}}
	authorityDocument, err := environment.ParseAuthority(authorityRaw, roots)
	if err != nil {
		t.Fatal(err)
	}
	var manager environment.Binding
	for _, binding := range authorityDocument.Bindings {
		if binding.SubjectKindName() == "manager_cli" {
			manager = binding
			break
		}
	}
	if manager.SigningKeyID == "" || len(managerSeed) != ed25519.SeedSize {
		t.Fatal("shared vector has no manager signing fixture")
	}

	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if err := db.Migrate(ctx, store); err != nil {
		t.Fatal(err)
	}
	suffix := strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	accountID, sessionID := authorityDocument.AccountID, "browser_env_replay_"+suffix
	operationID := "envop_" + strings.Repeat("0", 32-len(suffix)) + suffix
	t.Cleanup(func() {
		_, _ = store.SQL().ExecContext(ctx, `DELETE FROM paperboat.environment_key_enrollment_requests WHERE account_id=$1 AND operation_id=$2`, accountID, operationID)
	})
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users(id,workos_subject,primary_email,status) VALUES($1,$2,$3,'active') ON CONFLICT (id) DO NOTHING`, accountID, "workos_env_replay_"+suffix, "env-replay-"+suffix+"@canary.invalid"); err != nil {
		t.Fatal(err)
	}
	service := environment.NewService(store, audit.NewWriter(store), environmentCanaryRoots{root: roots})
	service.SetClock(func() time.Time { return time.Unix(1788134400, 0).UTC() })
	expiresAt := time.Unix(1788134640, 0).UTC()
	canonical, _, _, err := environment.CanonicalEnrollment(environment.EnrollmentCanonicalInput{
		AccountID: accountID, OperationID: operationID, SubjectKind: 2, SubjectID: sessionID, SubjectGeneration: 1, KeyGeneration: 1,
		SigningPublic: manager.SigningPublicKey, SigningKeyID: manager.SigningKeyID, RecipientPublic: manager.RecipientPublicKey[:], RecipientKeyID: manager.RecipientKeyID, ExpiresAt: expiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(managerSeed)
	if !bytes.Equal(private.Public().(ed25519.PublicKey), manager.SigningPublicKey) {
		t.Fatal("shared manager signing seed does not match authority")
	}
	signingProof := ed25519.Sign(private, environment.EnrollmentSigningBytes(canonical))
	createBody, _ := json.Marshal(map[string]any{
		"schema": "paperboat.environment-key-enrollment/v1", "operation_id": operationID, "subject_kind": "manager_browser", "subject_id": sessionID,
		"subject_generation": 1, "key_generation": 1, "endpoint_certificate": nil, "signing_public_key": base64.RawURLEncoding.EncodeToString(manager.SigningPublicKey),
		"signing_key_id": manager.SigningKeyID, "signing_proof": base64.RawURLEncoding.EncodeToString(signingProof), "recipient_public_key": base64.RawURLEncoding.EncodeToString(manager.RecipientPublicKey[:]),
		"recipient_key_id": manager.RecipientKeyID, "binding_not_after": nil, "request_expires_at": expiresAt,
	})
	withPrincipal := func(request *http.Request) *http.Request {
		return request.WithContext(context.WithValue(request.Context(), authContextKey{}, principal{User: auth.User{ID: accountID}, Session: auth.Session{ID: sessionID}}))
	}
	create := func() *httptest.ResponseRecorder {
		request := withPrincipal(httptest.NewRequest(http.MethodPost, "/v1/environment-key-enrollments", bytes.NewReader(createBody)))
		request.Header.Set("Idempotency-Key", operationID)
		result := httptest.NewRecorder()
		environmentEnrollmentPost(service).ServeHTTP(result, request)
		return result
	}
	first := create()
	if first.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", first.Code, first.Body.String())
	}
	var firstResponse struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &firstResponse); err != nil {
		t.Fatal(err)
	}
	requestID, _ := firstResponse.Data["request_id"].(string)
	challenge, challengePresent := firstResponse.Data["challenge"].(string)
	if requestID == "" || !challengePresent || challenge == "" || firstResponse.Data["state"] != "challenge" {
		t.Fatalf("initial enrollment response=%s", first.Body.String())
	}
	var expectedProof []byte
	if err := store.SQL().QueryRowContext(ctx, `SELECT expected_proof FROM paperboat.environment_key_enrollment_requests WHERE id=$1`, requestID).Scan(&expectedProof); err != nil {
		t.Fatal(err)
	}
	proofBody, _ := json.Marshal(map[string]any{"schema": "paperboat.environment-key-enrollment-proof/v1", "proof": base64.RawURLEncoding.EncodeToString(expectedProof)})
	proof := withPrincipal(httptest.NewRequest(http.MethodPut, "/v1/environment-key-enrollments/"+requestID+"/proof", bytes.NewReader(proofBody)))
	proof.SetPathValue("request_id", requestID)
	proofResult := httptest.NewRecorder()
	environmentEnrollmentProof(service).ServeHTTP(proofResult, proof)
	if proofResult.Code != http.StatusOK {
		t.Fatalf("proof status=%d body=%s", proofResult.Code, proofResult.Body.String())
	}

	// Model a lost proof response: the client repeats its exact create request.
	replay := create()
	if replay.Code != http.StatusCreated {
		t.Fatalf("replay status=%d body=%s", replay.Code, replay.Body.String())
	}
	var replayResponse struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(replay.Body.Bytes(), &replayResponse); err != nil {
		t.Fatal(err)
	}
	if replayResponse.Data["request_id"] != requestID || replayResponse.Data["state"] != "pending" {
		t.Fatalf("replay did not resume pending enrollment: %s", replay.Body.String())
	}
	if _, present := replayResponse.Data["challenge"]; present {
		t.Fatalf("pending create replay returned consumed challenge: %s", replay.Body.String())
	}
}
