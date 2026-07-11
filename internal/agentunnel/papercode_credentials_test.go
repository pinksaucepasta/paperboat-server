package agentunnel

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/mint"
)

func TestPapercodeCredentialIssuerCreatesSeparatedBearerSessions(t *testing.T) {
	var mu sync.Mutex
	var proofs []map[string]any
	var scopes []string
	var requestedTTLs []int64
	var revocation map[string]any
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("DPoP") != "" {
			t.Error("unexpected DPoP header")
		}
		switch r.URL.Path {
		case "/api/paperboat/mint-credential":
			var request struct {
				Proof string `json:"proof"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Error(err)
				return
			}
			parts := strings.Split(request.Proof, ".")
			if len(parts) != 3 {
				t.Errorf("proof parts = %d", len(parts))
				return
			}
			payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				t.Error(err)
				return
			}
			var payload map[string]any
			if err := json.Unmarshal(payloadBytes, &payload); err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			proofs = append(proofs, payload)
			count := len(proofs)
			mu.Unlock()
			writeTestJSON(t, w, map[string]any{"credential": "bootstrap-" + string(rune('0'+count)), "expiresAt": time.Now().Add(time.Minute).Format(time.RFC3339), "proof": "response-proof"})
		case "/oauth/token":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
				return
			}
			form, err := url.ParseQuery(string(body))
			if err != nil {
				t.Error(err)
				return
			}
			scope := form.Get("scope")
			requestedTTL, err := strconv.ParseInt(form.Get("expires_in"), 10, 64)
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			scopes = append(scopes, scope)
			requestedTTLs = append(requestedTTLs, requestedTTL)
			count := len(scopes)
			mu.Unlock()
			if form.Get("subject_token") == "" {
				t.Error("missing subject token")
			}
			writeTestJSON(t, w, map[string]any{"access_token": "access-" + scope, "session_id": "session-" + string(rune('0'+count)), "issued_token_type": "urn:ietf:params:oauth:token-type:access_token", "token_type": "Bearer", "expires_in": requestedTTL, "scope": scope})
		case "/api/auth/websocket-ticket":
			if got := r.Header.Get("Authorization"); got != "Bearer access-terminal:operate" {
				t.Errorf("authorization = %q", got)
			}
			writeTestJSON(t, w, map[string]any{"ticket": "ticket-1", "expiresAt": time.Now().Add(time.Minute).Format(time.RFC3339)})
		case "/api/paperboat/revoke-sessions":
			var request struct {
				Proof string `json:"proof"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Error(err)
				return
			}
			parts := strings.Split(request.Proof, ".")
			if len(parts) != 3 {
				t.Errorf("revocation proof parts = %d", len(parts))
				return
			}
			payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				t.Error(err)
				return
			}
			if err := json.Unmarshal(payloadBytes, &revocation); err != nil {
				t.Error(err)
				return
			}
			writeTestJSON(t, w, map[string]any{"revokedSessionIds": []string{"session-1", "session-2"}})
		default:
			http.NotFound(w, r)
		}
	})
	server := httptest.NewServer(handler)
	defer server.Close()
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 1
	signer, err := mint.New([]mint.Key{{ID: "key-1", PrivateKey: ed25519.NewKeyFromSeed(seed)}}, "key-1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &PapercodeCredentialIssuer{Issuer: "https://paperboat.example", Signer: signer, HTTPClient: server.Client(), ProofTTL: time.Minute}
	credentials, err := issuer.IssueCLI(t.Context(), CredentialInput{UserID: "usr_1", ProjectID: "prj_1", EnvironmentID: "env_1", ClientSessionID: "cls_1", HTTPBaseURL: server.URL, ExpiresAt: time.Now().Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if credentials.TerminalSessionID != "session-1" || credentials.FileSessionID != "session-2" {
		t.Fatalf("session ids = %q, %q", credentials.TerminalSessionID, credentials.FileSessionID)
	}
	if credentials.TerminalAuth["ticket"] != "ticket-1" {
		t.Fatalf("terminal auth = %#v", credentials.TerminalAuth)
	}
	if credentials.UploadAuth["token"] != "access-file:stage" {
		t.Fatalf("upload auth = %#v", credentials.UploadAuth)
	}
	if len(proofs) != 2 || proofs[0]["jti"] == proofs[1]["jti"] || proofs[0]["nonce"] == proofs[1]["nonce"] {
		t.Fatalf("proofs = %#v", proofs)
	}
	for _, proof := range proofs {
		if proof["aud"] != "t3-env:env_1" || proof["sub"] != "usr_1" || proof["clientSessionId"] != "cls_1" {
			t.Fatalf("proof = %#v", proof)
		}
		if _, ok := proof["cnf"]; ok {
			t.Fatal("unexpected cnf")
		}
	}
	if strings.Join(scopes, ",") != "terminal:operate,file:stage" {
		t.Fatalf("scopes = %#v", scopes)
	}
	for _, ttl := range requestedTTLs {
		if ttl <= 0 || ttl > 60 {
			t.Fatalf("requested ttl = %d", ttl)
		}
	}
	if err := issuer.RevokeCLI(t.Context(), CredentialRevocationInput{UserID: "usr_1", ProjectID: "prj_1", EnvironmentID: "env_1", ClientSessionID: "cls_1", HTTPBaseURL: server.URL, SessionIDs: []string{"session-1", "session-2"}, Reason: "logout"}); err != nil {
		t.Fatal(err)
	}
	if revocation["scope"].([]any)[0] != "environment:revoke" || revocation["reason"] != "logout" || len(revocation["sessionIds"].([]any)) != 2 {
		t.Fatalf("revocation = %#v", revocation)
	}
}

func TestPapercodeCredentialIssuerRequiresHTTPSInProduction(t *testing.T) {
	issuer := &PapercodeCredentialIssuer{RequireHTTPS: true}
	if _, err := issuer.validateBaseURL("http://route.example"); err == nil {
		t.Fatal("expected HTTPS error")
	}
}

func TestPapercodeCredentialIssuerRequiresCompleteRevocationAcknowledgement(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/paperboat/revoke-sessions" {
			http.NotFound(w, r)
			return
		}
		writeTestJSON(t, w, map[string]any{"revokedSessionIds": []string{"session-1"}})
	}))
	defer server.Close()

	issuer := testPapercodeIssuer(t, server)
	err := issuer.RevokeCLI(t.Context(), CredentialRevocationInput{
		UserID: "usr_1", ProjectID: "prj_1", EnvironmentID: "env_1",
		ClientSessionID: "cls_1", HTTPBaseURL: server.URL,
		SessionIDs: []string{"session-1", "session-2"}, Reason: "logout",
	})
	if err == nil || !strings.Contains(err.Error(), `session "session-2"`) {
		t.Fatalf("revocation error=%v, want missing session acknowledgement", err)
	}
}

func TestPapercodeCredentialIssuerCleansUpPartialIssuance(t *testing.T) {
	for _, tc := range []struct {
		name            string
		failTokenNumber int
		failTicket      bool
		failCleanup     bool
		wantRevoked     []string
		wantReturned    []string
	}{
		{name: "file exchange fails", failTokenNumber: 2, wantRevoked: []string{"session-1"}},
		{name: "ticket fails", failTicket: true, wantRevoked: []string{"session-1", "session-2"}},
		{name: "file exchange and cleanup fail", failTokenNumber: 2, failCleanup: true, wantReturned: []string{"session-1"}},
		{name: "ticket and cleanup fail", failTicket: true, failCleanup: true, wantReturned: []string{"session-1", "session-2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var tokenCount int
			var revoked []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/paperboat/mint-credential":
					writeTestJSON(t, w, map[string]any{"credential": "bootstrap"})
				case "/oauth/token":
					tokenCount++
					if tokenCount == tc.failTokenNumber {
						http.Error(w, "failed", http.StatusServiceUnavailable)
						return
					}
					body, _ := io.ReadAll(r.Body)
					form, _ := url.ParseQuery(string(body))
					ttl, _ := strconv.ParseInt(form.Get("expires_in"), 10, 64)
					writeTestJSON(t, w, map[string]any{"access_token": "access", "session_id": "session-" + strconv.Itoa(tokenCount), "token_type": "Bearer", "expires_in": ttl, "scope": form.Get("scope")})
				case "/api/auth/websocket-ticket":
					if tc.failTicket {
						http.Error(w, "failed", http.StatusServiceUnavailable)
						return
					}
					writeTestJSON(t, w, map[string]any{"ticket": "ticket", "expiresAt": time.Now().Add(time.Minute).Format(time.RFC3339)})
				case "/api/paperboat/revoke-sessions":
					if tc.failCleanup {
						http.Error(w, "failed", http.StatusServiceUnavailable)
						return
					}
					var request struct {
						Proof string `json:"proof"`
					}
					_ = json.NewDecoder(r.Body).Decode(&request)
					parts := strings.Split(request.Proof, ".")
					payloadBytes, _ := base64.RawURLEncoding.DecodeString(parts[1])
					var payload struct {
						SessionIDs []string `json:"sessionIds"`
					}
					_ = json.Unmarshal(payloadBytes, &payload)
					revoked = append(revoked, payload.SessionIDs...)
					writeTestJSON(t, w, map[string]any{"revokedSessionIds": payload.SessionIDs})
				}
			}))
			defer server.Close()
			issuer := testPapercodeIssuer(t, server)
			credentials, err := issuer.IssueCLI(t.Context(), testCredentialInput(server.URL, time.Now().Add(5*time.Minute)))
			if err == nil {
				t.Fatal("expected issuance failure")
			}
			if strings.Join(revoked, ",") != strings.Join(tc.wantRevoked, ",") {
				t.Fatalf("revoked = %#v, want %#v", revoked, tc.wantRevoked)
			}
			returned := compactSessionIDs(credentials.TerminalSessionID, credentials.FileSessionID)
			if strings.Join(returned, ",") != strings.Join(tc.wantReturned, ",") {
				t.Fatalf("returned partial session IDs = %#v, want %#v", returned, tc.wantReturned)
			}
		})
	}
}

func TestPapercodeCredentialIssuerRejectsAndRevokesOverlongSession(t *testing.T) {
	var revoked []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/paperboat/mint-credential":
			writeTestJSON(t, w, map[string]any{"credential": "bootstrap"})
		case "/oauth/token":
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			ttl, _ := strconv.ParseInt(form.Get("expires_in"), 10, 64)
			writeTestJSON(t, w, map[string]any{"access_token": "access", "session_id": "session-overlong", "token_type": "Bearer", "expires_in": ttl + 1, "scope": form.Get("scope")})
		case "/api/paperboat/revoke-sessions":
			var request struct {
				Proof string `json:"proof"`
			}
			_ = json.NewDecoder(r.Body).Decode(&request)
			parts := strings.Split(request.Proof, ".")
			payloadBytes, _ := base64.RawURLEncoding.DecodeString(parts[1])
			var payload struct {
				SessionIDs []string `json:"sessionIds"`
			}
			_ = json.Unmarshal(payloadBytes, &payload)
			revoked = append(revoked, payload.SessionIDs...)
			writeTestJSON(t, w, map[string]any{"revokedSessionIds": payload.SessionIDs})
		}
	}))
	defer server.Close()
	issuer := testPapercodeIssuer(t, server)
	_, err := issuer.IssueCLI(t.Context(), testCredentialInput(server.URL, time.Now().Add(5*time.Minute)))
	if err == nil || strings.Join(revoked, ",") != "session-overlong" {
		t.Fatalf("error = %v, revoked = %#v", err, revoked)
	}
}

func testPapercodeIssuer(t *testing.T, server *httptest.Server) *PapercodeCredentialIssuer {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 2
	signer, err := mint.New([]mint.Key{{ID: "key-1", PrivateKey: ed25519.NewKeyFromSeed(seed)}}, "key-1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return &PapercodeCredentialIssuer{Issuer: "https://paperboat.example", Signer: signer, HTTPClient: server.Client(), ProofTTL: time.Minute}
}

func testCredentialInput(baseURL string, expiresAt time.Time) CredentialInput {
	return CredentialInput{UserID: "usr_1", ProjectID: "prj_1", EnvironmentID: "env_1", ClientSessionID: "cls_1", HTTPBaseURL: baseURL, ExpiresAt: expiresAt}
}

func writeTestJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Error(err)
	}
}
