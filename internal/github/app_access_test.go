package github

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func TestGitHubAppBrokerResolvesAndIssuesRepositoryScopedToken(t *testing.T) {
	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustPKCS8(t, privateKey)})
	var issuedPermissions []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/user/installations":
			if r.Header.Get("Authorization") != "Bearer user-oauth" || r.URL.Query().Get("per_page") != "100" {
				t.Fatalf("installation request = %s %#v", r.URL.String(), r.Header)
			}
			writeGitHubJSON(t, w, map[string]any{"total_count": 1, "installations": []map[string]any{{"id": 42, "account": map[string]any{"login": "ignored-extra"}}}})
		case "/user/installations/42/repositories":
			writeGitHubJSON(t, w, map[string]any{"total_count": 1, "repositories": []map[string]any{{"id": 123, "name": "ignored-extra"}}})
		case "/app/installations/42/access_tokens":
			token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if len(strings.Split(token, ".")) != 3 {
				t.Fatalf("app JWT = %q", token)
			}
			parsed, parseErr := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			var claims jwt.Claims
			if err := parsed.Claims(&privateKey.PublicKey, &claims); err != nil {
				t.Fatal(err)
			}
			issuedAt := now.Add(-30 * time.Second)
			if claims.Issuer != "1" || claims.IssuedAt == nil || claims.Expiry == nil || !claims.IssuedAt.Time().Equal(issuedAt) || !claims.Expiry.Time().Equal(issuedAt.Add(2*time.Minute)) {
				t.Fatalf("app JWT claims = %#v", claims)
			}
			if r.Header.Get("Accept") != "application/vnd.github.v3+json" {
				t.Fatalf("app Accept header = %q", r.Header.Get("Accept"))
			}
			var request struct {
				RepositoryIDs []int64           `json:"repository_ids"`
				Permissions   map[string]string `json:"permissions"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if len(request.RepositoryIDs) != 1 || request.RepositoryIDs[0] != 123 ||
				(request.Permissions["contents"] != "write" && request.Permissions["contents"] != "read") ||
				request.Permissions["metadata"] != "read" {
				t.Fatalf("access request = %#v", request)
			}
			issuedPermissions = append(issuedPermissions, request.Permissions["contents"])
			writeGitHubJSON(t, w, map[string]any{
				"token": "installation-token", "expires_at": now.Add(time.Hour),
				"permissions":  map[string]string{"contents": request.Permissions["contents"], "metadata": "read"},
				"repositories": []map[string]any{{"id": 123}}, "repository_selection": "selected",
			})
		case "/installation/token":
			if r.Method != http.MethodDelete || r.Header.Get("Authorization") != "Bearer installation-token" {
				t.Fatalf("revoke request = %s %#v", r.Method, r.Header)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	httpClient := server.Client()
	httpClient.Timeout = time.Second
	broker, err := NewGitHubAppBroker(GitHubAppBrokerConfig{
		BaseURL: server.URL, AppID: "1", PrivateKeyPEM: string(privatePEM),
		Client: httpClient, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	authorizationRef, err := broker.ResolveInstallation(context.Background(), "user-oauth", "123")
	if err != nil || authorizationRef != "github-installation:42" {
		t.Fatalf("authorization = %q, %v", authorizationRef, err)
	}
	access, err := broker.Issue(context.Background(), authorizationRef, "123", "write")
	if err != nil || access.Token != "installation-token" || !access.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("access = %#v, %v", access, err)
	}
	if _, err := broker.Issue(context.Background(), authorizationRef, "123", "read"); err != nil {
		t.Fatal(err)
	}
	if len(issuedPermissions) != 2 || issuedPermissions[0] != "write" || issuedPermissions[1] != "read" {
		t.Fatalf("permissions = %#v", issuedPermissions)
	}
	if err := broker.Revoke(context.Background(), access.Token); err != nil {
		t.Fatal(err)
	}
}

func TestGitHubAppBrokerRejectsInvalidPrivateKeys(t *testing.T) {
	t.Parallel()
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: http.DefaultTransport, Timeout: time.Second}
	for name, key := range map[string]string{
		"missing":   "",
		"malformed": "not a PEM key",
		"weak":      string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(weak)})),
		"trailing":  string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(valid)})) + "unexpected",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewGitHubAppBroker(GitHubAppBrokerConfig{BaseURL: "https://api.github.test", AppID: "1", PrivateKeyPEM: key, Client: client}); !errors.Is(err, ErrRepositoryAccessUnavailable) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func mustPKCS8(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	data, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writeGitHubJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatal(err)
	}
}
