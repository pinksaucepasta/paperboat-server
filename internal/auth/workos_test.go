package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPWorkOSVerifierExchangesAuthorizationCode(t *testing.T) {
	var requestBody map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/user_management/authenticate" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"user":{"id":"user_123","email":"user@example.com","first_name":"Test","last_name":"User"}}`))
	}))
	t.Cleanup(server.Close)

	profile, err := HTTPWorkOSVerifier{
		BaseURL:      server.URL,
		ClientID:     "client_123",
		ClientSecret: "secret_123",
	}.VerifyCallback(context.Background(), CallbackInput{Code: "code_123", RedirectURI: "https://dashboard.example/callback"})
	if err != nil {
		t.Fatal(err)
	}
	if profile.Subject != "user_123" || profile.Email != "user@example.com" || profile.DisplayName != "Test User" {
		t.Fatalf("profile = %+v", profile)
	}
	if requestBody["grant_type"] != "authorization_code" || requestBody["code"] != "code_123" || requestBody["client_id"] != "client_123" || requestBody["client_secret"] != "secret_123" {
		t.Fatalf("request body = %#v", requestBody)
	}
}
