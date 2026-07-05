package auth

import (
	"net/http"
	"testing"
	"time"
)

func TestOAuthStateExpiresServerSide(t *testing.T) {
	now := time.Unix(1000, 0)
	service := NewService(nil, nil, nil, []string{"test-session-signing-key"}, false)
	service.now = func() time.Time { return now }
	state, err := service.NewOAuthState()
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, "/api/auth/workos/callback", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: OAuthStateCookieName, Value: state})
	if err := service.ValidateOAuthState(req, state); err != nil {
		t.Fatalf("fresh state rejected: %v", err)
	}
	service.now = func() time.Time { return now.Add(11 * time.Minute) }
	if err := service.ValidateOAuthState(req, state); err == nil {
		t.Fatal("expired state was accepted")
	}
}
