package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProductionSessionCookiesUseHostPrefixAndRequiredAttributes(t *testing.T) {
	service := NewService(nil, nil, nil, nil, true, "https://login.pprbt.dev")
	recorder := httptest.NewRecorder()
	service.SetSessionCookies(recorder, Session{Token: "session", CSRFToken: "csrf", ExpiresAt: time.Now().Add(time.Hour)})
	cookies := recorder.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatalf("cookies = %d, want 2", len(cookies))
	}
	assertCookie := func(cookie *http.Cookie, name string, httpOnly bool) {
		t.Helper()
		if cookie.Name != name || cookie.Path != "/" || cookie.Domain != "" || !cookie.Secure || cookie.HttpOnly != httpOnly || cookie.SameSite != http.SameSiteLaxMode {
			t.Fatalf("cookie = %#v", cookie)
		}
	}
	assertCookie(cookies[0], SessionCookieName, true)
	assertCookie(cookies[1], CSRFCookieName, false)
}

func TestDevelopmentCookiesUseSeparateHTTPNames(t *testing.T) {
	service := NewService(nil, nil, nil, nil, false, "http://100.64.0.10:3000")
	recorder := httptest.NewRecorder()
	service.SetSessionCookies(recorder, Session{Token: "session", CSRFToken: "csrf", ExpiresAt: time.Now().Add(time.Hour)})
	cookies := recorder.Result().Cookies()
	if cookies[0].Name != DevSessionCookieName || cookies[1].Name != DevCSRFCookieName || cookies[0].Secure || cookies[1].Secure {
		t.Fatalf("development cookies = %#v", cookies)
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Cookie", SessionCookieName+"=old; "+CSRFCookieName+"=old")
	if _, ok := service.CSRFToken(request); ok {
		t.Fatal("development mode accepted a production cookie")
	}
}

func TestValidateBrowserRequestRequiresExactOriginAndRejectsDuplicateReservedCookies(t *testing.T) {
	service := NewService(nil, nil, nil, nil, true, "https://login.pprbt.dev/")
	for _, origin := range []string{"", "https://LOGIN.pprbt.dev", "https://login.pprbt.dev/", "https://evil.example"} {
		request := httptest.NewRequest(http.MethodPost, "/v1/resource", nil)
		request.Header.Set("Origin", origin)
		if !errors.Is(service.ValidateBrowserRequest(request), ErrOrigin) {
			t.Fatalf("origin %q was accepted", origin)
		}
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/resource", nil)
	request.Header.Set("Origin", "https://login.pprbt.dev")
	request.Header.Set("Cookie", strings.Join([]string{SessionCookieName + "=one", SessionCookieName + "=two"}, "; "))
	if !errors.Is(service.ValidateBrowserRequest(request), ErrDuplicateCookie) {
		t.Fatalf("duplicate cookie error = %v", service.ValidateBrowserRequest(request))
	}
	request = httptest.NewRequest(http.MethodPost, "/v1/resource", nil)
	request.Header.Add("Origin", "https://login.pprbt.dev")
	request.Header.Add("Origin", "https://evil.example")
	if !errors.Is(service.ValidateBrowserRequest(request), ErrOrigin) {
		t.Fatalf("multiple origin error = %v", service.ValidateBrowserRequest(request))
	}
	request = httptest.NewRequest(http.MethodGet, "/v1/resource", nil)
	if err := service.ValidateBrowserRequest(request); err != nil {
		t.Fatalf("safe request rejected: %v", err)
	}
}
