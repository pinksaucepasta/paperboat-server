package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

const (
	SessionCookieName       = "__Host-pb-session"
	CSRFCookieName          = "__Host-pb-csrf"
	OAuthStateCookieName    = "__Host-pb-oauth-state"
	DevSessionCookieName    = "pb-dev-session"
	DevCSRFCookieName       = "pb-dev-csrf"
	DevOAuthStateCookieName = "pb-dev-oauth-state"
	CSRFHeaderName          = "X-CSRF-Token"
)

type Role string

const (
	RoleUser    Role = "user"
	RoleSupport Role = "support"
	RoleAdmin   Role = "admin"
	RoleSystem  Role = "system_worker"
)

type User struct {
	ID            string
	WorkOSSubject string
	PrimaryEmail  string
	DisplayName   string
	Status        string
	Role          Role
	CreatedAt     time.Time
}

type Session struct {
	ID        string
	UserID    string
	Token     string
	CSRFToken string
	ExpiresAt time.Time
}

type WorkOSProfile struct {
	Subject     string
	Email       string
	DisplayName string
}

type WorkOSVerifier interface {
	VerifyCallback(context.Context, CallbackInput) (WorkOSProfile, error)
}

type CallbackInput struct {
	Code        string
	RedirectURI string
	State       string
}

type Service struct {
	db            *db.DB
	audit         *audit.Writer
	verifier      WorkOSVerifier
	sessionKeys   []string
	cookieSecure  bool
	trustedOrigin string
	now           func() time.Time
}

func NewService(store *db.DB, auditWriter *audit.Writer, verifier WorkOSVerifier, sessionKeys []string, cookieSecure bool, trustedOrigin ...string) *Service {
	origin := ""
	if len(trustedOrigin) > 0 {
		origin = strings.TrimSuffix(strings.TrimSpace(trustedOrigin[0]), "/")
	}
	return &Service{
		db:            store,
		audit:         auditWriter,
		verifier:      verifier,
		sessionKeys:   sessionKeys,
		cookieSecure:  cookieSecure,
		trustedOrigin: origin,
		now:           func() time.Time { return time.Now().UTC() },
	}
}

func (s *Service) VerifyCallback(ctx context.Context, input CallbackInput) (User, Session, error) {
	if s.verifier == nil {
		return User{}, Session{}, errors.New("workos verifier is not configured")
	}
	profile, err := s.verifier.VerifyCallback(ctx, input)
	if err != nil {
		return User{}, Session{}, err
	}
	if strings.TrimSpace(profile.Subject) == "" || strings.TrimSpace(profile.Email) == "" {
		return User{}, Session{}, errors.New("workos profile is missing subject or email")
	}
	var user User
	sessionToken := newToken()
	csrfToken := newToken()
	sessionHash := tokenHash(sessionToken)
	csrfHash := tokenHash(csrfToken)
	expiresAt := s.now().Add(30 * 24 * time.Hour)
	err = s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		row, err := q.UpsertWorkOSUser(ctx, dbsqlc.UpsertWorkOSUserParams{UserID: newID("usr"), WorkosSubject: profile.Subject, PrimaryEmail: strings.ToLower(profile.Email), DisplayName: profile.DisplayName, IdentityID: newID("uid")})
		if err != nil {
			return err
		}
		user = User{ID: row.ID, WorkOSSubject: row.WorkosSubject, PrimaryEmail: row.PrimaryEmail, DisplayName: row.DisplayName, Status: row.Status, Role: Role(row.Role), CreatedAt: row.CreatedAt}
		err = q.CreateBrowserSession(ctx, dbsqlc.CreateBrowserSessionParams{ID: newID("ses"), UserID: user.ID, SessionHash: sessionHash, CsrfHash: csrfHash, ExpiresAt: expiresAt})
		if err != nil {
			return err
		}
		return s.audit.WriteTx(ctx, tx, audit.Event{
			ActorUserID:    user.ID,
			ActorType:      audit.ActorUser,
			EventType:      "auth.login",
			ResourceType:   "user",
			ResourceID:     user.ID,
			IdempotencyKey: "auth.login:" + user.ID + ":" + sessionHash,
			Metadata:       map[string]any{"provider": "workos"},
		})
	})
	if err != nil {
		return User{}, Session{}, fmt.Errorf("upsert workos user and session: %w", err)
	}
	return user, Session{UserID: user.ID, Token: sessionToken, CSRFToken: csrfToken, ExpiresAt: expiresAt}, nil
}

func (s *Service) NewOAuthState() (string, error) {
	payload := "login:" + newToken() + "." + strconv.FormatInt(s.now().Add(10*time.Minute).Unix(), 10)
	signed, err := s.signValue(payload)
	if err != nil {
		return "", err
	}
	return signed, nil
}

func (s *Service) ValidateOAuthState(r *http.Request, state string) error {
	state = strings.TrimSpace(state)
	if state == "" {
		return ErrOAuthState
	}
	cookie, err := singleCookie(r, s.oauthStateCookieName())
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return ErrOAuthState
	}
	if !hmac.Equal([]byte(cookie.Value), []byte(state)) {
		return ErrOAuthState
	}
	if !s.validSignedValue(state) {
		return ErrOAuthState
	}
	nonce, expiresAt, ok := parseExpiringSignedValue(state)
	if !ok || !strings.HasPrefix(nonce, "login:") || !s.now().Before(expiresAt) {
		return ErrOAuthState
	}
	return nil
}

func (s *Service) AuthenticateRequest(ctx context.Context, r *http.Request) (User, Session, error) {
	cookie, err := singleCookie(r, s.sessionCookieName())
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return User{}, Session{}, ErrUnauthenticated
	}
	sessionHash := tokenHash(cookie.Value)
	row, err := s.db.Queries().AuthenticateBrowserSession(ctx, sessionHash)
	if err != nil {
		return User{}, Session{}, ErrUnauthenticated
	}
	user := User{ID: row.ID, WorkOSSubject: row.WorkosSubject, PrimaryEmail: row.PrimaryEmail, DisplayName: row.DisplayName, Status: row.Status, Role: Role(row.Role), CreatedAt: row.CreatedAt}
	session := Session{ID: row.SessionID, UserID: row.UserID, ExpiresAt: row.ExpiresAt}
	session.Token = cookie.Value
	return user, session, nil
}

func (s *Service) RotateSession(ctx context.Context, session Session) (Session, error) {
	if session.ID == "" {
		return Session{}, ErrUnauthenticated
	}
	next := Session{
		ID:        session.ID,
		UserID:    session.UserID,
		Token:     newToken(),
		CSRFToken: newToken(),
		ExpiresAt: s.now().Add(30 * 24 * time.Hour),
	}
	rows, err := s.db.Queries().RotateBrowserSession(ctx, dbsqlc.RotateBrowserSessionParams{SessionHash: tokenHash(next.Token), CsrfHash: tokenHash(next.CSRFToken), ExpiresAt: next.ExpiresAt, ID: session.ID})
	if err != nil {
		return Session{}, err
	}
	if rows != 1 {
		return Session{}, ErrUnauthenticated
	}
	return next, nil
}

func (s *Service) RefreshCSRF(ctx context.Context, session Session) (string, error) {
	if session.ID == "" {
		return "", ErrUnauthenticated
	}
	token := newToken()
	rows, err := s.db.Queries().RefreshBrowserSessionCSRF(ctx, dbsqlc.RefreshBrowserSessionCSRFParams{CsrfHash: tokenHash(token), ID: session.ID})
	if err != nil {
		return "", err
	}
	if rows != 1 {
		return "", ErrUnauthenticated
	}
	return token, nil
}

func (s *Service) ShouldRotate(session Session) bool {
	return !session.ExpiresAt.IsZero() && session.ExpiresAt.Before(s.now().Add(7*24*time.Hour))
}

func (s *Service) Logout(ctx context.Context, r *http.Request) error {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		return nil
	}
	sessionHash := tokenHash(cookie.Value)
	return s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		userID, err := tx.Queries().RevokeBrowserSession(ctx, sessionHash)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		return s.audit.WriteTx(ctx, tx, audit.Event{
			ActorUserID:    userID,
			ActorType:      audit.ActorUser,
			EventType:      "auth.logout",
			ResourceType:   "user",
			ResourceID:     userID,
			IdempotencyKey: "auth.logout:" + sessionHash,
			Metadata:       map[string]any{},
		})
	})
}

func (s *Service) SetSessionCookies(w http.ResponseWriter, session Session) {
	http.SetCookie(w, &http.Cookie{Name: s.sessionCookieName(), Value: session.Token, Path: "/", HttpOnly: true, Secure: s.cookieSecure, SameSite: http.SameSiteLaxMode, Expires: session.ExpiresAt})
	http.SetCookie(w, &http.Cookie{Name: s.csrfCookieName(), Value: session.CSRFToken, Path: "/", Secure: s.cookieSecure, SameSite: http.SameSiteLaxMode, Expires: session.ExpiresAt})
}

func (s *Service) SetCSRFCookie(w http.ResponseWriter, token string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{Name: s.csrfCookieName(), Value: token, Path: "/", Secure: s.cookieSecure, SameSite: http.SameSiteLaxMode, Expires: expiresAt})
}

func (s *Service) SetOAuthStateCookie(w http.ResponseWriter, state string) {
	http.SetCookie(w, &http.Cookie{Name: s.oauthStateCookieName(), Value: state, Path: "/", HttpOnly: true, Secure: s.cookieSecure, SameSite: http.SameSiteLaxMode, Expires: s.now().Add(10 * time.Minute), MaxAge: 600})
}

func (s *Service) ClearSessionCookies(w http.ResponseWriter) {
	clearCookie(w, s.sessionCookieName(), true, s.cookieSecure)
	clearCookie(w, s.csrfCookieName(), false, s.cookieSecure)
	clearCookie(w, s.oauthStateCookieName(), true, s.cookieSecure)
}

func (s *Service) ClearOAuthStateCookie(w http.ResponseWriter) {
	clearCookie(w, s.oauthStateCookieName(), true, s.cookieSecure)
}

func clearCookie(w http.ResponseWriter, name string, httpOnly bool, secure bool) {
	clearCookiePath(w, name, "/", httpOnly, secure)
}
func clearCookiePath(w http.ResponseWriter, name, path string, httpOnly, secure bool) {
	expired := time.Unix(0, 0)
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: path, HttpOnly: httpOnly, Secure: secure, SameSite: http.SameSiteLaxMode, Expires: expired, MaxAge: -1})
}

func (s *Service) CSRFToken(r *http.Request) (string, bool) {
	cookie, err := singleCookie(r, s.csrfCookieName())
	if err != nil || cookie.Value == "" {
		return "", false
	}
	return cookie.Value, true
}

func (s *Service) ValidateCSRF(ctx context.Context, r *http.Request) error {
	cookie, err := singleCookie(r, s.csrfCookieName())
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return ErrCSRF
	}
	header := strings.TrimSpace(r.Header.Get(CSRFHeaderName))
	if header == "" || !hmac.Equal([]byte(header), []byte(cookie.Value)) {
		return ErrCSRF
	}
	sessionCookie, err := singleCookie(r, s.sessionCookieName())
	if err != nil {
		return ErrCSRF
	}
	exists, err := s.db.Queries().BrowserSessionCSRFExists(ctx, dbsqlc.BrowserSessionCSRFExistsParams{SessionHash: tokenHash(sessionCookie.Value), CsrfHash: tokenHash(cookie.Value)})
	if err != nil {
		return err
	}
	if !exists {
		return ErrCSRF
	}
	return nil
}

// ValidateBrowserRequest enforces the exact trusted browser origin on unsafe
// cookie-authenticated requests. An unset origin fails closed.
func (s *Service) ValidateBrowserRequest(r *http.Request) error {
	if !unsafeMethod(r.Method) {
		return nil
	}
	origins := r.Header.Values("Origin")
	if s.trustedOrigin == "" || len(origins) != 1 || origins[0] != s.trustedOrigin {
		return ErrOrigin
	}
	for _, name := range []string{SessionCookieName, CSRFCookieName, OAuthStateCookieName, DevSessionCookieName, DevCSRFCookieName, DevOAuthStateCookieName} {
		if _, err := singleCookie(r, name); err != nil && !errors.Is(err, http.ErrNoCookie) {
			return ErrDuplicateCookie
		}
	}
	return nil
}

func (s *Service) sessionCookieName() string {
	if s.cookieSecure {
		return SessionCookieName
	}
	return DevSessionCookieName
}
func (s *Service) csrfCookieName() string {
	if s.cookieSecure {
		return CSRFCookieName
	}
	return DevCSRFCookieName
}
func (s *Service) oauthStateCookieName() string {
	if s.cookieSecure {
		return OAuthStateCookieName
	}
	return DevOAuthStateCookieName
}

func singleCookie(r *http.Request, name string) (*http.Cookie, error) {
	cookies := r.CookiesNamed(name)
	if len(cookies) == 0 {
		return nil, http.ErrNoCookie
	}
	if len(cookies) != 1 {
		return nil, ErrDuplicateCookie
	}
	return cookies[0], nil
}

func unsafeMethod(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

func (s *Service) HasActiveEntitlement(ctx context.Context, userID string) (bool, error) {
	return s.db.Queries().UserHasActiveSubscription(ctx, userID)
}

// Fast path: once the free-plan resources have been provisioned, the write
// transaction below is a no-op. Skip it with a cheap read so that reads stay
// cheap and concurrent entitlement checks (e.g. the dashboard loading
// several gated endpoints at once) don't contend on the same rows under
// serializable isolation.

// freeResourcesProvisioned reports whether the free-plan credit grant and
// included-storage ledger entries already exist for the user, using cheap
// read-only lookups (no write transaction). The idempotency keys match those
// written in ensureFreeEntitlementResources.

func (s *Service) OwnsProject(ctx context.Context, userID, projectID string) (bool, error) {
	return s.db.Queries().UserOwnsProject(ctx, dbsqlc.UserOwnsProjectParams{ID: projectID, UserID: userID})
}

var (
	ErrUnauthenticated = errors.New("unauthenticated")
	ErrCSRF            = errors.New("csrf validation failed")
	ErrOAuthState      = errors.New("oauth state validation failed")
	ErrOrigin          = errors.New("browser origin validation failed")
	ErrDuplicateCookie = errors.New("duplicate reserved cookie")
)

func (s *Service) signValue(value string) (string, error) {
	key, err := s.currentSessionKey()
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte(value))
	return value + "." + hex.EncodeToString(mac.Sum(nil)), nil
}

func (s *Service) validSignedValue(signed string) bool {
	value, signature, ok := splitSignedValue(signed)
	if !ok {
		return false
	}
	for _, key := range s.sessionKeys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		mac := hmac.New(sha256.New, []byte(key))
		_, _ = mac.Write([]byte(value))
		if hmac.Equal([]byte(hex.EncodeToString(mac.Sum(nil))), []byte(signature)) {
			return true
		}
	}
	return false
}

func parseExpiringSignedValue(signed string) (string, time.Time, bool) {
	value, _, ok := splitSignedValue(signed)
	if !ok {
		return "", time.Time{}, false
	}
	nonce, rawExpires, ok := strings.Cut(value, ".")
	if !ok || nonce == "" || rawExpires == "" {
		return "", time.Time{}, false
	}
	expiresUnix, err := strconv.ParseInt(rawExpires, 10, 64)
	if err != nil || expiresUnix <= 0 {
		return "", time.Time{}, false
	}
	return nonce, time.Unix(expiresUnix, 0), true
}

func splitSignedValue(signed string) (string, string, bool) {
	index := strings.LastIndex(signed, ".")
	if index <= 0 || index == len(signed)-1 {
		return "", "", false
	}
	return signed[:index], signed[index+1:], true
}

func (s *Service) currentSessionKey() (string, error) {
	if len(s.sessionKeys) == 0 || strings.TrimSpace(s.sessionKeys[0]) == "" {
		return "", errors.New("session signing key is not configured")
	}
	return strings.TrimSpace(s.sessionKeys[0]), nil
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func newToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

func newID(prefix string) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return prefix + "_" + hex.EncodeToString(b[:])
}
