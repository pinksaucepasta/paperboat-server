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
)

const (
	SessionCookieName    = "paperboat_session"
	CSRFCookieName       = "paperboat_csrf"
	OAuthStateCookieName = "paperboat_oauth_state"
	CSRFHeaderName       = "X-CSRF-Token"
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
	db           *db.DB
	audit        *audit.Writer
	verifier     WorkOSVerifier
	sessionKeys  []string
	cookieSecure bool
	now          func() time.Time
}

func NewService(store *db.DB, auditWriter *audit.Writer, verifier WorkOSVerifier, sessionKeys []string, cookieSecure bool) *Service {
	return &Service{
		db:           store,
		audit:        auditWriter,
		verifier:     verifier,
		sessionKeys:  sessionKeys,
		cookieSecure: cookieSecure,
		now:          func() time.Time { return time.Now().UTC() },
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
		row := tx.QueryRow(ctx, `
WITH upsert_user AS (
	INSERT INTO users (id, workos_subject, primary_email, display_name, status, created_at, updated_at)
	VALUES ($1, $2, $3, $4, 'active', now(), now())
	ON CONFLICT (workos_subject) DO UPDATE SET
		primary_email = EXCLUDED.primary_email,
		display_name = EXCLUDED.display_name,
		updated_at = now(),
		version = users.version + 1
	RETURNING id, workos_subject, primary_email, display_name, status, role, created_at
),
identity AS (
	INSERT INTO user_identities (id, user_id, provider, provider_subject, email, created_at, updated_at)
	SELECT $5, id, 'workos', workos_subject, primary_email, now(), now() FROM upsert_user
	ON CONFLICT (provider, provider_subject) DO UPDATE SET
		email = EXCLUDED.email,
		updated_at = now()
)
SELECT id, workos_subject, primary_email, display_name, status, role, created_at FROM upsert_user`,
			newID("usr"), profile.Subject, strings.ToLower(profile.Email), profile.DisplayName, newID("uid"))
		if err := row.Scan(&user.ID, &user.WorkOSSubject, &user.PrimaryEmail, &user.DisplayName, &user.Status, &user.Role, &user.CreatedAt); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
INSERT INTO sessions (id, user_id, session_hash, csrf_hash, expires_at, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, now(), now())`,
			newID("ses"), user.ID, sessionHash, csrfHash, expiresAt)
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
	payload := newToken() + "." + strconv.FormatInt(s.now().Add(10*time.Minute).Unix(), 10)
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
	cookie, err := r.Cookie(OAuthStateCookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return ErrOAuthState
	}
	if !hmac.Equal([]byte(cookie.Value), []byte(state)) {
		return ErrOAuthState
	}
	if !s.validSignedValue(state) {
		return ErrOAuthState
	}
	_, expiresAt, ok := parseExpiringSignedValue(state)
	if !ok || !s.now().Before(expiresAt) {
		return ErrOAuthState
	}
	return nil
}

func (s *Service) AuthenticateRequest(ctx context.Context, r *http.Request) (User, Session, error) {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return User{}, Session{}, ErrUnauthenticated
	}
	sessionHash := tokenHash(cookie.Value)
	var user User
	var session Session
	var csrfHash string
	err = s.db.SQL().QueryRowContext(ctx, `
SELECT s.id, s.user_id, s.expires_at, s.csrf_hash,
       u.id, u.workos_subject, u.primary_email, u.display_name, u.status, u.role, u.created_at
FROM paperboat.sessions s
JOIN paperboat.users u ON u.id = s.user_id
WHERE s.session_hash = $1
  AND s.revoked_at IS NULL
  AND s.expires_at > now()
	AND u.status = 'active'`, sessionHash).Scan(
		&session.ID, &session.UserID, &session.ExpiresAt, &csrfHash,
		&user.ID, &user.WorkOSSubject, &user.PrimaryEmail, &user.DisplayName, &user.Status, &user.Role, &user.CreatedAt,
	)
	if err != nil {
		return User{}, Session{}, ErrUnauthenticated
	}
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
	result, err := s.db.SQL().ExecContext(ctx, `
UPDATE paperboat.sessions
SET session_hash = $1,
    csrf_hash = $2,
    expires_at = $3,
    rotated_at = now(),
    updated_at = now(),
    version = version + 1
WHERE id = $4 AND revoked_at IS NULL AND expires_at > now()`,
		tokenHash(next.Token), tokenHash(next.CSRFToken), next.ExpiresAt, session.ID)
	if err != nil {
		return Session{}, err
	}
	rows, err := result.RowsAffected()
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
	result, err := s.db.SQL().ExecContext(ctx, `
UPDATE paperboat.sessions
SET csrf_hash = $1, updated_at = now()
WHERE id = $2 AND revoked_at IS NULL AND expires_at > now()`,
		tokenHash(token), session.ID)
	if err != nil {
		return "", err
	}
	rows, err := result.RowsAffected()
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
		var userID string
		err := tx.QueryRow(ctx, `
UPDATE paperboat.sessions
SET revoked_at = now(), updated_at = now(), version = version + 1
WHERE session_hash = $1 AND revoked_at IS NULL
RETURNING user_id`, sessionHash).Scan(&userID)
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
	http.SetCookie(w, &http.Cookie{Name: SessionCookieName, Value: session.Token, Path: "/", HttpOnly: true, Secure: s.cookieSecure, SameSite: http.SameSiteLaxMode, Expires: session.ExpiresAt})
	http.SetCookie(w, &http.Cookie{Name: CSRFCookieName, Value: session.CSRFToken, Path: "/", HttpOnly: false, Secure: s.cookieSecure, SameSite: http.SameSiteLaxMode, Expires: session.ExpiresAt})
}

func (s *Service) SetCSRFCookie(w http.ResponseWriter, token string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{Name: CSRFCookieName, Value: token, Path: "/", HttpOnly: false, Secure: s.cookieSecure, SameSite: http.SameSiteLaxMode, Expires: expiresAt})
}

func (s *Service) SetOAuthStateCookie(w http.ResponseWriter, state string) {
	http.SetCookie(w, &http.Cookie{Name: OAuthStateCookieName, Value: state, Path: "/", HttpOnly: true, Secure: s.cookieSecure, SameSite: http.SameSiteLaxMode, Expires: s.now().Add(10 * time.Minute), MaxAge: 600})
}

func (s *Service) ClearSessionCookies(w http.ResponseWriter) {
	clearCookie(w, SessionCookieName, true, s.cookieSecure)
	clearCookie(w, CSRFCookieName, false, s.cookieSecure)
	clearCookie(w, OAuthStateCookieName, true, s.cookieSecure)
}

func (s *Service) ClearOAuthStateCookie(w http.ResponseWriter) {
	clearCookie(w, OAuthStateCookieName, true, s.cookieSecure)
}

func clearCookie(w http.ResponseWriter, name string, httpOnly bool, secure bool) {
	expired := time.Unix(0, 0)
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", HttpOnly: httpOnly, Secure: secure, SameSite: http.SameSiteLaxMode, Expires: expired, MaxAge: -1})
}

func (s *Service) CSRFToken(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(CSRFCookieName)
	if err != nil || cookie.Value == "" {
		return "", false
	}
	return cookie.Value, true
}

func (s *Service) ValidateCSRF(ctx context.Context, r *http.Request) error {
	cookie, err := r.Cookie(CSRFCookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return ErrCSRF
	}
	header := strings.TrimSpace(r.Header.Get(CSRFHeaderName))
	if header == "" || !hmac.Equal([]byte(header), []byte(cookie.Value)) {
		return ErrCSRF
	}
	sessionCookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		return ErrCSRF
	}
	var exists bool
	if err := s.db.SQL().QueryRowContext(ctx, `
SELECT EXISTS (
	SELECT 1 FROM paperboat.sessions
	WHERE session_hash = $1 AND csrf_hash = $2 AND revoked_at IS NULL AND expires_at > now()
)`, tokenHash(sessionCookie.Value), tokenHash(cookie.Value)).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrCSRF
	}
	return nil
}

func (s *Service) HasActiveEntitlement(ctx context.Context, userID string) (bool, error) {
	var exists bool
	err := s.db.SQL().QueryRowContext(ctx, `
SELECT EXISTS (
	SELECT 1 FROM paperboat.subscriptions
	WHERE user_id = $1
	  AND state IN ('active', 'trialing')
	  AND (current_period_end IS NULL OR current_period_end > now())
)`, userID).Scan(&exists)
	return exists, err
}

func (s *Service) OwnsProject(ctx context.Context, userID, projectID string) (bool, error) {
	var exists bool
	err := s.db.SQL().QueryRowContext(ctx, `
SELECT EXISTS (SELECT 1 FROM paperboat.projects WHERE id = $1 AND user_id = $2 AND state <> 'deleted')`, projectID, userID).Scan(&exists)
	return exists, err
}

var (
	ErrUnauthenticated = errors.New("unauthenticated")
	ErrCSRF            = errors.New("csrf validation failed")
	ErrOAuthState      = errors.New("oauth state validation failed")
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
