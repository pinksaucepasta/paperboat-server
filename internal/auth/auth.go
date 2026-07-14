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
	SessionCookieName     = "paperboat_session"
	CSRFCookieName        = "paperboat_csrf"
	OAuthStateCookieName  = "paperboat_oauth_state"
	ReauthProofCookieName = "paperboat_reauth_proof"
	CSRFHeaderName        = "X-CSRF-Token"
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
	nonce, expiresAt, ok := parseExpiringSignedValue(state)
	if !ok || !strings.HasPrefix(nonce, "login:") || !s.now().Before(expiresAt) {
		return ErrOAuthState
	}
	return nil
}

func (s *Service) NewReauthState(userID, purpose string) (string, error) {
	if !validReauthPurpose(purpose) || strings.TrimSpace(userID) == "" {
		return "", ErrOAuthState
	}
	payload := "reauth:" + userID + ":" + purpose + ":" + newToken() + "." + strconv.FormatInt(s.now().Add(10*time.Minute).Unix(), 10)
	return s.signValue(payload)
}

func (s *Service) VerifyReauthentication(ctx context.Context, r *http.Request, input CallbackInput, user User, purpose string) (string, error) {
	if !validReauthPurpose(purpose) || strings.TrimSpace(user.ID) == "" {
		return "", ErrOAuthState
	}
	cookie, err := r.Cookie(OAuthStateCookieName)
	if err != nil || !hmac.Equal([]byte(cookie.Value), []byte(input.State)) || !s.validSignedValue(input.State) {
		return "", ErrOAuthState
	}
	nonce, expires, ok := parseExpiringSignedValue(input.State)
	prefix := "reauth:" + user.ID + ":" + purpose + ":"
	if !ok || !strings.HasPrefix(nonce, prefix) || !s.now().Before(expires) {
		return "", ErrOAuthState
	}
	profile, err := s.verifier.VerifyCallback(ctx, input)
	if err != nil || profile.Subject != user.WorkOSSubject {
		return "", ErrUnauthenticated
	}
	return s.signValue("reauth-proof:" + user.ID + ":" + purpose + ":" + newToken() + "." + strconv.FormatInt(s.now().Add(5*time.Minute).Unix(), 10))
}

func (s *Service) ValidateReauthProof(r *http.Request, userID, purpose string) error {
	cookie, err := r.Cookie(ReauthProofCookieName)
	if err != nil || !s.validSignedValue(cookie.Value) {
		return ErrUnauthenticated
	}
	nonce, expires, ok := parseExpiringSignedValue(cookie.Value)
	if !ok || !strings.HasPrefix(nonce, "reauth-proof:"+userID+":"+purpose+":") || !s.now().Before(expires) {
		return ErrUnauthenticated
	}
	return nil
}

func validReauthPurpose(value string) bool {
	return value == "config_recovery_export" || value == "config_key_rotation"
}

func (s *Service) AuthenticateRequest(ctx context.Context, r *http.Request) (User, Session, error) {
	cookie, err := r.Cookie(SessionCookieName)
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
	http.SetCookie(w, &http.Cookie{Name: SessionCookieName, Value: session.Token, Path: "/", HttpOnly: true, Secure: s.cookieSecure, SameSite: http.SameSiteLaxMode, Expires: session.ExpiresAt})
	http.SetCookie(w, &http.Cookie{Name: CSRFCookieName, Value: session.CSRFToken, Path: "/", HttpOnly: false, Secure: s.cookieSecure, SameSite: http.SameSiteLaxMode, Expires: session.ExpiresAt})
}

func (s *Service) SetCSRFCookie(w http.ResponseWriter, token string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{Name: CSRFCookieName, Value: token, Path: "/", HttpOnly: false, Secure: s.cookieSecure, SameSite: http.SameSiteLaxMode, Expires: expiresAt})
}

func (s *Service) SetOAuthStateCookie(w http.ResponseWriter, state string) {
	http.SetCookie(w, &http.Cookie{Name: OAuthStateCookieName, Value: state, Path: "/", HttpOnly: true, Secure: s.cookieSecure, SameSite: http.SameSiteLaxMode, Expires: s.now().Add(10 * time.Minute), MaxAge: 600})
}

func (s *Service) SetReauthProofCookie(w http.ResponseWriter, proof string) {
	http.SetCookie(w, &http.Cookie{Name: ReauthProofCookieName, Value: proof, Path: "/", HttpOnly: true, Secure: s.cookieSecure, SameSite: http.SameSiteStrictMode, Expires: s.now().Add(5 * time.Minute), MaxAge: 300})
}
func (s *Service) ClearReauthProofCookie(w http.ResponseWriter) {
	clearCookiePath(w, ReauthProofCookieName, "/", true, s.cookieSecure)
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
	clearCookiePath(w, name, "/", httpOnly, secure)
}
func clearCookiePath(w http.ResponseWriter, name, path string, httpOnly, secure bool) {
	expired := time.Unix(0, 0)
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: path, HttpOnly: httpOnly, Secure: secure, SameSite: http.SameSiteLaxMode, Expires: expired, MaxAge: -1})
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
	exists, err := s.db.Queries().BrowserSessionCSRFExists(ctx, dbsqlc.BrowserSessionCSRFExistsParams{SessionHash: tokenHash(sessionCookie.Value), CsrfHash: tokenHash(cookie.Value)})
	if err != nil {
		return err
	}
	if !exists {
		return ErrCSRF
	}
	return nil
}

func (s *Service) HasActiveEntitlement(ctx context.Context, userID string) (bool, error) {
	return s.db.Queries().UserHasActiveSubscription(ctx, userID)
}

func (s *Service) ensureFreeEntitlementResources(ctx context.Context, userID string) (bool, error) {
	plan, err := s.db.Queries().GetFreePlanEntitlement(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	// Fast path: once the free-plan resources have been provisioned, the write
	// transaction below is a no-op. Skip it with a cheap read so that reads stay
	// cheap and concurrent entitlement checks (e.g. the dashboard loading
	// several gated endpoints at once) don't contend on the same rows under
	// serializable isolation.
	provisioned, err := s.freeResourcesProvisioned(ctx, plan, userID)
	if err != nil {
		return false, err
	}
	if provisioned {
		return true, nil
	}
	return true, s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		creditAccountID, err := ensureCreditAccountTx(ctx, tx, userID)
		if err != nil {
			return err
		}
		if positiveNumericString(plan.IncludedCredits) {
			if err := grantCreditsOnceTx(ctx, tx, creditAccountID, "free-plan:"+plan.ID+":credits:"+userID, plan.ID, plan.IncludedCredits); err != nil {
				return err
			}
		}
		storageAccountID, err := ensureStorageAccountTx(ctx, tx, userID)
		if err != nil {
			return err
		}
		return setIncludedStorageOnceTx(ctx, tx, storageAccountID, "free-plan:"+plan.ID+":storage:"+userID, plan.ID, int(plan.IncludedStorageGb))
	})
}

// freeResourcesProvisioned reports whether the free-plan credit grant and
// included-storage ledger entries already exist for the user, using cheap
// read-only lookups (no write transaction). The idempotency keys match those
// written in ensureFreeEntitlementResources.
func (s *Service) freeResourcesProvisioned(ctx context.Context, plan dbsqlc.GetFreePlanEntitlementRow, userID string) (bool, error) {
	q := s.db.Queries()
	if positiveNumericString(plan.IncludedCredits) {
		seen, err := q.CreditLedgerEntryExists(ctx, "free-plan:"+plan.ID+":credits:"+userID)
		if err != nil {
			return false, err
		}
		if !seen {
			return false, nil
		}
	}
	if _, err := q.GetStorageLedgerEntryByIdempotencyKey(ctx, "free-plan:"+plan.ID+":storage:"+userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (s *Service) OwnsProject(ctx context.Context, userID, projectID string) (bool, error) {
	return s.db.Queries().UserOwnsProject(ctx, dbsqlc.UserOwnsProjectParams{ID: projectID, UserID: userID})
}

func ensureCreditAccountTx(ctx context.Context, tx *db.Tx, userID string) (string, error) {
	return tx.Queries().EnsureCreditAccount(ctx, dbsqlc.EnsureCreditAccountParams{ID: newID("cred"), UserID: userID})
}

func ensureStorageAccountTx(ctx context.Context, tx *db.Tx, userID string) (string, error) {
	return tx.Queries().EnsureStorageAccount(ctx, dbsqlc.EnsureStorageAccountParams{ID: newID("stor"), UserID: userID})
}

func grantCreditsOnceTx(ctx context.Context, tx *db.Tx, accountID, idempotencyKey, planVersionID, amount string) error {
	q := tx.Queries()
	seen, err := q.CreditLedgerEntryExists(ctx, idempotencyKey)
	if err != nil || seen {
		return err
	}
	rows, err := q.InsertFreeCreditGrant(ctx, dbsqlc.InsertFreeCreditGrantParams{ID: newID("cled"), AccountID: accountID, Amount: amount, SourceID: planVersionID, IdempotencyKey: idempotencyKey})
	if err != nil {
		return err
	}
	if rows == 0 {
		return err
	}
	return q.IncreaseCreditBalance(ctx, dbsqlc.IncreaseCreditBalanceParams{ID: accountID, Amount: amount})
}

func setIncludedStorageOnceTx(ctx context.Context, tx *db.Tx, accountID, idempotencyKey, planVersionID string, includedGB int) error {
	q := tx.Queries()
	usage, err := q.GetStorageUsageForUpdate(ctx, accountID)
	if err != nil {
		return err
	}
	if int(usage.AllocatedGb) > includedGB+int(usage.PurchasedGb) {
		return errors.New("free included storage is below allocated storage")
	}
	if err := q.SetIncludedStorage(ctx, dbsqlc.SetIncludedStorageParams{ID: accountID, IncludedGb: int32(includedGB)}); err != nil {
		return err
	}
	rows, err := q.InsertFreeIncludedStorageLedger(ctx, dbsqlc.InsertFreeIncludedStorageLedgerParams{ID: newID("sled"), AccountID: accountID, AmountGb: int32(includedGB), SourceID: planVersionID, IdempotencyKey: idempotencyKey})
	if err != nil {
		return err
	}
	if rows > 0 {
		return err
	}
	return storageLedgerEntryMatchesTx(ctx, tx, accountID, "included_set", includedGB, "plan", planVersionID, idempotencyKey)
}

func storageLedgerEntryMatchesTx(ctx context.Context, tx *db.Tx, accountID, entryType string, amountGB int, sourceType, sourceID, idempotencyKey string) error {
	existing, err := tx.Queries().GetStorageLedgerEntryByIdempotencyKey(ctx, idempotencyKey)
	if err != nil {
		return err
	}
	if existing.AccountID != accountID || existing.EntryType != entryType || int(existing.AmountGb) != amountGB || existing.SourceType != sourceType || existing.SourceID != sourceID {
		return errors.New("storage ledger idempotency key conflicts with existing entry")
	}
	return err
}

func positiveNumericString(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && value != "0" && value != "0.0" && value != "0.000000"
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
