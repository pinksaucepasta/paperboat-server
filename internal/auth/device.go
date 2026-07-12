package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/observability"
)

type DeviceError struct {
	Code       string
	Interval   int
	RetryAfter int
}

func (e *DeviceError) Error() string { return e.Code }

type DeviceAuthorizationInput struct {
	ClientID, ClientLabel, DeviceType, OS string
	Scopes                                []string
	Network                               string
}

type DeviceAuthorization struct {
	DeviceCode, UserCode, VerificationURI, VerificationURIComplete string
	ExpiresIn, Interval                                            int
}

type DeviceTokenInput struct{ ClientID, DeviceCode, Network string }

type TokenSet struct {
	AccessToken, RefreshToken, TokenType, Scope, ClientSessionID string
	ExpiresIn                                                    int
}

type DeviceRequest struct {
	ClientLabel, DeviceType, OS, UserCode, State string
	Scopes                                       []string
	IssuedAt, ExpiresAt                          time.Time
}

type ClientPrincipal struct {
	SessionID string
	User      User
	Scopes    []string
}

func (p ClientPrincipal) HasScope(scope string) bool { return slices.Contains(p.Scopes, scope) }

type ClientSession struct {
	ID, ClientID, ClientLabel, DeviceType, OS, State string
	Scopes                                           []string
	CreatedAt, ApprovedAt                            time.Time
	LastUsedAt, RevokedAt                            *time.Time
	RevocationReason                                 *string
	Current                                          bool
}

type ClientSessionPage struct {
	Items                []ClientSession
	Limit, Offset, Total int
	NextOffset           *int
}

type DeviceService struct {
	db         *db.DB
	audit      *audit.Writer
	cfg        config.CLIAuth
	keys       [][]byte
	downstream DownstreamSessionRevoker
	now        func() time.Time
}

type DownstreamSessionRevoker interface {
	RevokeClientSessions(context.Context, string, string) error
}

func NewDeviceService(store *db.DB, auditWriter *audit.Writer, cfg config.CLIAuth, hashKeys []string) *DeviceService {
	keys := make([][]byte, 0, len(hashKeys))
	for _, key := range hashKeys {
		if key != "" {
			keys = append(keys, []byte(key))
		}
	}
	return &DeviceService{db: store, audit: auditWriter, cfg: cfg, keys: keys, now: func() time.Time { return time.Now().UTC() }}
}

func (s *DeviceService) SetDownstreamRevoker(revoker DownstreamSessionRevoker) {
	s.downstream = revoker
}

func (s *DeviceService) Authorize(ctx context.Context, in DeviceAuthorizationInput) (DeviceAuthorization, error) {
	if in.ClientID != s.cfg.ClientID {
		return DeviceAuthorization{}, &DeviceError{Code: "invalid_client"}
	}
	in.ClientLabel = strings.TrimSpace(in.ClientLabel)
	if in.ClientLabel == "" || len(in.ClientLabel) > s.cfg.MaxClientLabelLength || strings.TrimSpace(in.OS) == "" || !slices.Contains([]string{"desktop", "server", "container"}, in.DeviceType) {
		return DeviceAuthorization{}, &DeviceError{Code: "validation_failed"}
	}
	if !exactScopes(in.Scopes, s.cfg.AllowedScopes) {
		return DeviceAuthorization{}, &DeviceError{Code: "invalid_scope"}
	}
	verification := strings.TrimRight(s.cfg.VerificationURL, "/")
	u, err := url.Parse(verification)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return DeviceAuthorization{}, errors.New("verification URL is invalid")
	}
	if err := s.takeRate(ctx, "network:"+s.hash(in.Network), s.cfg.NetworkRequestsPerMinute); err != nil {
		return DeviceAuthorization{}, err
	}
	deviceCode := randomToken(32)
	userCode := randomUserCode()
	now := s.now()
	expires := now.Add(s.cfg.DeviceGrantLifetime)
	interval := max(1, int(s.cfg.PollInterval/time.Second))
	grantID := newID("dgr")
	err = s.inTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := tx.Queries().CreateDeviceGrant(ctx, dbsqlc.CreateDeviceGrantParams{ID: grantID, ClientID: in.ClientID, ClientLabel: in.ClientLabel, DeviceType: in.DeviceType, Os: strings.TrimSpace(in.OS), Scopes: normalizedScopes(in.Scopes), DeviceCodeHash: s.hash(deviceCode), UserCodeHash: s.hashUserCode(userCode), IssuedAt: now, ExpiresAt: expires, PollIntervalSeconds: int32(interval), CreatedNetworkHash: s.hash(in.Network)}); err != nil {
			return err
		}
		return s.audit.WriteTx(ctx, tx, audit.Event{ActorType: audit.ActorSystem, EventType: "auth.device.requested", ResourceType: "device_grant", ResourceID: grantID, IdempotencyKey: "auth.device.requested:" + grantID, Metadata: map[string]any{"client_id": in.ClientID, "device_type": in.DeviceType}})
	})
	if err != nil {
		return DeviceAuthorization{}, fmt.Errorf("create device grant: %w", err)
	}
	observability.DeviceRequested()
	q := u.Query()
	q.Set("code", userCode)
	u.RawQuery = q.Encode()
	return DeviceAuthorization{DeviceCode: deviceCode, UserCode: userCode, VerificationURI: verification, VerificationURIComplete: u.String(), ExpiresIn: int(s.cfg.DeviceGrantLifetime / time.Second), Interval: interval}, nil
}

func (s *DeviceService) Poll(ctx context.Context, in DeviceTokenInput) (TokenSet, error) {
	if in.ClientID != s.cfg.ClientID {
		return TokenSet{}, &DeviceError{Code: "invalid_client"}
	}
	if strings.TrimSpace(in.DeviceCode) == "" {
		return TokenSet{}, &DeviceError{Code: "invalid_grant"}
	}
	if err := s.takeRate(ctx, "network:"+s.hash(in.Network), s.cfg.NetworkRequestsPerMinute); err != nil {
		return TokenSet{}, err
	}
	if err := s.takeRate(ctx, "grant:"+s.hash(in.DeviceCode), s.cfg.GrantPollsPerMinute); err != nil {
		return TokenSet{}, err
	}
	var out TokenSet
	var outcomeErr error
	var completionLatency int64 = -1
	err := s.inTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		grant, err := q.GetDeviceGrantForPoll(ctx, s.hashList(in.DeviceCode))
		if errors.Is(err, sql.ErrNoRows) {
			return &DeviceError{Code: "invalid_grant"}
		}
		if err != nil {
			return err
		}
		if grant.ClientID != in.ClientID {
			return &DeviceError{Code: "invalid_grant"}
		}
		if !s.matchesHash(grant.DeviceCodeHash, in.DeviceCode) {
			return &DeviceError{Code: "invalid_grant"}
		}
		now := s.now()
		if !now.Before(grant.ExpiresAt) {
			_ = q.ExpireDeviceGrant(ctx, grant.ID)
			outcomeErr = &DeviceError{Code: "expired_token"}
			return nil
		}
		switch grant.State {
		case "denied":
			outcomeErr = &DeviceError{Code: "access_denied"}
			return nil
		case "consumed", "expired":
			return &DeviceError{Code: "invalid_grant"}
		}
		if grant.State == "approved" {
			userStatus, err := q.GetUserStatus(ctx, grant.UserID)
			if err != nil {
				return err
			}
			if userStatus != "active" {
				if err := q.DenyApprovedDeviceGrant(ctx, dbsqlc.DenyApprovedDeviceGrantParams{ID: grant.ID, DeniedAt: sql.NullTime{Time: now, Valid: true}}); err != nil {
					return err
				}
				outcomeErr = &DeviceError{Code: "access_denied"}
				return nil
			}
		}
		interval := int(grant.PollIntervalSeconds)
		if now.Before(grant.NextPollAt) {
			interval += 5
			err = q.SlowDeviceGrantPoll(ctx, dbsqlc.SlowDeviceGrantPollParams{ID: grant.ID, PollIntervalSeconds: int32(interval), NextPollAt: now.Add(time.Duration(interval) * time.Second)})
			if err != nil {
				return err
			}
			outcomeErr = &DeviceError{Code: "slow_down", Interval: interval}
			return nil
		}
		err = q.AdvanceDeviceGrantPoll(ctx, dbsqlc.AdvanceDeviceGrantPollParams{ID: grant.ID, NextPollAt: now.Add(time.Duration(interval) * time.Second)})
		if err != nil {
			return err
		}
		switch grant.State {
		case "pending":
			outcomeErr = &DeviceError{Code: "authorization_pending"}
			return nil
		case "approved":
		default:
			return &DeviceError{Code: "invalid_grant"}
		}
		if err := s.takeRate(ctx, "account:"+grant.UserID, s.cfg.AccountActionsPerMinute); err != nil {
			return err
		}
		access, refresh := randomToken(32), randomToken(32)
		sessionID := newID("cls")
		approvedAt, err := q.GetDeviceGrantApprovedAt(ctx, grant.ID)
		if err != nil {
			return err
		}
		if err = q.CreateClientSession(ctx, dbsqlc.CreateClientSessionParams{ID: sessionID, UserID: grant.UserID, ClientID: grant.ClientID, ClientLabel: grant.ClientLabel, DeviceType: grant.DeviceType, Os: grant.Os, Scopes: grant.Scopes, CreatedAt: now, ApprovedAt: approvedAt.Time}); err != nil {
			return err
		}
		if err = q.CreateClientAccessToken(ctx, dbsqlc.CreateClientAccessTokenParams{TokenHash: s.hash(access), ClientSessionID: sessionID, ExpiresAt: now.Add(s.cfg.AccessTokenLifetime), CreatedAt: now}); err != nil {
			return err
		}
		if err = q.CreateClientRefreshToken(ctx, dbsqlc.CreateClientRefreshTokenParams{TokenHash: s.hash(refresh), ClientSessionID: sessionID, ExpiresAt: now.Add(s.cfg.RefreshTokenLifetime), CreatedAt: now}); err != nil {
			return err
		}
		rows, err := q.ConsumeDeviceGrant(ctx, dbsqlc.ConsumeDeviceGrantParams{ID: grant.ID, ConsumedAt: sql.NullTime{Time: now, Valid: true}})
		if err != nil {
			return err
		}
		if rows != 1 {
			return &DeviceError{Code: "invalid_grant"}
		}
		if err := s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: grant.UserID, ActorType: audit.ActorUser, EventType: "auth.client.approved", ResourceType: "client_session", ResourceID: sessionID, IdempotencyKey: "auth.client.approved:" + sessionID, Metadata: map[string]any{"client_id": grant.ClientID}}); err != nil {
			return err
		}
		completionLatency = now.Sub(grant.IssuedAt).Milliseconds()
		if completionLatency < 0 {
			completionLatency = 0
		}
		if err := s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: grant.UserID, ActorType: audit.ActorUser, EventType: "auth.device.completed", ResourceType: "device_grant", ResourceID: grant.ID, IdempotencyKey: "auth.device.completed:" + grant.ID, Metadata: map[string]any{"client_id": grant.ClientID, "client_session_id": sessionID, "latency_ms": completionLatency}}); err != nil {
			return err
		}
		out = TokenSet{AccessToken: access, RefreshToken: refresh, TokenType: "Bearer", ExpiresIn: int(s.cfg.AccessTokenLifetime / time.Second), Scope: grant.Scopes, ClientSessionID: sessionID}
		return nil
	})
	if err != nil {
		return TokenSet{}, err
	}
	if completionLatency >= 0 {
		observability.DeviceCompleted(completionLatency)
	}
	return out, outcomeErr
}

func (s *DeviceService) Request(ctx context.Context, userCode string) (DeviceRequest, error) {
	row, err := s.db.Queries().GetDeviceGrantRequest(ctx, s.userCodeHashList(userCode))
	out := DeviceRequest{ClientLabel: row.ClientLabel, DeviceType: row.DeviceType, OS: row.Os, IssuedAt: row.IssuedAt, ExpiresAt: row.ExpiresAt, State: row.State}
	if errors.Is(err, sql.ErrNoRows) {
		return out, &DeviceError{Code: "device_request_not_found"}
	}
	if err != nil {
		return out, err
	}
	if !s.matchesHash(row.UserCodeHash, "user-code:"+normalizeUserCode(userCode)) {
		return out, &DeviceError{Code: "invalid_grant"}
	}
	out.Scopes = strings.Fields(row.Scopes)
	normalized := normalizeUserCode(userCode)
	if len(normalized) == 8 {
		out.UserCode = normalized[:4] + "-" + normalized[4:]
	}
	if !s.now().Before(out.ExpiresAt) && (out.State == "pending" || out.State == "approved") {
		out.State = "expired"
	}
	return out, nil
}

func (s *DeviceService) RateAccount(ctx context.Context, userID string) error {
	return s.takeRate(ctx, "account:"+userID, s.cfg.AccountActionsPerMinute)
}

func (s *DeviceService) Decide(ctx context.Context, userCode, userID string, approve bool) (DeviceRequest, error) {
	if err := s.takeRate(ctx, "account:"+userID, s.cfg.AccountActionsPerMinute); err != nil {
		return DeviceRequest{}, err
	}
	var outcomeErr error
	err := s.inTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		grant, err := q.GetDeviceGrantForDecision(ctx, s.userCodeHashList(userCode))
		if errors.Is(err, sql.ErrNoRows) {
			return &DeviceError{Code: "device_request_not_found"}
		}
		if err != nil {
			return err
		}
		if !s.matchesHash(grant.UserCodeHash, "user-code:"+normalizeUserCode(userCode)) {
			return &DeviceError{Code: "invalid_grant"}
		}
		if !s.now().Before(grant.ExpiresAt) {
			_ = q.ExpireDeviceGrantWithoutVersion(ctx, grant.ID)
			outcomeErr = &DeviceError{Code: "device_request_expired"}
			return nil
		}
		wanted := "denied"
		if approve {
			wanted = "approved"
		}
		if grant.State == wanted && grant.UserID == userID {
			return nil
		}
		if grant.State == "consumed" {
			return &DeviceError{Code: "device_request_consumed"}
		}
		if grant.State != "pending" {
			return &DeviceError{Code: "device_request_not_pending"}
		}
		now := s.now()
		if approve {
			err = q.ApproveDeviceGrant(ctx, dbsqlc.ApproveDeviceGrantParams{ID: grant.ID, UserID: sql.NullString{String: userID, Valid: true}, ApprovedAt: sql.NullTime{Time: now, Valid: true}})
		} else {
			err = q.DenyDeviceGrant(ctx, dbsqlc.DenyDeviceGrantParams{ID: grant.ID, UserID: sql.NullString{String: userID, Valid: true}, DeniedAt: sql.NullTime{Time: now, Valid: true}})
		}
		if err != nil {
			return err
		}
		return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "auth.device." + wanted, ResourceType: "device_grant", ResourceID: grant.ID, IdempotencyKey: "auth.device." + wanted + ":" + grant.ID, Metadata: map[string]any{"client_id": grant.ClientID}})
	})
	if err != nil {
		return DeviceRequest{}, err
	}
	if outcomeErr != nil {
		return DeviceRequest{}, outcomeErr
	}
	return s.Request(ctx, userCode)
}

func (s *DeviceService) Authenticate(ctx context.Context, token string) (ClientPrincipal, error) {
	row, err := s.db.Queries().AuthenticateClientAccessToken(ctx, dbsqlc.AuthenticateClientAccessTokenParams{TokenHashes: s.hashList(token), Now: s.now()})
	if err != nil {
		return ClientPrincipal{}, ErrUnauthenticated
	}
	p := ClientPrincipal{SessionID: row.ID, Scopes: strings.Fields(row.Scopes), User: User{ID: row.UserID, WorkOSSubject: row.WorkosSubject, PrimaryEmail: row.PrimaryEmail, DisplayName: row.DisplayName, Status: row.Status, Role: Role(row.Role), CreatedAt: row.CreatedAt}}
	_ = s.db.Queries().TouchClientSession(ctx, dbsqlc.TouchClientSessionParams{ID: p.SessionID, LastUsedAt: sql.NullTime{Time: s.now(), Valid: true}})
	return p, nil
}

func (s *DeviceService) Refresh(ctx context.Context, token string) (TokenSet, error) {
	var out TokenSet
	var replay bool
	var replaySID string
	err := s.inTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		stored, err := q.GetClientRefreshTokenForUpdate(ctx, s.hashList(token))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnauthenticated
		}
		if err != nil {
			return err
		}
		if !s.matchesHash(stored.TokenHash, token) {
			return ErrUnauthenticated
		}
		if stored.State != "active" {
			replay = true
			replaySID = stored.ClientSessionID
			return s.revokeTx(ctx, tx, stored.ClientSessionID, "refresh_replay")
		}
		if !s.now().Before(stored.ExpiresAt) {
			return ErrUnauthenticated
		}
		now := s.now()
		access, refresh := randomToken(32), randomToken(32)
		if err = q.MarkClientRefreshTokenRotated(ctx, dbsqlc.MarkClientRefreshTokenRotatedParams{TokenHash: stored.TokenHash, RotatedAt: sql.NullTime{Time: now, Valid: true}}); err != nil {
			return err
		}
		if err = q.CreateClientRefreshToken(ctx, dbsqlc.CreateClientRefreshTokenParams{TokenHash: s.hash(refresh), ClientSessionID: stored.ClientSessionID, ExpiresAt: now.Add(s.cfg.RefreshTokenLifetime), CreatedAt: now}); err != nil {
			return err
		}
		if err = q.CreateClientAccessToken(ctx, dbsqlc.CreateClientAccessTokenParams{TokenHash: s.hash(access), ClientSessionID: stored.ClientSessionID, ExpiresAt: now.Add(s.cfg.AccessTokenLifetime), CreatedAt: now}); err != nil {
			return err
		}
		out = TokenSet{AccessToken: access, RefreshToken: refresh, TokenType: "Bearer", ExpiresIn: int(s.cfg.AccessTokenLifetime / time.Second), Scope: stored.Scopes, ClientSessionID: stored.ClientSessionID}
		return nil
	})
	if err != nil {
		return TokenSet{}, err
	}
	if replay {
		if s.downstream != nil {
			if err := s.downstream.RevokeClientSessions(ctx, replaySID, "refresh_replay"); err != nil {
				return TokenSet{}, err
			}
		}
		return TokenSet{}, ErrUnauthenticated
	}
	return out, nil
}

func (s *DeviceService) RevokeToken(ctx context.Context, token, reason string) error {
	var sid string
	err := s.inTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		var err error
		sid, err = tx.Queries().FindClientSessionByToken(ctx, s.hashList(token))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnauthenticated
		}
		if err != nil {
			return err
		}
		return s.revokeTx(ctx, tx, sid, reason)
	})
	if err != nil {
		return err
	}
	if sid != "" && s.downstream != nil {
		return s.downstream.RevokeClientSessions(ctx, sid, reason)
	}
	return nil
}

func (s *DeviceService) revokeTx(ctx context.Context, tx *db.Tx, sid, reason string) error {
	now := s.now()
	q := tx.Queries()
	identity, err := q.GetClientSessionIdentity(ctx, sid)
	if err != nil {
		return err
	}
	err = q.RevokeClientSession(ctx, dbsqlc.RevokeClientSessionParams{ID: sid, RevokedAt: sql.NullTime{Time: now, Valid: true}, RevocationReason: sql.NullString{String: reason, Valid: true}})
	if err != nil {
		return err
	}
	err = q.RevokeClientAccessTokens(ctx, dbsqlc.RevokeClientAccessTokensParams{ClientSessionID: sid, RevokedAt: sql.NullTime{Time: now, Valid: true}})
	if err != nil {
		return err
	}
	err = q.RevokeClientRefreshTokens(ctx, dbsqlc.RevokeClientRefreshTokensParams{ClientSessionID: sid, RevokedAt: sql.NullTime{Time: now, Valid: true}})
	if err != nil {
		return err
	}
	return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: identity.UserID, ActorType: audit.ActorUser, EventType: "auth.client.revoked", ResourceType: "client_session", ResourceID: sid, IdempotencyKey: "auth.client.revoked:" + sid, Metadata: map[string]any{"client_id": identity.ClientID, "reason": reason}})
}

func (s *DeviceService) RevokeClient(ctx context.Context, userID, sid, reason string) error {
	err := s.inTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		owner, err := tx.Queries().GetClientSessionOwnerForUpdate(ctx, sid)
		if err != nil {
			return err
		}
		if owner != userID {
			return sql.ErrNoRows
		}
		return s.revokeTx(ctx, tx, sid, reason)
	})
	if err != nil {
		return err
	}
	if s.downstream != nil {
		return s.downstream.RevokeClientSessions(ctx, sid, reason)
	}
	return nil
}

func (s *DeviceService) ListClients(ctx context.Context, userID, state, current string, limit, offset int) (ClientSessionPage, error) {
	if limit < 1 || limit > 200 || offset < 0 {
		return ClientSessionPage{}, &DeviceError{Code: "validation_failed"}
	}
	if state != "" && state != "active" && state != "revoked" {
		return ClientSessionPage{}, &DeviceError{Code: "validation_failed"}
	}
	var page ClientSessionPage
	page.Limit = limit
	page.Offset = offset
	q := s.db.Queries()
	total, err := q.CountClientSessions(ctx, dbsqlc.CountClientSessionsParams{UserID: userID, StateFilter: state})
	if err != nil {
		return page, err
	}
	page.Total = int(total)
	rows, err := q.ListClientSessions(ctx, dbsqlc.ListClientSessionsParams{UserID: userID, StateFilter: state, RowLimit: int32(limit), RowOffset: int32(offset)})
	if err != nil {
		return page, err
	}
	for _, row := range rows {
		item := ClientSession{ID: row.ID, ClientID: row.ClientID, ClientLabel: row.ClientLabel, DeviceType: row.DeviceType, OS: row.Os, Scopes: strings.Fields(row.Scopes), State: row.State, CreatedAt: row.CreatedAt, ApprovedAt: row.ApprovedAt, LastUsedAt: nullTimePointer(row.LastUsedAt), RevokedAt: nullTimePointer(row.RevokedAt), RevocationReason: nullStringPointer(row.RevocationReason)}
		item.Current = item.ID == current
		page.Items = append(page.Items, item)
	}
	if offset+len(page.Items) < page.Total {
		next := offset + len(page.Items)
		page.NextOffset = &next
	}
	return page, nil
}

func (s *DeviceService) takeRate(ctx context.Context, key string, limit int) error {
	window := s.now().Truncate(time.Minute)
	count, err := s.db.Queries().TakeAuthRateLimit(ctx, dbsqlc.TakeAuthRateLimitParams{BucketKey: key, RateWindow: window, Cutoff: window.Add(-time.Minute)})
	if err != nil {
		return err
	}
	if int(count) > limit {
		return &DeviceError{Code: "rate_limited", RetryAfter: max(1, int(time.Until(window.Add(time.Minute))/time.Second))}
	}
	return nil
}

func nullTimePointer(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	return &value.Time
}

func nullStringPointer(value sql.NullString) *string {
	if !value.Valid {
		return nil
	}
	return &value.String
}

func (s *DeviceService) inTx(ctx context.Context, fn func(context.Context, *db.Tx) error) error {
	for attempt := 0; attempt < 3; attempt++ {
		err := s.db.InTx(ctx, fn)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "40001" {
			return err
		}
	}
	return errors.New("authorization transaction retry limit exceeded")
}
func (s *DeviceService) hash(v string) string {
	if len(s.keys) == 0 {
		panic("device hash keys are not configured")
	}
	return hashWithKey(s.keys[0], v)
}
func hashWithKey(key []byte, v string) string {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write([]byte(v))
	return hex.EncodeToString(m.Sum(nil))
}
func (s *DeviceService) hashList(v string) string {
	hashes := make([]string, 0, len(s.keys))
	for _, key := range s.keys {
		hashes = append(hashes, hashWithKey(key, v))
	}
	return strings.Join(hashes, " ")
}
func (s *DeviceService) matchesHash(stored, v string) bool {
	matched := false
	for _, key := range s.keys {
		if hmac.Equal([]byte(stored), []byte(hashWithKey(key, v))) {
			matched = true
		}
	}
	return matched
}
func (s *DeviceService) hashUserCode(v string) string {
	return s.hash("user-code:" + normalizeUserCode(v))
}
func (s *DeviceService) userCodeHashList(v string) string {
	return s.hashList("user-code:" + normalizeUserCode(v))
}
func exactScopes(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := map[string]bool{}
	for _, v := range got {
		if seen[v] || !slices.Contains(want, v) {
			return false
		}
		seen[v] = true
	}
	return true
}
func normalizedScopes(scopes []string) string {
	out := append([]string(nil), scopes...)
	slices.Sort(out)
	return strings.Join(out, " ")
}
func normalizeUserCode(v string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(v), "-", ""))
}
func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func randomUserCode() string {
	const alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
	b := make([]byte, 8)
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		panic(err)
	}
	for i := range b {
		b[i] = alphabet[int(raw[i])%len(alphabet)]
	}
	return string(b[:4]) + "-" + string(b[4:])
}
