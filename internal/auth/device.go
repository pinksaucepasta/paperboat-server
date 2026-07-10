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
	_, err = s.db.SQL().ExecContext(ctx, `
INSERT INTO paperboat.device_grants
(id, client_id, client_label, device_type, os, scopes, device_code_hash, user_code_hash, state, issued_at, expires_at, poll_interval_seconds, next_poll_at, created_network_hash)
VALUES ($1,$2,$3,$4,$5,string_to_array($6,' '),$7,$8,'pending',$9,$10,$11,$9,$12)`,
		newID("dgr"), in.ClientID, in.ClientLabel, in.DeviceType, strings.TrimSpace(in.OS), normalizedScopes(in.Scopes), s.hash(deviceCode), s.hashUserCode(userCode), now, expires, interval, s.hash(in.Network))
	if err != nil {
		return DeviceAuthorization{}, fmt.Errorf("create device grant: %w", err)
	}
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
	err := s.inTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		var id, clientID, state, userID, label, deviceType, osName, scopeString, storedHash string
		var expiresAt, nextPoll time.Time
		var interval int
		err := tx.QueryRow(ctx, `SELECT id,client_id,state,coalesce(user_id,''),client_label,device_type,os,array_to_string(scopes,' '),expires_at,next_poll_at,poll_interval_seconds,device_code_hash FROM device_grants WHERE device_code_hash = ANY(string_to_array($1,' ')) FOR UPDATE`, s.hashList(in.DeviceCode)).Scan(&id, &clientID, &state, &userID, &label, &deviceType, &osName, &scopeString, &expiresAt, &nextPoll, &interval, &storedHash)
		if errors.Is(err, sql.ErrNoRows) {
			return &DeviceError{Code: "invalid_grant"}
		}
		if err != nil {
			return err
		}
		if clientID != in.ClientID {
			return &DeviceError{Code: "invalid_grant"}
		}
		if !s.matchesHash(storedHash, in.DeviceCode) {
			return &DeviceError{Code: "invalid_grant"}
		}
		now := s.now()
		if !now.Before(expiresAt) {
			_, _ = tx.Exec(ctx, `UPDATE device_grants SET state='expired',version=version+1 WHERE id=$1 AND state IN ('pending','approved')`, id)
			outcomeErr = &DeviceError{Code: "expired_token"}
			return nil
		}
		switch state {
		case "denied":
			outcomeErr = &DeviceError{Code: "access_denied"}
			return nil
		case "consumed", "expired":
			return &DeviceError{Code: "invalid_grant"}
		}
		if state == "approved" {
			var userStatus string
			if err := tx.QueryRow(ctx, `SELECT status FROM users WHERE id=$1`, userID).Scan(&userStatus); err != nil {
				return err
			}
			if userStatus != "active" {
				if _, err := tx.Exec(ctx, `UPDATE device_grants SET state='denied',denied_at=$2,version=version+1 WHERE id=$1 AND state='approved'`, id, now); err != nil {
					return err
				}
				outcomeErr = &DeviceError{Code: "access_denied"}
				return nil
			}
		}
		if now.Before(nextPoll) {
			interval += 5
			_, err = tx.Exec(ctx, `UPDATE device_grants SET poll_interval_seconds=$2,next_poll_at=$3,version=version+1 WHERE id=$1`, id, interval, now.Add(time.Duration(interval)*time.Second))
			if err != nil {
				return err
			}
			outcomeErr = &DeviceError{Code: "slow_down", Interval: interval}
			return nil
		}
		_, err = tx.Exec(ctx, `UPDATE device_grants SET next_poll_at=$2,version=version+1 WHERE id=$1`, id, now.Add(time.Duration(interval)*time.Second))
		if err != nil {
			return err
		}
		switch state {
		case "pending":
			outcomeErr = &DeviceError{Code: "authorization_pending"}
			return nil
		case "approved":
		default:
			return &DeviceError{Code: "invalid_grant"}
		}
		if err := s.takeRate(ctx, "account:"+userID, s.cfg.AccountActionsPerMinute); err != nil {
			return err
		}
		access, refresh := randomToken(32), randomToken(32)
		sessionID := newID("cls")
		approvedAt := now
		if err := tx.QueryRow(ctx, `SELECT approved_at FROM device_grants WHERE id=$1`, id).Scan(&approvedAt); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO client_sessions (id,user_id,client_id,client_label,device_type,os,scopes,state,created_at,approved_at) VALUES ($1,$2,$3,$4,$5,$6,string_to_array($7,' '),'active',$8,$9)`, sessionID, userID, clientID, label, deviceType, osName, scopeString, now, approvedAt); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO client_access_tokens (token_hash,client_session_id,expires_at,created_at) VALUES ($1,$2,$3,$4)`, s.hash(access), sessionID, now.Add(s.cfg.AccessTokenLifetime), now); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO client_refresh_tokens (token_hash,client_session_id,state,expires_at,created_at) VALUES ($1,$2,'active',$3,$4)`, s.hash(refresh), sessionID, now.Add(s.cfg.RefreshTokenLifetime), now); err != nil {
			return err
		}
		result, err := tx.Exec(ctx, `UPDATE device_grants SET state='consumed',consumed_at=$2,version=version+1 WHERE id=$1 AND state='approved'`, id, now)
		if err != nil {
			return err
		}
		rows, _ := result.RowsAffected()
		if rows != 1 {
			return &DeviceError{Code: "invalid_grant"}
		}
		if err := s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "auth.client.approved", ResourceType: "client_session", ResourceID: sessionID, IdempotencyKey: "auth.client.approved:" + sessionID, Metadata: map[string]any{"client_id": clientID}}); err != nil {
			return err
		}
		out = TokenSet{AccessToken: access, RefreshToken: refresh, TokenType: "Bearer", ExpiresIn: int(s.cfg.AccessTokenLifetime / time.Second), Scope: scopeString, ClientSessionID: sessionID}
		return nil
	})
	if err != nil {
		return TokenSet{}, err
	}
	return out, outcomeErr
}

func (s *DeviceService) Request(ctx context.Context, userCode string) (DeviceRequest, error) {
	var out DeviceRequest
	var scopeString, storedHash string
	err := s.db.SQL().QueryRowContext(ctx, `SELECT client_label,device_type,os,array_to_string(scopes,' '),issued_at,expires_at,state,user_code_hash FROM paperboat.device_grants WHERE user_code_hash = ANY(string_to_array($1,' '))`, s.userCodeHashList(userCode)).Scan(&out.ClientLabel, &out.DeviceType, &out.OS, &scopeString, &out.IssuedAt, &out.ExpiresAt, &out.State, &storedHash)
	if errors.Is(err, sql.ErrNoRows) {
		return out, &DeviceError{Code: "device_request_not_found"}
	}
	if err != nil {
		return out, err
	}
	if !s.matchesHash(storedHash, "user-code:"+normalizeUserCode(userCode)) {
		return out, &DeviceError{Code: "invalid_grant"}
	}
	out.Scopes = strings.Fields(scopeString)
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
		var id, state, boundUser, storedHash, clientID string
		var expires time.Time
		err := tx.QueryRow(ctx, `SELECT id,state,coalesce(user_id,''),expires_at,user_code_hash,client_id FROM device_grants WHERE user_code_hash = ANY(string_to_array($1,' ')) FOR UPDATE`, s.userCodeHashList(userCode)).Scan(&id, &state, &boundUser, &expires, &storedHash, &clientID)
		if errors.Is(err, sql.ErrNoRows) {
			return &DeviceError{Code: "device_request_not_found"}
		}
		if err != nil {
			return err
		}
		if !s.matchesHash(storedHash, "user-code:"+normalizeUserCode(userCode)) {
			return &DeviceError{Code: "invalid_grant"}
		}
		if !s.now().Before(expires) {
			_, _ = tx.Exec(ctx, `UPDATE device_grants SET state='expired' WHERE id=$1 AND state IN ('pending','approved')`, id)
			outcomeErr = &DeviceError{Code: "device_request_expired"}
			return nil
		}
		wanted := "denied"
		column := "denied_at"
		if approve {
			wanted = "approved"
			column = "approved_at"
		}
		if state == wanted && boundUser == userID {
			return nil
		}
		if state == "consumed" {
			return &DeviceError{Code: "device_request_consumed"}
		}
		if state != "pending" {
			return &DeviceError{Code: "device_request_not_pending"}
		}
		_, err = tx.Exec(ctx, fmt.Sprintf(`UPDATE device_grants SET state=$2,user_id=$3,%s=$4,version=version+1 WHERE id=$1 AND state='pending'`, column), id, wanted, userID, s.now())
		if err != nil {
			return err
		}
		return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "auth.device." + wanted, ResourceType: "device_grant", ResourceID: id, IdempotencyKey: "auth.device." + wanted + ":" + id, Metadata: map[string]any{"client_id": clientID}})
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
	var p ClientPrincipal
	var scopeString string
	err := s.db.SQL().QueryRowContext(ctx, `SELECT cs.id,array_to_string(cs.scopes,' '),u.id,u.workos_subject,u.primary_email,u.display_name,u.status,u.role,u.created_at FROM paperboat.client_access_tokens t JOIN paperboat.client_sessions cs ON cs.id=t.client_session_id JOIN paperboat.users u ON u.id=cs.user_id WHERE t.token_hash = ANY(string_to_array($1,' ')) AND t.revoked_at IS NULL AND t.expires_at>$2 AND cs.state='active' AND u.status='active'`, s.hashList(token), s.now()).Scan(&p.SessionID, &scopeString, &p.User.ID, &p.User.WorkOSSubject, &p.User.PrimaryEmail, &p.User.DisplayName, &p.User.Status, &p.User.Role, &p.User.CreatedAt)
	if err != nil {
		return ClientPrincipal{}, ErrUnauthenticated
	}
	p.Scopes = strings.Fields(scopeString)
	_, _ = s.db.SQL().ExecContext(ctx, `UPDATE paperboat.client_sessions SET last_used_at=$2 WHERE id=$1`, p.SessionID, s.now())
	return p, nil
}

func (s *DeviceService) Refresh(ctx context.Context, token string) (TokenSet, error) {
	var out TokenSet
	var replay bool
	var replaySID string
	err := s.inTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		var sid, state, scopeString, storedHash string
		var expires time.Time
		err := tx.QueryRow(ctx, `SELECT rt.client_session_id,rt.state,rt.expires_at,array_to_string(cs.scopes,' '),rt.token_hash FROM client_refresh_tokens rt JOIN client_sessions cs ON cs.id=rt.client_session_id WHERE rt.token_hash = ANY(string_to_array($1,' ')) FOR UPDATE OF rt,cs`, s.hashList(token)).Scan(&sid, &state, &expires, &scopeString, &storedHash)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnauthenticated
		}
		if err != nil {
			return err
		}
		if !s.matchesHash(storedHash, token) {
			return ErrUnauthenticated
		}
		if state != "active" {
			replay = true
			replaySID = sid
			return s.revokeTx(ctx, tx, sid, "refresh_replay")
		}
		if !s.now().Before(expires) {
			return ErrUnauthenticated
		}
		now := s.now()
		access, refresh := randomToken(32), randomToken(32)
		if _, err = tx.Exec(ctx, `UPDATE client_refresh_tokens SET state='rotated',rotated_at=$2 WHERE token_hash=$1`, storedHash, now); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO client_refresh_tokens(token_hash,client_session_id,state,expires_at,created_at) VALUES($1,$2,'active',$3,$4)`, s.hash(refresh), sid, now.Add(s.cfg.RefreshTokenLifetime), now); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO client_access_tokens(token_hash,client_session_id,expires_at,created_at) VALUES($1,$2,$3,$4)`, s.hash(access), sid, now.Add(s.cfg.AccessTokenLifetime), now); err != nil {
			return err
		}
		out = TokenSet{AccessToken: access, RefreshToken: refresh, TokenType: "Bearer", ExpiresIn: int(s.cfg.AccessTokenLifetime / time.Second), Scope: scopeString, ClientSessionID: sid}
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
		err := tx.QueryRow(ctx, `SELECT client_session_id FROM client_access_tokens WHERE token_hash = ANY(string_to_array($1,' ')) UNION SELECT client_session_id FROM client_refresh_tokens WHERE token_hash = ANY(string_to_array($1,' ')) LIMIT 1`, s.hashList(token)).Scan(&sid)
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
	var userID, clientID string
	if err := tx.QueryRow(ctx, `SELECT user_id,client_id FROM client_sessions WHERE id=$1`, sid).Scan(&userID, &clientID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE client_sessions SET state='revoked',revoked_at=coalesce(revoked_at,$2),revocation_reason=coalesce(revocation_reason,$3),version=version+1 WHERE id=$1`, sid, now, reason)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE client_access_tokens SET revoked_at=coalesce(revoked_at,$2) WHERE client_session_id=$1`, sid, now)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE client_refresh_tokens SET state='revoked',revoked_at=coalesce(revoked_at,$2) WHERE client_session_id=$1 AND state<>'revoked'`, sid, now)
	if err != nil {
		return err
	}
	return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "auth.client.revoked", ResourceType: "client_session", ResourceID: sid, IdempotencyKey: "auth.client.revoked:" + sid, Metadata: map[string]any{"client_id": clientID, "reason": reason}})
}

func (s *DeviceService) RevokeClient(ctx context.Context, userID, sid, reason string) error {
	err := s.inTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		var owner string
		if err := tx.QueryRow(ctx, `SELECT user_id FROM client_sessions WHERE id=$1 FOR UPDATE`, sid).Scan(&owner); err != nil {
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
	if err := s.db.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.client_sessions WHERE user_id=$1 AND ($2='' OR state=$2)`, userID, state).Scan(&page.Total); err != nil {
		return page, err
	}
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT id,client_id,client_label,device_type,os,array_to_string(scopes,' '),state,created_at,approved_at,last_used_at,revoked_at,revocation_reason FROM paperboat.client_sessions WHERE user_id=$1 AND ($2='' OR state=$2) ORDER BY created_at DESC LIMIT $3 OFFSET $4`, userID, state, limit, offset)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var item ClientSession
		var scopes string
		if err := rows.Scan(&item.ID, &item.ClientID, &item.ClientLabel, &item.DeviceType, &item.OS, &scopes, &item.State, &item.CreatedAt, &item.ApprovedAt, &item.LastUsedAt, &item.RevokedAt, &item.RevocationReason); err != nil {
			return page, err
		}
		item.Scopes = strings.Fields(scopes)
		item.Current = item.ID == current
		page.Items = append(page.Items, item)
	}
	if offset+len(page.Items) < page.Total {
		next := offset + len(page.Items)
		page.NextOffset = &next
	}
	return page, rows.Err()
}

func (s *DeviceService) takeRate(ctx context.Context, key string, limit int) error {
	window := s.now().Truncate(time.Minute)
	var count int
	err := s.db.SQL().QueryRowContext(ctx, `WITH cleanup AS (DELETE FROM paperboat.auth_rate_limits WHERE window_start < $3) INSERT INTO paperboat.auth_rate_limits(bucket_key,window_start,request_count) VALUES($1,$2,1) ON CONFLICT(bucket_key,window_start) DO UPDATE SET request_count=auth_rate_limits.request_count+1 RETURNING request_count`, key, window, window.Add(-time.Minute)).Scan(&count)
	if err != nil {
		return err
	}
	if count > limit {
		return &DeviceError{Code: "rate_limited", RetryAfter: max(1, int(time.Until(window.Add(time.Minute))/time.Second))}
	}
	return nil
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
