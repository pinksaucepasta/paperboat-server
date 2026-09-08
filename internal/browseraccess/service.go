package browseraccess

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pinksaucepasta/paperboat-server/internal/auth"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/teams"
)

const (
	transactionTTL     = 120 * time.Second
	handoffTTL         = 30 * time.Second
	sessionAbsoluteTTL = 12 * time.Hour
	sessionIdleTTL     = 30 * time.Minute
	decisionTTL        = 10 * time.Second
)

var (
	ErrInvalid         = errors.New("invalid browser access request")
	ErrExpired         = errors.New("browser access expired")
	ErrNotAuthorized   = errors.New("browser access not authorized")
	ErrAlreadyRedeemed = errors.New("browser access handoff already redeemed")
	ErrCapacity        = errors.New("browser access capacity reached")
)

type BeginRequest struct {
	Host       string `json:"host"`
	ReturnPath string `json:"return_path"`
}
type BeginResult struct {
	TransactionID string    `json:"transaction_id"`
	State         string    `json:"state"`
	ExpiresAt     time.Time `json:"expires_at"`
}
type IssueRequest struct {
	TransactionID string       `json:"transaction_id"`
	Principal     auth.Session `json:"-"`
}
type IssueResult struct {
	TransactionID  string    `json:"transaction_id"`
	Handoff        string    `json:"handoff"`
	CallbackOrigin string    `json:"callback_origin"`
	ExpiresAt      time.Time `json:"expires_at"`
}
type RedeemRequest struct {
	TransactionID string `json:"transaction_id"`
	State         string `json:"state"`
	Handoff       string `json:"handoff"`
	Host          string `json:"host"`
}
type RedeemResult struct {
	Token      string    `json:"token"`
	ReturnPath string    `json:"return_path"`
	ExpiresAt  time.Time `json:"expires_at"`
}
type AuthorizeRequest struct {
	Token        string `json:"token"`
	Host         string `json:"host"`
	ResourceKind string `json:"resource_kind"`
	ResourceID   string `json:"resource_id"`
	RouteID      string `json:"route_id"`
}
type Authorization struct {
	AccountID            string    `json:"account_id"`
	OwnerAccountID       string    `json:"owner_account_id"`
	ResourceKind         string    `json:"resource_kind"`
	ResourceID           string    `json:"resource_id"`
	ResourceGeneration   int64     `json:"resource_generation"`
	RouteID              string    `json:"route_id"`
	RouteGeneration      int64     `json:"route_generation"`
	Hostname             string    `json:"hostname"`
	AccessMode           string    `json:"access_mode"`
	GrantID              string    `json:"grant_id"`
	TeamID               string    `json:"team_id,omitempty"`
	TeamGeneration       int64     `json:"team_generation,omitempty"`
	MembershipGeneration int64     `json:"membership_generation,omitempty"`
	BindingGeneration    int64     `json:"binding_generation,omitempty"`
	GrantGeneration      int64     `json:"grant_generation,omitempty"`
	IssuedAt             time.Time `json:"issued_at"`
	ExpiresAt            time.Time `json:"expires_at"`
	SessionExpiresAt     time.Time `json:"session_expires_at"`
}
type MachineCredentialRequest struct {
	AccountID    string        `json:"-"`
	Host         string        `json:"host"`
	ResourceKind string        `json:"resource_kind"`
	ResourceID   string        `json:"resource_id"`
	RouteID      string        `json:"route_id"`
	Action       string        `json:"action"`
	TTL          time.Duration `json:"-"`
}
type MachineCredentialResult struct {
	CredentialID string    `json:"credential_id"`
	Token        string    `json:"token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type Service struct {
	db            *db.DB
	trustedOrigin string
	now           func() time.Time
}

func NewService(store *db.DB, trustedLoginOrigin string) (*Service, error) {
	return newService(store, trustedLoginOrigin, false)
}

// NewDevelopmentService permits one explicitly configured HTTP trusted origin
// for the private Tailscale development dashboard. Production wiring uses
// NewService, which remains HTTPS-only.
func NewDevelopmentService(store *db.DB, trustedLoginOrigin string) (*Service, error) {
	return newService(store, trustedLoginOrigin, true)
}
func newService(store *db.DB, trustedLoginOrigin string, developmentHTTP bool) (*Service, error) {
	u, err := url.Parse(trustedLoginOrigin)
	if err != nil || (u.Scheme != "https" && !(developmentHTTP && u.Scheme == "http")) || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("trusted login origin: %w", ErrInvalid)
	}
	return &Service{db: store, trustedOrigin: u.Scheme + "://" + u.Host, now: func() time.Time { return time.Now().UTC() }}, nil
}

func (s *Service) Begin(ctx context.Context, in BeginRequest) (BeginResult, error) {
	host, err := validHost(in.Host)
	if err != nil || !validReturn(in.ReturnPath) {
		return BeginResult{}, ErrInvalid
	}
	id, err := secret("bat_")
	if err != nil {
		return BeginResult{}, err
	}
	state, err := secret("bas_")
	if err != nil {
		return BeginResult{}, err
	}
	now := s.now()
	out := BeginResult{TransactionID: id, State: state, ExpiresAt: now.Add(transactionTTL)}
	h := digest(state)
	err = s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if _, e := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(260026)`); e != nil {
			return e
		}
		_, _ = tx.Exec(ctx, `DELETE FROM browser_access_transactions WHERE transaction_id IN (SELECT transaction_id FROM browser_access_transactions WHERE expires_at<=$1 ORDER BY expires_at LIMIT 256)`, now)
		var n int
		if e := tx.QueryRow(ctx, `SELECT count(*) FROM browser_access_transactions WHERE expires_at>$1`, now).Scan(&n); e != nil {
			return e
		}
		if n >= 4096 {
			return ErrCapacity
		}
		_, e := tx.Exec(ctx, `INSERT INTO browser_access_transactions(transaction_id,state_hash,hostname,return_path,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6)`, id, h[:], host, in.ReturnPath, now, out.ExpiresAt)
		return e
	})
	return out, err
}

type authority struct {
	kind, id, owner, mode, route string
	previewOwnerSession          string
	generation, routeGeneration  int64
	expires                      time.Time
	sessionCap                   time.Time
	team                         string
	td                           teams.Decision
}

func (s *Service) Issue(ctx context.Context, in IssueRequest) (IssueResult, error) {
	if in.TransactionID == "" || in.Principal.ID == "" || in.Principal.UserID == "" {
		return IssueResult{}, ErrInvalid
	}
	handoff, err := secret("bah_")
	if err != nil {
		return IssueResult{}, err
	}
	hh := digest(handoff)
	now := s.now()
	var out IssueResult
	err = s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		var host string
		var expires time.Time
		var raw []byte
		if err := tx.QueryRow(ctx, `SELECT hostname,state_hash,expires_at FROM browser_access_transactions WHERE transaction_id=$1 FOR UPDATE`, in.TransactionID).Scan(&host, &raw, &expires); err != nil {
			return mapMissing(err)
		}
		if !expires.After(now) {
			return ErrExpired
		}
		var sessionExpiry time.Time
		var sessionVersion int64
		if err := tx.QueryRow(ctx, `SELECT expires_at,version FROM sessions WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL AND expires_at>$3`, in.Principal.ID, in.Principal.UserID, now).Scan(&sessionExpiry, &sessionVersion); err != nil {
			return ErrNotAuthorized
		}
		a, err := resolveAuthority(ctx, tx, host, in.Principal.UserID, now)
		if err != nil {
			return err
		}
		end := minTime(now.Add(handoffTTL), sessionExpiry, a.expires)
		result, err := tx.Exec(ctx, `UPDATE browser_access_transactions SET account_id=$2,resource_kind=$3,resource_id=$4,resource_generation=$5,preview_owner_session_id=$6,owner_account_id=$7,access_mode=$8,team_id=$9,team_generation=$10,membership_generation=$11,binding_generation=$12,grant_generation=$13,trusted_session_id=$14,trusted_session_version=$15,trusted_session_expires_at=$16,handoff_hash=$17,handoff_expires_at=$18,issued_at=$19 WHERE transaction_id=$1 AND issued_at IS NULL`, in.TransactionID, in.Principal.UserID, a.kind, a.id, a.generation, nullString(a.previewOwnerSession), a.owner, a.mode, nullString(a.team), nullUint(a.td.TeamGeneration), nullUint(a.td.MembershipGeneration), nullUint(a.td.BindingGeneration), nullUint(a.td.GrantGeneration), in.Principal.ID, sessionVersion, sessionExpiry, hh[:], end, now)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return ErrNotAuthorized
		}
		out = IssueResult{TransactionID: in.TransactionID, Handoff: handoff, CallbackOrigin: "https://" + host, ExpiresAt: end}
		return nil
	})
	return out, err
}

func (s *Service) Redeem(ctx context.Context, in RedeemRequest) (RedeemResult, error) {
	host, err := validHost(in.Host)
	if err != nil {
		return RedeemResult{}, ErrInvalid
	}
	sh, hh := digest(in.State), digest(in.Handoff)
	token, err := secret("bae_")
	if err != nil {
		return RedeemResult{}, err
	}
	th := digest(token)
	grant, err := secret("bag_")
	if err != nil {
		return RedeemResult{}, err
	}
	now := s.now()
	var out RedeemResult
	err = s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		var stateRaw, handoffRaw []byte
		var storedHost, returnPath, account, kind, id, owner, mode, sessionID string
		var previewOwner *string
		var gen, sessionVersion int64
		var teamID *string
		var tg, mg, bg, gg *int64
		var txExp, handExp, authExp time.Time
		var redeemed *time.Time
		err := tx.QueryRow(ctx, `SELECT state_hash,handoff_hash,hostname,return_path,account_id,resource_kind,resource_id,resource_generation,preview_owner_session_id,owner_account_id,access_mode,team_id,team_generation,membership_generation,binding_generation,grant_generation,trusted_session_id,trusted_session_version,trusted_session_expires_at,expires_at,handoff_expires_at,redeemed_at FROM browser_access_transactions WHERE transaction_id=$1 FOR UPDATE`, in.TransactionID).Scan(&stateRaw, &handoffRaw, &storedHost, &returnPath, &account, &kind, &id, &gen, &previewOwner, &owner, &mode, &teamID, &tg, &mg, &bg, &gg, &sessionID, &sessionVersion, &authExp, &txExp, &handExp, &redeemed)
		if err != nil {
			return mapMissing(err)
		}
		if storedHost != host {
			return ErrNotAuthorized
		}
		if redeemed != nil {
			return ErrAlreadyRedeemed
		}
		if !txExp.After(now) || !handExp.After(now) {
			return ErrExpired
		}
		if !equalHash(stateRaw, sh) || !equalHash(handoffRaw, hh) {
			return ErrNotAuthorized
		}
		var currentSessionExpiry time.Time
		if err := tx.QueryRow(ctx, `SELECT expires_at FROM sessions WHERE id=$1 AND user_id=$2 AND version=$3 AND revoked_at IS NULL AND expires_at>$4`, sessionID, account, sessionVersion, now).Scan(&currentSessionExpiry); err != nil {
			return ErrNotAuthorized
		}
		authExp = minTime(authExp, currentSessionExpiry)
		a, err := resolveBound(ctx, tx, account, host, kind, id, "", now)
		if err != nil {
			return err
		}
		if (kind != "preview" && a.generation != gen) || (kind == "preview" && (previewOwner == nil || *previewOwner != a.previewOwnerSession)) || a.owner != owner || a.mode != mode {
			return ErrNotAuthorized
		}
		absolute := minTime(now.Add(sessionAbsoluteTTL), authExp, a.sessionCap)
		expiry := minTime(now.Add(sessionIdleTTL), absolute)
		var active int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM browser_access_sessions WHERE account_id=$1 AND revoked_at IS NULL AND expires_at>$2`, account, now).Scan(&active); err != nil {
			return err
		}
		if active >= 128 {
			return ErrCapacity
		}
		_, err = tx.Exec(ctx, `INSERT INTO browser_access_sessions(grant_id,token_hash,account_id,hostname,resource_kind,resource_id,resource_generation,preview_owner_session_id,owner_account_id,access_mode,team_id,team_generation,membership_generation,binding_generation,grant_generation,trusted_session_id,trusted_session_version,trusted_session_expires_at,issued_at,last_seen_at,absolute_expires_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$19,$20,$21)`, grant, th[:], account, host, kind, id, a.generation, nullString(a.previewOwnerSession), owner, mode, nullString(a.team), nullUint(a.td.TeamGeneration), nullUint(a.td.MembershipGeneration), nullUint(a.td.BindingGeneration), nullUint(a.td.GrantGeneration), sessionID, sessionVersion, authExp, now, absolute, expiry)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE browser_access_transactions SET redeemed_at=$2 WHERE transaction_id=$1`, in.TransactionID, now)
		if err == nil {
			out = RedeemResult{Token: token, ReturnPath: returnPath, ExpiresAt: expiry}
		}
		return err
	})
	return out, err
}

func (s *Service) Authorize(ctx context.Context, in AuthorizeRequest) (Authorization, error) {
	h := digest(in.Token)
	return s.authorize(ctx, in.Host, in.ResourceKind, in.ResourceID, in.RouteID, `token_hash=$1`, h[:])
}
func (s *Service) AuthorizeGrant(ctx context.Context, grantID, host, kind, id, route string) (Authorization, error) {
	if strings.HasPrefix(grantID, "bac_") {
		return s.authorizeMachine(ctx, grantID, host, kind, id, route, "use", "credential_id=$1")
	}
	return s.authorize(ctx, host, kind, id, route, `grant_id=$1`, grantID)
}

// IssueMachineCredential is called only after transport authentication has
// established AccountID. The returned secret is shown once and is never a
// browser cookie or login credential. It remains independently valid until its
// at-most-five-minute expiry even if the issuing browser logs out; every use
// still rechecks the account and current resource/team authority.
func (s *Service) IssueMachineCredential(ctx context.Context, in MachineCredentialRequest) (MachineCredentialResult, error) {
	if in.AccountID == "" || in.ResourceKind == "" || in.ResourceID == "" || in.RouteID == "" || in.Action != "use" || in.TTL <= 0 || in.TTL > 5*time.Minute {
		return MachineCredentialResult{}, ErrInvalid
	}
	host, err := validHost(in.Host)
	if err != nil {
		return MachineCredentialResult{}, ErrInvalid
	}
	// Machine-only clients may never call Begin, so they must also drive the
	// bounded expiry cleanup before admission.
	_, _ = s.Cleanup(ctx, 256)
	token, err := secret("bam_")
	if err != nil {
		return MachineCredentialResult{}, err
	}
	id, err := secret("bac_")
	if err != nil {
		return MachineCredentialResult{}, err
	}
	h := digest(token)
	now := s.now()
	out := MachineCredentialResult{CredentialID: id, Token: token, ExpiresAt: now.Add(in.TTL)}
	err = s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		a, e := resolveBound(ctx, tx, in.AccountID, host, in.ResourceKind, in.ResourceID, in.RouteID, now)
		if e != nil {
			return e
		}
		out.ExpiresAt = minTime(out.ExpiresAt, a.sessionCap)
		var active int
		if e = tx.QueryRow(ctx, `SELECT count(*) FROM browser_machine_credentials WHERE account_id=$1 AND revoked_at IS NULL AND expires_at>$2`, in.AccountID, now).Scan(&active); e != nil {
			return e
		}
		if active >= 128 {
			return ErrCapacity
		}
		_, e = tx.Exec(ctx, `INSERT INTO browser_machine_credentials(credential_id,token_hash,account_id,hostname,resource_kind,resource_id,route_id,action,resource_generation,preview_owner_session_id,owner_account_id,access_mode,team_id,team_generation,membership_generation,binding_generation,grant_generation,issued_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`, id, h[:], in.AccountID, host, a.kind, a.id, a.route, in.Action, a.generation, nullString(a.previewOwnerSession), a.owner, a.mode, nullString(a.team), nullUint(a.td.TeamGeneration), nullUint(a.td.MembershipGeneration), nullUint(a.td.BindingGeneration), nullUint(a.td.GrantGeneration), now, out.ExpiresAt)
		return e
	})
	return out, err
}

func (s *Service) AuthorizeMachineCredential(ctx context.Context, token, host, kind, id, route, action string) (Authorization, error) {
	h := digest(token)
	return s.authorizeMachine(ctx, h[:], host, kind, id, route, action, "token_hash=$1")
}
func (s *Service) authorizeMachine(ctx context.Context, key any, host, kind, id, route, action, predicate string) (Authorization, error) {
	if action != "use" {
		return Authorization{}, ErrInvalid
	}
	host, e := validHost(host)
	if e != nil {
		return Authorization{}, ErrInvalid
	}
	now := s.now()
	var out Authorization
	e = s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		var credential, account, shost, skind, sid, sroute, saction, owner, mode string
		var gen int64
		var previewOwner, team *string
		var tg, mg, bg, gg *int64
		var expiry time.Time
		if e := tx.QueryRow(ctx, `SELECT credential_id,account_id,hostname,resource_kind,resource_id,route_id,action,resource_generation,preview_owner_session_id,owner_account_id,access_mode,team_id,team_generation,membership_generation,binding_generation,grant_generation,expires_at FROM browser_machine_credentials WHERE `+predicate+` AND revoked_at IS NULL FOR UPDATE`, key).Scan(&credential, &account, &shost, &skind, &sid, &sroute, &saction, &gen, &previewOwner, &owner, &mode, &team, &tg, &mg, &bg, &gg, &expiry); e != nil {
			return mapMissing(e)
		}
		kind, id, route, err := storedSelectors(ctx, tx, skind, sid, gen, kind, id, route, now)
		if err != nil {
			return err
		}
		if shost != host || skind != kind || sid != id || sroute != route || saction != action || !expiry.After(now) {
			return ErrNotAuthorized
		}
		a, e := resolveBound(ctx, tx, account, host, kind, id, route, now)
		if e != nil {
			return e
		}
		if (kind != "preview" && a.generation != gen) || (kind == "preview" && (previewOwner == nil || *previewOwner != a.previewOwnerSession)) || a.owner != owner || a.mode != mode || !sameTeamAuthority(a, team, tg, mg, bg, gg) {
			return ErrNotAuthorized
		}
		out = Authorization{AccountID: account, OwnerAccountID: owner, ResourceKind: kind, ResourceID: id, ResourceGeneration: a.generation, RouteID: a.route, RouteGeneration: a.routeGeneration, Hostname: host, AccessMode: mode, GrantID: credential, TeamID: a.team, TeamGeneration: int64(a.td.TeamGeneration), MembershipGeneration: int64(a.td.MembershipGeneration), BindingGeneration: int64(a.td.BindingGeneration), GrantGeneration: int64(a.td.GrantGeneration), IssuedAt: now, ExpiresAt: minTime(now.Add(decisionTTL), expiry, a.expires), SessionExpiresAt: expiry}
		return nil
	})
	return out, e
}
func (s *Service) authorize(ctx context.Context, host, kind, id, route, predicate string, key any) (Authorization, error) {
	host, err := validHost(host)
	if err != nil {
		return Authorization{}, ErrInvalid
	}
	now := s.now()
	var out Authorization
	err = s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := `SELECT grant_id,account_id,hostname,resource_kind,resource_id,resource_generation,preview_owner_session_id,owner_account_id,access_mode,team_id,team_generation,membership_generation,binding_generation,grant_generation,trusted_session_id,trusted_session_version,issued_at,expires_at,absolute_expires_at,trusted_session_expires_at FROM browser_access_sessions WHERE ` + predicate + ` AND revoked_at IS NULL FOR UPDATE`
		var grant, account, storedHost, skind, sid, owner, mode, trustedSessionID string
		var storedTeam *string
		var storedTG, storedMG, storedBG, storedGG *int64
		var storedGen, sessionVersion int64
		var previewOwner *string
		var issued, expiry, absolute, authExpiry time.Time
		if err := tx.QueryRow(ctx, q, key).Scan(&grant, &account, &storedHost, &skind, &sid, &storedGen, &previewOwner, &owner, &mode, &storedTeam, &storedTG, &storedMG, &storedBG, &storedGG, &trustedSessionID, &sessionVersion, &issued, &expiry, &absolute, &authExpiry); err != nil {
			return mapMissing(err)
		}
		kind, id, route, selectorErr := storedSelectors(ctx, tx, skind, sid, storedGen, kind, id, route, now)
		if selectorErr != nil {
			return selectorErr
		}
		if host != storedHost || kind != skind || id != sid || !expiry.After(now) || !absolute.After(now) || !authExpiry.After(now) {
			return ErrNotAuthorized
		}
		var currentSessionExpiry time.Time
		if err := tx.QueryRow(ctx, `SELECT expires_at FROM sessions WHERE id=$1 AND user_id=$2 AND version=$3 AND revoked_at IS NULL AND expires_at>$4`, trustedSessionID, account, sessionVersion, now).Scan(&currentSessionExpiry); err != nil {
			return ErrNotAuthorized
		}
		authExpiry = minTime(authExpiry, currentSessionExpiry)
		a, err := resolveBound(ctx, tx, account, host, kind, id, route, now)
		if err != nil {
			return err
		}
		if (kind != "preview" && a.generation != storedGen) || (kind == "preview" && (previewOwner == nil || *previewOwner != a.previewOwnerSession)) || a.owner != owner || a.mode != mode {
			return ErrNotAuthorized
		}
		if !sameTeamAuthority(a, storedTeam, storedTG, storedMG, storedBG, storedGG) {
			return ErrNotAuthorized
		}
		newExpiry := minTime(now.Add(sessionIdleTTL), absolute, authExpiry, a.sessionCap)
		_, err = tx.Exec(ctx, `UPDATE browser_access_sessions SET last_seen_at=$2,expires_at=$3 WHERE grant_id=$1`, grant, now, newExpiry)
		if err != nil {
			return err
		}
		out = Authorization{AccountID: account, OwnerAccountID: owner, ResourceKind: kind, ResourceID: id, ResourceGeneration: a.generation, RouteID: a.route, RouteGeneration: a.routeGeneration, Hostname: host, AccessMode: mode, GrantID: grant, TeamID: a.team, TeamGeneration: int64(a.td.TeamGeneration), MembershipGeneration: int64(a.td.MembershipGeneration), BindingGeneration: int64(a.td.BindingGeneration), GrantGeneration: int64(a.td.GrantGeneration), IssuedAt: now, ExpiresAt: minTime(now.Add(decisionTTL), newExpiry, a.expires), SessionExpiresAt: newExpiry}
		return nil
	})
	return out, err
}

// Cleanup removes at most limit expired records. Callers may repeat it; a bound
// keeps maintenance from monopolizing the database.
func (s *Service) Cleanup(ctx context.Context, limit int) (int64, error) {
	if limit < 1 || limit > 1000 {
		return 0, ErrInvalid
	}
	now := s.now()
	result, err := s.db.Pool().Exec(ctx, `WITH doomed AS (SELECT grant_id FROM browser_access_sessions WHERE expires_at<=$1 OR revoked_at IS NOT NULL ORDER BY expires_at LIMIT $2) DELETE FROM browser_access_sessions s USING doomed d WHERE s.grant_id=d.grant_id`, now, limit)
	if err != nil {
		return 0, err
	}
	removed := result.RowsAffected()
	if removed < int64(limit) {
		result, err = s.db.Pool().Exec(ctx, `WITH doomed AS (SELECT credential_id FROM browser_machine_credentials WHERE expires_at<=$1 OR revoked_at IS NOT NULL ORDER BY expires_at LIMIT $2) DELETE FROM browser_machine_credentials c USING doomed d WHERE c.credential_id=d.credential_id`, now, limit-int(removed))
		if err != nil {
			return removed, err
		}
		removed += result.RowsAffected()
	}
	if removed < int64(limit) {
		result, err = s.db.Pool().Exec(ctx, `WITH doomed AS (SELECT transaction_id FROM browser_access_transactions WHERE expires_at<=$1 ORDER BY expires_at LIMIT $2) DELETE FROM browser_access_transactions t USING doomed d WHERE t.transaction_id=d.transaction_id`, now, limit-int(removed))
		if err != nil {
			return removed, err
		}
		removed += result.RowsAffected()
	}
	return removed, nil
}

func sameTeamAuthority(a authority, team *string, tg, mg, bg, gg *int64) bool {
	if a.mode == "private" {
		return team == nil && tg == nil && mg == nil && bg == nil && gg == nil
	}
	return team != nil && *team == a.team && tg != nil && uint64(*tg) == a.td.TeamGeneration && mg != nil && uint64(*mg) == a.td.MembershipGeneration && bg != nil && uint64(*bg) == a.td.BindingGeneration && gg != nil && uint64(*gg) == a.td.GrantGeneration
}

func resolveAuthority(ctx context.Context, tx *db.Tx, host, account string, now time.Time) (authority, error) {
	// A lazy hostname belongs to its policy even while a lease exists. Login and
	// viewer grants must survive idle lease cleanup without becoming lease grants.
	if a, e := resolveResource(ctx, tx, host, "lazy_policy", "", "", now); e == nil {
		return applyPrincipal(ctx, tx, a, account)
	} else if !errors.Is(e, ErrNotAuthorized) {
		return authority{}, e
	}
	var reserved bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM lazy_access_policies WHERE hostname=$1)`, host).Scan(&reserved); err != nil {
		return authority{}, err
	}
	if reserved {
		// A revoked, expired or replaced policy keeps owning its reserved name.
		// An old lease at that hostname cannot become an explicit preview grant.
		return authority{}, ErrNotAuthorized
	}
	if a, e := resolveResource(ctx, tx, host, "preview", "", "", now); e == nil {
		return applyPrincipal(ctx, tx, a, account)
	} else if !errors.Is(e, ErrNotAuthorized) {
		return authority{}, e
	}
	if a, e := resolveResource(ctx, tx, host, "tunnel", "", "", now); e == nil {
		return applyPrincipal(ctx, tx, a, account)
	} else if !errors.Is(e, ErrNotAuthorized) {
		return authority{}, e
	}
	return authority{}, ErrNotAuthorized
}
func resolveBound(ctx context.Context, tx *db.Tx, account, host, kind, id, route string, now time.Time) (authority, error) {
	a, e := resolveResource(ctx, tx, host, kind, id, route, now)
	if e != nil {
		return a, e
	}
	return applyPrincipal(ctx, tx, a, account)
}
func resolveResource(ctx context.Context, tx *db.Tx, host, kind, id, route string, now time.Time) (authority, error) {
	var a authority
	if kind == "lazy_policy" {
		err := tx.QueryRow(ctx, lazyPolicySQL, host, id, route, now).Scan(&a.id, &a.owner, &a.mode, &a.generation, &a.expires)
		if err != nil {
			return a, mapMissing(err)
		}
		a.kind, a.route, a.routeGeneration, a.sessionCap = kind, a.id, a.generation, a.expires
		return a, nil
	}
	if kind == "preview" {
		q := `SELECT p.id,p.account_id,p.access_mode,p.generation,x.route_id,x.route_generation,LEAST(p.lease_deadline,COALESCE(p.user_deadline,p.lease_deadline),x.expires_at),COALESCE(p.user_deadline,$4::timestamptz+interval '100 years'),concat_ws(chr(31),p.owner_device_id,p.owner_session_id,p.target_scheme,p.target_address) FROM preview_leases p JOIN preview_lease_carrier_attachments x ON x.preview_id=p.id AND x.account_id=p.account_id WHERE p.endpoint=$1 AND ($2='' OR p.id=$2) AND ($3='' OR x.route_id=$3) AND p.terminal_state='active' AND p.lease_deadline>$4 AND x.state='ready' AND x.expires_at>$4 AND NOT EXISTS (SELECT 1 FROM lazy_access_policies lp WHERE 'https://'||lp.hostname=p.endpoint)`
		err := tx.QueryRow(ctx, q, "https://"+host, id, route, now).Scan(&a.id, &a.owner, &a.mode, &a.generation, &a.route, &a.routeGeneration, &a.expires, &a.sessionCap, &a.previewOwnerSession)
		if err != nil {
			return a, mapMissing(err)
		}
		a.kind = "preview"
		// Lease ETag generations advance on heartbeats. The attachment route
		// generation is the stable target/authorization generation; the stored
		// owner/target tuple separately fences replacement.
		a.generation = a.routeGeneration
		return a, nil
	}
	if kind != "tunnel" {
		return a, ErrInvalid
	}
	q := `SELECT t.id,t.account_id,t.access_mode,t.generation,r.id,r.generation,COALESCE(t.expires_at,$4::timestamptz+interval '100 years') FROM tunnels t JOIN tunnel_routes r ON r.tunnel_id=t.id WHERE t.stable_endpoint=$1 AND ($2='' OR t.id=$2) AND ($3='' OR r.id=$3) AND t.desired_state='active' AND t.deleted_at IS NULL AND (t.expires_at IS NULL OR t.expires_at>$4) AND r.desired_state='active' ORDER BY r.priority,r.id LIMIT 1`
	err := tx.QueryRow(ctx, q, "https://"+host, id, route, now).Scan(&a.id, &a.owner, &a.mode, &a.generation, &a.route, &a.routeGeneration, &a.expires)
	if err != nil {
		return a, mapMissing(err)
	}
	a.kind = "tunnel"
	a.sessionCap = a.expires
	return a, nil
}
func applyPrincipal(ctx context.Context, tx *db.Tx, a authority, account string) (authority, error) {
	var active bool
	if err := tx.QueryRow(ctx, `SELECT (SELECT status='active' FROM users WHERE id=$1) IS TRUE AND (SELECT status='active' FROM users WHERE id=$2) IS TRUE`, account, a.owner).Scan(&active); err != nil {
		return a, err
	}
	if !active {
		return a, ErrNotAuthorized
	}
	if a.mode == "private" {
		if account != a.owner {
			return a, ErrNotAuthorized
		}
		return a, nil
	}
	if a.mode != "team" {
		return a, ErrNotAuthorized
	}
	rows, err := tx.Query(ctx, `SELECT team_id FROM team_resource_bindings WHERE resource_kind=$1 AND resource_id=$2 AND owner_account=$3 AND active ORDER BY team_id`, a.kind, a.id, a.owner)
	if err != nil {
		return a, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return a, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return a, err
	}
	for _, id := range ids {
		if err = teams.Lock(ctx, tx); err != nil {
			return a, err
		}
		d, e := teams.AuthorizeTx(ctx, tx, account, id, a.kind, a.id, "use")
		if e == nil {
			a.team = id
			a.td = d
			return a, nil
		}
		if !errors.Is(e, teams.ErrForbidden) && !errors.Is(e, teams.ErrNotFound) {
			return a, e
		}
	}
	return a, ErrNotAuthorized
}

func validHost(v string) (string, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	u, e := url.Parse("https://" + v)
	if e != nil || u.Host != v || u.Hostname() != v || strings.ContainsAny(v, "/\\:@") || len(v) > 253 || v == "" {
		return "", ErrInvalid
	}
	return v, nil
}
func validReturn(v string) bool {
	if len(v) < 1 || len(v) > 2048 || v[0] != '/' || strings.HasPrefix(v, "//") || strings.Contains(v, "\\") {
		return false
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	u, e := url.Parse(v)
	return e == nil && u.IsAbs() == false && u.Host == "" && u.User == nil
}
func secret(prefix string) (string, error) {
	var b [32]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", e
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b[:]), nil
}
func digest(v string) [32]byte { return sha256.Sum256([]byte(v)) }
func equalHash(a []byte, b [32]byte) bool {
	return len(a) == 32 && subtle.ConstantTimeCompare(a, b[:]) == 1
}
func minTime(v time.Time, rest ...time.Time) time.Time {
	for _, x := range rest {
		if x.Before(v) {
			v = x
		}
	}
	return v
}
func mapMissing(e error) error {
	if errors.Is(e, pgx.ErrNoRows) {
		return ErrNotAuthorized
	}
	return e
}
func nullString(v string) any {
	if v == "" {
		return nil
	}
	return v
}
func nullUint(v uint64) any {
	if v == 0 {
		return nil
	}
	return v
}
