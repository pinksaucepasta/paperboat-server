// Package inspectaccess owns server-side inspector authorization: short-lived
// opaque credentials binding a principal to one exact resource/action, and
// per-use re-resolution against current owner/team authority. It reuses the
// teams membership/binding/grant generations and mirrors the browseraccess
// machine-credential pattern (opaque token, hashed storage, bounded cleanup,
// 10-second decisions). Inspector actions are exact-match: login, team
// membership, preview viewing (use), management (manage) and machine
// connectivity imply neither inspect nor replay, and inspect does not imply
// replay.
package inspectaccess

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/teams"
)

const (
	credentialTTLMax           = 5 * time.Minute
	decisionTTL                = 10 * time.Second
	maxActiveCredentials       = 128
	maxCleanupRows             = 256
	maxGeneration        int64 = 9007199254740991
)

var (
	ErrInvalid       = errors.New("invalid inspector access request")
	ErrNotAuthorized = errors.New("inspector access not authorized")
	ErrCapacity      = errors.New("inspector credential capacity reached")
)

type IssueRequest struct {
	// AccountID is the principal the credential is issued to (from the user
	// session; issuance is always for self).
	AccountID    string
	ResourceKind string
	ResourceID   string
	RouteID      string
	Action       string
	TTL          time.Duration
}
type IssueResult struct {
	CredentialID string
	Token        string
	ExpiresAt    time.Time
}
type AuthorizeRequest struct {
	// MachineAccount is the daemon machine identity's account. It must equal
	// the resource owner: enforcement stays on owner infrastructure.
	MachineAccount string
	Token          string
	ResourceKind   string
	ResourceID     string
	RouteID        string
	Action         string
}
type Decision struct {
	AccountID            string
	OwnerAccountID       string
	ResourceKind         string
	ResourceID           string
	RouteID              string
	ResourceGeneration   uint64
	RouteGeneration      uint64
	TargetGeneration     uint64
	TeamID               string
	TeamGeneration       uint64
	MembershipGeneration uint64
	BindingGeneration    uint64
	GrantGeneration      uint64
	CredentialID         string
	IssuedAt             time.Time
	ExpiresAt            time.Time
}

type Service struct {
	db  *db.DB
	now func() time.Time
}

func NewService(store *db.DB) *Service {
	return &Service{db: store, now: func() time.Time { return time.Now().UTC() }}
}

func validKind(kind string) bool     { return kind == "preview" || kind == "tunnel" }
func validAction(action string) bool { return action == "inspect" || action == "replay" }
func validID(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

func secret(prefix string) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b[:]), nil
}

func digest(v string) [32]byte { return sha256.Sum256([]byte(v)) }

func minTime(v time.Time, rest ...time.Time) time.Time {
	for _, t := range rest {
		if t.Before(v) {
			v = t
		}
	}
	return v
}

func mapMissing(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotAuthorized
	}
	return err
}

// authority is the currently resolved resource state plus the principal's
// path to it (direct ownership or one team grant).
type authority struct {
	kind, id, route, owner string
	resourceGeneration     uint64
	routeGeneration        uint64
	targetGeneration       uint64
	expires                time.Time
	team                   string
	teamGeneration         uint64
	membershipGeneration   uint64
	bindingGeneration      uint64
	grantGeneration        uint64
}

// resolveResource returns the current stable authority triple for an exact
// resource. Previews resolve through the ready carrier attachment (its route
// generation is the stable authorization generation); tunnels resolve through
// the active route. Missing, terminal, expired or detached resources fail
// closed.
func resolveResource(ctx context.Context, tx *db.Tx, kind, id, route string, now time.Time) (authority, error) {
	var a authority
	if kind == "preview" {
		var owner string
		var routeGen int64
		var expiry time.Time
		err := tx.QueryRow(ctx, `SELECT p.account_id,x.route_id,x.route_generation,LEAST(p.lease_deadline,COALESCE(p.user_deadline,p.lease_deadline),x.expires_at) FROM preview_leases p JOIN preview_lease_carrier_attachments x ON x.preview_id=p.id AND x.account_id=p.account_id WHERE p.id=$1 AND p.terminal_state='active' AND p.lease_deadline>$2 AND x.state='ready' AND x.expires_at>$2`, id, now).Scan(&owner, &a.route, &routeGen, &expiry)
		if err != nil {
			return a, mapMissing(err)
		}
		if routeGen < 1 || routeGen > maxGeneration {
			return a, ErrNotAuthorized
		}
		a.kind, a.id, a.owner = kind, id, owner
		a.resourceGeneration = uint64(routeGen)
		a.routeGeneration = uint64(routeGen)
		a.targetGeneration = uint64(routeGen)
		a.expires = expiry
		return a, nil
	}
	if kind != "tunnel" {
		return a, ErrInvalid
	}
	var owner, routeID string
	var tunnelGen, routeGen int64
	var expiry time.Time
	err := tx.QueryRow(ctx, `SELECT t.account_id,r.id,t.generation,r.generation,COALESCE(t.expires_at,$4::timestamptz+interval '100 years') FROM tunnels t JOIN tunnel_routes r ON r.tunnel_id=t.id WHERE t.id=$1 AND r.id=$2 AND t.desired_state='active' AND t.deleted_at IS NULL AND (t.expires_at IS NULL OR t.expires_at>$3) AND r.desired_state='active' AND r.deleted_at IS NULL`, id, route, now, now).Scan(&owner, &routeID, &tunnelGen, &routeGen, &expiry)
	if err != nil {
		return a, mapMissing(err)
	}
	if tunnelGen < 1 || tunnelGen > maxGeneration || routeGen < 1 || routeGen > maxGeneration {
		return a, ErrNotAuthorized
	}
	a.kind, a.id, a.route, a.owner = kind, id, routeID, owner
	a.resourceGeneration = uint64(tunnelGen)
	a.routeGeneration = uint64(routeGen)
	a.targetGeneration = uint64(routeGen)
	a.expires = expiry
	return a, nil
}

// resolveTeamPrincipal binds a non-owner principal through the first team
// carrying a current grant for the exact wanted action.
func resolveTeamPrincipal(ctx context.Context, tx *db.Tx, a authority, account, action string) (authority, error) {
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
		d, e := teams.AuthorizeTx(ctx, tx, account, id, a.kind, a.id, action)
		if e == nil {
			a.team = id
			a.teamGeneration = d.TeamGeneration
			a.membershipGeneration = d.MembershipGeneration
			a.bindingGeneration = d.BindingGeneration
			a.grantGeneration = d.GrantGeneration
			return a, nil
		}
		if !errors.Is(e, teams.ErrForbidden) && !errors.Is(e, teams.ErrNotFound) {
			return a, e
		}
	}
	return a, ErrNotAuthorized
}

// resolvePrincipal binds a principal to the resource for one exact action:
// direct ownership, or the first team carrying a current grant for that
// action. Every other path (login, membership alone, viewing, management,
// machine connectivity) fails closed here.
func resolvePrincipal(ctx context.Context, tx *db.Tx, a authority, account, action string) (authority, error) {
	var bothActive bool
	if err := tx.QueryRow(ctx, `SELECT (SELECT status='active' FROM users WHERE id=$1) IS TRUE AND (SELECT status='active' FROM users WHERE id=$2) IS TRUE`, account, a.owner).Scan(&bothActive); err != nil {
		return a, err
	}
	if !bothActive {
		return a, ErrNotAuthorized
	}
	if account == a.owner {
		return a, nil
	}
	return resolveTeamPrincipal(ctx, tx, a, account, action)
}

// Issue mints a short-lived opaque credential for the caller's own current
// authority. Denial mints nothing: row counts are unchanged (no side effects).
func (s *Service) Issue(ctx context.Context, in IssueRequest) (IssueResult, error) {
	if !validID(in.AccountID) || !validKind(in.ResourceKind) || !validID(in.ResourceID) || !validID(in.RouteID) || !validAction(in.Action) || in.TTL <= 0 || in.TTL > credentialTTLMax {
		return IssueResult{}, ErrInvalid
	}
	token, err := secret("iat_")
	if err != nil {
		return IssueResult{}, err
	}
	id, err := secret("iac_")
	if err != nil {
		return IssueResult{}, err
	}
	h := digest(token)
	now := s.now()
	out := IssueResult{CredentialID: id, Token: token, ExpiresAt: now.Add(in.TTL)}
	err = s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if _, e := tx.Exec(ctx, `DELETE FROM inspector_credentials WHERE credential_id IN (SELECT credential_id FROM inspector_credentials WHERE expires_at<=$1 OR revoked_at IS NOT NULL ORDER BY expires_at LIMIT $2)`, now, maxCleanupRows); e != nil {
			return e
		}
		a, e := resolveResource(ctx, tx, in.ResourceKind, in.ResourceID, in.RouteID, now)
		if e != nil {
			return e
		}
		if in.ResourceKind == "preview" && in.RouteID != in.ResourceID {
			return ErrNotAuthorized
		}
		// Daemons address previews by lease ID (the carrier route is an
		// opaque server hash); the ready attachment only sources the stable
		// generation triple.
		if in.ResourceKind == "preview" {
			a.route = a.id
		}
		a, e = resolvePrincipal(ctx, tx, a, in.AccountID, in.Action)
		if e != nil {
			return e
		}
		out.ExpiresAt = minTime(out.ExpiresAt, a.expires)
		if !out.ExpiresAt.After(now) {
			return ErrNotAuthorized
		}
		var active int
		if e = tx.QueryRow(ctx, `SELECT count(*) FROM inspector_credentials WHERE account_id=$1 AND revoked_at IS NULL AND expires_at>$2`, in.AccountID, now).Scan(&active); e != nil {
			return e
		}
		if active >= maxActiveCredentials {
			return ErrCapacity
		}
		_, e = tx.Exec(ctx, `INSERT INTO inspector_credentials(credential_id,token_hash,account_id,resource_kind,resource_id,route_id,action,resource_generation,route_generation,target_generation,owner_account_id,team_id,team_generation,membership_generation,binding_generation,grant_generation,issued_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`, id, h[:], in.AccountID, a.kind, a.id, a.route, in.Action, a.resourceGeneration, a.routeGeneration, a.targetGeneration, a.owner, nullString(a.team), nullUint(a.teamGeneration), nullUint(a.membershipGeneration), nullUint(a.bindingGeneration), nullUint(a.grantGeneration), now, out.ExpiresAt)
		return e
	})
	if err != nil {
		return IssueResult{}, err
	}
	return out, nil
}

// Authorize re-resolves current authority for a presented credential and
// returns a 10-second decision. The daemon machine account must equal the
// resource owner, keeping enforcement on owner infrastructure. Every drift
// (revocation, expiry, generation, owner, team, route mismatch) fails closed.
func (s *Service) Authorize(ctx context.Context, in AuthorizeRequest) (Decision, error) {
	if !validID(in.MachineAccount) || !validID(in.ResourceID) || !validID(in.RouteID) || !validKind(in.ResourceKind) || !validAction(in.Action) || strings.TrimSpace(in.Token) == "" {
		return Decision{}, ErrInvalid
	}
	h := digest(in.Token)
	now := s.now()
	var out Decision
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		var credential, account, skind, sid, sroute, saction, owner string
		var team *string
		var resourceGen, routeGen, targetGen int64
		var tg, mg, bg, gg *int64
		var expiry time.Time
		if e := tx.QueryRow(ctx, `SELECT credential_id,account_id,resource_kind,resource_id,route_id,action,resource_generation,route_generation,target_generation,owner_account_id,team_id,team_generation,membership_generation,binding_generation,grant_generation,expires_at FROM inspector_credentials WHERE token_hash=$1 AND revoked_at IS NULL FOR UPDATE`, h[:]).Scan(&credential, &account, &skind, &sid, &sroute, &saction, &resourceGen, &routeGen, &targetGen, &owner, &team, &tg, &mg, &bg, &gg, &expiry); e != nil {
			return mapMissing(e)
		}
		if skind != in.ResourceKind || sid != in.ResourceID || sroute != in.RouteID || saction != in.Action || !expiry.After(now) {
			return ErrNotAuthorized
		}
		a, e := resolveResource(ctx, tx, in.ResourceKind, in.ResourceID, in.RouteID, now)
		if e != nil {
			return e
		}
		if in.ResourceKind == "preview" {
			// Previews are daemon-addressed by lease ID; the ready
			// attachment only sources the stable generation triple.
			a.route = a.id
		}
		if a.owner != owner || in.MachineAccount != owner {
			return ErrNotAuthorized
		}
		if a.resourceGeneration != uint64(resourceGen) || a.routeGeneration != uint64(routeGen) || a.targetGeneration != uint64(targetGen) {
			return ErrNotAuthorized
		}
		if team != nil {
			if err := teams.Lock(ctx, tx); err != nil {
				return err
			}
			d, e := teams.AuthorizeTx(ctx, tx, account, *team, a.kind, a.id, saction)
			if e != nil {
				return ErrNotAuthorized
			}
			if d.TeamGeneration != uint64(orZero(tg)) || d.MembershipGeneration != uint64(orZero(mg)) || d.BindingGeneration != uint64(orZero(bg)) || d.GrantGeneration != uint64(orZero(gg)) {
				return ErrNotAuthorized
			}
			a.team = *team
			a.teamGeneration = uint64(orZero(tg))
			a.membershipGeneration = uint64(orZero(mg))
			a.bindingGeneration = uint64(orZero(bg))
			a.grantGeneration = uint64(orZero(gg))
		} else if _, e := resolvePrincipal(ctx, tx, a, account, saction); e != nil {
			// The owner path pins to ownership at use time: a former owner
			// who delegated nothing loses access the moment ownership moves.
			return ErrNotAuthorized
		}
		out = Decision{AccountID: account, OwnerAccountID: owner, ResourceKind: a.kind, ResourceID: a.id, RouteID: a.route, ResourceGeneration: a.resourceGeneration, RouteGeneration: a.routeGeneration, TargetGeneration: a.targetGeneration, TeamID: a.team, TeamGeneration: a.teamGeneration, MembershipGeneration: a.membershipGeneration, BindingGeneration: a.bindingGeneration, GrantGeneration: a.grantGeneration, CredentialID: credential, IssuedAt: now, ExpiresAt: minTime(now.Add(decisionTTL), expiry, a.expires)}
		return nil
	})
	return out, err
}

// RevokeCredential revokes one credential. The credential holder or the
// current resource owner may revoke; anyone else is denied without effect.
func (s *Service) RevokeCredential(ctx context.Context, principal, credentialID string) error {
	if !validID(principal) || strings.TrimSpace(credentialID) == "" {
		return ErrInvalid
	}
	return s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		var account, owner string
		if e := tx.QueryRow(ctx, `SELECT account_id,owner_account_id FROM inspector_credentials WHERE credential_id=$1 AND revoked_at IS NULL`, credentialID).Scan(&account, &owner); e != nil {
			return mapMissing(e)
		}
		if principal != account && principal != owner {
			return ErrNotAuthorized
		}
		_, e := tx.Exec(ctx, `UPDATE inspector_credentials SET revoked_at=$2 WHERE credential_id=$1 AND revoked_at IS NULL`, credentialID, s.now())
		return e
	})
}

// Cleanup removes at most limit expired or revoked rows.
func (s *Service) Cleanup(ctx context.Context, limit int) (int64, error) {
	if limit < 1 || limit > 1000 {
		return 0, ErrInvalid
	}
	result, err := s.db.Pool().Exec(ctx, `WITH doomed AS (SELECT credential_id FROM inspector_credentials WHERE expires_at<=$1 OR revoked_at IS NOT NULL ORDER BY expires_at LIMIT $2) DELETE FROM inspector_credentials s USING doomed d WHERE s.credential_id=d.credential_id`, s.now(), limit)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
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
	return int64(v)
}

func orZero(v *int64) int64 {
	if v == nil {
		return 0
	}
	return *v
}
