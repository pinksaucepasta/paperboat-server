package lazyaccess

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pinksaucepasta/paperboat-server/internal/browseraccess"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelapi"
	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelstore"
	"github.com/pinksaucepasta/paperboat-server/internal/previewv1"
)

const ActivationTimeout = 10 * time.Second

type ActivationError struct{ Code string }

func (e *ActivationError) Error() string { return e.Code }
func activationError(code string) error  { return &ActivationError{Code: code} }

type RuntimeObservation struct {
	Schema                 string    `json:"schema"`
	BootID                 string    `json:"boot_id"`
	InstallationGeneration int64     `json:"installation_generation"`
	StartedAt              time.Time `json:"started_at"`
}

func validRuntimeBoot(boot string) bool {
	if len(boot) < 16 || len(boot) > 64 {
		return false
	}
	for _, ch := range boot {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '-') {
			return false
		}
	}
	return true
}

type Activator struct {
	DB     *db.DB
	Leases *previewv1.Service
}

// RecordLazyRuntimeObservation is called only for a signed machine observation.
// A reservation alone cannot register ownership or restore a forwarding lease.
func (s *Activator) RecordLazyRuntimeObservation(ctx context.Context, environment, machine string, r RuntimeObservation) error {
	now := time.Now().UTC()
	if r.Schema != "paperboat.lazy-runtime/v1" || !validRuntimeBoot(r.BootID) || r.InstallationGeneration < 1 || r.StartedAt.IsZero() || r.StartedAt.After(now.Add(5*time.Second)) {
		return ErrInvalid
	}
	result, err := s.DB.Pool().Exec(ctx, `INSERT INTO lazy_runtime_owners(machine_id,account_id,installation_generation,boot_id,started_at,expires_at)
 SELECT id,user_id,installation_generation,$4,$5,$6 FROM user_machines WHERE id=$1 AND environment_id=$2 AND installation_generation=$3 AND revoked_at IS NULL AND deleted_at IS NULL AND seat_state='occupied' AND state NOT IN ('pending','revoked','deleted')
 ON CONFLICT(machine_id) DO UPDATE SET account_id=EXCLUDED.account_id,installation_generation=EXCLUDED.installation_generation,boot_id=EXCLUDED.boot_id,started_at=EXCLUDED.started_at,expires_at=EXCLUDED.expires_at
 WHERE lazy_runtime_owners.installation_generation<EXCLUDED.installation_generation OR (lazy_runtime_owners.installation_generation=EXCLUDED.installation_generation AND ((lazy_runtime_owners.boot_id=EXCLUDED.boot_id AND lazy_runtime_owners.started_at=EXCLUDED.started_at) OR (lazy_runtime_owners.boot_id<>EXCLUDED.boot_id AND lazy_runtime_owners.started_at<EXCLUDED.started_at)))`, machine, environment, r.InstallationGeneration, r.BootID, r.StartedAt, now.Add(30*time.Second))
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}

type ActivationRequest struct {
	PolicyID          string
	OwnerAccountID    string
	PolicyGeneration  int64
	AuthorityDeadline time.Time
	// Check rereads current browser/machine credentials and exact resource grants.
	Check func(context.Context) error
}

type activationClaim struct {
	policy                         Policy
	boot, id, preview, environment string
	previousPreview                string
	leader                         bool
	deadline                       time.Time
	authorityDeadline              time.Time
}

func activationID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "laz_" + hex.EncodeToString(b[:]), nil
}

func checkActivation(ctx context.Context, check func(context.Context) error) error {
	err := check(ctx)
	if ctx.Err() != nil {
		return activationError("activation_timeout")
	}
	return err
}

// Activate accepts no HTTP body and never retries a forwarded application request.
// PostgreSQL owns admission and waiter counts, including across server processes.
func (s *Activator) Activate(ctx context.Context, in ActivationRequest) (string, error) {
	if in.Check == nil || in.PolicyID == "" || in.OwnerAccountID == "" || in.PolicyGeneration < 1 || !in.AuthorityDeadline.After(time.Now().UTC()) {
		return "", ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, ActivationTimeout)
	defer cancel()
	if err := checkActivation(ctx, in.Check); err != nil {
		return "", err
	}
	waiter, err := activationID()
	if err != nil {
		if ctx.Err() != nil {
			return "", activationError("activation_timeout")
		}
		return "", err
	}
	claim, err := s.claim(ctx, in, waiter)
	if err != nil {
		if ctx.Err() != nil {
			return "", activationError("activation_timeout")
		}
		return "", err
	}
	if claim.preview != "" {
		if err := checkActivation(ctx, in.Check); err != nil {
			return "", err
		}
		return claim.preview, nil
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, _ = s.DB.Pool().Exec(cleanup, `DELETE FROM lazy_activation_waiters WHERE waiter_id=$1`, waiter)
	}()
	if claim.leader {
		go s.run(claim)
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := checkActivation(ctx, in.Check); err != nil {
			return "", err
		}
		var state, preview, code, boot string
		var generation int64
		err = s.DB.Pool().QueryRow(ctx, `SELECT state,coalesce(preview_id,''),error_code,policy_generation,boot_id FROM lazy_activations WHERE policy_id=$1 AND activation_id=$2`, in.PolicyID, claim.id).Scan(&state, &preview, &code, &generation, &boot)
		if errors.Is(err, pgx.ErrNoRows) {
			return "", activationError("generation_conflict")
		}
		if err != nil {
			if ctx.Err() != nil {
				return "", activationError("activation_timeout")
			}
			return "", err
		}
		if generation != in.PolicyGeneration || boot != claim.boot {
			return "", activationError("generation_conflict")
		}
		if state == "ready" {
			// Readiness and the exact policy/runtime binding must still hold when
			// this waiter observes the result, not only when the leader committed.
			if !s.ready(ctx, in.PolicyID, in.PolicyGeneration, preview) {
				if ctx.Err() != nil {
					return "", activationError("activation_timeout")
				}
				return "", activationError("generation_conflict")
			}
			return preview, nil
		}
		if state == "failed" {
			return "", activationError(code)
		}
		select {
		case <-ctx.Done():
			return "", activationError("activation_timeout")
		case <-ticker.C:
		}
	}
}

func (s *Activator) claim(ctx context.Context, in ActivationRequest, waiter string) (activationClaim, error) {
	var c activationClaim
	err := s.DB.InReadCommittedTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		c = activationClaim{authorityDeadline: in.AuthorityDeadline}
		// The account lock serializes all admission reads and writes. Read committed
		// takes a fresh snapshot after a queued lock, avoiding a serializable retry
		// convoy for requests coalescing behind the same activation.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,27))`, in.OwnerAccountID); err != nil {
			return err
		}
		now := time.Now().UTC()
		p := &c.policy
		err := tx.QueryRow(ctx, `SELECT p.id,p.hostname,p.account_id,p.environment_id,p.machine_id,p.installation_generation,p.generation,p.target_scheme,p.target_address,p.access_mode,p.expires_at,coalesce(o.boot_id,''),COALESCE((SELECT old.id FROM preview_leases old WHERE old.account_id=p.account_id AND old.endpoint='https://'||p.hostname AND old.terminal_state='active'),'')
 FROM lazy_access_policies p JOIN user_machines m ON m.id=p.machine_id AND m.user_id=p.account_id AND m.installation_generation=p.installation_generation
 LEFT JOIN lazy_runtime_owners o ON o.machine_id=m.id AND o.account_id=p.account_id AND o.installation_generation=p.installation_generation AND o.expires_at>$4 AND m.online AND m.state='online'
 WHERE p.id=$1 AND p.account_id=$2 AND p.generation=$3 AND p.deleted_at IS NULL AND p.expires_at>$4 AND m.deleted_at IS NULL AND m.revoked_at IS NULL AND m.environment_id=p.environment_id AND m.seat_state='occupied' AND m.state NOT IN ('pending','revoked','deleted')`, in.PolicyID, in.OwnerAccountID, in.PolicyGeneration, now).Scan(&p.ID, &p.Hostname, &p.AccountID, &c.environment, &p.MachineID, &p.InstallationGeneration, &p.Generation, &p.Target.Scheme, &p.Target.Address, &p.AccessMode, &p.ExpiresAt, &c.boot, &c.previousPreview)
		if errors.Is(err, pgx.ErrNoRows) {
			return activationError("generation_conflict")
		}
		if err != nil {
			return err
		}
		if c.boot == "" {
			return activationError("host_offline")
		}
		var state, oldBoot string
		var generation int64
		var deadline, cooldown time.Time
		err = tx.QueryRow(ctx, `SELECT activation_id,state,coalesce(preview_id,''),policy_generation,boot_id,deadline,cooldown_until FROM lazy_activations WHERE policy_id=$1 FOR UPDATE`, p.ID).Scan(&c.id, &state, &c.preview, &generation, &oldBoot, &deadline, &cooldown)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		same := err == nil && generation == p.Generation && oldBoot == c.boot
		if same && state == "ready" && c.preview != "" {
			var preview, route string
			var routeGeneration int64
			var expiry time.Time
			err := tx.QueryRow(ctx, browseraccess.LazyPreviewSQL, p.ID, p.Generation, c.preview, "", now).Scan(&preview, &route, &routeGeneration, &expiry)
			if err == nil {
				return nil
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		c.preview = ""
		if same && state == "failed" && cooldown.After(now) {
			return activationError("activation_cooldown")
		}
		join := same && state == "running" && deadline.After(now)
		if !join {
			var environmentRunning, accountRunning, environmentActive, accountActive int
			err = tx.QueryRow(ctx, `SELECT count(*) FILTER(WHERE p.environment_id=$2 AND a.state='running' AND a.deadline>$3),count(*) FILTER(WHERE a.state='running' AND a.deadline>$3),count(*) FILTER(WHERE p.environment_id=$2 AND ((a.state='running' AND a.deadline>$3) OR (l.terminal_state='active' AND l.lease_deadline>$3))),count(*) FILTER(WHERE (a.state='running' AND a.deadline>$3) OR (l.terminal_state='active' AND l.lease_deadline>$3))
 FROM lazy_activations a JOIN lazy_access_policies p ON p.id=a.policy_id LEFT JOIN preview_leases l ON l.id=a.preview_id WHERE p.account_id=$1 AND p.id<>$4`, p.AccountID, c.environment, now, p.ID).Scan(&environmentRunning, &accountRunning, &environmentActive, &accountActive)
			if err != nil {
				return err
			}
			if environmentRunning >= 4 || accountRunning >= 16 || environmentActive >= 32 || accountActive >= 128 {
				return ErrCapacity
			}
			// Expired claims cannot be adopted. Each attempt gets a fresh operation fence.
			if _, err := tx.Exec(ctx, `DELETE FROM lazy_activation_waiters WHERE activation_id=$1`, c.id); err != nil {
				return err
			}
			c.id, err = activationID()
			if err != nil {
				return err
			}
			c.leader = true
			c.deadline = now.Add(ActivationTimeout)
			if requestDeadline, ok := ctx.Deadline(); ok && requestDeadline.Before(c.deadline) {
				c.deadline = requestDeadline
			}
			_, err = tx.Exec(ctx, `INSERT INTO lazy_activations(policy_id,policy_generation,boot_id,activation_id,deadline,state,cooldown_until) VALUES($1,$2,$3,$4,$5,'running',$6)
 ON CONFLICT(policy_id) DO UPDATE SET policy_generation=EXCLUDED.policy_generation,boot_id=EXCLUDED.boot_id,activation_id=EXCLUDED.activation_id,deadline=EXCLUDED.deadline,state='running',error_code='',cooldown_until=EXCLUDED.cooldown_until`, p.ID, p.Generation, c.boot, c.id, c.deadline, now)
			if err != nil {
				return err
			}
		}
		if !c.leader {
			c.deadline = deadline
		}
		if _, err := tx.Exec(ctx, `DELETE FROM lazy_activation_waiters WHERE activation_id=$1 AND expires_at<=$2`, c.id, now); err != nil {
			return err
		}
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM lazy_activation_waiters WHERE activation_id=$1`, c.id).Scan(&count); err != nil {
			return err
		}
		if count >= 32 {
			return ErrCapacity
		}
		_, err = tx.Exec(ctx, `INSERT INTO lazy_activation_waiters(waiter_id,activation_id,expires_at)VALUES($1,$2,$3)`, waiter, c.id, c.deadline)
		return err
	})
	return c, err
}

// currentActivationSQL is shared by polling and the atomic readiness transition.
// The latter must not publish a stale result between a check and a separate UPDATE.
const currentActivationSQL = `SELECT a.activation_id FROM lazy_activations a
JOIN lazy_access_policies p ON p.id=a.policy_id
JOIN lazy_runtime_owners o ON o.machine_id=p.machine_id AND o.account_id=p.account_id
JOIN user_machines m ON m.id=p.machine_id AND m.user_id=p.account_id
WHERE a.activation_id=$1 AND a.state='running' AND a.deadline>now()
 AND p.generation=a.policy_generation AND p.deleted_at IS NULL AND p.expires_at>now()
 AND o.boot_id=a.boot_id AND o.expires_at>now() AND o.installation_generation=p.installation_generation
 AND m.installation_generation=p.installation_generation AND m.environment_id=p.environment_id
 AND m.revoked_at IS NULL AND m.deleted_at IS NULL AND m.seat_state='occupied'
 AND m.online AND m.state='online'
 AND EXISTS(SELECT 1 FROM lazy_activation_waiters w WHERE w.activation_id=a.activation_id AND w.expires_at>now())`

func (s *Activator) current(ctx context.Context, c activationClaim) bool {
	var ok bool
	err := s.DB.Pool().QueryRow(ctx, `SELECT EXISTS(`+currentActivationSQL+`)`, c.id).Scan(&ok)
	return err == nil && ok
}

func (s *Activator) ready(ctx context.Context, policy string, generation int64, preview string) bool {
	var id, route string
	var routeGeneration int64
	var expiry time.Time
	return s.DB.Pool().QueryRow(ctx, browseraccess.LazyPreviewSQL, policy, generation, preview, "", time.Now().UTC()).Scan(&id, &route, &routeGeneration, &expiry) == nil
}

func (s *Activator) run(c activationClaim) {
	ctx, cancel := context.WithDeadline(context.Background(), c.deadline)
	defer cancel()
	done := make(chan struct{})
	defer close(done)
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				if !s.current(ctx, c) {
					cancel()
					return
				}
			}
		}
	}()
	p := c.policy
	request := previewtunnelapi.RequestContext{Actor: previewtunnelapi.Actor{AccountID: p.AccountID, ActorID: p.AccountID, Role: "user", Scopes: []string{"previews:write", "previews:read"}}, RequestID: c.id, CorrelationID: c.id}
	// The account-locked claim captured the previous exact-host lease. Retire
	// that ID before creating its replacement; a delayed worker must never look
	// up the hostname again and accidentally select a newer worker's lease.
	preview := c.previousPreview
	var err error
	if preview != "" {
		err = s.stop(ctx, request, preview, c.id+"_retire")
	}
	if err == nil {
		result, e := s.DB.Pool().Exec(ctx, `UPDATE lazy_activations SET preview_id=NULL WHERE activation_id=$1 AND activation_id IN (`+currentActivationSQL+`)`, c.id)
		err = e
		if err == nil && result.RowsAffected() != 1 {
			err = activationError("generation_conflict")
		}
	}
	if err != nil {
		s.fail(c, request, preview, err)
		return
	}
	preview = ""
	end := time.Now().UTC().Add(8 * time.Hour)
	if p.ExpiresAt.Before(end) {
		end = p.ExpiresAt
	}
	if c.authorityDeadline.Before(end) {
		end = c.authorityDeadline
	}
	result, err := s.Leases.Create(ctx, request, previewv1.CreateRequest{OwnerDeviceID: p.MachineID, OwnerSessionID: "lazy_" + c.boot, Target: previewv1.Target{Scheme: p.Target.Scheme, Address: p.Target.Address}, AccessMode: p.AccessMode, ExpiresAt: &end, IdempotencyKey: c.id, ReservedEndpoint: "https://" + p.Hostname, Lazy: &previewv1.LazyBinding{PolicyID: p.ID, PolicyGeneration: p.Generation, InstallationGeneration: p.InstallationGeneration, BootID: c.boot}})
	preview = result.Preview.ID
	if err == nil {
		updated, e := s.DB.Pool().Exec(ctx, `UPDATE lazy_activations SET preview_id=$2 WHERE activation_id=$1 AND state='running'`, c.id, preview)
		err = e
		if err == nil && updated.RowsAffected() != 1 {
			err = activationError("generation_conflict")
		}
	}
	if err == nil {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			got, e := s.Leases.Get(ctx, request, preview)
			if e != nil {
				err = e
				break
			}
			if got.Preview.State == "ready" {
				// The attachment and lease must be ready in the same SQL statement that
				// publishes the activation; viewer authority is still checked separately.
				updated, e := s.DB.Pool().Exec(ctx, `UPDATE lazy_activations SET state='ready'
WHERE activation_id=$1 AND activation_id IN (`+currentActivationSQL+`)
 AND EXISTS(SELECT 1 FROM preview_leases v JOIN preview_lease_carrier_attachments x ON x.preview_id=v.id AND x.account_id=v.account_id
 WHERE v.id=lazy_activations.preview_id AND v.terminal_state='active' AND v.lease_deadline>now()
 AND (v.user_deadline IS NULL OR v.user_deadline>now()) AND x.lease_generation=v.generation
 AND x.state='ready' AND x.edge_ready AND x.origin_ready AND x.expires_at>now())`, c.id)
				if e != nil {
					err = e
					break
				}
				if updated.RowsAffected() == 1 {
					return
				}
				if !s.current(ctx, c) {
					err = activationError("generation_conflict")
					break
				}
			}
			if got.Preview.OriginState == "unavailable" {
				err = activationError("origin_unavailable")
				break
			}
			if got.Preview.State == "stopped" || got.Preview.State == "expired" || got.Preview.State == "owner_disconnected" {
				err = activationError("owner_replaced")
				break
			}
			select {
			case <-ctx.Done():
				err = ctx.Err()
			case <-ticker.C:
			}
			if err != nil {
				break
			}
		}
	}
	s.fail(c, request, preview, err)
}

// stop uses the existing lease engine and retries only a demonstrated heartbeat
// generation race. A failed stop keeps the preview identity for the next request
// to recover; it must not be reported as successful resource cleanup.
func (s *Activator) stop(ctx context.Context, request previewtunnelapi.RequestContext, preview, key string) error {
	for attempt := 0; attempt < 2; attempt++ {
		got, err := s.Leases.Get(ctx, request, preview)
		if err != nil {
			return err
		}
		generation, err := previewtunnelapi.ParseIfMatch(mapHeader(got.ETag), previewv1.Kind, preview)
		if err != nil {
			return err
		}
		_, err = s.Leases.Stop(ctx, request, preview, previewv1.MutationRequest{ExpectedGeneration: generation, IdempotencyKey: key + "_" + strconv.FormatInt(generation, 10)})
		if !errors.Is(err, previewtunnelstore.ErrGenerationConflict) {
			return err
		}
	}
	return previewtunnelstore.ErrGenerationConflict
}

func (s *Activator) fail(c activationClaim, request previewtunnelapi.RequestContext, preview string, cause error) {
	cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	// A failed Create may have persisted a lease before dispatch failed.
	if preview == "" {
		err := s.DB.Pool().QueryRow(cleanup, `SELECT resource_id FROM operations WHERE account_id=$1 AND idempotency_key=$2`, c.policy.AccountID, c.id).Scan(&preview)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			cause = activationError("forwarding_failed")
		}
	}
	if preview != "" {
		if err := s.stop(cleanup, request, preview, c.id+"_stop"); err != nil {
			cause = activationError("forwarding_failed")
		} else {
			preview = ""
		}
	}
	cancel()
	code := "forwarding_failed"
	var stateError *ActivationError
	if errors.As(cause, &stateError) {
		code = stateError.Code
	} else if errors.Is(cause, context.DeadlineExceeded) || errors.Is(cause, context.Canceled) {
		code = "activation_timeout"
	} else if errors.Is(cause, previewtunnelstore.ErrOwnerNotFound) {
		code = "host_offline"
	} else if errors.Is(cause, previewv1.ErrOwnerDenied) {
		code = "owner_replaced"
	}
	finish, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// SQL/control loss may prevent this update; the retained running deadline is
	// still finite, and the next claim recovers any lease by its reserved hostname.
	_, _ = s.DB.Pool().Exec(finish, `UPDATE lazy_activations SET state='failed',preview_id=NULLIF($3,''),error_code=$2,cooldown_until=now()+interval '2 seconds' WHERE activation_id=$1 AND state='running'`, c.id, code, preview)
}

func mapHeader(etag string) map[string][]string { return map[string][]string{"If-Match": {etag}} }
