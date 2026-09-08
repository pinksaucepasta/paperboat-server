package lazyaccess

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

const maxPoliciesPerEnvironment = 32

var (
	ErrInvalid  = errors.New("invalid lazy access policy")
	ErrDenied   = errors.New("lazy access policy denied")
	ErrConflict = errors.New("lazy access policy generation conflict")
	ErrCapacity = errors.New("lazy access policy capacity exceeded")
)

type Target struct {
	Scheme  string `json:"scheme"`
	Address string `json:"address"`
}

type Policy struct {
	ID                     string     `json:"id"`
	Hostname               string     `json:"hostname"`
	AccountID              string     `json:"account_id"`
	MachineID              string     `json:"machine_id"`
	InstallationGeneration int64      `json:"installation_generation"`
	Generation             int64      `json:"generation"`
	Target                 Target     `json:"target"`
	AccessMode             string     `json:"access_mode"`
	OwnershipMode          string     `json:"ownership_mode"`
	ExpiresAt              time.Time  `json:"expires_at"`
	DeletedAt              *time.Time `json:"deleted_at,omitempty"`
}

type UpsertRequest struct {
	ID                 string    `json:"id,omitempty"`
	MachineID          string    `json:"machine_id"`
	ExpectedGeneration int64     `json:"expected_generation"`
	Target             Target    `json:"target"`
	AccessMode         string    `json:"access_mode"`
	OwnershipMode      string    `json:"ownership_mode"`
	ExpiresAt          time.Time `json:"expires_at"`
}

type Service struct {
	db             *db.DB
	endpointDomain string
	now            func() time.Time
}

func NewService(database *db.DB, endpointDomain string) (*Service, error) {
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(endpointDomain), "."))
	if database == nil || database.SQL() == nil || !validDNSName(domain) {
		return nil, ErrInvalid
	}
	return &Service{db: database, endpointDomain: domain, now: time.Now}, nil
}

func (s *Service) Upsert(ctx context.Context, accountID string, input UpsertRequest) (Policy, error) {
	now := s.now().UTC()
	if input.OwnershipMode == "" {
		input.OwnershipMode = "persistent_port"
	}
	if err := validateUpsert(accountID, input, now); err != nil {
		return Policy{}, err
	}
	tx, err := s.db.SQL().BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Policy{}, fmt.Errorf("begin lazy policy transaction: %w", err)
	}
	defer tx.Rollback()

	var environmentID string
	var installationGeneration int64
	err = tx.QueryRowContext(ctx, `SELECT environment_id,installation_generation FROM paperboat.user_machines
WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL AND deleted_at IS NULL AND state NOT IN ('revoked','deleted') FOR SHARE`, input.MachineID, accountID).Scan(&environmentID, &installationGeneration)
	if errors.Is(err, sql.ErrNoRows) {
		return Policy{}, ErrDenied
	}
	if err != nil {
		return Policy{}, fmt.Errorf("resolve lazy policy machine: %w", err)
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,168))`, environmentID); err != nil {
		return Policy{}, fmt.Errorf("lock lazy policy environment: %w", err)
	}

	var policy Policy
	if input.ExpectedGeneration == 0 {
		policy, err = s.create(ctx, tx, accountID, environmentID, installationGeneration, input, now)
	} else {
		policy, err = s.update(ctx, tx, accountID, environmentID, installationGeneration, input, now)
	}
	if err != nil {
		return Policy{}, err
	}
	if err = tx.Commit(); err != nil {
		return Policy{}, mapWriteError(err)
	}
	return policy, nil
}

func (s *Service) create(ctx context.Context, tx *sql.Tx, accountID, environmentID string, installationGeneration int64, input UpsertRequest, now time.Time) (Policy, error) {
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM paperboat.lazy_access_policies WHERE environment_id=$1 AND deleted_at IS NULL`, environmentID).Scan(&count); err != nil {
		return Policy{}, fmt.Errorf("count lazy policies: %w", err)
	}
	if count >= maxPoliciesPerEnvironment {
		return Policy{}, ErrCapacity
	}
	id := input.ID
	if id == "" {
		token, err := randomToken(16)
		if err != nil {
			return Policy{}, err
		}
		id = "lap_" + token
	}
	if !validID(id) {
		return Policy{}, ErrInvalid
	}
	var label string
	err := tx.QueryRowContext(ctx, `SELECT environment_label FROM paperboat.lazy_environment_identities WHERE environment_id=$1`, environmentID).Scan(&label)
	if errors.Is(err, sql.ErrNoRows) {
		label, err = randomToken(10)
		if err != nil {
			return Policy{}, err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO paperboat.lazy_environment_identities(environment_id,environment_label) VALUES($1,$2)`, environmentID, label); err != nil {
			return Policy{}, mapWriteError(err)
		}
	} else if err != nil {
		return Policy{}, fmt.Errorf("read lazy environment identity: %w", err)
	}
	_, port, _ := net.SplitHostPort(input.Target.Address)
	hostname := "p" + port + "-" + label + "." + s.endpointDomain
	policy := Policy{ID: id, Hostname: hostname, AccountID: accountID, MachineID: input.MachineID, InstallationGeneration: installationGeneration, Generation: 1, Target: input.Target, AccessMode: input.AccessMode, OwnershipMode: input.OwnershipMode, ExpiresAt: input.ExpiresAt.UTC()}
	_, err = tx.ExecContext(ctx, `INSERT INTO paperboat.lazy_access_policies
(id,hostname,account_id,environment_id,machine_id,installation_generation,generation,target_scheme,target_address,access_mode,ownership_mode,expires_at,created_at,updated_at)
VALUES($1,$2,$3,$4,$5,$6,1,$7,$8,$9,$10,$11,$12,$12)`, policy.ID, policy.Hostname, accountID, environmentID, policy.MachineID, installationGeneration, policy.Target.Scheme, policy.Target.Address, policy.AccessMode, policy.OwnershipMode, policy.ExpiresAt, now)
	if err != nil {
		return Policy{}, mapWriteError(err)
	}
	return policy, nil
}

func (s *Service) update(ctx context.Context, tx *sql.Tx, accountID, environmentID string, installationGeneration int64, input UpsertRequest, now time.Time) (Policy, error) {
	if !validID(input.ID) {
		return Policy{}, ErrInvalid
	}
	var existing Policy
	var deleted sql.NullTime
	err := tx.QueryRowContext(ctx, `SELECT id,hostname,account_id,machine_id,installation_generation,generation,target_scheme,target_address,access_mode,ownership_mode,expires_at,deleted_at
FROM paperboat.lazy_access_policies WHERE id=$1 AND account_id=$2 FOR UPDATE`, input.ID, accountID).Scan(&existing.ID, &existing.Hostname, &existing.AccountID, &existing.MachineID, &existing.InstallationGeneration, &existing.Generation, &existing.Target.Scheme, &existing.Target.Address, &existing.AccessMode, &existing.OwnershipMode, &existing.ExpiresAt, &deleted)
	if errors.Is(err, sql.ErrNoRows) {
		return Policy{}, ErrDenied
	}
	if err != nil {
		return Policy{}, fmt.Errorf("read lazy policy for update: %w", err)
	}
	_, oldPort, _ := net.SplitHostPort(existing.Target.Address)
	_, newPort, _ := net.SplitHostPort(input.Target.Address)
	if deleted.Valid || existing.MachineID != input.MachineID || oldPort != newPort || existing.Generation != input.ExpectedGeneration {
		return Policy{}, ErrConflict
	}
	existing.Target = input.Target
	existing.Generation++
	existing.InstallationGeneration = installationGeneration
	existing.AccessMode, existing.OwnershipMode, existing.ExpiresAt = input.AccessMode, input.OwnershipMode, input.ExpiresAt.UTC()
	result, err := tx.ExecContext(ctx, `UPDATE paperboat.lazy_access_policies SET generation=$1,installation_generation=$2,access_mode=$3,ownership_mode=$4,expires_at=$5,updated_at=$6,target_scheme=$11,target_address=$12 WHERE id=$7 AND account_id=$8 AND environment_id=$9 AND generation=$10 AND deleted_at IS NULL`, existing.Generation, existing.InstallationGeneration, existing.AccessMode, existing.OwnershipMode, existing.ExpiresAt, now, existing.ID, accountID, environmentID, input.ExpectedGeneration, input.Target.Scheme, input.Target.Address)
	if err != nil {
		return Policy{}, mapWriteError(err)
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return Policy{}, ErrConflict
	}
	return existing, nil
}

func (s *Service) Get(ctx context.Context, accountID, id string) (Policy, error) {
	if strings.TrimSpace(accountID) == "" || !validID(id) {
		return Policy{}, ErrInvalid
	}
	var p Policy
	var deleted sql.NullTime
	err := s.db.SQL().QueryRowContext(ctx, `SELECT p.id,p.hostname,p.account_id,p.machine_id,p.installation_generation,p.generation,p.target_scheme,p.target_address,p.access_mode,p.ownership_mode,p.expires_at,p.deleted_at
FROM paperboat.lazy_access_policies p JOIN paperboat.user_machines m ON m.id=p.machine_id AND m.environment_id=p.environment_id
WHERE p.id=$1 AND p.account_id=$2 AND p.deleted_at IS NULL AND m.user_id=$2 AND m.installation_generation=p.installation_generation AND m.revoked_at IS NULL AND m.deleted_at IS NULL AND m.state NOT IN ('revoked','deleted')`, id, accountID).Scan(&p.ID, &p.Hostname, &p.AccountID, &p.MachineID, &p.InstallationGeneration, &p.Generation, &p.Target.Scheme, &p.Target.Address, &p.AccessMode, &p.OwnershipMode, &p.ExpiresAt, &deleted)
	if errors.Is(err, sql.ErrNoRows) {
		return Policy{}, ErrDenied
	}
	if err != nil {
		return Policy{}, fmt.Errorf("get lazy policy: %w", err)
	}
	return p, nil
}

func (s *Service) Delete(ctx context.Context, accountID, id string, expectedGeneration int64) error {
	if strings.TrimSpace(accountID) == "" || !validID(id) || expectedGeneration < 1 {
		return ErrInvalid
	}
	now := s.now().UTC()
	result, err := s.db.SQL().ExecContext(ctx, `UPDATE paperboat.lazy_access_policies p SET deleted_at=$1,updated_at=$1,generation=generation+1
FROM paperboat.user_machines m WHERE p.id=$2 AND p.account_id=$3 AND p.generation=$4 AND p.deleted_at IS NULL AND m.id=p.machine_id AND m.environment_id=p.environment_id AND m.user_id=$3 AND m.installation_generation=p.installation_generation AND m.revoked_at IS NULL AND m.deleted_at IS NULL AND m.state NOT IN ('revoked','deleted')`, now, id, accountID, expectedGeneration)
	if err != nil {
		return fmt.Errorf("delete lazy policy: %w", err)
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return ErrConflict
	}
	return nil
}

func validateUpsert(accountID string, in UpsertRequest, now time.Time) error {
	if strings.TrimSpace(accountID) == "" || strings.TrimSpace(in.MachineID) == "" || in.ExpectedGeneration < 0 || !in.ExpiresAt.After(now) {
		return ErrInvalid
	}
	if in.OwnershipMode != "persistent_port" {
		return ErrInvalid
	}
	if in.AccessMode != "private" && in.AccessMode != "team" {
		return ErrInvalid
	}
	if in.Target.Scheme != "http" && in.Target.Scheme != "https" && in.Target.Scheme != "h2c" {
		return ErrInvalid
	}
	host, port, err := net.SplitHostPort(in.Target.Address)
	if err != nil || host == "" || port == "" {
		return ErrInvalid
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return ErrInvalid
	}
	if !strings.EqualFold(host, "localhost") {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return ErrInvalid
		}
	}
	return nil
}

func validID(v string) bool {
	if len(v) < 1 || len(v) > 128 {
		return false
	}
	for _, r := range v {
		if !(r == '_' || r == '-' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}
func validDNSName(v string) bool {
	if len(v) < 1 || len(v) > 253 || strings.Contains(v, "..") {
		return false
	}
	for _, label := range strings.Split(v, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r == '-' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
				return false
			}
		}
	}
	return true
}
func randomToken(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate lazy policy identity: %w", err)
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)), nil
}
func mapWriteError(err error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && (pg.Code == "23505" || pg.Code == "40001") {
		return ErrConflict
	}
	return fmt.Errorf("persist lazy policy: %w", err)
}
