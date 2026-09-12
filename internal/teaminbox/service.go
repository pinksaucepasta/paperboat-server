package teaminbox

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/observability"
	"github.com/pinksaucepasta/paperboat-server/internal/teams"
)

const (
	MaximumFiles         = 10
	MaximumManifestBytes = 16 << 10
	MaximumPending       = 128
	MaximumLifetime      = 24 * time.Hour
)

var safeID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$`)

var (
	ErrInvalid   = errors.New("invalid team inbox request")
	ErrForbidden = errors.New("team inbox request is forbidden")
	ErrNotFound  = errors.New("team inbox request was not found")
	ErrConflict  = errors.New("team inbox request changed")
	ErrPending   = errors.New("team inbox request awaits recipient approval")
	ErrDeclined  = errors.New("team inbox request was declined")
	ErrExpired   = errors.New("team inbox request expired")
	ErrRevoked   = errors.New("team inbox authorization was revoked")
	ErrLimit     = errors.New("too many pending team inbox requests")
	ErrOffline   = errors.New("team inbox recipient is offline")
)

func noRows(err error) bool { return errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) }

type File struct {
	Basename string `json:"basename"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
}

type RequestInput struct {
	RequestID            string
	OperationID          string
	SenderAccount        string
	SourceMachineID      string
	DestinationMachineID string
	BatchID              string
	Files                []File
	ExpiresAt            time.Time
}

type Request struct {
	RequestID            string    `json:"request_id"`
	TeamID               string    `json:"team_id"`
	SenderAccount        string    `json:"sender_account"`
	RecipientAccount     string    `json:"recipient_account"`
	SourceMachineID      string    `json:"source_machine_id"`
	DestinationMachineID string    `json:"destination_machine_id"`
	BatchID              string    `json:"batch_id"`
	ManifestDigest       string    `json:"manifest_digest"`
	Files                []File    `json:"files"`
	Status               string    `json:"status"`
	DecisionGeneration   uint64    `json:"decision_generation"`
	ExpiresAt            time.Time `json:"expires_at"`
	ReceiptNotification  string    `json:"receipt_notification,omitempty"`
}

type Page struct {
	Requests []Request `json:"requests"`
}

type Service struct {
	db            *db.DB
	now           func() time.Time
	encryptionKey string
	smtpFactory   func(SMTPConfig) (ReceiptSender, error)
}

func (s *Service) ConfigureEncryptionKey(key string) { s.encryptionKey = key }

type Policy struct {
	Acceptance   string `json:"acceptance"`
	ReceiptEmail bool   `json:"receipt_email"`
	Generation   uint64 `json:"generation"`
}

func New(store *db.DB) (*Service, error) {
	if store == nil {
		return nil, ErrInvalid
	}
	return &Service{db: store, now: func() time.Time { return time.Now().UTC() }, smtpFactory: func(config SMTPConfig) (ReceiptSender, error) { return NewSMTPReceiptSender(config) }}, nil
}

func (s *Service) SetPolicy(ctx context.Context, account string, policy Policy, expected uint64) (Policy, error) {
	if !safeID.MatchString(account) || policy.Acceptance != "manual" && policy.Acceptance != "automatic" {
		return Policy{}, ErrInvalid
	}
	var out Policy
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := teams.Lock(ctx, tx); err != nil {
			return err
		}
		// An account without a stored row is projected as generation 1 by Policy.
		// Accept that generation on first write, and fence every later update.
		if expected == 0 {
			expected = 1
		}
		err := tx.QueryRow(ctx, `INSERT INTO team_inbox_policies(account_id,acceptance,receipt_email,generation,updated_at)
			VALUES($1,$2,$3,1,$4)
			ON CONFLICT(account_id) DO UPDATE SET acceptance=EXCLUDED.acceptance,receipt_email=EXCLUDED.receipt_email,generation=team_inbox_policies.generation+1,updated_at=EXCLUDED.updated_at
			WHERE team_inbox_policies.generation=$5
			RETURNING acceptance,receipt_email,generation`, account, policy.Acceptance, policy.ReceiptEmail, s.now().UTC(), expected).Scan(&out.Acceptance, &out.ReceiptEmail, &out.Generation)
		if noRows(err) {
			return ErrConflict
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE team_inbox_requests SET status='pending',decision_kind='manual',decision_generation=decision_generation+1,decided_at=NULL,updated_at=$2 WHERE recipient_account=$1 AND status='approved' AND decision_kind='automatic'`, account, s.now().UTC()); err != nil {
			return err
		}
		return nil
	})
	return out, err
}

func (s *Service) Policy(ctx context.Context, account string) (Policy, error) {
	if !safeID.MatchString(account) {
		return Policy{}, ErrInvalid
	}
	var out Policy
	err := s.db.SQL().QueryRowContext(ctx, `SELECT acceptance,receipt_email,generation FROM paperboat.team_inbox_policies WHERE account_id=$1`, account).Scan(&out.Acceptance, &out.ReceiptEmail, &out.Generation)
	if noRows(err) {
		return Policy{Acceptance: "manual", Generation: 1}, nil
	}
	return out, err
}

func (s *Service) List(ctx context.Context, account string) (Page, error) {
	if !safeID.MatchString(account) {
		return Page{}, ErrInvalid
	}
	if _, err := s.db.SQL().ExecContext(ctx, `UPDATE paperboat.team_inbox_requests SET status='expired',decision_generation=decision_generation+1,updated_at=now() WHERE status='pending' AND expires_at<=now() AND (sender_account=$1 OR recipient_account=$1)`, account); err != nil {
		return Page{}, err
	}
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT r.request_id,r.team_id,r.sender_account,r.recipient_account,r.source_machine_id,r.destination_machine_id,r.batch_id,r.manifest_digest,r.manifest,r.status,r.decision_generation,r.expires_at,coalesce(o.status,'') FROM paperboat.team_inbox_requests r LEFT JOIN paperboat.team_inbox_receipt_outbox o USING(request_id) WHERE r.sender_account=$1 OR r.recipient_account=$1 ORDER BY r.created_at DESC,r.request_id DESC LIMIT 128`, account)
	if err != nil {
		return Page{}, err
	}
	defer rows.Close()
	out := Page{Requests: []Request{}}
	for rows.Next() {
		var request Request
		var manifest []byte
		if err = rows.Scan(&request.RequestID, &request.TeamID, &request.SenderAccount, &request.RecipientAccount, &request.SourceMachineID, &request.DestinationMachineID, &request.BatchID, &request.ManifestDigest, &manifest, &request.Status, &request.DecisionGeneration, &request.ExpiresAt, &request.ReceiptNotification); err != nil {
			return Page{}, err
		}
		if err = json.Unmarshal(manifest, &request.Files); err != nil {
			return Page{}, err
		}
		out.Requests = append(out.Requests, request)
	}
	return out, rows.Err()
}

func (s *Service) Get(ctx context.Context, account, requestID string) (Request, error) {
	if !safeID.MatchString(account) || !safeID.MatchString(requestID) {
		return Request{}, ErrInvalid
	}
	if _, err := s.db.SQL().ExecContext(ctx, `UPDATE paperboat.team_inbox_requests SET status='expired',decision_generation=decision_generation+1,updated_at=now() WHERE request_id=$1 AND status='pending' AND expires_at<=now() AND (sender_account=$2 OR recipient_account=$2)`, requestID, account); err != nil {
		return Request{}, err
	}
	var out Request
	var manifest []byte
	err := s.db.SQL().QueryRowContext(ctx, `SELECT r.request_id,r.team_id,r.sender_account,r.recipient_account,r.source_machine_id,r.destination_machine_id,r.batch_id,r.manifest_digest,r.manifest,r.status,r.decision_generation,r.expires_at,coalesce(o.status,'') FROM paperboat.team_inbox_requests r LEFT JOIN paperboat.team_inbox_receipt_outbox o USING(request_id) WHERE r.request_id=$1 AND (r.sender_account=$2 OR r.recipient_account=$2)`, requestID, account).Scan(&out.RequestID, &out.TeamID, &out.SenderAccount, &out.RecipientAccount, &out.SourceMachineID, &out.DestinationMachineID, &out.BatchID, &out.ManifestDigest, &manifest, &out.Status, &out.DecisionGeneration, &out.ExpiresAt, &out.ReceiptNotification)
	if noRows(err) {
		return Request{}, ErrNotFound
	}
	if err == nil {
		err = json.Unmarshal(manifest, &out.Files)
	}
	return out, err
}

func (s *Service) SetSenderPolicy(ctx context.Context, recipient, sender, acceptance string) error {
	if !safeID.MatchString(recipient) || !safeID.MatchString(sender) || recipient == sender || acceptance != "manual" && acceptance != "automatic" {
		return ErrInvalid
	}
	return s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := teams.Lock(ctx, tx); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO team_inbox_sender_policies(recipient_account,sender_account,acceptance) VALUES($1,$2,$3) ON CONFLICT(recipient_account,sender_account) DO UPDATE SET acceptance=EXCLUDED.acceptance,generation=team_inbox_sender_policies.generation+1,updated_at=now()`, recipient, sender, acceptance); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE team_inbox_requests SET status='pending',decision_kind='manual',decision_generation=decision_generation+1,decided_at=NULL,updated_at=$3 WHERE recipient_account=$1 AND sender_account=$2 AND status='approved' AND decision_kind='automatic'`, recipient, sender, s.now().UTC())
		return err
	})
}

func canonicalFiles(files []File) ([]byte, string, error) {
	if len(files) < 1 || len(files) > MaximumFiles {
		return nil, "", ErrInvalid
	}
	for _, file := range files {
		if file.Basename == "" || file.Basename != strings.TrimSpace(file.Basename) || strings.ContainsAny(file.Basename, "/\\\x00\r\n") || len(file.Basename) > 255 || file.Size < 0 || len(file.SHA256) != 64 {
			return nil, "", ErrInvalid
		}
		if digest, err := hex.DecodeString(file.SHA256); err != nil || len(digest) != sha256.Size {
			return nil, "", ErrInvalid
		}
	}
	payload, err := json.Marshal(files)
	if err != nil || len(payload) > MaximumManifestBytes {
		return nil, "", ErrInvalid
	}
	digest := sha256.Sum256(payload)
	return payload, hex.EncodeToString(digest[:]), nil
}

func validInput(in RequestInput, now time.Time) bool {
	for _, value := range []string{in.RequestID, in.OperationID, in.SenderAccount, in.SourceMachineID, in.DestinationMachineID, in.BatchID} {
		if !safeID.MatchString(value) {
			return false
		}
	}
	return in.SourceMachineID != in.DestinationMachineID && in.ExpiresAt.After(now) && in.ExpiresAt.Sub(now) <= MaximumLifetime
}

func auditLifecycleTx(ctx context.Context, tx *db.Tx, actor string, request Request, action, operation, status string) error {
	target := request.RecipientAccount
	if actor == request.RecipientAccount {
		target = request.SenderAccount
	}
	// The generic writer normally projects the HTTP correlation ID into
	// metadata.request_id. Inbox activity owns that field for its resource ID.
	ctx = observability.WithRequestID(ctx, "")
	return teams.AuditTx(ctx, tx, actor, request.TeamID, "inbox_"+action, operation, map[string]any{
		"request_id":     request.RequestID,
		"target_account": target,
		"status":         status,
	})
}

// Create records the recipient decision before any payload stream can be opened.
// Exact machine capability is checked under the same team lock used by Task 39.
func (s *Service) Create(ctx context.Context, in RequestInput) (Request, error) {
	now := s.now().UTC()
	manifest, digest, err := canonicalFiles(in.Files)
	if err != nil || !validInput(in, now) {
		return Request{}, ErrInvalid
	}
	var result Request
	err = s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := teams.Lock(ctx, tx); err != nil {
			return err
		}
		var sameAccount bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM user_machines source JOIN user_machines destination ON destination.id=$2 WHERE source.id=$1 AND source.user_id=$3 AND destination.user_id=$3 AND source.revoked_at IS NULL AND source.deleted_at IS NULL AND destination.revoked_at IS NULL AND destination.deleted_at IS NULL)`, in.SourceMachineID, in.DestinationMachineID, in.SenderAccount).Scan(&sameAccount); err != nil {
			return err
		}
		if sameAccount {
			result = Request{RequestID: in.RequestID, SenderAccount: in.SenderAccount, RecipientAccount: in.SenderAccount, SourceMachineID: in.SourceMachineID, DestinationMachineID: in.DestinationMachineID, BatchID: in.BatchID, ManifestDigest: digest, Files: in.Files, Status: "not_required", ExpiresAt: in.ExpiresAt.UTC()}
			return nil
		}
		var recipient, team, destinationState string
		var online, configured, observed bool
		err := tx.QueryRow(ctx, `SELECT destination.user_id,b.team_id,destination.state,destination.online,destination.configured_capabilities @> ARRAY['file_receive'],destination.observed_capabilities @> ARRAY['file_receive'] FROM user_machines source JOIN user_machines destination ON destination.id=$2 JOIN team_resource_bindings b ON b.resource_kind='machine' AND b.resource_id=destination.id AND b.active JOIN team_members recipient_member ON recipient_member.team_id=b.team_id AND recipient_member.account_id=destination.user_id AND recipient_member.active WHERE source.id=$1 AND source.user_id=$3 AND source.revoked_at IS NULL AND source.deleted_at IS NULL AND destination.user_id<>$3 AND destination.revoked_at IS NULL AND destination.deleted_at IS NULL AND team_machine_capability_allowed($3,b.team_id,destination.id,'files') ORDER BY b.team_id LIMIT 1`, in.SourceMachineID, in.DestinationMachineID, in.SenderAccount).Scan(&recipient, &team, &destinationState, &online, &configured, &observed)
		if noRows(err) {
			return ErrForbidden
		}
		if err != nil {
			return err
		}
		if destinationState != "online" || !online || !configured || !observed {
			return ErrOffline
		}
		var pending int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM team_inbox_requests WHERE recipient_account=$1 AND status='pending' AND expires_at>$2`, recipient, now).Scan(&pending); err != nil {
			return err
		}
		if pending >= MaximumPending {
			return ErrLimit
		}
		var mode string
		var generation uint64
		err = tx.QueryRow(ctx, `SELECT acceptance,generation FROM team_inbox_sender_policies WHERE recipient_account=$1 AND sender_account=$2`, recipient, in.SenderAccount).Scan(&mode, &generation)
		if noRows(err) {
			err = tx.QueryRow(ctx, `SELECT acceptance,generation FROM team_inbox_policies WHERE account_id=$1`, recipient).Scan(&mode, &generation)
		}
		if noRows(err) {
			mode, generation, err = "manual", 1, nil
		}
		if err != nil {
			return err
		}
		status := "pending"
		if mode == "automatic" {
			status = "approved"
		}
		_, err = tx.Exec(ctx, `INSERT INTO team_inbox_requests(request_id,operation_id,team_id,sender_account,recipient_account,source_machine_id,destination_machine_id,batch_id,manifest_digest,manifest,status,decision_kind,policy_generation,expires_at,decided_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,CASE WHEN $11::text='approved' THEN $15::timestamptz ELSE NULL END) ON CONFLICT(sender_account,operation_id) DO NOTHING`, in.RequestID, in.OperationID, team, in.SenderAccount, recipient, in.SourceMachineID, in.DestinationMachineID, in.BatchID, digest, manifest, status, mode, generation, in.ExpiresAt.UTC(), now)
		if err != nil {
			return err
		}
		result, err = readOperationTx(ctx, tx, in.SenderAccount, in.OperationID)
		if err != nil {
			return err
		}
		if result.ManifestDigest != digest || result.BatchID != in.BatchID || result.SourceMachineID != in.SourceMachineID || result.DestinationMachineID != in.DestinationMachineID {
			return ErrConflict
		}
		return auditLifecycleTx(ctx, tx, in.SenderAccount, result, "request", in.OperationID, result.Status)
	})
	return result, err
}

func readTx(ctx context.Context, tx *db.Tx, requestID, account string) (Request, error) {
	var out Request
	var manifest []byte
	err := tx.QueryRow(ctx, `SELECT request_id,team_id,sender_account,recipient_account,source_machine_id,destination_machine_id,batch_id,manifest_digest,manifest,status,decision_generation,expires_at FROM team_inbox_requests WHERE request_id=$1 AND ($2='' OR sender_account=$2 OR recipient_account=$2)`, requestID, account).Scan(&out.RequestID, &out.TeamID, &out.SenderAccount, &out.RecipientAccount, &out.SourceMachineID, &out.DestinationMachineID, &out.BatchID, &out.ManifestDigest, &manifest, &out.Status, &out.DecisionGeneration, &out.ExpiresAt)
	if noRows(err) {
		return Request{}, ErrNotFound
	}
	if err == nil {
		err = json.Unmarshal(manifest, &out.Files)
	}
	return out, err
}

func readOperationTx(ctx context.Context, tx *db.Tx, sender, operation string) (Request, error) {
	var requestID string
	if err := tx.QueryRow(ctx, `SELECT request_id FROM team_inbox_requests WHERE sender_account=$1 AND operation_id=$2`, sender, operation).Scan(&requestID); err != nil {
		if noRows(err) {
			return Request{}, ErrNotFound
		}
		return Request{}, err
	}
	return readTx(ctx, tx, requestID, sender)
}

func (s *Service) Decide(ctx context.Context, recipient, requestID, decision string, expected uint64) (Request, error) {
	if !safeID.MatchString(recipient) || !safeID.MatchString(requestID) || expected == 0 || decision != "approved" && decision != "declined" {
		return Request{}, ErrInvalid
	}
	var out Request
	var outcomeErr error
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := teams.Lock(ctx, tx); err != nil {
			return err
		}
		now := s.now().UTC()
		current, readErr := readTx(ctx, tx, requestID, recipient)
		if readErr != nil {
			return readErr
		}
		if current.RecipientAccount != recipient {
			return ErrNotFound
		}
		var authorized bool
		if readErr = tx.QueryRow(ctx, `SELECT EXISTS(
			SELECT 1 FROM team_inbox_requests r
			JOIN teams t ON t.team_id=r.team_id AND t.deleted_at IS NULL
			JOIN team_members sender ON sender.team_id=r.team_id AND sender.account_id=r.sender_account AND sender.active
			JOIN team_members recipient_member ON recipient_member.team_id=r.team_id AND recipient_member.account_id=r.recipient_account AND recipient_member.active
			JOIN user_machines source ON source.id=r.source_machine_id AND source.user_id=r.sender_account AND source.revoked_at IS NULL AND source.deleted_at IS NULL
			JOIN user_machines destination ON destination.id=r.destination_machine_id AND destination.user_id=r.recipient_account AND destination.revoked_at IS NULL AND destination.deleted_at IS NULL
			WHERE r.request_id=$1 AND r.recipient_account=$2
			AND destination.configured_capabilities @> ARRAY['file_receive'] AND destination.observed_capabilities @> ARRAY['file_receive']
			AND team_machine_capability_allowed(r.sender_account,r.team_id,r.destination_machine_id,'files'))`, requestID, recipient).Scan(&authorized); readErr != nil {
			return readErr
		}
		if !authorized {
			if _, readErr = tx.Exec(ctx, `UPDATE team_inbox_requests SET status='revoked',decision_generation=decision_generation+1,updated_at=$2 WHERE request_id=$1 AND status IN ('pending','approved')`, requestID, now); readErr != nil {
				return readErr
			}
			outcomeErr = ErrRevoked
			return nil
		}
		if !current.ExpiresAt.After(now) && current.Status == "pending" {
			if _, readErr = tx.Exec(ctx, `UPDATE team_inbox_requests SET status='expired',decision_generation=decision_generation+1,updated_at=$2 WHERE request_id=$1 AND status='pending'`, requestID, now); readErr != nil {
				return readErr
			}
			outcomeErr = ErrExpired
			return nil
		}
		result, err := tx.Exec(ctx, `UPDATE team_inbox_requests SET status=$1,decision_kind='manual',decision_generation=decision_generation+1,decided_at=$2,updated_at=$2 WHERE request_id=$3 AND recipient_account=$4 AND status='pending' AND decision_generation=$5`, decision, now, requestID, recipient, expected)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return ErrConflict
		}
		out, err = readTx(ctx, tx, requestID, recipient)
		if err != nil {
			return err
		}
		return auditLifecycleTx(ctx, tx, recipient, out, "decide", requestID+":"+decision, decision)
	})
	if err == nil && outcomeErr != nil {
		return out, outcomeErr
	}
	return out, err
}

// Consume is called immediately before minting the file-transfer credential.
// It rechecks current team authority and makes an approval single-use.
func (s *Service) Consume(ctx context.Context, sender, requestID, digest string) (Request, error) {
	var out Request
	var outcomeErr error
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := teams.Lock(ctx, tx); err != nil {
			return err
		}
		var allowed bool
		err := tx.QueryRow(ctx, `SELECT team_machine_capability_allowed(r.sender_account,r.team_id,r.destination_machine_id,'files') AND EXISTS(SELECT 1 FROM team_members recipient_member JOIN user_machines destination ON destination.id=r.destination_machine_id AND destination.user_id=r.recipient_account AND destination.revoked_at IS NULL AND destination.deleted_at IS NULL WHERE recipient_member.team_id=r.team_id AND recipient_member.account_id=r.recipient_account AND recipient_member.active) FROM team_inbox_requests r WHERE r.request_id=$1 AND r.sender_account=$2 FOR UPDATE`, requestID, sender).Scan(&allowed)
		if noRows(err) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		out, err = readTx(ctx, tx, requestID, sender)
		if err != nil {
			return err
		}
		if !allowed {
			if _, err = tx.Exec(ctx, `UPDATE team_inbox_requests SET status='revoked',decision_generation=decision_generation+1,updated_at=$2 WHERE request_id=$1 AND status IN ('pending','approved','consumed')`, requestID, s.now().UTC()); err != nil {
				return err
			}
			outcomeErr = ErrRevoked
			return nil
		}
		if out.ManifestDigest != digest {
			return ErrConflict
		}
		if !out.ExpiresAt.After(s.now().UTC()) {
			if _, err = tx.Exec(ctx, `UPDATE team_inbox_requests SET status='expired',decision_generation=decision_generation+1,updated_at=$2 WHERE request_id=$1 AND status IN ('pending','approved')`, requestID, s.now().UTC()); err != nil {
				return err
			}
			outcomeErr = ErrExpired
			return nil
		}
		switch out.Status {
		case "pending":
			return ErrPending
		case "declined":
			return ErrDeclined
		case "approved":
		case "consumed":
			// An exact retry may remint a short-lived credential for resumability.
			return auditLifecycleTx(ctx, tx, sender, out, "consume", requestID, "consumed")
		default:
			return ErrConflict
		}
		_, err = tx.Exec(ctx, `UPDATE team_inbox_requests SET status='consumed',decision_generation=decision_generation+1,consumed_at=$2,updated_at=$2 WHERE request_id=$1`, requestID, s.now().UTC())
		if err != nil {
			return err
		}
		return auditLifecycleTx(ctx, tx, sender, out, "consume", requestID, "consumed")
	})
	if err == nil && outcomeErr != nil {
		return out, outcomeErr
	}
	return out, err
}

// Complete projects a successful atomic publication. Notification enqueueing is
// recipient-controlled and cannot change the already successful transfer result.
func (s *Service) Complete(ctx context.Context, recipient, requestID, digest string) (Request, error) {
	var out Request
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := teams.Lock(ctx, tx); err != nil {
			return err
		}
		var err error
		out, err = readTx(ctx, tx, requestID, recipient)
		if err != nil {
			return err
		}
		if out.RecipientAccount != recipient {
			return ErrNotFound
		}
		if out.ManifestDigest != digest || out.Status != "consumed" && out.Status != "completed" {
			return ErrConflict
		}
		if out.Status == "consumed" {
			if _, err = tx.Exec(ctx, `UPDATE team_inbox_requests SET status='completed',decision_generation=decision_generation+1,completed_at=$2,updated_at=$2 WHERE request_id=$1 AND status='consumed'`, requestID, s.now().UTC()); err != nil {
				return err
			}
			out, err = readTx(ctx, tx, requestID, recipient)
			if err != nil {
				return err
			}
		}
		var optedIn bool
		if err = tx.QueryRow(ctx, `SELECT coalesce((SELECT receipt_email FROM team_inbox_policies WHERE account_id=$1),false)`, recipient).Scan(&optedIn); err != nil {
			return err
		}
		if optedIn {
			_, err = tx.Exec(ctx, `INSERT INTO team_inbox_receipt_outbox(request_id,recipient_account) VALUES($1,$2) ON CONFLICT(request_id) DO NOTHING`, requestID, recipient)
			if err != nil {
				return err
			}
		}
		return auditLifecycleTx(ctx, tx, recipient, out, "complete", requestID, "completed")
	})
	return out, err
}

func ManifestDigest(files []File) (string, error) {
	_, digest, err := canonicalFiles(files)
	return digest, err
}

func (r Request) String() string { return fmt.Sprintf("%s:%s", r.RequestID, r.Status) }
