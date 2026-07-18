package terminalsessions

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/mint"
	"github.com/pinksaucepasta/paperboat-server/internal/observability"
	"github.com/pinksaucepasta/paperboat-server/internal/projects"
)

var (
	ErrNotFound               = errors.New("terminal session not found")
	ErrReserved               = errors.New("terminal session is reserved")
	ErrLimit                  = errors.New("terminal session limit reached")
	ErrConflict               = errors.New("terminal session name conflict")
	ErrInvalidName            = errors.New("invalid terminal session name")
	ErrIdempotencyKeyRequired = errors.New("idempotency key is required")
)

var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

type Service struct {
	db                     *db.DB
	projects               *projects.Service
	controlRoute           func(context.Context, string) (string, error)
	signer                 *mint.Provider
	issuer                 string
	http                   *http.Client
	maxActivePerProject    int
	retryBackoff           time.Duration
	maxAttemptsBeforeAlert int
}

func New(store *db.DB, projectService *projects.Service, maxActivePerProject int, retryBackoff time.Duration, maxAttemptsBeforeAlert int) *Service {
	if maxActivePerProject <= 0 {
		maxActivePerProject = 32
	}
	if retryBackoff <= 0 {
		retryBackoff = time.Second
	}
	if maxAttemptsBeforeAlert <= 0 {
		maxAttemptsBeforeAlert = 10
	}
	return &Service{db: store, projects: projectService, maxActivePerProject: maxActivePerProject, retryBackoff: retryBackoff, maxAttemptsBeforeAlert: maxAttemptsBeforeAlert}
}

func (s *Service) ConfigureControl(route func(context.Context, string) (string, error), signer *mint.Provider, issuer string, httpClient *http.Client) {
	s.controlRoute, s.signer, s.issuer = route, signer, strings.TrimRight(issuer, "/")
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	s.http = httpClient
}

func (s *Service) Worker(interval time.Duration) func(context.Context) error {
	if interval <= 0 {
		interval = time.Second
	}
	return func(ctx context.Context) error {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			s.processDue(ctx)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
			}
		}
	}
}

func (s *Service) processDue(ctx context.Context) {
	if s.controlRoute == nil || s.signer == nil || s.http == nil || s.issuer == "" {
		return
	}
	items, err := s.db.Queries().ListDueTerminalSessionOperations(ctx, 32)
	if err != nil {
		return
	}
	_ = s.applyOperations(ctx, items)
}

// ApplyPending applies operations already due for one project after its runtime
// is healthy and before a client can be given a descriptor for that runtime.
func (s *Service) ApplyPending(ctx context.Context, projectID string) error {
	for {
		items, err := s.db.Queries().ListPendingTerminalSessionOperationsForProject(ctx, dbsqlc.ListPendingTerminalSessionOperationsForProjectParams{ProjectID: projectID, BatchSize: 32})
		if err != nil {
			return err
		}
		if len(items) == 0 {
			return nil
		}
		if s.controlRoute == nil || s.signer == nil || s.http == nil || s.issuer == "" {
			return errors.New("terminal session control is unavailable")
		}
		operations := make([]dbsqlc.ListDueTerminalSessionOperationsRow, 0, len(items))
		for _, item := range items {
			operations = append(operations, dbsqlc.ListDueTerminalSessionOperationsRow{
				ID: item.ID, ProjectID: item.ProjectID, TerminalSessionID: item.TerminalSessionID,
				Operation: item.Operation, Attempts: item.Attempts, UserID: item.UserID,
				ThreadID: item.ThreadID, TerminalID: item.TerminalID,
			})
		}
		if err := s.applyOperations(ctx, operations); err != nil {
			return err
		}
	}
}

func (s *Service) applyOperations(ctx context.Context, items []dbsqlc.ListDueTerminalSessionOperationsRow) error {
	var firstErr error
	for _, item := range items {
		if item.Operation == "close" {
			// Papercode removes the live terminal before answering close. Capture
			// its CWD first so a later attach restarts the same session directory.
			_, _ = s.snapshot(ctx, item.ProjectID, item.UserID, []dbsqlc.ProjectTerminalSession{{
				ID: item.TerminalSessionID, ThreadID: item.ThreadID, TerminalID: item.TerminalID,
			}})
		}
		route, err := s.controlRoute(ctx, item.ProjectID)
		if err == nil {
			jti, jtiErr := randomID("jti")
			nonce, nonceErr := randomID("nonce")
			if jtiErr == nil && nonceErr == nil {
				now := time.Now().UTC()
				proof, signErr := s.signer.SignTerminalControl(mint.TerminalControlInput{Issuer: s.issuer, EnvironmentID: item.ProjectID, UserID: item.UserID, JTI: jti, Nonce: nonce, IssuedAt: now, ExpiresAt: now.Add(mint.MaxProofTTL), Operation: item.Operation, ThreadID: item.ThreadID, TerminalIDs: []string{item.TerminalID}})
				if signErr == nil {
					var runtime terminalControlResponse
					runtime, err = s.postControl(ctx, route, proof)
					if err == nil {
						err = requireControlOperation(runtime, item.Operation)
					}
					if err == nil && len(runtime.Terminals) == 1 {
						err = s.updateRuntime(ctx, item.TerminalSessionID, runtime.Terminals[0])
					}
					if err == nil && item.Operation == "close" {
						err = s.db.Queries().MarkTerminalSessionRuntimeClosed(ctx, item.TerminalSessionID)
					}
				} else {
					err = signErr
				}
			} else if jtiErr != nil {
				err = jtiErr
			} else {
				err = nonceErr
			}
		}
		if err == nil {
			observability.TerminalOperationApplied()
			if markErr := s.db.Queries().MarkTerminalSessionOperationApplied(ctx, item.ID); markErr != nil && firstErr == nil {
				firstErr = markErr
			}
			continue
		}
		if firstErr == nil {
			firstErr = err
		}
		if int(item.Attempts)+1 == s.maxAttemptsBeforeAlert {
			observability.TerminalOperationAlerted()
			slog.Error("terminal session operation retry threshold reached", "operation_id", item.ID, "project_id", item.ProjectID, "terminal_session_id", item.TerminalSessionID, "operation", item.Operation, "attempts", item.Attempts+1, "error", err)
		}
		observability.TerminalOperationRetried()
		multiplier := 1 << minInt(8, int(item.Attempts))
		backoff := s.retryBackoff.Seconds() * float64(multiplier)
		if backoff > 300 {
			backoff = 300
		}
		_ = s.db.Queries().RetryTerminalSessionOperation(ctx, dbsqlc.RetryTerminalSessionOperationParams{ID: item.ID, RetrySeconds: backoff, LastError: sql.NullString{String: truncateError(err), Valid: true}})
	}
	return firstErr
}

type terminalRuntime struct {
	TerminalID      string `json:"terminalId"`
	State           string `json:"state"`
	AttachmentCount int    `json:"attachmentCount"`
	LastActivityAt  string `json:"lastActivityAt"`
	Cwd             string `json:"cwd"`
	ExitCode        *int   `json:"exitCode"`
	ExitSignal      *int   `json:"exitSignal"`
	Sequence        int    `json:"sequence"`
}
type terminalControlResponse struct {
	Operation string            `json:"operation"`
	Terminals []terminalRuntime `json:"terminals"`
}

func requireControlOperation(response terminalControlResponse, expected string) error {
	if response.Operation != expected {
		return fmt.Errorf("terminal control returned operation %q for %q", response.Operation, expected)
	}
	return nil
}

func (s *Service) postControl(ctx context.Context, route, proof string) (terminalControlResponse, error) {
	body, err := json.Marshal(map[string]string{"proof": proof})
	if err != nil {
		return terminalControlResponse{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(route, "/")+"/api/paperboat/terminal-sessions/control", strings.NewReader(string(body)))
	if err != nil {
		return terminalControlResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.http.Do(req)
	if err != nil {
		return terminalControlResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return terminalControlResponse{}, fmt.Errorf("terminal control returned %s", resp.Status)
	}
	var decoded terminalControlResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return terminalControlResponse{}, fmt.Errorf("decode terminal control response: %w", err)
	}
	return decoded, nil
}

func randomID(prefix string) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(b[:]), nil
}
func truncateError(err error) string {
	value := err.Error()
	if len(value) > 500 {
		return value[:500]
	}
	return value
}
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type Session struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	IsDefault     bool       `json:"is_default"`
	State         string     `json:"state"`
	AttachedCount *int       `json:"attached_count"`
	LastActiveAt  *time.Time `json:"last_active_at"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

func (s *Service) List(ctx context.Context, userID, projectID string) ([]Session, error) {
	project, err := s.projects.Get(ctx, userID, projectID)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.Queries().ListActiveTerminalSessions(ctx, projectID)
	if err != nil {
		return nil, err
	}
	runtime := map[string]terminalRuntime{}
	if project.State == "running" {
		// Listing is best-effort: a transient control-plane failure must not turn
		// a read-only session list into an outage.
		runtime, _ = s.snapshot(ctx, projectID, userID, rows)
	}
	out := make([]Session, 0, len(rows))
	for _, row := range rows {
		session := mapSession(row)
		if project.State == "stopped" {
			zero := 0
			session.State = "stopped"
			session.AttachedCount = &zero
		} else if observed, ok := runtime[row.TerminalID]; ok {
			count := observed.AttachmentCount
			session.State = observed.State
			session.AttachedCount = &count
			if observedAt, parseErr := time.Parse(time.RFC3339Nano, observed.LastActivityAt); parseErr == nil {
				session.LastActiveAt = &observedAt
			}
		}
		out = append(out, session)
	}
	return out, nil
}

// SnapshotProject persists the state needed to restart terminal sessions after
// a VM stop. It is intended for lifecycle callers, which decide whether a
// snapshot failure should delay their provider operation.
func (s *Service) SnapshotProject(ctx context.Context, projectID string) error {
	userID, err := s.db.Queries().GetTerminalSessionProjectOwner(ctx, projectID)
	if err != nil {
		observability.TerminalSnapshotFailed()
		return err
	}
	rows, err := s.db.Queries().ListActiveTerminalSessions(ctx, projectID)
	if err != nil {
		observability.TerminalSnapshotFailed()
		return err
	}
	_, err = s.snapshot(ctx, projectID, userID, rows)
	if err != nil {
		observability.TerminalSnapshotFailed()
		return err
	}
	observability.TerminalSnapshot()
	return nil
}

func (s *Service) snapshot(ctx context.Context, projectID, userID string, rows []dbsqlc.ProjectTerminalSession) (map[string]terminalRuntime, error) {
	if len(rows) == 0 {
		return map[string]terminalRuntime{}, nil
	}
	if s.controlRoute == nil || s.signer == nil || s.http == nil || s.issuer == "" {
		return nil, errors.New("terminal session control is unavailable")
	}
	route, err := s.controlRoute(ctx, projectID)
	if err != nil {
		return nil, err
	}
	jti, err := randomID("jti")
	if err != nil {
		return nil, err
	}
	nonce, err := randomID("nonce")
	if err != nil {
		return nil, err
	}
	terminalIDs := make([]string, 0, len(rows))
	for _, row := range rows {
		terminalIDs = append(terminalIDs, row.TerminalID)
	}
	now := time.Now().UTC()
	proof, err := s.signer.SignTerminalControl(mint.TerminalControlInput{Issuer: s.issuer, EnvironmentID: projectID, UserID: userID, JTI: jti, Nonce: nonce, IssuedAt: now, ExpiresAt: now.Add(mint.MaxProofTTL), Operation: "snapshot", ThreadID: rows[0].ThreadID, TerminalIDs: terminalIDs})
	if err != nil {
		return nil, err
	}
	response, err := s.postControl(ctx, route, proof)
	if err != nil {
		return nil, err
	}
	if err := requireControlOperation(response, "snapshot"); err != nil {
		return nil, err
	}
	runtime := make(map[string]terminalRuntime, len(response.Terminals))
	for _, terminal := range response.Terminals {
		runtime[terminal.TerminalID] = terminal
	}
	for _, row := range rows {
		observed, ok := runtime[row.TerminalID]
		if !ok {
			continue
		}
		if err := s.updateRuntime(ctx, row.ID, observed); err != nil {
			return nil, err
		}
	}
	return runtime, nil
}

func (s *Service) updateRuntime(ctx context.Context, sessionID string, observed terminalRuntime) error {
	lastActivity := sql.NullTime{}
	if parsed, err := time.Parse(time.RFC3339Nano, observed.LastActivityAt); err == nil {
		lastActivity = sql.NullTime{Time: parsed, Valid: true}
	}
	return s.db.Queries().UpdateTerminalSessionRuntime(ctx, dbsqlc.UpdateTerminalSessionRuntimeParams{
		ID:                  sessionID,
		RuntimeState:        observed.State,
		LaunchCwd:           observed.Cwd,
		LastActivityAt:      lastActivity,
		LastRuntimeSequence: sql.NullInt64{Int64: int64(observed.Sequence), Valid: true},
	})
}

func (s *Service) Create(ctx context.Context, userID, projectID, name, idempotencyKey string) (Session, error) {
	if _, err := s.projects.Get(ctx, userID, projectID); err != nil {
		return Session{}, err
	}
	idempotencyKey = strings.TrimSpace(idempotencyKey)
	if idempotencyKey == "" {
		return Session{}, ErrIdempotencyKeyRequired
	}
	if existing, err := s.db.Queries().GetTerminalSessionByIdempotencyKey(ctx, dbsqlc.GetTerminalSessionByIdempotencyKeyParams{ProjectID: projectID, IdempotencyKey: sql.NullString{String: idempotencyKey, Valid: true}}); err == nil {
		return mapSession(existing), nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return Session{}, err
	}
	requestedName := strings.TrimSpace(name)
	if requestedName != "" && !validName(requestedName) {
		return Session{}, ErrInvalidName
	}
	var id string
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		sessionName := requestedName
		if _, err := q.LockProjectTerminalSessions(ctx, projectID); err != nil {
			return err
		}
		count, err := q.CountActiveTerminalSessions(ctx, projectID)
		if err != nil {
			return err
		}
		if count >= int32(s.maxActivePerProject) {
			return ErrLimit
		}
		ordinal := int32(0)
		if sessionName == "" {
			ordinal, err = q.NextTerminalSessionOrdinal(ctx, projectID)
			if err != nil {
				return err
			}
			sessionName = fmt.Sprintf("shell-%d", ordinal)
		}
		id = newID("pts")
		return q.CreateTerminalSession(ctx, dbsqlc.CreateTerminalSessionParams{ID: id, ProjectID: projectID, TerminalID: newID("term"), Name: sessionName, AutoNameOrdinal: ordinal, IdempotencyKey: sql.NullString{String: idempotencyKey, Valid: true}})
	})
	if err != nil {
		if unique(err) {
			existing, lookupErr := s.db.Queries().GetTerminalSessionByIdempotencyKey(ctx, dbsqlc.GetTerminalSessionByIdempotencyKeyParams{ProjectID: projectID, IdempotencyKey: sql.NullString{String: idempotencyKey, Valid: true}})
			if lookupErr == nil {
				return mapSession(existing), nil
			}
			if !errors.Is(lookupErr, sql.ErrNoRows) {
				return Session{}, lookupErr
			}
			return Session{}, ErrConflict
		}
		return Session{}, err
	}
	created, err := s.get(ctx, projectID, id)
	if err == nil {
		observability.TerminalSessionCreated()
	}
	return created, err
}

func (s *Service) Rename(ctx context.Context, userID, projectID, id, name string) (Session, error) {
	if _, err := s.projects.Get(ctx, userID, projectID); err != nil {
		return Session{}, err
	}
	if !validName(name) {
		return Session{}, ErrInvalidName
	}
	n, err := s.db.Queries().RenameTerminalSession(ctx, dbsqlc.RenameTerminalSessionParams{ProjectID: projectID, ID: id, Name: name})
	if err != nil {
		if unique(err) {
			return Session{}, ErrConflict
		}
		return Session{}, err
	}
	if n == 0 {
		return Session{}, ErrNotFound
	}
	return s.get(ctx, projectID, id)
}
func (s *Service) Close(ctx context.Context, userID, projectID, id string) (bool, error) {
	if _, err := s.projects.Get(ctx, userID, projectID); err != nil {
		return false, err
	}
	if err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		if _, err := q.LockProjectTerminalSessions(ctx, projectID); err != nil {
			return err
		}
		n, err := q.CloseTerminalSession(ctx, dbsqlc.CloseTerminalSessionParams{ProjectID: projectID, ID: id})
		if err != nil {
			return err
		}
		if n == 0 {
			// A prior close may already be pending or applied. Preserve that
			// operation instead of enqueueing another physical PTY close.
			if _, err := q.GetActiveTerminalSession(ctx, dbsqlc.GetActiveTerminalSessionParams{ProjectID: projectID, ID: id}); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return ErrNotFound
				}
				return err
			}
			return nil
		}
		return q.QueueTerminalSessionOperation(ctx, dbsqlc.QueueTerminalSessionOperationParams{ID: newID("tso"), ProjectID: projectID, TerminalSessionID: id, Operation: "close"})
	}); err != nil {
		return false, err
	}
	observability.TerminalSessionClosed()
	return s.operationApplied(ctx, projectID, id)
}
func (s *Service) Delete(ctx context.Context, userID, projectID, id string) (bool, error) {
	if _, err := s.projects.Get(ctx, userID, projectID); err != nil {
		return false, err
	}
	if err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		if _, err := q.LockProjectTerminalSessions(ctx, projectID); err != nil {
			return err
		}
		current, err := q.GetActiveTerminalSession(ctx, dbsqlc.GetActiveTerminalSessionParams{ProjectID: projectID, ID: id})
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if current.IsDefault {
			return ErrReserved
		}
		n, err := q.DeleteTerminalSession(ctx, dbsqlc.DeleteTerminalSessionParams{ProjectID: projectID, ID: id})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrNotFound
		}
		return q.QueueTerminalSessionOperation(ctx, dbsqlc.QueueTerminalSessionOperationParams{ID: newID("tso"), ProjectID: projectID, TerminalSessionID: id, Operation: "delete_history"})
	}); err != nil {
		return false, err
	}
	observability.TerminalSessionDeleted()
	return s.operationApplied(ctx, projectID, id)
}

func (s *Service) operationApplied(ctx context.Context, projectID, sessionID string) (bool, error) {
	// A control-route failure leaves the durable operation for the worker. The
	// caller still receives a successful pending response rather than losing
	// the logical close/delete request.
	_ = s.ApplyPending(ctx, projectID)
	pending, err := s.db.Queries().TerminalSessionOperationPending(ctx, dbsqlc.TerminalSessionOperationPendingParams{ProjectID: projectID, TerminalSessionID: sessionID})
	return !pending, err
}
func (s *Service) get(ctx context.Context, projectID, id string) (Session, error) {
	row, err := s.db.Queries().GetActiveTerminalSession(ctx, dbsqlc.GetActiveTerminalSessionParams{ProjectID: projectID, ID: id})
	if err != nil {
		return Session{}, ErrNotFound
	}
	return mapSession(row), nil
}
func mapSession(row dbsqlc.ProjectTerminalSession) Session {
	var active *time.Time
	if row.LastActivityAt.Valid {
		value := row.LastActivityAt.Time
		active = &value
	}
	return Session{ID: row.ID, Name: row.Name, IsDefault: row.IsDefault, State: row.RuntimeState, LastActiveAt: active, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}
}

func validName(name string) bool {
	return name != "default" && !regexp.MustCompile(`^shell-[0-9]+$`).MatchString(name) && namePattern.MatchString(name)
}
func unique(err error) bool { var pg *pgconn.PgError; return errors.As(err, &pg) && pg.Code == "23505" }
func newID(prefix string) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return prefix + "_" + hex.EncodeToString(b[:])
}
