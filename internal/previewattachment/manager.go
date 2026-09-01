package previewattachment

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Manager owns the short-lived attachment state.  The state can be rebuilt
// from a live lease and a fresh carrier session after a server restart; it is
// never used to restore a host's carrier or any private material.
type Manager struct {
	authority Authority
	publisher AdmissionPublisher
	now       func() time.Time

	mu sync.Mutex
	// Allocation is serialized so two first requests cannot mint two
	// preview-ephemeral carrier identities before the idempotency row exists.
	// Admission/readiness remain concurrent behind mu.
	allocateMu  sync.Mutex
	byOperation map[string]*record
	byPreview   map[string]*record
}

type record struct {
	attachment Attachment
	actorID    string
}

func NewManager(authority Authority) (*Manager, error) {
	if authority == nil {
		return nil, fmt.Errorf("%w: nil attachment authority", ErrInvalid)
	}
	return &Manager{
		authority:   authority,
		now:         func() time.Time { return time.Now().UTC() },
		byOperation: make(map[string]*record),
		byPreview:   make(map[string]*record),
	}, nil
}

// SetClock is intended for deterministic tests and controlled integration
// tests.  Production callers should leave the default clock in place.
func (m *Manager) SetClock(now func() time.Time) error {
	if now == nil {
		return fmt.Errorf("%w: nil clock", ErrInvalid)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.now = now
	return nil
}

// SetAdmissionPublisher installs the server-to-edge write boundary.  An
// attachment cannot become admitted without this publisher accepting the
// exact generation-fenced request.
func (m *Manager) SetAdmissionPublisher(publisher AdmissionPublisher) error {
	if publisher == nil {
		return fmt.Errorf("%w: nil admission publisher", ErrInvalid)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.publisher = publisher
	return nil
}

// Allocate creates the first attachment for a preview operation.  Repeating
// the exact request is idempotent.  If the live connector has reconnected,
// the same operation is re-bound to the newer connector session and its
// attachment generation advances; no second route or URL is allocated.
func (m *Manager) Allocate(ctx context.Context, proof MachineProof, req Request) (Attachment, error) {
	if err := validateRequestProof(proof, req); err != nil {
		return Attachment{}, err
	}
	m.allocateMu.Lock()
	defer m.allocateMu.Unlock()
	resolution, err := m.resolve(ctx, proof, req)
	if err != nil {
		return Attachment{}, err
	}
	now := m.clock()
	if err := validateResolution(now, resolution); err != nil {
		return Attachment{}, err
	}
	if err := authorizeResolution(proof, req, resolution); err != nil {
		return Attachment{}, err
	}
	hash, err := req.Hash(resolution.Lease.AccountID)
	if err != nil {
		return Attachment{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.expireLocked(now)
	opKey := operationKey(resolution.Lease.AccountID, req.OperationID)
	previewKey := operationKey(resolution.Lease.AccountID, req.PreviewID)
	if existing := m.byOperation[opKey]; existing != nil {
		if existing.attachment.RequestHash != hash {
			return Attachment{}, fmt.Errorf("%w: operation %s was already used with another request", ErrIdempotencyConflict, req.OperationID)
		}
		if isTerminal(existing.attachment.State) {
			return Attachment{}, fmt.Errorf("%w: operation %s", ErrTerminal, req.OperationID)
		}
		if err := m.rebindLocked(existing, resolution, now); err != nil {
			return Attachment{}, err
		}
		return cloneAttachment(existing.attachment), nil
	}
	if existing := m.byPreview[previewKey]; existing != nil && !isTerminal(existing.attachment.State) {
		return Attachment{}, fmt.Errorf("%w: preview already has operation %s", ErrConflict, existing.attachment.OperationID)
	}
	attachment := attachmentFromResolution(req, hash, resolution, now)
	if err := attachment.Validate(now); err != nil {
		return Attachment{}, err
	}
	r := &record{attachment: attachment, actorID: resolution.Lease.ActorID}
	m.byOperation[opKey] = r
	m.byPreview[previewKey] = r
	return cloneAttachment(attachment), nil
}

// Admit publishes the exact server allocation to the authenticated edge and
// records accepted/already-accepted delivery. Edge readiness is confirmed by
// ObserveEdge; origin readiness is observed separately, so this method can
// never make a host request look ready by itself.
func (m *Manager) Admit(ctx context.Context, proof MachineProof, req Request, binding Binding, generation uint64) (Attachment, error) {
	if err := validateRequestProof(proof, req); err != nil {
		return Attachment{}, err
	}
	resolution, err := m.resolve(ctx, proof, req)
	if err != nil {
		return Attachment{}, err
	}
	now := m.clock()
	if err := validateResolution(now, resolution); err != nil {
		return Attachment{}, err
	}
	if err := authorizeResolution(proof, req, resolution); err != nil {
		return Attachment{}, err
	}
	currentBinding := bindingFromResolution(resolution)
	if !carrierBindingEqual(binding, currentBinding) {
		return Attachment{}, fmt.Errorf("%w: current carrier session no longer matches", ErrStaleBinding)
	}

	m.mu.Lock()
	m.expireLocked(now)
	r := m.byOperation[operationKey(resolution.Lease.AccountID, req.OperationID)]
	if r == nil {
		m.mu.Unlock()
		return Attachment{}, ErrNotFound
	}
	if err := checkRecordRequest(r.attachment, req, resolution.Lease.AccountID); err != nil {
		m.mu.Unlock()
		return Attachment{}, err
	}
	if r.attachment.AttachmentGeneration == generation+1 && r.attachment.Binding == binding && r.attachment.State == StateAdmitted {
		result := cloneAttachment(r.attachment)
		m.mu.Unlock()
		return result, nil
	}
	if err := checkGenerationAndBinding(r.attachment, binding, generation); err != nil {
		m.mu.Unlock()
		return Attachment{}, err
	}
	if isTerminal(r.attachment.State) {
		m.mu.Unlock()
		return Attachment{}, fmt.Errorf("%w: cannot admit %s", ErrTerminal, req.OperationID)
	}
	if r.attachment.State != StatePending {
		result := cloneAttachment(r.attachment)
		m.mu.Unlock()
		return result, nil
	}
	publisher := m.publisher
	if publisher == nil {
		m.mu.Unlock()
		return Attachment{}, fmt.Errorf("%w: no edge admission publisher configured", ErrAdmissionUnavailable)
	}
	admission, err := r.attachment.AdmissionRequest()
	if err != nil {
		m.mu.Unlock()
		return Attachment{}, err
	}
	m.mu.Unlock()
	delivery, err := publisher.PublishPreviewCarrierAdmission(ctx, admission)
	if err != nil {
		return Attachment{}, fmt.Errorf("%w: %v", ErrAdmissionUnavailable, err)
	}
	if !delivery.Accepted() {
		return Attachment{}, fmt.Errorf("%w: edge returned %s", ErrAdmissionUnavailable, delivery.Status)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.expireLocked(now)
	r = m.byOperation[operationKey(resolution.Lease.AccountID, req.OperationID)]
	if r == nil {
		return Attachment{}, ErrNotFound
	}
	if err := checkRecordRequest(r.attachment, req, resolution.Lease.AccountID); err != nil {
		return Attachment{}, err
	}
	if r.attachment.AttachmentGeneration == generation+1 && r.attachment.Binding == binding && r.attachment.State == StateAdmitted {
		return cloneAttachment(r.attachment), nil
	}
	if err := checkGenerationAndBinding(r.attachment, binding, generation); err != nil {
		return Attachment{}, err
	}
	if r.attachment.State != StatePending {
		return cloneAttachment(r.attachment), nil
	}
	r.attachment.State = StateAdmitted
	r.attachment.AttachmentGeneration++
	if err := r.attachment.Validate(now); err != nil {
		return Attachment{}, err
	}
	return cloneAttachment(r.attachment), nil
}

// ObserveEdge records the authenticated edge publisher's successful carrier
// attach. It deliberately has no MachineProof argument: only the edge mTLS
// transport adapter may call it. A host request cannot self-assert edge
// readiness through ObserveOrigin.
func (m *Manager) ObserveEdge(ctx context.Context, req Request, binding Binding, generation uint64) (Attachment, error) {
	if ctx == nil {
		return Attachment{}, fmt.Errorf("%w: nil context", ErrInvalid)
	}
	if err := ctx.Err(); err != nil {
		return Attachment{}, err
	}
	if err := req.Validate(); err != nil {
		return Attachment{}, err
	}
	if req.OperationID != binding.OperationID || req.PreviewID != binding.PreviewID || req.OwnerDeviceID != binding.OwnerDeviceID || req.OwnerSessionID != binding.OwnerSessionID {
		return Attachment{}, fmt.Errorf("%w: edge admission request does not match binding", ErrUnauthorized)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.clockLocked()
	m.expireLocked(now)
	r := m.byOperation[operationKey(binding.AccountID, req.OperationID)]
	if r == nil {
		return Attachment{}, ErrNotFound
	}
	if err := checkRecordRequest(r.attachment, req, binding.AccountID); err != nil {
		return Attachment{}, err
	}
	if r.attachment.AttachmentGeneration == generation+1 && r.attachment.Binding == binding && r.attachment.State == StateEdgeReady && r.attachment.EdgeReady {
		return cloneAttachment(r.attachment), nil
	}
	if err := checkGenerationAndBinding(r.attachment, binding, generation); err != nil {
		return Attachment{}, err
	}
	if isTerminal(r.attachment.State) {
		return Attachment{}, fmt.Errorf("%w: cannot observe edge for %s", ErrTerminal, req.OperationID)
	}
	if r.attachment.EdgeReady {
		return cloneAttachment(r.attachment), nil
	}
	if r.attachment.State != StateAdmitted {
		return Attachment{}, fmt.Errorf("%w: edge admission has not been accepted", ErrAdmissionUnavailable)
	}
	r.attachment.EdgeReady = true
	r.attachment.State = StateEdgeReady
	r.attachment.AttachmentGeneration++
	if err := r.attachment.Validate(now); err != nil {
		return Attachment{}, err
	}
	return cloneAttachment(r.attachment), nil
}

// ObserveOrigin records only the owner host's origin result. Edge readiness
// must already have been confirmed by ObserveEdge, and a host cannot clear or
// forge that flag.
func (m *Manager) ObserveOrigin(ctx context.Context, proof MachineProof, req Request, binding Binding, generation uint64, originReady bool) (Attachment, error) {
	if err := validateRequestProof(proof, req); err != nil {
		return Attachment{}, err
	}
	resolution, err := m.resolve(ctx, proof, req)
	if err != nil {
		return Attachment{}, err
	}
	now := m.clock()
	if err := validateResolution(now, resolution); err != nil {
		return Attachment{}, err
	}
	if err := authorizeResolution(proof, req, resolution); err != nil {
		return Attachment{}, err
	}
	if !carrierBindingEqual(binding, bindingFromResolution(resolution)) {
		return Attachment{}, fmt.Errorf("%w: readiness callback is not for the current carrier", ErrStaleBinding)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.expireLocked(now)
	r := m.byOperation[operationKey(resolution.Lease.AccountID, req.OperationID)]
	if r == nil {
		return Attachment{}, ErrNotFound
	}
	if err := checkRecordRequest(r.attachment, req, resolution.Lease.AccountID); err != nil {
		return Attachment{}, err
	}
	postState := StateEdgeReady
	if originReady {
		postState = StateReady
	}
	if r.attachment.AttachmentGeneration == generation+1 && r.attachment.Binding == binding && r.attachment.State == postState && r.attachment.EdgeReady && r.attachment.OriginReady == originReady {
		return cloneAttachment(r.attachment), nil
	}
	if err := checkGenerationAndBinding(r.attachment, binding, generation); err != nil {
		return Attachment{}, err
	}
	if isTerminal(r.attachment.State) {
		return Attachment{}, fmt.Errorf("%w: cannot observe %s", ErrTerminal, req.OperationID)
	}
	if !r.attachment.EdgeReady || (r.attachment.State != StateEdgeReady && r.attachment.State != StateReady) {
		return Attachment{}, fmt.Errorf("%w: edge admission has not been accepted", ErrAdmissionUnavailable)
	}
	if r.attachment.OriginReady == originReady {
		return cloneAttachment(r.attachment), nil
	}
	r.attachment.OriginReady = originReady
	r.attachment.AttachmentGeneration++
	if originReady {
		nowCopy := now
		r.attachment.ReadyAt = &nowCopy
		r.attachment.State = StateReady
	} else {
		r.attachment.ReadyAt = nil
		r.attachment.State = StateEdgeReady
	}
	if err := r.attachment.Validate(now); err != nil {
		return Attachment{}, err
	}
	return cloneAttachment(r.attachment), nil
}

// Renew extends only to the current authoritative lease/carrier deadline.
// It may rebind a reconnecting connector session, but never changes the
// preview, operation, owner, tunnel, connector, or route identity.
func (m *Manager) Renew(ctx context.Context, proof MachineProof, req Request, generation uint64) (Attachment, error) {
	if err := validateRequestProof(proof, req); err != nil {
		return Attachment{}, err
	}
	resolution, err := m.resolve(ctx, proof, req)
	if err != nil {
		return Attachment{}, err
	}
	now := m.clock()
	if err := validateResolution(now, resolution); err != nil {
		return Attachment{}, err
	}
	if err := authorizeResolution(proof, req, resolution); err != nil {
		return Attachment{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expireLocked(now)
	r := m.byOperation[operationKey(resolution.Lease.AccountID, req.OperationID)]
	if r == nil {
		return Attachment{}, ErrNotFound
	}
	if err := checkRecordRequest(r.attachment, req, resolution.Lease.AccountID); err != nil {
		return Attachment{}, err
	}
	if generation != r.attachment.AttachmentGeneration {
		return Attachment{}, fmt.Errorf("%w: expected attachment generation %d, got %d", ErrStaleBinding, r.attachment.AttachmentGeneration, generation)
	}
	if isTerminal(r.attachment.State) {
		return Attachment{}, fmt.Errorf("%w: cannot renew %s", ErrTerminal, req.OperationID)
	}
	if err := m.rebindLocked(r, resolution, now); err != nil {
		return Attachment{}, err
	}
	return cloneAttachment(r.attachment), nil
}

// Release is idempotent for the current exact generation and binding.  A
// delayed release from an old session cannot release a newer reconnect.
func (m *Manager) Release(_ context.Context, proof MachineProof, req Request, binding Binding, generation uint64) (Attachment, error) {
	if err := validateRequestProof(proof, req); err != nil {
		return Attachment{}, err
	}
	now := m.clock()
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.findOperationLocked(req.OperationID)
	if r == nil {
		return Attachment{}, ErrNotFound
	}
	if r.actorID != proof.UserID || r.attachment.OwnerDeviceID != proof.MachineID || r.attachment.OperationID != proof.OperationID {
		return Attachment{}, ErrUnauthorized
	}
	if err := checkRecordRequest(r.attachment, req, r.attachment.AccountID); err != nil {
		return Attachment{}, err
	}
	if r.attachment.AttachmentGeneration == generation+1 && r.attachment.Binding == binding && r.attachment.State == StateReleased {
		return cloneAttachment(r.attachment), nil
	}
	if err := checkGenerationAndBinding(r.attachment, binding, generation); err != nil {
		return Attachment{}, err
	}
	if r.attachment.State == StateReleased {
		return cloneAttachment(r.attachment), nil
	}
	if r.attachment.State == StateFailed {
		return cloneAttachment(r.attachment), nil
	}
	r.attachment.State = StateReleased
	r.attachment.EdgeReady = false
	r.attachment.OriginReady = false
	r.attachment.ReadyAt = nil
	nowCopy := now
	r.attachment.ReleasedAt = &nowCopy
	r.attachment.AttachmentGeneration++
	if now.After(r.attachment.IssuedAt) {
		r.attachment.ExpiresAt = now
	}
	return cloneAttachment(r.attachment), nil
}

func (m *Manager) Get(accountID, operationID string) (Attachment, error) {
	if !validID(accountID) || !validID(operationID) {
		return Attachment{}, fmt.Errorf("%w: invalid lookup key", ErrInvalid)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.byOperation[operationKey(accountID, operationID)]
	if r == nil {
		return Attachment{}, ErrNotFound
	}
	return cloneAttachment(r.attachment), nil
}

func (m *Manager) resolve(ctx context.Context, proof MachineProof, req Request) (Resolution, error) {
	resolution, err := m.authority.ResolvePreviewAttachment(ctx, ResolveRequest{Proof: proof, Request: req})
	if err != nil {
		return Resolution{}, err
	}
	return resolution, nil
}

func (m *Manager) rebindLocked(r *record, resolution Resolution, now time.Time) error {
	if err := validateResolution(now, resolution); err != nil {
		return err
	}
	newBinding := bindingFromResolution(resolution)
	if !logicalBindingEqual(r.attachment.Binding, newBinding) {
		return fmt.Errorf("%w: route or canonical identity changed for operation %s", ErrConflict, r.attachment.OperationID)
	}
	newExpiry := minTime(resolution.Lease.LeaseDeadline, resolution.Carrier.LeaseDeadline)
	if !carrierBindingEqual(r.attachment.Binding, newBinding) {
		if newBinding.ProcessGeneration < r.attachment.ProcessGeneration || newBinding.ConfigGeneration < r.attachment.ConfigGeneration || newBinding.RouteGeneration < r.attachment.RouteGeneration {
			return fmt.Errorf("%w: authority returned an older carrier generation", ErrStaleBinding)
		}
		carrierChanged := !dataCarrierBindingEqual(r.attachment.Binding, newBinding)
		r.attachment.Binding = newBinding
		r.attachment.ConfigContentHash = resolution.Carrier.ConfigContentHash
		r.attachment.EdgeEndpoints = append([]string(nil), resolution.Carrier.EdgeEndpoints...)
		r.attachment.AttachmentGeneration++
		if carrierChanged {
			r.attachment.EdgeReady = false
			r.attachment.OriginReady = false
			r.attachment.ReadyAt = nil
			r.attachment.State = StatePending
		}
	}
	r.attachment.ExpiresAt = newExpiry
	if err := r.attachment.Validate(now); err != nil {
		return err
	}
	return nil
}

func (m *Manager) expireLocked(now time.Time) {
	for _, r := range m.byOperation {
		if isTerminal(r.attachment.State) || r.attachment.ExpiresAt.After(now) {
			continue
		}
		r.attachment.State = StateFailed
		r.attachment.EdgeReady = false
		r.attachment.OriginReady = false
		r.attachment.ReadyAt = nil
		r.attachment.ReleasedAt = nil
		r.attachment.AttachmentGeneration++
	}
}

func (m *Manager) clock() time.Time {
	m.mu.Lock()
	now := m.clockLocked()
	m.mu.Unlock()
	return now
}

func (m *Manager) clockLocked() time.Time {
	return m.now().UTC()
}

func (m *Manager) findOperationLocked(operationID string) *record {
	var found *record
	for _, r := range m.byOperation {
		if r.attachment.OperationID != operationID {
			continue
		}
		if found != nil {
			return nil
		}
		found = r
	}
	return found
}

func attachmentFromResolution(req Request, hash string, resolution Resolution, now time.Time) Attachment {
	return Attachment{
		Schema: Schema, Kind: Kind,
		Binding:        bindingFromResolution(resolution),
		IdempotencyKey: req.IdempotencyKey, RequestID: req.RequestID, CorrelationID: req.CorrelationID, RequestHash: hash,
		Endpoint: resolution.Lease.Endpoint, Target: resolution.Lease.Target, AccessMode: resolution.Lease.AccessMode,
		ConfigContentHash:    resolution.Carrier.ConfigContentHash,
		EdgeEndpoints:        append([]string(nil), resolution.Carrier.EdgeEndpoints...),
		AttachmentGeneration: 1, IssuedAt: now, ExpiresAt: minTime(resolution.Lease.LeaseDeadline, resolution.Carrier.LeaseDeadline), State: StatePending,
	}
}

func validateRequestProof(proof MachineProof, req Request) error {
	if err := proof.Validate(); err != nil {
		return err
	}
	if err := req.Validate(); err != nil {
		return err
	}
	if proof.OperationID != req.OperationID || proof.MachineID != req.OwnerDeviceID {
		return fmt.Errorf("%w: proof identity does not match request owner or operation", ErrUnauthorized)
	}
	if proof.OperationID != req.IdempotencyKey {
		return fmt.Errorf("%w: idempotency key must equal proof operation ID", ErrUnauthorized)
	}
	return nil
}

func authorizeResolution(proof MachineProof, req Request, resolution Resolution) error {
	if resolution.Lease.ActorID != proof.UserID || resolution.Lease.OwnerDeviceID != proof.MachineID || resolution.Lease.OperationID != proof.OperationID || resolution.Lease.OwnerSessionID != req.OwnerSessionID {
		return fmt.Errorf("%w: authoritative lease does not match proof or owner session", ErrUnauthorized)
	}
	return nil
}

func checkRecordRequest(a Attachment, req Request, accountID string) error {
	hash, err := req.Hash(accountID)
	if err != nil {
		return err
	}
	if a.RequestHash != hash {
		return fmt.Errorf("%w: request hash differs from allocation", ErrIdempotencyConflict)
	}
	return nil
}

func checkGenerationAndBinding(a Attachment, binding Binding, generation uint64) error {
	if generation != a.AttachmentGeneration {
		return fmt.Errorf("%w: expected attachment generation %d, got %d", ErrStaleBinding, a.AttachmentGeneration, generation)
	}
	if !carrierBindingEqual(a.Binding, binding) {
		return fmt.Errorf("%w: attachment binding differs from current binding", ErrStaleBinding)
	}
	return nil
}

func operationKey(accountID, value string) string { return accountID + "\x00" + value }

func isTerminal(state string) bool { return state == StateFailed || state == StateReleased }

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func cloneAttachment(a Attachment) Attachment {
	a.EdgeEndpoints = append([]string(nil), a.EdgeEndpoints...)
	if a.ReadyAt != nil {
		readyAt := *a.ReadyAt
		a.ReadyAt = &readyAt
	}
	return a
}
