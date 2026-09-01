package previewattachment

import (
	"context"
	"fmt"
	"time"
)

// AttachmentRepository is the persistence boundary used by Service. The SQL
// repository is the production implementation; keeping the interface here
// makes state-machine tests deterministic without silently making the
// in-memory Manager a production authority.
type AttachmentRepository interface {
	Get(context.Context, string, string) (Attachment, error)
	CreatePending(context.Context, Attachment) (Attachment, error)
	Admit(context.Context, Attachment, time.Time) (Attachment, error)
	ObserveEdge(context.Context, Attachment, time.Time) (Attachment, error)
	ObserveOrigin(context.Context, Attachment, bool, time.Time) (Attachment, error)
	Renew(context.Context, Attachment, Attachment, time.Time) (Attachment, error)
	Release(context.Context, Attachment, time.Time) (Attachment, error)
}

// PreviewCarrierAdmissionOutbox is implemented by SQLRepository. Prepare is
// called before the edge side effect, so a process crash after delivery but
// before the state CAS leaves replayable work instead of an untracked route.
type PreviewCarrierAdmissionOutbox interface {
	PreparePreviewCarrierAdmission(context.Context, Attachment, time.Time) error
}

// Service is the SQL-backed production orchestration layer. It owns
// authorization and publisher ordering, while every durable state transition
// is delegated to AttachmentRepository. Manager remains useful as a
// deterministic policy harness, but must not be wired into production.
type Service struct {
	repository AttachmentRepository
	authority  Authority
	publisher  AdmissionPublisher
	now        func() time.Time
}

func NewService(repository AttachmentRepository, authority Authority, publisher AdmissionPublisher) (*Service, error) {
	if repository == nil || authority == nil {
		return nil, fmt.Errorf("%w: attachment service dependencies are incomplete", ErrInvalid)
	}
	return &Service{
		repository: repository,
		authority:  authority,
		publisher:  publisher,
		now:        func() time.Time { return time.Now().UTC() },
	}, nil
}

func (s *Service) SetClock(now func() time.Time) error {
	if s == nil || now == nil {
		return fmt.Errorf("%w: nil service clock", ErrInvalid)
	}
	s.now = now
	return nil
}

func (s *Service) SetAdmissionPublisher(publisher AdmissionPublisher) error {
	if s == nil || publisher == nil {
		return fmt.Errorf("%w: nil edge admission publisher", ErrInvalid)
	}
	s.publisher = publisher
	return nil
}

// Allocate resolves the durable lease and current canonical carrier before
// inserting the pending row. Exact operation replays return the stored row;
// a reconnect may only advance the same route binding through the repository
// CAS and can never create a second live operation for one preview.
func (s *Service) Allocate(ctx context.Context, proof MachineProof, req Request) (Attachment, error) {
	if err := validateRequestProof(proof, req); err != nil {
		return Attachment{}, err
	}
	if s == nil || s.repository == nil || s.authority == nil || ctx == nil {
		return Attachment{}, fmt.Errorf("%w: attachment service is not available", ErrInvalid)
	}
	resolution, err := s.authority.ResolvePreviewAttachment(ctx, ResolveRequest{Proof: proof, Request: req})
	if err != nil {
		return Attachment{}, err
	}
	now := s.clock()
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
	pending := attachmentFromResolution(req, hash, resolution, now)
	current, err := s.repository.CreatePending(ctx, pending)
	if err != nil {
		return Attachment{}, err
	}
	if current.RequestHash != hash {
		return Attachment{}, fmt.Errorf("%w: operation %s was already used with another request", ErrIdempotencyConflict, req.OperationID)
	}
	if isTerminal(current.State) {
		return Attachment{}, fmt.Errorf("%w: operation %s", ErrTerminal, req.OperationID)
	}
	if !logicalBindingEqual(current.Binding, pending.Binding) {
		return Attachment{}, fmt.Errorf("%w: route or canonical identity changed for operation %s", ErrConflict, req.OperationID)
	}
	if current.AttachmentGeneration == 0 {
		return Attachment{}, fmt.Errorf("%w: persisted attachment has no generation", ErrConflict)
	}
	if carrierBindingEqual(current.Binding, pending.Binding) && current.ExpiresAt.Equal(pending.ExpiresAt) {
		return current, nil
	}
	pending.AttachmentGeneration = current.AttachmentGeneration
	return s.repository.Renew(ctx, current, pending, now)
}

// Admit publishes only the exact current generation. The persisted state is
// advanced after accepted/already-accepted delivery; a transport timeout
// therefore leaves the row pending and safe to retry.
func (s *Service) Admit(ctx context.Context, proof MachineProof, req Request, binding Binding, generation uint64) (Attachment, error) {
	if err := validateRequestProof(proof, req); err != nil {
		return Attachment{}, err
	}
	if s == nil || s.repository == nil || s.authority == nil || ctx == nil {
		return Attachment{}, fmt.Errorf("%w: attachment service is not available", ErrInvalid)
	}
	resolution, err := s.authority.ResolvePreviewAttachment(ctx, ResolveRequest{Proof: proof, Request: req})
	if err != nil {
		return Attachment{}, err
	}
	now := s.clock()
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
	current, err := s.repository.Get(ctx, currentBinding.AccountID, req.OperationID)
	if err != nil {
		return Attachment{}, err
	}
	if err := checkRecordRequest(current, req, current.AccountID); err != nil {
		return Attachment{}, err
	}
	if current.Binding != binding {
		return Attachment{}, fmt.Errorf("%w: attachment binding differs from current binding", ErrStaleBinding)
	}
	if current.AttachmentGeneration == generation+1 && current.Binding == binding && current.State == StateAdmitted {
		return current, nil
	}
	if current.AttachmentGeneration != generation {
		return Attachment{}, fmt.Errorf("%w: expected attachment generation %d, got %d", ErrStaleBinding, current.AttachmentGeneration, generation)
	}
	if isTerminal(current.State) {
		return Attachment{}, fmt.Errorf("%w: cannot admit %s", ErrTerminal, req.OperationID)
	}
	if current.State != StatePending {
		return current, nil
	}
	if s.publisher == nil {
		return Attachment{}, fmt.Errorf("%w: no edge admission publisher configured", ErrAdmissionUnavailable)
	}
	if outbox, ok := s.repository.(PreviewCarrierAdmissionOutbox); ok {
		if err := outbox.PreparePreviewCarrierAdmission(ctx, current, now); err != nil {
			return Attachment{}, err
		}
	}
	admission, err := current.AdmissionRequest()
	if err != nil {
		return Attachment{}, err
	}
	delivery, err := s.publisher.PublishPreviewCarrierAdmission(ctx, admission)
	if err != nil {
		return Attachment{}, fmt.Errorf("%w: %v", ErrAdmissionUnavailable, err)
	}
	if !delivery.Accepted() {
		return Attachment{}, fmt.Errorf("%w: edge returned %s", ErrAdmissionUnavailable, delivery.Status)
	}
	return s.repository.Admit(ctx, current, now)
}

// ObserveEdge is reserved for the authenticated edge transport adapter. Do
// not expose it through the machine-proof HTTP handler.
func (s *Service) ObserveEdge(ctx context.Context, req Request, binding Binding, generation uint64) (Attachment, error) {
	if ctx == nil {
		return Attachment{}, fmt.Errorf("%w: nil context", ErrInvalid)
	}
	if err := req.Validate(); err != nil {
		return Attachment{}, err
	}
	if req.OperationID != binding.OperationID || req.PreviewID != binding.PreviewID || req.OwnerDeviceID != binding.OwnerDeviceID || req.OwnerSessionID != binding.OwnerSessionID {
		return Attachment{}, fmt.Errorf("%w: edge admission request does not match binding", ErrUnauthorized)
	}
	current, err := s.repository.Get(ctx, binding.AccountID, req.OperationID)
	if err != nil {
		return Attachment{}, err
	}
	if err := checkRecordRequest(current, req, binding.AccountID); err != nil {
		return Attachment{}, err
	}
	if current.Binding != binding {
		return Attachment{}, fmt.Errorf("%w: attachment binding differs from current binding", ErrStaleBinding)
	}
	if current.AttachmentGeneration != generation {
		if current.AttachmentGeneration > generation && current.EdgeReady {
			return current, nil
		}
		return Attachment{}, fmt.Errorf("%w: expected attachment generation %d, got %d", ErrStaleBinding, current.AttachmentGeneration, generation)
	}
	return s.repository.ObserveEdge(ctx, current, s.clock())
}

// ObserveOrigin is the only readiness operation reachable with a machine
// proof. It can report the owner's origin result only after the repository
// records edge admission, and can never set edge_ready itself.
func (s *Service) ObserveOrigin(ctx context.Context, proof MachineProof, req Request, binding Binding, generation uint64, originReady bool) (Attachment, error) {
	if err := validateRequestProof(proof, req); err != nil {
		return Attachment{}, err
	}
	if s == nil || s.repository == nil || s.authority == nil || ctx == nil {
		return Attachment{}, fmt.Errorf("%w: attachment service is not available", ErrInvalid)
	}
	resolution, err := s.authority.ResolvePreviewAttachment(ctx, ResolveRequest{Proof: proof, Request: req})
	if err != nil {
		return Attachment{}, err
	}
	now := s.clock()
	if err := validateResolution(now, resolution); err != nil {
		return Attachment{}, err
	}
	if err := authorizeResolution(proof, req, resolution); err != nil {
		return Attachment{}, err
	}
	if !carrierBindingEqual(binding, bindingFromResolution(resolution)) {
		return Attachment{}, fmt.Errorf("%w: readiness callback is not for the current carrier", ErrStaleBinding)
	}
	current, err := s.repository.Get(ctx, resolution.Lease.AccountID, req.OperationID)
	if err != nil {
		return Attachment{}, err
	}
	if err := checkRecordRequest(current, req, current.AccountID); err != nil {
		return Attachment{}, err
	}
	if current.Binding != binding {
		return Attachment{}, fmt.Errorf("%w: attachment binding differs from current binding", ErrStaleBinding)
	}
	if current.AttachmentGeneration != generation {
		postState := StateEdgeReady
		if originReady {
			postState = StateReady
		}
		if current.AttachmentGeneration == generation+1 && current.State == postState && current.EdgeReady && current.OriginReady == originReady {
			return current, nil
		}
		return Attachment{}, fmt.Errorf("%w: expected attachment generation %d, got %d", ErrStaleBinding, current.AttachmentGeneration, generation)
	}
	return s.repository.ObserveOrigin(ctx, current, originReady, now)
}

// Renew resolves the current canonical session, then performs a fenced SQL
// update. Session changes require a higher process generation and reset
// readiness in the repository; route identity never changes.
func (s *Service) Renew(ctx context.Context, proof MachineProof, req Request, generation uint64) (Attachment, error) {
	if err := validateRequestProof(proof, req); err != nil {
		return Attachment{}, err
	}
	if s == nil || s.repository == nil || s.authority == nil || ctx == nil {
		return Attachment{}, fmt.Errorf("%w: attachment service is not available", ErrInvalid)
	}
	resolution, err := s.authority.ResolvePreviewAttachment(ctx, ResolveRequest{Proof: proof, Request: req})
	if err != nil {
		return Attachment{}, err
	}
	now := s.clock()
	if err := validateResolution(now, resolution); err != nil {
		return Attachment{}, err
	}
	if err := authorizeResolution(proof, req, resolution); err != nil {
		return Attachment{}, err
	}
	current, err := s.repository.Get(ctx, resolution.Lease.AccountID, req.OperationID)
	if err != nil {
		return Attachment{}, err
	}
	if err := checkRecordRequest(current, req, current.AccountID); err != nil {
		return Attachment{}, err
	}
	if current.AttachmentGeneration == generation+1 && current.Binding == bindingFromResolution(resolution) && current.ExpiresAt.After(now) {
		return current, nil
	}
	if current.AttachmentGeneration != generation {
		return Attachment{}, fmt.Errorf("%w: expected attachment generation %d, got %d", ErrStaleBinding, current.AttachmentGeneration, generation)
	}
	if isTerminal(current.State) {
		return Attachment{}, fmt.Errorf("%w: cannot renew %s", ErrTerminal, req.OperationID)
	}
	next := attachmentFromResolution(req, current.RequestHash, resolution, now)
	next.AttachmentGeneration = current.AttachmentGeneration
	return s.repository.Renew(ctx, current, next, now)
}

// Release accepts the exact attachment returned to the host. It does not
// resolve the live lease again, so cleanup remains possible after dashboard
// Stop terminalizes that lease. The SQL trigger still checks the immutable
// account/preview/operation/owner relationship.
func (s *Service) Release(ctx context.Context, proof MachineProof, req Request, attachment Attachment, generation uint64) (Attachment, error) {
	if err := validateRequestProof(proof, req); err != nil {
		return Attachment{}, err
	}
	if s == nil || s.repository == nil || ctx == nil {
		return Attachment{}, fmt.Errorf("%w: attachment service is not available", ErrInvalid)
	}
	if attachment.OperationID != req.OperationID || attachment.OwnerDeviceID != proof.MachineID || attachment.OwnerDeviceID != req.OwnerDeviceID || attachment.OperationID != proof.OperationID || attachment.AccountID == "" {
		return Attachment{}, ErrUnauthorized
	}
	if err := checkRecordRequest(attachment, req, attachment.AccountID); err != nil {
		return Attachment{}, err
	}
	current, err := s.repository.Get(ctx, attachment.AccountID, req.OperationID)
	if err != nil {
		return Attachment{}, err
	}
	if current.Binding != attachment.Binding {
		return Attachment{}, fmt.Errorf("%w: attachment binding differs from current binding", ErrStaleBinding)
	}
	if current.AttachmentGeneration == generation+1 && current.State == StateReleased {
		return current, nil
	}
	if current.AttachmentGeneration != generation {
		return Attachment{}, fmt.Errorf("%w: expected attachment generation %d, got %d", ErrStaleBinding, current.AttachmentGeneration, generation)
	}
	return s.repository.Release(ctx, current, s.clock())
}

func (s *Service) Get(ctx context.Context, accountID, operationID string) (Attachment, error) {
	if s == nil || s.repository == nil || ctx == nil {
		return Attachment{}, fmt.Errorf("%w: attachment service is not available", ErrInvalid)
	}
	return s.repository.Get(ctx, accountID, operationID)
}

func (s *Service) Expire(ctx context.Context) error {
	if s == nil || s.repository == nil || ctx == nil {
		return fmt.Errorf("%w: attachment service is not available", ErrInvalid)
	}
	if expirer, ok := s.repository.(interface {
		Expire(context.Context, time.Time) error
	}); ok {
		return expirer.Expire(ctx, s.clock())
	}
	return fmt.Errorf("%w: attachment repository does not support expiry", ErrInvalid)
}

func (s *Service) clock() time.Time {
	if s == nil || s.now == nil {
		return time.Now().UTC()
	}
	return s.now().UTC()
}
