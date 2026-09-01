package previewattachment

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pinksaucepasta/paperboat-server/internal/canonicaljson"
	"github.com/pinksaucepasta/paperboat-server/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

const (
	// These paths intentionally match the canonical paperboat-tunnel control
	// client. Admissions are a complete desired-state snapshot; observations,
	// detachment notifications, and ACKs are separate authenticated batches.
	EdgeAdmissionPullPath = "/v1/edge/previews/carrier-admissions"
	EdgeAdmissionAckPath  = "/v1/edge/previews/carrier-admissions/ack"
	EdgeObservationPath   = "/v1/edge/previews/carrier-observations"
	EdgeDetachmentPath    = "/v1/edge/previews/carrier-detachments"

	// EdgeAdmissionMaxItems is a hard server safety bound. It is never a page
	// size accepted from the edge: a complete snapshot is either returned in
	// full or rejected closed.
	EdgeAdmissionMaxItems = maxPreviewCarrierAdmissions

	// EdgeControlMaxRequestBytes matches the canonical edge snapshot document
	// budget. A complete ACK/observation/detachment batch can legitimately be
	// larger than the 64 KiB host attachment request budget, so edge control
	// traffic must use its own bounded reader.
	EdgeControlMaxRequestBytes = 16 << 20
)

// PreviewEdgeIdentity is the server-known identity of one registered edge
// process. The opaque process epoch is required in addition to the stable
// node ID so an old overlapping process cannot mutate the replacement's
// admissions.
type PreviewEdgeIdentity struct {
	NodeID       string
	ProcessEpoch string
}

// PreviewEdgeRequestVerifier authenticates the edge control request and
// returns the server-known edge node and process identity. Implementations
// should bind this identity to the edge's mTLS peer certificate where
// available.
type PreviewEdgeRequestVerifier interface {
	VerifyPreviewEdgeRequest(context.Context, *http.Request, []byte) (PreviewEdgeIdentity, error)
}

// DBPreviewEdgeRequestVerifier is the default control-plane verifier. It
// reuses the existing edge-control credential and requires the node ID to be
// a currently registered node. The canonical data-plane peer verifier still
// validates the machine certificate against Binding.MachineIdentityPublicKey
// before installing a carrier route.
type DBPreviewEdgeRequestVerifier struct {
	db         *db.DB
	credential string
	now        func() time.Time
}

func NewDBPreviewEdgeRequestVerifier(database *db.DB, credential string) (*DBPreviewEdgeRequestVerifier, error) {
	if database == nil || database.Pool() == nil || strings.TrimSpace(credential) == "" {
		return nil, fmt.Errorf("%w: edge request verifier dependencies are incomplete", ErrInvalid)
	}
	return &DBPreviewEdgeRequestVerifier{db: database, credential: credential, now: func() time.Time { return time.Now().UTC() }}, nil
}

func (v *DBPreviewEdgeRequestVerifier) SetClock(now func() time.Time) error {
	if v == nil || now == nil {
		return fmt.Errorf("%w: nil edge verifier clock", ErrInvalid)
	}
	v.now = now
	return nil
}

func (v *DBPreviewEdgeRequestVerifier) VerifyPreviewEdgeRequest(ctx context.Context, r *http.Request, body []byte) (PreviewEdgeIdentity, error) {
	if v == nil || v.db == nil || v.db.Pool() == nil || r == nil || ctx == nil {
		return PreviewEdgeIdentity{}, ErrUnauthorized
	}
	if values := r.Header.Values("Authorization"); len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") || subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(values[0], "Bearer ")), []byte(v.credential)) != 1 {
		return PreviewEdgeIdentity{}, ErrUnauthorized
	}
	identity, err := edgeNodeIdentity(r, body)
	if err != nil {
		return PreviewEdgeIdentity{}, ErrUnauthorized
	}
	var currentEpoch string
	var available bool
	err = v.db.Pool().QueryRow(ctx, verifyPreviewEdgeNodeSQL, identity.NodeID, v.clock()).Scan(&currentEpoch, &available)
	if errors.Is(err, pgx.ErrNoRows) {
		return PreviewEdgeIdentity{}, ErrUnauthorized
	}
	if err != nil {
		return PreviewEdgeIdentity{}, err
	}
	if !available || currentEpoch != identity.ProcessEpoch {
		return PreviewEdgeIdentity{}, ErrUnauthorized
	}
	identity.ProcessEpoch = currentEpoch
	return identity, nil
}

func (v *DBPreviewEdgeRequestVerifier) clock() time.Time {
	if v == nil || v.now == nil {
		return time.Now().UTC()
	}
	return v.now().UTC()
}

// EdgeHTTPHandler exposes the complete authenticated edge control boundary.
// Pulling a snapshot never changes server state. Only an exact edge ACK may
// move a pending attachment to admitted; only a later edge observation may
// move it to edge_ready.
type EdgeHTTPHandler struct {
	service  *Service
	outbox   PreviewCarrierOutbox
	verifier PreviewEdgeRequestVerifier
	aliases  PreviewCarrierAliasProjector
}

type PreviewCarrierAliasBinding struct {
	AccountID            string
	PreviewID            string
	RouteID              string
	PreviewGeneration    uint64
	AttachmentGeneration uint64
}

// PreviewCarrierAliasProjector returns the complete certificate-ready alias
// set for the exact requested admission bindings. It must never return a key
// that was not requested. Empty slices explicitly withdraw aliases.
type PreviewCarrierAliasProjector interface {
	ProjectPreviewCarrierAliases(context.Context, string, string, []PreviewCarrierAliasBinding, time.Time) (map[PreviewCarrierAliasBinding][]CarrierAlias, error)
}

func NewEdgeHTTPHandler(service *Service, outbox PreviewCarrierOutbox, verifier PreviewEdgeRequestVerifier) (*EdgeHTTPHandler, error) {
	if service == nil || outbox == nil || verifier == nil {
		return nil, fmt.Errorf("%w: edge attachment HTTP dependencies are incomplete", ErrInvalid)
	}
	return &EdgeHTTPHandler{service: service, outbox: outbox, verifier: verifier}, nil
}

func (h *EdgeHTTPHandler) SetAliasProjector(projector PreviewCarrierAliasProjector) error {
	if h == nil || projector == nil {
		return fmt.Errorf("%w: preview carrier alias projector is required", ErrInvalid)
	}
	h.aliases = projector
	return nil
}

func (h *EdgeHTTPHandler) Register(mux *http.ServeMux) error {
	if h == nil || mux == nil {
		return fmt.Errorf("%w: nil edge attachment HTTP handler or mux", ErrInvalid)
	}
	mux.Handle("POST "+EdgeAdmissionPullPath, h)
	mux.Handle("POST "+EdgeAdmissionAckPath, h)
	mux.Handle("POST "+EdgeObservationPath, h)
	mux.Handle("POST "+EdgeDetachmentPath, h)
	return nil
}

func (h *EdgeHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.service == nil || h.outbox == nil || h.verifier == nil {
		writeAttachmentError(w, http.StatusServiceUnavailable, "edge_attachment_unavailable", "Preview edge attachment service is unavailable.", true)
		return
	}
	if r == nil || r.Method != http.MethodPost {
		writeAttachmentError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Preview edge control operations require POST.", false)
		return
	}
	raw, err := readEdgeControlBody(r)
	if err != nil {
		writeAttachmentError(w, http.StatusBadRequest, "invalid_request", "Preview edge attachment request is invalid.", false)
		return
	}
	identity, err := h.verifier.VerifyPreviewEdgeRequest(r.Context(), r, raw)
	if err != nil || !validID(identity.NodeID) || connectorprotocol.ValidateOpaqueEpoch(identity.ProcessEpoch) != nil {
		writeAttachmentError(w, http.StatusUnauthorized, "edge_identity_invalid", "The edge identity could not be verified.", false)
		return
	}
	switch strings.TrimSuffix(r.URL.Path, "/") {
	case EdgeAdmissionPullPath:
		h.pull(w, r, identity, raw)
	case EdgeAdmissionAckPath:
		h.ack(w, r, identity, raw)
	case EdgeObservationPath:
		h.observe(w, r, identity, raw)
	case EdgeDetachmentPath:
		h.detach(w, r, identity, raw)
	default:
		writeAttachmentError(w, http.StatusNotFound, "not_found", "Preview edge attachment endpoint was not found.", false)
	}
}

type edgeNodeRequest struct {
	EdgeNodeID   string `json:"edge_node_id"`
	ProcessEpoch string `json:"edge_process_epoch"`
}

func (h *EdgeHTTPHandler) pull(w http.ResponseWriter, r *http.Request, identity PreviewEdgeIdentity, raw []byte) {
	var input edgeNodeRequest
	if err := decodeEdgeJSON(raw, &input); err != nil || input.EdgeNodeID != identity.NodeID || input.ProcessEpoch != identity.ProcessEpoch {
		writeAttachmentError(w, http.StatusBadRequest, "invalid_request", "Preview edge admission pull is invalid.", false)
		return
	}
	items, err := h.outbox.PullPreviewCarrierSnapshot(r.Context(), identity.NodeID, identity.ProcessEpoch)
	if err != nil {
		writeAttachmentServiceError(w, err)
		return
	}
	detachItems, err := h.outbox.PullPreviewCarrierDetachOutbox(r.Context(), identity.NodeID, identity.ProcessEpoch)
	if err != nil {
		writeAttachmentServiceError(w, err)
		return
	}
	admissions := make([]CarrierAdmission, 0, len(items))
	for _, item := range items {
		admission, convertErr := carrierAdmissionFromOutbox(item, h.service.clock())
		if convertErr != nil {
			writeAttachmentServiceError(w, convertErr)
			return
		}
		admissions = append(admissions, admission)
	}
	if h.aliases != nil && len(admissions) > 0 {
		bindings := make([]PreviewCarrierAliasBinding, len(admissions))
		requested := make(map[PreviewCarrierAliasBinding]struct{}, len(admissions))
		for index, admission := range admissions {
			binding := PreviewCarrierAliasBinding{
				AccountID: admission.Binding.AccountID, PreviewID: admission.Binding.PreviewID,
				RouteID: admission.Binding.RouteID, PreviewGeneration: admission.Binding.LeaseGeneration,
				AttachmentGeneration: admission.AttachmentGeneration,
			}
			bindings[index] = binding
			requested[binding] = struct{}{}
		}
		projected, projectErr := h.aliases.ProjectPreviewCarrierAliases(r.Context(), identity.NodeID, identity.ProcessEpoch, bindings, h.service.clock())
		if projectErr != nil {
			writeAttachmentServiceError(w, projectErr)
			return
		}
		for binding := range projected {
			if _, ok := requested[binding]; !ok {
				writeAttachmentServiceError(w, fmt.Errorf("%w: alias projector returned an unrequested binding", ErrConflict))
				return
			}
		}
		for index := range admissions {
			admissions[index].Aliases = append([]CarrierAlias(nil), projected[bindings[index]]...)
			if validateErr := admissions[index].Validate(h.service.clock()); validateErr != nil {
				writeAttachmentServiceError(w, validateErr)
				return
			}
		}
	}
	detachments := make([]PreviewCarrierDetachment, 0, len(detachItems))
	for _, item := range detachItems {
		detachment, convertErr := carrierDetachmentFromOutbox(item, h.service.clock())
		if convertErr != nil {
			writeAttachmentServiceError(w, convertErr)
			return
		}
		detachments = append(detachments, detachment)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Schema      string                     `json:"schema"`
		Kind        string                     `json:"kind"`
		Complete    bool                       `json:"complete"`
		Admissions  []CarrierAdmission         `json:"admissions"`
		Detachments []PreviewCarrierDetachment `json:"detachments"`
	}{Schema: Schema, Kind: Kind, Complete: true, Admissions: admissions, Detachments: detachments})
}

type edgeAdmissionAckRequest struct {
	EdgeNodeID   string             `json:"edge_node_id"`
	ProcessEpoch string             `json:"edge_process_epoch"`
	Admissions   []CarrierAdmission `json:"admissions"`
}

func (h *EdgeHTTPHandler) ack(w http.ResponseWriter, r *http.Request, identity PreviewEdgeIdentity, raw []byte) {
	var input edgeAdmissionAckRequest
	if err := decodeEdgeJSON(raw, &input); err != nil || input.EdgeNodeID != identity.NodeID || input.ProcessEpoch != identity.ProcessEpoch || len(input.Admissions) > EdgeAdmissionMaxItems {
		writeAttachmentError(w, http.StatusBadRequest, "invalid_request", "Preview edge admission acknowledgement is invalid.", false)
		return
	}
	now := h.service.clock()
	for _, admission := range input.Admissions {
		if admission.Binding.EdgeNodeID != identity.NodeID || admission.Binding.EdgeProcessEpoch != identity.ProcessEpoch {
			writeAttachmentError(w, http.StatusBadRequest, "invalid_request", "Preview edge admission is bound to another edge node.", false)
			return
		}
		if err := admission.Validate(now); err != nil {
			writeAttachmentServiceError(w, err)
			return
		}
	}
	for _, admission := range input.Admissions {
		if err := h.outbox.AcknowledgePreviewCarrierOutbox(r.Context(), identity.NodeID, identity.ProcessEpoch, admission.Binding.AccountID, admission.Binding.OperationID, admission.AttachmentGeneration, "admit"); err != nil {
			writeAttachmentServiceError(w, err)
			return
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

type edgeObservationBatch struct {
	EdgeNodeID   string                      `json:"edge_node_id"`
	ProcessEpoch string                      `json:"edge_process_epoch"`
	Observations []PreviewCarrierObservation `json:"observations"`
}

type PreviewCarrierObservation struct {
	Schema               string    `json:"schema"`
	Kind                 string    `json:"kind"`
	Binding              Binding   `json:"binding"`
	AttachmentGeneration uint64    `json:"attachment_generation"`
	State                string    `json:"state"`
	Reason               string    `json:"reason,omitempty"`
	ObservedAt           time.Time `json:"observed_at"`
}

func (h *EdgeHTTPHandler) observe(w http.ResponseWriter, r *http.Request, identity PreviewEdgeIdentity, raw []byte) {
	var input edgeObservationBatch
	if err := decodeEdgeJSON(raw, &input); err != nil || input.EdgeNodeID != identity.NodeID || input.ProcessEpoch != identity.ProcessEpoch || len(input.Observations) > EdgeAdmissionMaxItems {
		writeAttachmentError(w, http.StatusBadRequest, "invalid_request", "Preview edge observation is invalid.", false)
		return
	}
	now := h.service.clock()
	for _, observation := range input.Observations {
		if err := validateEdgeObservation(observation, identity.NodeID, identity.ProcessEpoch, now); err != nil {
			writeAttachmentServiceError(w, err)
			return
		}
	}
	for _, observation := range input.Observations {
		if err := h.observeOne(r, observation); err != nil {
			writeAttachmentServiceError(w, err)
			return
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (h *EdgeHTTPHandler) observeOne(r *http.Request, observation PreviewCarrierObservation) error {
	current, err := h.service.Get(r.Context(), observation.Binding.AccountID, observation.Binding.OperationID)
	if err != nil {
		return err
	}
	if current.Binding != observation.Binding {
		return ErrStaleBinding
	}
	switch observation.State {
	case "edge_ready":
		// The worker reports the command generation that it installed. ACK has
		// already advanced the server row by one. A later edge/origin update is
		// an idempotent replay against the persisted current generation.
		if current.State == StateAdmitted {
			if current.AttachmentGeneration != observation.AttachmentGeneration+1 {
				return ErrStaleBinding
			}
		} else if !current.EdgeReady || current.AttachmentGeneration < observation.AttachmentGeneration+1 {
			return ErrAdmissionUnavailable
		}
		request := requestFromAttachment(current)
		_, err = h.service.ObserveEdge(r.Context(), request, current.Binding, current.AttachmentGeneration)
		return err
	case "detached", "expired":
		// A detach/expiry observation is informational. Release/expiry on the
		// server is the authority that enqueues the durable detach command.
		if observation.AttachmentGeneration > current.AttachmentGeneration {
			return ErrStaleBinding
		}
		return nil
	default:
		return fmt.Errorf("%w: unknown edge observation state", ErrInvalid)
	}
}

type edgeDetachmentBatch struct {
	EdgeNodeID   string                     `json:"edge_node_id"`
	ProcessEpoch string                     `json:"edge_process_epoch"`
	Detachments  []PreviewCarrierDetachment `json:"detachments"`
}

type PreviewCarrierDetachment struct {
	Schema               string    `json:"schema"`
	Kind                 string    `json:"kind"`
	Binding              Binding   `json:"binding"`
	AttachmentGeneration uint64    `json:"attachment_generation"`
	Reason               string    `json:"reason"`
	ObservedAt           time.Time `json:"observed_at"`
}

func (h *EdgeHTTPHandler) detach(w http.ResponseWriter, r *http.Request, identity PreviewEdgeIdentity, raw []byte) {
	var input edgeDetachmentBatch
	if err := decodeEdgeJSON(raw, &input); err != nil || input.EdgeNodeID != identity.NodeID || input.ProcessEpoch != identity.ProcessEpoch || len(input.Detachments) > EdgeAdmissionMaxItems {
		writeAttachmentError(w, http.StatusBadRequest, "invalid_request", "Preview edge detachment is invalid.", false)
		return
	}
	now := h.service.clock()
	for _, detachment := range input.Detachments {
		if err := validateEdgeDetachment(detachment, identity.NodeID, identity.ProcessEpoch, now); err != nil {
			writeAttachmentServiceError(w, err)
			return
		}
	}
	for _, detachment := range input.Detachments {
		current, err := h.service.Get(r.Context(), detachment.Binding.AccountID, detachment.Binding.OperationID)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				continue
			}
			writeAttachmentServiceError(w, err)
			return
		}
		if current.Binding != detachment.Binding || detachment.AttachmentGeneration > current.AttachmentGeneration {
			writeAttachmentServiceError(w, ErrStaleBinding)
			return
		}
		// Release increments the attachment generation and writes a detach
		// intent in the same transaction. ACK it when the edge reports that
		// exact terminal generation; older route observations remain harmless.
		if (current.State == StateReleased || current.State == StateFailed) && current.AttachmentGeneration == detachment.AttachmentGeneration {
			if err := h.outbox.AcknowledgePreviewCarrierOutbox(r.Context(), identity.NodeID, identity.ProcessEpoch, current.AccountID, current.OperationID, current.AttachmentGeneration, "detach"); err != nil && !errors.Is(err, ErrNotFound) {
				writeAttachmentServiceError(w, err)
				return
			}
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func carrierAdmissionFromOutbox(item PreviewCarrierOutboxItem, now time.Time) (CarrierAdmission, error) {
	if err := item.validate(now, item.Binding.EdgeNodeID); err != nil {
		return CarrierAdmission{}, err
	}
	admission := CarrierAdmission{
		Schema: Schema, Kind: Kind, Binding: item.Binding, AccessMode: item.AccessMode,
		AttachmentGeneration: item.AttachmentGeneration, ConfigContentHash: item.ConfigContentHash,
		EdgeEndpoints: append([]string(nil), item.EdgeEndpoints...), Endpoint: item.Endpoint,
		ExpiresAt: item.ExpiresAt, State: item.State, Hostname: endpointHostname(item.Endpoint),
		RouteKind: routeKindForAccessMode(item.AccessMode), RouteRevision: item.Binding.RouteGeneration,
	}
	if err := admission.Validate(now); err != nil {
		return CarrierAdmission{}, err
	}
	return admission, nil
}

func carrierDetachmentFromOutbox(item PreviewCarrierOutboxItem, now time.Time) (PreviewCarrierDetachment, error) {
	if item.Action != "detach" {
		return PreviewCarrierDetachment{}, fmt.Errorf("%w: outbox item is not a detach command", ErrInvalid)
	}
	if err := item.validate(now, item.Binding.EdgeNodeID); err != nil {
		return PreviewCarrierDetachment{}, err
	}
	detachment := PreviewCarrierDetachment{
		Schema: Schema, Kind: Kind, Binding: item.Binding,
		AttachmentGeneration: item.AttachmentGeneration,
		Reason:               "server_detach", ObservedAt: now.UTC(),
	}
	if err := validateEdgeDetachment(detachment, item.Binding.EdgeNodeID, "", now); err != nil {
		return PreviewCarrierDetachment{}, err
	}
	return detachment, nil
}

func validateEdgeObservation(observation PreviewCarrierObservation, nodeID, processEpoch string, now time.Time) error {
	if observation.Schema != Schema || observation.Kind != Kind || observation.Binding.EdgeNodeID != nodeID || observation.Binding.EdgeProcessEpoch != processEpoch || observation.AttachmentGeneration == 0 || observation.ObservedAt.IsZero() || len(observation.Reason) > 512 || strings.ContainsAny(observation.Reason, "\r\n\x00") {
		return fmt.Errorf("%w: malformed edge observation", ErrInvalid)
	}
	if observation.State != "edge_ready" && observation.State != "detached" && observation.State != "expired" {
		return fmt.Errorf("%w: unknown edge observation state", ErrInvalid)
	}
	if !observation.ObservedAt.Before(now.Add(5 * time.Minute)) {
		return fmt.Errorf("%w: edge observation timestamp is in the future", ErrInvalid)
	}
	return observation.Binding.validate()
}

func validateEdgeDetachment(detachment PreviewCarrierDetachment, nodeID, processEpoch string, now time.Time) error {
	if detachment.Schema != Schema || detachment.Kind != Kind || detachment.Binding.EdgeNodeID != nodeID || processEpoch != "" && detachment.Binding.EdgeProcessEpoch != processEpoch || detachment.AttachmentGeneration == 0 || detachment.ObservedAt.IsZero() || detachment.Reason == "" || len(detachment.Reason) > 512 || strings.ContainsAny(detachment.Reason, "\r\n\x00") {
		return fmt.Errorf("%w: malformed edge detachment", ErrInvalid)
	}
	if !detachment.ObservedAt.Before(now.Add(5 * time.Minute)) {
		return fmt.Errorf("%w: edge detachment timestamp is in the future", ErrInvalid)
	}
	return detachment.Binding.validate()
}

func edgeNodeIdentity(r *http.Request, raw []byte) (PreviewEdgeIdentity, error) {
	var headerID, headerEpoch string
	if values := r.Header.Values("X-Paperboat-Edge-Node-ID"); len(values) > 1 {
		return PreviewEdgeIdentity{}, ErrUnauthorized
	} else if len(values) == 1 {
		headerID = strings.TrimSpace(values[0])
		if headerID != values[0] || !validID(headerID) {
			return PreviewEdgeIdentity{}, ErrUnauthorized
		}
	}
	if values := r.Header.Values("X-Paperboat-Edge-Process-Epoch"); len(values) > 1 {
		return PreviewEdgeIdentity{}, ErrUnauthorized
	} else if len(values) == 1 {
		headerEpoch = strings.TrimSpace(values[0])
		if headerEpoch != values[0] || connectorprotocol.ValidateOpaqueEpoch(headerEpoch) != nil {
			return PreviewEdgeIdentity{}, ErrUnauthorized
		}
	}
	var bodyID string
	var bodyEpoch string
	if len(raw) != 0 {
		if err := canonicaljson.RejectDuplicateFields(raw); err != nil {
			return PreviewEdgeIdentity{}, ErrUnauthorized
		}
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil {
			return PreviewEdgeIdentity{}, ErrUnauthorized
		}
		if value, ok := object["edge_node_id"]; ok {
			if err := json.Unmarshal(value, &bodyID); err != nil || !validID(bodyID) {
				return PreviewEdgeIdentity{}, ErrUnauthorized
			}
		}
		if value, ok := object["edge_process_epoch"]; ok {
			if err := json.Unmarshal(value, &bodyEpoch); err != nil || connectorprotocol.ValidateOpaqueEpoch(bodyEpoch) != nil {
				return PreviewEdgeIdentity{}, ErrUnauthorized
			}
		}
	}
	if headerID != "" && bodyID != "" && headerID != bodyID {
		return PreviewEdgeIdentity{}, ErrUnauthorized
	}
	if headerEpoch != "" && bodyEpoch != "" && headerEpoch != bodyEpoch {
		return PreviewEdgeIdentity{}, ErrUnauthorized
	}
	if headerID == "" {
		headerID = bodyID
	}
	if headerEpoch == "" {
		headerEpoch = bodyEpoch
	}
	if !validID(headerID) || connectorprotocol.ValidateOpaqueEpoch(headerEpoch) != nil {
		return PreviewEdgeIdentity{}, ErrUnauthorized
	}
	return PreviewEdgeIdentity{NodeID: headerID, ProcessEpoch: headerEpoch}, nil
}

func requestFromAttachment(attachment Attachment) Request {
	return Request{
		PreviewID: attachment.PreviewID, OperationID: attachment.OperationID,
		OwnerDeviceID: attachment.OwnerDeviceID, OwnerSessionID: attachment.OwnerSessionID,
		IdempotencyKey: attachment.IdempotencyKey, RequestID: attachment.RequestID,
		CorrelationID: attachment.CorrelationID,
	}
}

func decodeEdgeJSON(raw []byte, target any) error {
	if len(raw) == 0 || len(raw) > EdgeControlMaxRequestBytes {
		return ErrInvalid
	}
	if err := canonicaljson.RejectDuplicateFields(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	return nil
}

func readEdgeControlBody(r *http.Request) ([]byte, error) {
	if r == nil || r.Body == nil {
		return nil, fmt.Errorf("%w: edge control request body is required", ErrInvalid)
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, EdgeControlMaxRequestBytes+1))
	if err != nil || len(body) > EdgeControlMaxRequestBytes {
		return nil, fmt.Errorf("%w: edge control request body is too large or unreadable", ErrInvalid)
	}
	return body, nil
}

const verifyPreviewEdgeNodeSQL = `
SELECT node.process_epoch,
       (
         ((node.state = 'ready' AND node.ready) OR node.state = 'draining')
         AND (node.last_heartbeat_at IS NULL OR node.last_heartbeat_at > $2::timestamptz - interval '2 minutes')
         AND (node.drain_deadline IS NULL OR node.drain_deadline > $2::timestamptz)
       ) AS available
FROM control_tunnel_nodes AS node
WHERE node.id = $1`
