package tunnelcert

// This file contains the internal server-to-edge certificate distribution
// transport.  It is deliberately separate from the public HTTP API: the
// endpoint is mounted only beneath the authenticated edge-control handler and
// carries certificate bytes over that already authenticated TLS connection.
// No message is written to an audit record or log, and the hub drops the
// plaintext bundle as soon as the edge acknowledges the action.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	CertificateDistributionPullPath    = "/v1/edge/certificates/distributions/pull"
	CertificateDistributionAckPath     = "/v1/edge/certificates/distributions/ack"
	CertificateDistributionRequestPath = "/v1/edge/certificates/distributions/request"
	maxDistributionBody                = 16 << 20
	maxDistributionMessages            = 128
	maxDistributionLifetime            = 10 * time.Minute
	maxDistributionPendingBytes        = 64 << 20
)

var (
	ErrDistributionTransportInvalid = errors.New("invalid certificate distribution transport")
	ErrDistributionTransportAuth    = errors.New("certificate distribution transport is not authenticated")
	ErrDistributionTransportStale   = errors.New("certificate distribution message is stale")
	ErrDistributionTransportFailed  = errors.New("certificate distribution was rejected")
)

// DistributionMessage is an internal wire message. CertificatePEM and
// PrivateKeyPEM are only present on this authenticated control transport;
// callers must never marshal this type into a public response, audit event,
// or log line.
type DistributionMessage struct {
	Version               int       `json:"version"`
	Action                string    `json:"action"`
	CertificateID         string    `json:"certificate_id"`
	AccountID             string    `json:"account_id"`
	TunnelID              string    `json:"tunnel_id"`
	DomainID              string    `json:"domain_id"`
	TargetKind            string    `json:"target_kind"`
	RouteID               string    `json:"route_id"`
	PreviewID             string    `json:"preview_id"`
	PreviewGeneration     uint64    `json:"preview_generation"`
	PreviewState          string    `json:"preview_state"`
	PreviewExpiresAt      time.Time `json:"preview_expires_at"`
	Hostname              string    `json:"hostname"`
	OnDemandLeaf          bool      `json:"on_demand_leaf"`
	DomainGeneration      uint64    `json:"domain_generation"`
	CertificateGeneration uint64    `json:"certificate_generation"`
	EdgeNodeID            string    `json:"edge_node_id"`
	EdgeProcessEpoch      string    `json:"edge_process_epoch"`
	AssignmentGeneration  uint64    `json:"assignment_generation"`
	Fingerprint           string    `json:"fingerprint"`
	Issuer                string    `json:"issuer"`
	NotBefore             time.Time `json:"not_before"`
	// ExpiresAt is the short-lived transport envelope deadline.  It is
	// deliberately independent from the certificate's validity interval so a
	// queued message can never be replayed for the lifetime of a leaf.
	ExpiresAt            time.Time `json:"expires_at"`
	CertificateExpiresAt time.Time `json:"certificate_expires_at"`
	CertificatePEM       []byte    `json:"certificate_pem"`
	PrivateKeyPEM        []byte    `json:"private_key_pem"`
	IssuedAt             time.Time `json:"issued_at"`
	Proof                string    `json:"proof"`
}

type distributionAck struct {
	Version               int       `json:"version"`
	Action                string    `json:"action"`
	CertificateID         string    `json:"certificate_id"`
	AccountID             string    `json:"account_id"`
	TunnelID              string    `json:"tunnel_id"`
	DomainID              string    `json:"domain_id"`
	TargetKind            string    `json:"target_kind"`
	RouteID               string    `json:"route_id"`
	PreviewID             string    `json:"preview_id"`
	PreviewGeneration     uint64    `json:"preview_generation"`
	PreviewState          string    `json:"preview_state"`
	PreviewExpiresAt      time.Time `json:"preview_expires_at"`
	Hostname              string    `json:"hostname"`
	DomainGeneration      uint64    `json:"domain_generation"`
	CertificateGeneration uint64    `json:"certificate_generation"`
	EdgeNodeID            string    `json:"edge_node_id"`
	EdgeProcessEpoch      string    `json:"edge_process_epoch"`
	AssignmentGeneration  uint64    `json:"assignment_generation"`
	Fingerprint           string    `json:"fingerprint"`
	Status                string    `json:"status"`
	Code                  string    `json:"code,omitempty"`
}

type distributionPull struct {
	EdgeNodeID       string `json:"edge_node_id"`
	EdgeProcessEpoch string `json:"edge_process_epoch"`
	Limit            int    `json:"limit,omitempty"`
	Cursor           string `json:"cursor,omitempty"`
}

type distributionRequest struct {
	Hostname string `json:"hostname"`
}

type distributionResult struct {
	status string
	code   string
}

type distributionEntry struct {
	message DistributionMessage
	done    chan struct{}
}

// DistributionHub is both the CertificateDistributor transport used by the
// server coordinator and the authenticated pull/ack endpoint consumed by an
// edge.  A pending action is retained until the exact node, process epoch,
// certificate, assignment generation, and fingerprint are acknowledged.
// This makes retries idempotent while fencing stale edge processes.
type DistributionHub struct {
	credential   []byte
	credentialMu sync.RWMutex
	now          func() time.Time
	maximum      int
	maximumBytes int64
	identity     DistributionNodeIdentityResolver
	onDemand     func(context.Context, DistributionNodeIdentity, string) error

	mu           sync.Mutex
	closed       bool
	pending      map[string]*distributionEntry
	pendingBytes int64
	results      map[string]distributionResult
}

type DistributionHubConfig struct {
	Credential     []byte
	MaximumPending int
	// MaximumPendingBytes bounds the aggregate plaintext certificate and key
	// material retained by the hub. It is deliberately independent of the
	// action count because a small number of large wildcard bundles must not
	// exhaust process memory.
	MaximumPendingBytes int64
	Now                 func() time.Time
	// Identity authenticates the edge process independently of the shared
	// control bearer.  Pull/ACK bodies are compared to this result and are
	// never used as an identity source.
	Identity DistributionNodeIdentityResolver
	// OnDemand handles an authenticated exact-SNI request. The callback must
	// resolve verified wildcard policy and the current edge assignment from
	// server state before issuing or distributing a leaf.
	OnDemand func(context.Context, DistributionNodeIdentity, string) error
}

// DistributionNodeIdentity is the authenticated edge-control principal.
// Implementations should derive it from the mTLS peer certificate or an
// equivalent node-specific proof, not from a request body/header.
type DistributionNodeIdentity struct {
	NodeID       string
	ProcessEpoch string
}

type DistributionNodeIdentityResolver interface {
	ResolveDistributionNode(context.Context, *http.Request) (DistributionNodeIdentity, error)
}

type DistributionNodeIdentityResolverFunc func(context.Context, *http.Request) (DistributionNodeIdentity, error)

func (f DistributionNodeIdentityResolverFunc) ResolveDistributionNode(ctx context.Context, r *http.Request) (DistributionNodeIdentity, error) {
	return f(ctx, r)
}

func NewDistributionHub(config DistributionHubConfig) (*DistributionHub, error) {
	if !validDistributionCredential(config.Credential) {
		return nil, fmt.Errorf("%w: credential is required", ErrDistributionTransportInvalid)
	}
	if config.MaximumPending <= 0 || config.MaximumPending > 4096 {
		config.MaximumPending = 1024
	}
	if config.MaximumPendingBytes <= 0 || config.MaximumPendingBytes > 512<<20 {
		config.MaximumPendingBytes = maxDistributionPendingBytes
	}
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	if config.Identity == nil {
		return nil, fmt.Errorf("%w: node identity resolver is required", ErrDistributionTransportInvalid)
	}
	return &DistributionHub{credential: append([]byte(nil), config.Credential...), now: config.Now, maximum: config.MaximumPending, maximumBytes: config.MaximumPendingBytes, identity: config.Identity, onDemand: config.OnDemand, pending: make(map[string]*distributionEntry), results: make(map[string]distributionResult)}, nil
}

// Close invalidates all outstanding distribution actions and wipes every
// encoded certificate/private-key buffer retained by the hub. A closed hub
// cannot be restarted; callers should construct a new deployment component
// for a new process epoch.
func (h *DistributionHub) Close() error {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil
	}
	h.closed = true
	for key, entry := range h.pending {
		wipeDistributionMessage(&entry.message)
		close(entry.done)
		delete(h.pending, key)
	}
	h.credentialMu.Lock()
	clear(h.credential)
	h.credential = nil
	h.credentialMu.Unlock()
	h.pendingBytes = 0
	clear(h.results)
	h.mu.Unlock()
	return nil
}

// Handler returns an internal handler.  It authenticates independently so a
// caller cannot accidentally mount it outside EdgeService's authenticated
// mux without preserving the machine credential boundary.
func (h *DistributionHub) Handler() http.Handler {
	if h == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		})
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+CertificateDistributionPullPath, h.handlePull)
	mux.HandleFunc("POST "+CertificateDistributionAckPath, h.handleAck)
	mux.HandleFunc("POST "+CertificateDistributionRequestPath, h.handleRequest)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !h.authorized(r) {
			writeDistributionError(w, http.StatusUnauthorized)
			return
		}
		identity, err := h.identity.ResolveDistributionNode(r.Context(), r)
		if err != nil || !validDistributionIdentity(identity.NodeID, identity.ProcessEpoch) {
			writeDistributionError(w, http.StatusUnauthorized)
			return
		}
		r = r.WithContext(withDistributionNodeIdentity(r.Context(), identity))
		mux.ServeHTTP(w, r)
	})
}

// Stage queues a certificate for the authenticated edge transport.
func (h *DistributionHub) Stage(ctx context.Context, request DistributionRequest) error {
	if err := request.Validate(); err != nil {
		return err
	}
	_, err := h.enqueue(ctx, "stage", request)
	return err
}

func (h *DistributionHub) WaitReady(ctx context.Context, request DistributionRequest) error {
	if err := request.Validate(); err != nil {
		return err
	}
	return h.wait(ctx, distributionKey("stage", request))
}

func (h *DistributionHub) Activate(ctx context.Context, request DistributionRequest) error {
	if err := request.Validate(); err != nil {
		return err
	}
	return h.waitForAction(ctx, "activate", request, "active")
}

func (h *DistributionHub) Retire(ctx context.Context, certificate StoredCertificate, target DistributionTarget) error {
	if err := certificate.validateDistributionMetadata(); err != nil {
		return err
	}
	if err := target.Validate(); err != nil {
		return err
	}
	return h.waitForAction(ctx, "retire", DistributionRequest{Certificate: certificate, Target: target}, "retired")
}

// Revoke is used by SQLDistributor when a durable certificate is revoked.
// It differs from Retire so the edge registry records the terminal revoked
// state rather than merely retiring a still-authoritative certificate.
func (h *DistributionHub) Revoke(ctx context.Context, certificate StoredCertificate, target DistributionTarget) error {
	if err := certificate.validateDistributionMetadata(); err != nil {
		return err
	}
	if err := target.Validate(); err != nil {
		return err
	}
	return h.waitForAction(ctx, "revoke", DistributionRequest{Certificate: certificate, Target: target}, "revoked")
}

func (h *DistributionHub) waitForAction(ctx context.Context, action string, request DistributionRequest, status string) error {
	if _, err := h.enqueue(ctx, action, request); err != nil {
		return err
	}
	return h.waitStatus(ctx, distributionKey(action, request), status)
}

func (h *DistributionHub) enqueue(ctx context.Context, action string, request DistributionRequest) (DistributionMessage, error) {
	if h == nil {
		return DistributionMessage{}, ErrDistributionTransportInvalid
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := distributionContextError(ctx); err != nil {
		return DistributionMessage{}, err
	}
	if action != "stage" && action != "activate" && action != "retire" && action != "revoke" {
		return DistributionMessage{}, ErrDistributionTransportInvalid
	}
	now := h.now().UTC()
	message := DistributionMessage{
		Version: 1, Action: action, CertificateID: request.Certificate.ID,
		AccountID: request.Certificate.AccountID, TunnelID: request.Certificate.TunnelID,
		DomainID: request.Certificate.DomainID, TargetKind: string(request.Certificate.TargetKind), RouteID: request.Certificate.RouteID,
		PreviewID: request.Certificate.PreviewID, PreviewGeneration: request.Certificate.PreviewGeneration, PreviewState: request.Certificate.PreviewState, PreviewExpiresAt: request.Certificate.PreviewExpiresAt,
		Hostname:         request.Certificate.Hostname,
		OnDemandLeaf:     request.Certificate.LeafHostname == "" && request.Certificate.Strategy == StrategyOnDemandLeaf,
		DomainGeneration: request.Certificate.DomainGeneration, CertificateGeneration: request.Certificate.CertificateGeneration,
		EdgeNodeID: request.Target.NodeID, EdgeProcessEpoch: request.Target.ProcessEpoch,
		AssignmentGeneration: request.Target.Generation, Fingerprint: base64.RawURLEncoding.EncodeToString(request.Certificate.Fingerprint[:]),
		Issuer: request.Certificate.Issuer, NotBefore: request.Certificate.NotBefore,
		ExpiresAt: distributionExpiry(now, request.Certificate.ExpiresAt), CertificateExpiresAt: request.Certificate.ExpiresAt,
		CertificatePEM: append([]byte(nil), request.Bundle.CertificatePEM...), PrivateKeyPEM: append([]byte(nil), request.Bundle.PrivateKeyPEM...), IssuedAt: now,
	}
	if action != "stage" {
		// The edge needs the exact previously staged bundle metadata for every
		// action, but sending bytes again is unnecessary.  Keep action messages
		// secret-minimal and let the receiver use its staged in-memory entry.
		message.CertificatePEM = nil
		message.PrivateKeyPEM = nil
	}
	message.Proof = h.sign(message)
	key := distributionMessageKey(message)
	if action == "stage" && !distributionMessageFitsResponse(message) {
		return DistributionMessage{}, ErrDistributionTransportFailed
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return DistributionMessage{}, ErrDistributionTransportInvalid
	}
	h.purgeExpiredLocked(now)
	if action != "stage" {
		// Activate/retire/revoke are meaningful only for the exact staged
		// certificate target. Never queue an action that an edge could accept
		// without a corresponding stage record after a restart or replay-ledger
		// eviction.
		stageKey := distributionKey("stage", request)
		if _, staged := h.pending[stageKey]; !staged {
			result, completed := h.results[stageKey]
			if !completed || result.status != "ready" && result.status != "active" {
				return DistributionMessage{}, ErrDistributionTransportStale
			}
		}
	}
	if existing, ok := h.pending[key]; ok {
		return cloneDistributionMessage(existing.message), nil
	}
	if existing, ok := h.results[key]; ok {
		if existing.status == "ready" || existing.status == "active" || existing.status == "retired" || existing.status == "revoked" {
			return message, nil
		}
	}
	if len(h.pending) >= h.maximum {
		return DistributionMessage{}, ErrDistributionTransportFailed
	}
	secretBytes := distributionMessageSecretBytes(message)
	if h.pendingBytes > h.maximumBytes-secretBytes {
		return DistributionMessage{}, ErrDistributionTransportFailed
	}
	h.pending[key] = &distributionEntry{message: message, done: make(chan struct{})}
	h.pendingBytes += secretBytes
	return cloneDistributionMessage(message), nil
}

func (h *DistributionHub) wait(ctx context.Context, key string) error {
	return h.waitStatus(ctx, key, "ready")
}

func (h *DistributionHub) waitStatus(ctx context.Context, key, want string) error {
	if h == nil {
		return ErrDistributionTransportInvalid
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		h.mu.Lock()
		h.purgeExpiredLocked(h.now().UTC())
		if result, ok := h.results[key]; ok {
			h.mu.Unlock()
			if result.status == want {
				return nil
			}
			if result.status == "failed" {
				return fmt.Errorf("%w: %s", ErrDistributionTransportFailed, result.code)
			}
			return ErrDistributionTransportStale
		}
		entry, ok := h.pending[key]
		if !ok {
			h.mu.Unlock()
			return ErrDistributionTransportStale
		}
		done := entry.done
		expires := entry.message.ExpiresAt
		h.mu.Unlock()
		if !expires.After(h.now().UTC()) {
			return ErrDistributionTransportStale
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
		}
	}
}

func (h *DistributionHub) handlePull(w http.ResponseWriter, r *http.Request) {
	var input distributionPull
	if !decodeDistributionBody(w, r, &input) || !validDistributionIdentity(input.EdgeNodeID, input.EdgeProcessEpoch) {
		return
	}
	if !validDistributionCursor(input.Cursor) {
		writeDistributionError(w, http.StatusBadRequest)
		return
	}
	cursor, ok := decodeDistributionCursor(input.Cursor)
	if !ok {
		writeDistributionError(w, http.StatusBadRequest)
		return
	}
	identity, ok := distributionNodeIdentityFromContext(r.Context())
	if !ok || input.EdgeNodeID != identity.NodeID || input.EdgeProcessEpoch != identity.ProcessEpoch {
		writeDistributionError(w, http.StatusForbidden)
		return
	}
	limit := input.Limit
	if limit <= 0 || limit > maxDistributionMessages {
		limit = maxDistributionMessages
	}
	now := h.now().UTC()
	h.mu.Lock()
	h.purgeExpiredLocked(now)
	// Sort only lightweight keys while holding the mutex. Cloning certificate
	// and private-key buffers for every matching row before applying the page
	// limit can otherwise multiply the plaintext memory footprint.
	matching := make([]string, 0, len(h.pending))
	for key, entry := range h.pending {
		if entry == nil || entry.message.EdgeNodeID != input.EdgeNodeID || entry.message.EdgeProcessEpoch != input.EdgeProcessEpoch || key <= cursor {
			continue
		}
		matching = append(matching, key)
	}
	sort.Strings(matching)
	messages := make([]DistributionMessage, 0, minInt(limit, len(matching)))
	defer func() {
		for index := range messages {
			wipeDistributionMessage(&messages[index])
		}
	}()
	selectedKeys := make([]string, 0, cap(messages))
	encodedBytes := 256
	for _, key := range matching {
		if len(selectedKeys) >= limit {
			break
		}
		entry := h.pending[key]
		if entry == nil {
			continue
		}
		candidate := cloneDistributionMessage(entry.message)
		candidateJSON, marshalErr := json.Marshal(candidate)
		clear(candidateJSON)
		if marshalErr != nil {
			wipeDistributionMessage(&candidate)
			h.mu.Unlock()
			writeDistributionError(w, http.StatusServiceUnavailable)
			return
		}
		// Reserve a conservative envelope margin for version, cursor, commas,
		// JSON escaping, and the Encoder newline. A candidate that cannot fit
		// alone is rejected at enqueue, so this always makes progress.
		if encodedBytes+len(candidateJSON)+1 > maxDistributionBody-4096 && len(messages) > 0 {
			wipeDistributionMessage(&candidate)
			break
		}
		if encodedBytes+len(candidateJSON)+1 > maxDistributionBody-4096 {
			wipeDistributionMessage(&candidate)
			h.mu.Unlock()
			writeDistributionError(w, http.StatusServiceUnavailable)
			return
		}
		encodedBytes += len(candidateJSON) + 1
		messages = append(messages, candidate)
		selectedKeys = append(selectedKeys, key)
	}
	complete := len(selectedKeys) == len(matching)
	nextCursor := ""
	if !complete && len(messages) > 0 {
		nextCursor = encodeDistributionCursor(selectedKeys[len(selectedKeys)-1])
	}
	h.mu.Unlock()
	writeDistributionJSON(w, http.StatusOK, struct {
		Version    int                   `json:"version"`
		Complete   bool                  `json:"complete"`
		NextCursor string                `json:"next_cursor,omitempty"`
		Messages   []DistributionMessage `json:"messages"`
	}{Version: 1, Complete: complete, NextCursor: nextCursor, Messages: messages})
}

func (h *DistributionHub) handleRequest(w http.ResponseWriter, r *http.Request) {
	var input distributionRequest
	if !decodeDistributionBody(w, r, &input) {
		return
	}
	identity, ok := distributionNodeIdentityFromContext(r.Context())
	if !ok || !validDistributionIdentity(identity.NodeID, identity.ProcessEpoch) {
		writeDistributionError(w, http.StatusForbidden)
		return
	}
	hostname, wildcard, err := normalizeHostname(input.Hostname)
	if err != nil || wildcard || hostname != input.Hostname {
		writeDistributionError(w, http.StatusBadRequest)
		return
	}
	if h == nil || h.onDemand == nil {
		writeDistributionError(w, http.StatusServiceUnavailable)
		return
	}
	if err := h.onDemand(r.Context(), identity, hostname); err != nil {
		status := http.StatusServiceUnavailable
		if errors.Is(err, ErrInvalid) || errors.Is(err, ErrGenerationConflict) || errors.Is(err, ErrCertificateRevoked) {
			status = http.StatusConflict
		}
		writeDistributionError(w, status)
		return
	}
	writeDistributionJSON(w, http.StatusNoContent, nil)
}

func (h *DistributionHub) handleAck(w http.ResponseWriter, r *http.Request) {
	var input distributionAck
	if !decodeDistributionBody(w, r, &input) || !validDistributionIdentity(input.EdgeNodeID, input.EdgeProcessEpoch) {
		return
	}
	identity, ok := distributionNodeIdentityFromContext(r.Context())
	if !ok || input.EdgeNodeID != identity.NodeID || input.EdgeProcessEpoch != identity.ProcessEpoch {
		writeDistributionError(w, http.StatusForbidden)
		return
	}
	if input.Version != 1 || input.Action != "stage" && input.Action != "activate" && input.Action != "retire" && input.Action != "revoke" || input.Status != "ready" && input.Status != "active" && input.Status != "retired" && input.Status != "revoked" && input.Status != "failed" || !distributionAckStatusMatchesAction(input.Action, input.Status) {
		writeDistributionError(w, http.StatusBadRequest)
		return
	}
	key := distributionAckKey(input)
	h.mu.Lock()
	entry, pending := h.pending[key]
	if !pending {
		if result, ok := h.results[key]; ok && result.status == input.Status {
			h.mu.Unlock()
			writeDistributionJSON(w, http.StatusNoContent, nil)
			return
		}
		h.mu.Unlock()
		writeDistributionError(w, http.StatusConflict)
		return
	}
	if !ackMatchesMessage(input, entry.message) {
		h.mu.Unlock()
		writeDistributionError(w, http.StatusConflict)
		return
	}
	if input.Status == "failed" && (input.Code == "" || len(input.Code) > 128 || strings.ContainsAny(input.Code, "\r\n\x00")) || input.Status != "failed" && input.Code != "" {
		h.mu.Unlock()
		writeDistributionError(w, http.StatusBadRequest)
		return
	}
	result := distributionResult{status: input.Status, code: input.Code}
	h.results[key] = result
	delete(h.pending, key)
	h.pendingBytes -= distributionMessageSecretBytes(entry.message)
	if h.pendingBytes < 0 {
		h.pendingBytes = 0
	}
	close(entry.done)
	wipeDistributionMessage(&entry.message)
	// Bound the replay ledger. Results are metadata only and can be rebuilt by
	// a subsequent coordinator retry; never retain key bytes after ACK.
	if len(h.results) > h.maximum*2 {
		for resultKey := range h.results {
			delete(h.results, resultKey)
			if len(h.results) <= h.maximum {
				break
			}
		}
	}
	h.mu.Unlock()
	writeDistributionJSON(w, http.StatusNoContent, nil)
}

func (h *DistributionHub) authorized(r *http.Request) bool {
	if h == nil || r == nil {
		return false
	}
	credential := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	h.credentialMu.RLock()
	defer h.credentialMu.RUnlock()
	return hmac.Equal([]byte(credential), h.credential)
}

func (h *DistributionHub) sign(message DistributionMessage) string {
	message.Proof = ""
	canonical, err := json.Marshal(message)
	if err != nil {
		return ""
	}
	defer clear(canonical)
	h.credentialMu.RLock()
	defer h.credentialMu.RUnlock()
	hash := hmac.New(sha256.New, h.credential)
	_, _ = hash.Write(canonical)
	return base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}

func VerifyDistributionMessageProof(message DistributionMessage, credential []byte) error {
	if len(credential) < 32 || message.Proof == "" {
		return ErrDistributionTransportAuth
	}
	proof, err := base64.RawURLEncoding.Strict().DecodeString(message.Proof)
	if err != nil || len(proof) != sha256.Size {
		return ErrDistributionTransportAuth
	}
	defer clear(proof)
	message.Proof = ""
	canonical, err := json.Marshal(message)
	if err != nil {
		return ErrDistributionTransportAuth
	}
	defer clear(canonical)
	hash := hmac.New(sha256.New, credential)
	_, _ = hash.Write(canonical)
	if !hmac.Equal(proof, hash.Sum(nil)) {
		return ErrDistributionTransportAuth
	}
	return nil
}

func validDistributionCredential(credential []byte) bool {
	return len(credential) >= 32 && bytes.Equal(bytes.TrimSpace(credential), credential) && bytes.IndexByte(credential, '\r') < 0 && bytes.IndexByte(credential, '\n') < 0 && bytes.IndexByte(credential, 0) < 0
}

func distributionKey(action string, request DistributionRequest) string {
	return distributionMessageKey(DistributionMessage{Action: action, CertificateID: request.Certificate.ID, AccountID: request.Certificate.AccountID, TunnelID: request.Certificate.TunnelID, DomainID: request.Certificate.DomainID, TargetKind: string(request.Certificate.TargetKind), RouteID: request.Certificate.RouteID, PreviewID: request.Certificate.PreviewID, PreviewGeneration: request.Certificate.PreviewGeneration, PreviewState: request.Certificate.PreviewState, PreviewExpiresAt: request.Certificate.PreviewExpiresAt, Hostname: request.Certificate.Hostname, DomainGeneration: request.Certificate.DomainGeneration, CertificateGeneration: request.Certificate.CertificateGeneration, EdgeNodeID: request.Target.NodeID, EdgeProcessEpoch: request.Target.ProcessEpoch, AssignmentGeneration: request.Target.Generation, Fingerprint: base64.RawURLEncoding.EncodeToString(request.Certificate.Fingerprint[:])})
}

func distributionMessageKey(message DistributionMessage) string {
	return strings.Join([]string{message.Action, message.CertificateID, message.AccountID, message.TunnelID, message.DomainID, message.TargetKind, message.RouteID, message.PreviewID, fmt.Sprint(message.PreviewGeneration), message.PreviewState, message.PreviewExpiresAt.UTC().Format(time.RFC3339Nano), message.Hostname, fmt.Sprint(message.DomainGeneration), fmt.Sprint(message.CertificateGeneration), message.EdgeNodeID, message.EdgeProcessEpoch, fmt.Sprint(message.AssignmentGeneration), message.Fingerprint}, "\x00")
}

func distributionAckKey(input distributionAck) string {
	return distributionMessageKey(DistributionMessage{Action: input.Action, CertificateID: input.CertificateID, AccountID: input.AccountID, TunnelID: input.TunnelID, DomainID: input.DomainID, TargetKind: input.TargetKind, RouteID: input.RouteID, PreviewID: input.PreviewID, PreviewGeneration: input.PreviewGeneration, PreviewState: input.PreviewState, PreviewExpiresAt: input.PreviewExpiresAt, Hostname: input.Hostname, DomainGeneration: input.DomainGeneration, CertificateGeneration: input.CertificateGeneration, EdgeNodeID: input.EdgeNodeID, EdgeProcessEpoch: input.EdgeProcessEpoch, AssignmentGeneration: input.AssignmentGeneration, Fingerprint: input.Fingerprint})
}

func ackMatchesMessage(input distributionAck, message DistributionMessage) bool {
	return input.Version == message.Version && input.Action == message.Action && input.CertificateID == message.CertificateID && input.AccountID == message.AccountID && input.TunnelID == message.TunnelID && input.DomainID == message.DomainID && input.TargetKind == message.TargetKind && input.RouteID == message.RouteID && input.PreviewID == message.PreviewID && input.PreviewGeneration == message.PreviewGeneration && input.PreviewState == message.PreviewState && input.PreviewExpiresAt.Equal(message.PreviewExpiresAt) && input.Hostname == message.Hostname && input.DomainGeneration == message.DomainGeneration && input.CertificateGeneration == message.CertificateGeneration && input.EdgeNodeID == message.EdgeNodeID && input.EdgeProcessEpoch == message.EdgeProcessEpoch && input.AssignmentGeneration == message.AssignmentGeneration && input.Fingerprint == message.Fingerprint
}

func cloneDistributionMessage(message DistributionMessage) DistributionMessage {
	message.CertificatePEM = append([]byte(nil), message.CertificatePEM...)
	message.PrivateKeyPEM = append([]byte(nil), message.PrivateKeyPEM...)
	return message
}

func wipeDistributionMessage(message *DistributionMessage) {
	if message == nil {
		return
	}
	clear(message.CertificatePEM)
	clear(message.PrivateKeyPEM)
	message.CertificatePEM = nil
	message.PrivateKeyPEM = nil
}

func (h *DistributionHub) purgeExpiredLocked(now time.Time) {
	for key, entry := range h.pending {
		if entry == nil {
			delete(h.pending, key)
			continue
		}
		if entry.message.ExpiresAt.After(now) {
			continue
		}
		h.pendingBytes -= distributionMessageSecretBytes(entry.message)
		wipeDistributionMessage(&entry.message)
		close(entry.done)
		delete(h.pending, key)
	}
	if h.pendingBytes < 0 {
		h.pendingBytes = 0
	}
}

func distributionMessageSecretBytes(message DistributionMessage) int64 {
	return int64(len(message.CertificatePEM) + len(message.PrivateKeyPEM))
}

func distributionMessageFitsResponse(message DistributionMessage) bool {
	encoded, err := json.Marshal(message)
	if err != nil {
		return false
	}
	length := len(encoded)
	clear(encoded)
	return length > 0 && length+4096 <= maxDistributionBody
}

func validDistributionIdentity(nodeID, processEpoch string) bool {
	return validIdentifier(nodeID) && validEpoch(processEpoch)
}

func validDistributionCursor(cursor string) bool {
	return len(cursor) <= 4096 && (cursor == "" || strings.Trim(cursor, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") == "")
}

func decodeDistributionCursor(cursor string) (string, bool) {
	if cursor == "" {
		return "", true
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(cursor)
	if err != nil || len(decoded) > 2048 || bytes.IndexByte(decoded, '\r') >= 0 || bytes.IndexByte(decoded, '\n') >= 0 {
		return "", false
	}
	return string(decoded), true
}

func encodeDistributionCursor(cursor string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(cursor))
}

func distributionAckStatusMatchesAction(action, status string) bool {
	if status == "failed" {
		return true
	}
	switch action {
	case "stage":
		return status == "ready"
	case "activate":
		return status == "active"
	case "retire":
		return status == "retired"
	case "revoke":
		return status == "revoked"
	default:
		return false
	}
}

func decodeDistributionBody(w http.ResponseWriter, r *http.Request, target any) bool {
	if r == nil || r.Body == nil || !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		writeDistributionError(w, http.StatusBadRequest)
		return false
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, maxDistributionBody+1))
	if err != nil || len(body) == 0 || len(body) > maxDistributionBody {
		writeDistributionError(w, http.StatusBadRequest)
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		writeDistributionError(w, http.StatusBadRequest)
		return false
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		writeDistributionError(w, http.StatusBadRequest)
		return false
	}
	return true
}

func writeDistributionJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if value != nil {
		payload, err := json.Marshal(value)
		if err != nil {
			return
		}
		wire := make([]byte, len(payload)+1)
		copy(wire, payload)
		wire[len(payload)] = '\n'
		clear(payload)
		defer clear(wire)
		_, _ = w.Write(wire)
	}
}

func writeDistributionError(w http.ResponseWriter, status int) {
	writeDistributionJSON(w, status, map[string]any{"code": "certificate_distribution_unavailable", "retryable": status >= 500})
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

type distributionNodeIdentityContextKey struct{}

func withDistributionNodeIdentity(ctx context.Context, identity DistributionNodeIdentity) context.Context {
	return context.WithValue(ctx, distributionNodeIdentityContextKey{}, identity)
}

func distributionNodeIdentityFromContext(ctx context.Context) (DistributionNodeIdentity, bool) {
	if ctx == nil {
		return DistributionNodeIdentity{}, false
	}
	identity, ok := ctx.Value(distributionNodeIdentityContextKey{}).(DistributionNodeIdentity)
	return identity, ok
}

func distributionExpiry(now, certificateExpiry time.Time) time.Time {
	deadline := now.Add(maxDistributionLifetime)
	if certificateExpiry.IsZero() || certificateExpiry.Before(deadline) {
		return certificateExpiry
	}
	return deadline
}

func distributionContextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}
