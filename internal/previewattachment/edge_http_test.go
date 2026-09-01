package previewattachment

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestPreviewEdgeVerifierBindsHeartbeatClockAsTimestamp(t *testing.T) {
	for _, expression := range []string{
		"$2::timestamptz - interval '2 minutes'",
		"node.drain_deadline > $2::timestamptz",
	} {
		if !strings.Contains(verifyPreviewEdgeNodeSQL, expression) {
			t.Fatalf("edge verifier SQL is missing typed clock expression %q", expression)
		}
	}
}

type edgeOutboxFake struct {
	snapshot []PreviewCarrierOutboxItem
	detach   []PreviewCarrierOutboxItem
	acks     []string
}

func (f *edgeOutboxFake) PullPreviewCarrierSnapshot(context.Context, string, string) ([]PreviewCarrierOutboxItem, error) {
	return append([]PreviewCarrierOutboxItem(nil), f.snapshot...), nil
}

func (f *edgeOutboxFake) PullPreviewCarrierDetachOutbox(context.Context, string, string) ([]PreviewCarrierOutboxItem, error) {
	return append([]PreviewCarrierOutboxItem(nil), f.detach...), nil
}

func (f *edgeOutboxFake) AcknowledgePreviewCarrierOutbox(_ context.Context, _, _, accountID, operationID string, generation uint64, action string) error {
	f.acks = append(f.acks, accountID+"/"+operationID+"/"+strconv.FormatUint(generation, 10)+"/"+action)
	return nil
}

type edgeVerifierFake struct {
	nodeID string
}

type edgeAliasProjectorFake struct {
	project func([]PreviewCarrierAliasBinding) map[PreviewCarrierAliasBinding][]CarrierAlias
}

func (f edgeAliasProjectorFake) ProjectPreviewCarrierAliases(_ context.Context, _, _ string, bindings []PreviewCarrierAliasBinding, _ time.Time) (map[PreviewCarrierAliasBinding][]CarrierAlias, error) {
	if f.project == nil {
		return map[PreviewCarrierAliasBinding][]CarrierAlias{}, nil
	}
	return f.project(append([]PreviewCarrierAliasBinding(nil), bindings...)), nil
}

func (f edgeVerifierFake) VerifyPreviewEdgeRequest(context.Context, *http.Request, []byte) (PreviewEdgeIdentity, error) {
	return PreviewEdgeIdentity{NodeID: f.nodeID, ProcessEpoch: "edge-process-1"}, nil
}

func TestEdgeAdmissionPullReturnsCompleteEnvelopeAndExactDetachCommand(t *testing.T) {
	now := testNow()
	resolution := testResolution(now)
	req := testRequest()
	hash, err := req.Hash(resolution.Lease.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	attachment := attachmentFromResolution(req, hash, resolution, now)
	admit := PreviewCarrierOutboxItem{
		AccountID: attachment.AccountID, OperationID: attachment.OperationID,
		AttachmentGeneration: attachment.AttachmentGeneration, Action: "admit",
		Binding: attachment.Binding, AccessMode: attachment.AccessMode,
		ConfigContentHash: attachment.ConfigContentHash, EdgeEndpoints: attachment.EdgeEndpoints,
		Endpoint: attachment.Endpoint, ExpiresAt: attachment.ExpiresAt, State: "pending",
	}
	detach := admit
	detach.AttachmentGeneration = attachment.AttachmentGeneration + 1
	detach.Action = "detach"
	detach.State = "in_flight"
	outbox := &edgeOutboxFake{snapshot: []PreviewCarrierOutboxItem{admit}, detach: []PreviewCarrierOutboxItem{detach}}
	service, err := NewService(&serviceRepositoryFake{}, &testAuthority{resolution: resolution}, &testPublisher{})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.SetClock(func() time.Time { return now }); err != nil {
		t.Fatal(err)
	}
	handler, err := NewEdgeHTTPHandler(service, outbox, edgeVerifierFake{nodeID: attachment.EdgeNodeID})
	if err != nil {
		t.Fatal(err)
	}
	if err := handler.SetAliasProjector(edgeAliasProjectorFake{project: func(bindings []PreviewCarrierAliasBinding) map[PreviewCarrierAliasBinding][]CarrierAlias {
		if len(bindings) != 1 || bindings[0].PreviewID != attachment.PreviewID || bindings[0].RouteID != attachment.Binding.RouteID || bindings[0].PreviewGeneration != attachment.Binding.LeaseGeneration || bindings[0].AttachmentGeneration != attachment.AttachmentGeneration {
			t.Fatalf("alias bindings = %+v", bindings)
		}
		return map[PreviewCarrierAliasBinding][]CarrierAlias{bindings[0]: {{
			DomainID: "domain-preview-1", Hostname: "demo.customer.example", MatchType: "exact",
			PreviewGeneration: bindings[0].PreviewGeneration, DomainGeneration: 2, CertificateGeneration: 3,
		}}}
	}}); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"edge_node_id":"edge-node-1","edge_process_epoch":"edge-process-1"}`)
	request := httptest.NewRequest(http.MethodPost, EdgeAdmissionPullPath, bytes.NewReader(body))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("pull status = %d, body = %s", response.Code, response.Body.String())
	}
	var envelope struct {
		Schema      string                     `json:"schema"`
		Kind        string                     `json:"kind"`
		Complete    bool                       `json:"complete"`
		Admissions  []CarrierAdmission         `json:"admissions"`
		Detachments []PreviewCarrierDetachment `json:"detachments"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Schema != Schema || envelope.Kind != Kind || !envelope.Complete || envelope.Admissions == nil || envelope.Detachments == nil {
		t.Fatalf("pull envelope = %#v, want canonical complete non-null envelope", envelope)
	}
	if len(envelope.Admissions) != 1 || envelope.Admissions[0].AccessMode != "public" {
		t.Fatalf("admissions = %#v", envelope.Admissions)
	}
	if aliases := envelope.Admissions[0].Aliases; len(aliases) != 1 || aliases[0].Hostname != "demo.customer.example" || aliases[0].PreviewGeneration != attachment.Binding.LeaseGeneration {
		t.Fatalf("aliases = %#v", aliases)
	}
	if len(envelope.Detachments) != 1 || envelope.Detachments[0].AttachmentGeneration != detach.AttachmentGeneration || envelope.Detachments[0].Reason != "server_detach" {
		t.Fatalf("detachments = %#v", envelope.Detachments)
	}
}

func TestCarrierDetachmentFromOutboxRejectsPrivateRoute(t *testing.T) {
	now := testNow()
	resolution := testResolution(now)
	req := testRequest()
	hash, err := req.Hash(resolution.Lease.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	attachment := attachmentFromResolution(req, hash, resolution, now)
	item := PreviewCarrierOutboxItem{
		AccountID: attachment.AccountID, OperationID: attachment.OperationID,
		AttachmentGeneration: attachment.AttachmentGeneration, Action: "detach", Binding: attachment.Binding,
		AccessMode: "private", ConfigContentHash: attachment.ConfigContentHash,
		EdgeEndpoints: attachment.EdgeEndpoints, Endpoint: attachment.Endpoint,
		ExpiresAt: attachment.ExpiresAt, State: "pending",
	}
	if _, err := carrierDetachmentFromOutbox(item, now); !errors.Is(err, ErrAdmissionUnavailable) {
		t.Fatalf("private detachment error = %v, want ErrAdmissionUnavailable", err)
	}
}

func TestCarrierAdmissionRejectsUnknownOrTerminalState(t *testing.T) {
	now := testNow()
	resolution := testResolution(now)
	req := testRequest()
	hash, err := req.Hash(resolution.Lease.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	attachment := attachmentFromResolution(req, hash, resolution, now)
	for _, state := range []string{"", "failed", "released", "bogus"} {
		t.Run(state, func(t *testing.T) {
			admission := CarrierAdmission{
				Schema: Schema, Kind: Kind, Binding: attachment.Binding, AccessMode: attachment.AccessMode,
				AttachmentGeneration: attachment.AttachmentGeneration, ConfigContentHash: attachment.ConfigContentHash,
				EdgeEndpoints: attachment.EdgeEndpoints, Endpoint: attachment.Endpoint, ExpiresAt: attachment.ExpiresAt,
				State: state, Hostname: endpointHostname(attachment.Endpoint), RouteKind: routeKindForAccessMode(attachment.AccessMode),
				RouteRevision: attachment.RouteGeneration,
			}
			if err := admission.Validate(now); !errors.Is(err, ErrInvalid) {
				t.Fatalf("state %q validation error = %v, want ErrInvalid", state, err)
			}
		})
	}
}

func TestEdgeDetachmentRejectsReplacementProcessEpoch(t *testing.T) {
	now := testNow()
	resolution := testResolution(now)
	req := testRequest()
	hash, err := req.Hash(resolution.Lease.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	attachment := attachmentFromResolution(req, hash, resolution, now)
	detachment := PreviewCarrierDetachment{
		Schema: Schema, Kind: Kind, Binding: attachment.Binding,
		AttachmentGeneration: attachment.AttachmentGeneration + 1,
		Reason:               "server_detach", ObservedAt: now,
	}
	detachment.Binding.EdgeProcessEpoch = "edge-process-old"
	outbox := &edgeOutboxFake{}
	service, err := NewService(&serviceRepositoryFake{}, &testAuthority{resolution: resolution}, &testPublisher{})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.SetClock(func() time.Time { return now }); err != nil {
		t.Fatal(err)
	}
	handler, err := NewEdgeHTTPHandler(service, outbox, edgeVerifierFake{nodeID: attachment.EdgeNodeID})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(edgeDetachmentBatch{
		EdgeNodeID: attachment.EdgeNodeID, ProcessEpoch: attachment.EdgeProcessEpoch,
		Detachments: []PreviewCarrierDetachment{detachment},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, EdgeDetachmentPath, bytes.NewReader(body))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("replacement-epoch detachment status = %d, body = %s", response.Code, response.Body.String())
	}
	if len(outbox.acks) != 0 {
		t.Fatalf("replacement-epoch detachment produced ACKs = %#v", outbox.acks)
	}
}

func TestEdgeAdmissionAckAcceptsCanonicalBatchAboveHostRequestLimit(t *testing.T) {
	now := testNow()
	resolution := testResolution(now)
	req := testRequest()
	hash, err := req.Hash(resolution.Lease.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	attachment := attachmentFromResolution(req, hash, resolution, now)
	attachment.State = StateAdmitted
	admission, err := attachment.Admission()
	if err != nil {
		t.Fatal(err)
	}
	// A complete edge batch is allowed to exceed the 64 KiB host mutation
	// limit. Keep each entry valid while making the request large enough to
	// exercise the separate edge control reader.
	batch := make([]CarrierAdmission, 128)
	for index := range batch {
		batch[index] = admission
	}
	body, err := json.Marshal(edgeAdmissionAckRequest{
		EdgeNodeID: resolution.Carrier.EdgeNodeID, ProcessEpoch: resolution.Carrier.EdgeProcessEpoch,
		Admissions: batch,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(body) <= MaxRequestBytes {
		t.Fatalf("test ACK body = %d bytes, want larger than host request limit %d", len(body), MaxRequestBytes)
	}
	outbox := &edgeOutboxFake{}
	service, err := NewService(&serviceRepositoryFake{}, &testAuthority{resolution: resolution}, &testPublisher{})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.SetClock(func() time.Time { return now }); err != nil {
		t.Fatal(err)
	}
	handler, err := NewEdgeHTTPHandler(service, outbox, edgeVerifierFake{nodeID: resolution.Carrier.EdgeNodeID})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, EdgeAdmissionAckPath, bytes.NewReader(body))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("large ACK status = %d, body = %s", response.Code, response.Body.String())
	}
	if len(outbox.acks) != len(batch) {
		t.Fatalf("large ACK count = %d, want %d", len(outbox.acks), len(batch))
	}
}

func TestEdgeControlRejectsBodyAboveBound(t *testing.T) {
	now := testNow()
	resolution := testResolution(now)
	service, err := NewService(&serviceRepositoryFake{}, &testAuthority{resolution: resolution}, &testPublisher{})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.SetClock(func() time.Time { return now }); err != nil {
		t.Fatal(err)
	}
	handler, err := NewEdgeHTTPHandler(service, &edgeOutboxFake{}, edgeVerifierFake{nodeID: resolution.Carrier.EdgeNodeID})
	if err != nil {
		t.Fatal(err)
	}
	body := bytes.Repeat([]byte{' '}, EdgeControlMaxRequestBytes+1)
	request := httptest.NewRequest(http.MethodPost, EdgeAdmissionPullPath, bytes.NewReader(body))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("oversized edge control status = %d, body = %s", response.Code, response.Body.String())
	}
}
