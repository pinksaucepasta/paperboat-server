package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelapi"
	"github.com/pinksaucepasta/paperboat-server/internal/tunnelv1"
)

// The resource handlers deliberately keep the wire documents separate from
// the service records. This prevents database vocabulary (for example
// private_tcp) and server-owned fields from crossing the API boundary.

type tunnelResourceRouteHostMatchDocument struct {
	Type           string `json:"type"`
	Hostname       string `json:"hostname"`
	WildcardLabels *int   `json:"wildcard_labels"`
}

type tunnelResourceRouteTLSDocument struct {
	Verification              string  `json:"verification"`
	ServerName                *string `json:"server_name"`
	CAReference               *string `json:"ca_reference"`
	ClientCredentialReference *string `json:"client_credential_reference"`
}

type tunnelResourceRouteOriginDocument struct {
	Scheme       string                          `json:"scheme"`
	Address      string                          `json:"address"`
	PreserveHost *bool                           `json:"preserve_host"`
	HostOverride *string                         `json:"host_override"`
	TLS          *tunnelResourceRouteTLSDocument `json:"tls"`
}

type tunnelResourceRouteCreateDocument struct {
	Name                 string                               `json:"name"`
	Protocol             string                               `json:"protocol"`
	HostMatch            tunnelResourceRouteHostMatchDocument `json:"host_match"`
	PathPrefix           *string                              `json:"path_prefix"`
	Origin               tunnelResourceRouteOriginDocument    `json:"origin"`
	Priority             int32                                `json:"priority"`
	ConnectTimeoutMS     int32                                `json:"connect_timeout_ms"`
	IdleTimeoutMS        int32                                `json:"idle_timeout_ms"`
	MaxConcurrentStreams int32                                `json:"max_concurrent_streams"`
}

type tunnelResourceRoutePatchDocument struct {
	Name                 *string                               `json:"name"`
	Protocol             *string                               `json:"protocol"`
	HostMatch            *tunnelResourceRouteHostMatchDocument `json:"host_match"`
	PathPrefix           *string                               `json:"path_prefix"`
	Origin               *tunnelResourceRouteOriginDocument    `json:"origin"`
	Priority             *int32                                `json:"priority"`
	ConnectTimeoutMS     *int32                                `json:"connect_timeout_ms"`
	IdleTimeoutMS        *int32                                `json:"idle_timeout_ms"`
	MaxConcurrentStreams *int32                                `json:"max_concurrent_streams"`
	DesiredState         *string                               `json:"desired_state"`
	raw                  map[string]json.RawMessage
}

func (d *tunnelResourceRoutePatchDocument) UnmarshalJSON(data []byte) error {
	type alias tunnelResourceRoutePatchDocument
	var decoded alias
	if !decodeTunnelJSON(data, &decoded) {
		return errors.New("invalid route patch document")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
		return errors.New("route patch body must be a JSON object")
	}
	*d = tunnelResourceRoutePatchDocument(decoded)
	d.raw = fields
	return nil
}

type tunnelResourceDomainCreateDocument struct {
	Hostname            string `json:"hostname"`
	RouteID             string `json:"route_id"`
	Provider            string `json:"provider,omitempty"`
	CertificateStrategy string `json:"certificate_strategy,omitempty"`
}

type tunnelResourceEnrollmentDocument struct {
	HostID       string   `json:"host_id"`
	Capabilities []string `json:"capabilities"`
	TTLSeconds   int      `json:"ttl_seconds"`
}

type tunnelResourceEnrollmentExchangeDocument struct {
	Token                       string  `json:"token"`
	HostID                      string  `json:"host_id"`
	ProtocolVersion             string  `json:"protocol_version"`
	SoftwareVersion             *string `json:"software_version"`
	CredentialReference         string  `json:"credential_reference"`
	CredentialThumbprint        string  `json:"credential_thumbprint"`
	CredentialVerifierAlgorithm string  `json:"credential_verifier_algorithm"`
	CredentialVerifierPublicKey string  `json:"credential_verifier_public_key"`
	CredentialProof             string  `json:"credential_proof"`
	OperatingSystem             *string `json:"operating_system"`
	Architecture                *string `json:"architecture"`
}

func tunnelResourceRouteOrigin(document tunnelResourceRouteOriginDocument) (tunnelv1.RouteOriginRequest, error) {
	if document.PreserveHost == nil {
		return tunnelv1.RouteOriginRequest{}, fmt.Errorf("%w: origin.preserve_host is required", tunnelv1.ErrInvalidInput)
	}
	origin := tunnelv1.RouteOriginRequest{Scheme: document.Scheme, Address: document.Address, PreserveHost: *document.PreserveHost, HostOverride: document.HostOverride}
	if document.TLS != nil {
		origin.TLS = &tunnelv1.RouteTLSRequest{Verification: document.TLS.Verification, ServerName: document.TLS.ServerName, CAReference: document.TLS.CAReference, ClientCredentialReference: document.TLS.ClientCredentialReference}
	}
	return origin, nil
}

func tunnelResourceRouteHostMatch(document tunnelResourceRouteHostMatchDocument) (string, string, string, error) {
	if document.Type == "" {
		return "", "", "", fmt.Errorf("%w: host_match.type is required", tunnelv1.ErrInvalidInput)
	}
	if document.Type == "catch_all" {
		if document.Hostname != "" || document.WildcardLabels != nil {
			return "", "", "", fmt.Errorf("%w: catch-all host_match cannot include a hostname or wildcard_labels", tunnelv1.ErrInvalidInput)
		}
		return document.Type, "", "", nil
	}
	if document.Hostname == "" {
		return "", "", "", fmt.Errorf("%w: host_match.hostname is required", tunnelv1.ErrInvalidInput)
	}
	if document.Type == "one_label_wildcard" {
		if document.WildcardLabels == nil || *document.WildcardLabels != 1 || !strings.HasPrefix(document.Hostname, "*.") {
			return "", "", "", fmt.Errorf("%w: one-label wildcard requires hostname *.suffix and wildcard_labels 1", tunnelv1.ErrInvalidInput)
		}
	} else if document.WildcardLabels != nil {
		return "", "", "", fmt.Errorf("%w: wildcard_labels is only valid for one-label wildcard routes", tunnelv1.ErrInvalidInput)
	}
	return document.Type, document.Hostname, "", nil
}

func (d tunnelResourceRouteCreateDocument) request() (tunnelv1.RouteCreateRequest, error) {
	origin, err := tunnelResourceRouteOrigin(d.Origin)
	if err != nil {
		return tunnelv1.RouteCreateRequest{}, err
	}
	matchType, hostname, wildcard, err := tunnelResourceRouteHostMatch(d.HostMatch)
	if err != nil {
		return tunnelv1.RouteCreateRequest{}, err
	}
	if d.HostMatch.Type == "one_label_wildcard" {
		wildcard = d.HostMatch.Hostname
		hostname = ""
	}
	if d.HostMatch.Type == "one_label_wildcard" {
		wildcard = strings.TrimPrefix(wildcard, "*.")
	}
	return tunnelv1.RouteCreateRequest{Name: d.Name, Protocol: d.Protocol, MatchType: matchType, Hostname: hostname, WildcardSuffix: wildcard, PathPrefix: d.PathPrefix, Origin: origin, Priority: d.Priority,
		ConnectTimeoutMS: d.ConnectTimeoutMS, IdleTimeoutMS: d.IdleTimeoutMS, MaxConcurrentStreams: d.MaxConcurrentStreams}, nil
}

func (d tunnelResourceRoutePatchDocument) request() (tunnelv1.RoutePatchRequest, error) {
	result := tunnelv1.RoutePatchRequest{Name: d.Name, Protocol: d.Protocol, PathPrefix: d.PathPrefix, PathPrefixSet: hasJSONField(d.raw, "path_prefix"), Priority: d.Priority,
		ConnectTimeoutMS: d.ConnectTimeoutMS, IdleTimeoutMS: d.IdleTimeoutMS, MaxConcurrentStreams: d.MaxConcurrentStreams, DesiredState: d.DesiredState}
	if d.HostMatch != nil {
		matchType, hostname, wildcard, err := tunnelResourceRouteHostMatch(*d.HostMatch)
		if err != nil {
			return tunnelv1.RoutePatchRequest{}, err
		}
		if d.HostMatch.Type == "one_label_wildcard" {
			wildcard = d.HostMatch.Hostname
			hostname = ""
			wildcard = strings.TrimPrefix(wildcard, "*.")
		}
		result.MatchType, result.Hostname, result.WildcardSuffix = stringPtr(matchType), stringPtr(hostname), stringPtr(wildcard)
		if matchType == "catch_all" {
			result.Hostname = nil
			result.WildcardSuffix = nil
		}
	}
	if d.Origin != nil {
		origin, err := tunnelResourceRouteOrigin(*d.Origin)
		if err != nil {
			return tunnelv1.RoutePatchRequest{}, err
		}
		result.Origin = &origin
	}
	if hasJSONField(d.raw, "name") && d.Name == nil || hasJSONField(d.raw, "protocol") && d.Protocol == nil || hasJSONField(d.raw, "desired_state") && d.DesiredState == nil {
		return tunnelv1.RoutePatchRequest{}, fmt.Errorf("%w: nullable route patch fields are invalid", tunnelv1.ErrInvalidInput)
	}
	if hasJSONField(d.raw, "host_match") && d.HostMatch == nil || hasJSONField(d.raw, "origin") && d.Origin == nil {
		return tunnelv1.RoutePatchRequest{}, fmt.Errorf("%w: host_match and origin cannot be null", tunnelv1.ErrInvalidInput)
	}
	return result, nil
}

func hasJSONField(fields map[string]json.RawMessage, name string) bool {
	_, ok := fields[name]
	return ok
}

func stringPtr(value string) *string {
	return &value
}

func resourceMutationBody(w http.ResponseWriter, r *http.Request, allowEmpty bool) ([]byte, [32]byte, bool) {
	body, ok := readTunnelRequestBody(w, r)
	if !ok {
		return nil, [32]byte{}, false
	}
	if len(bytes.TrimSpace(body)) == 0 && allowEmpty {
		body = []byte("{}")
	}
	if allowEmpty && !isEmptyTunnelMutation(body) {
		writeTunnelResourceError(w, r, fmt.Errorf("%w: mutation body must be an empty JSON object", tunnelv1.ErrInvalidInput))
		return nil, [32]byte{}, false
	}
	if len(bytes.TrimSpace(body)) == 0 {
		writeTunnelResourceError(w, r, fmt.Errorf("%w: JSON body is required", tunnelv1.ErrInvalidInput))
		return nil, [32]byte{}, false
	}
	hash, err := previewtunnelapi.RequestHash(body)
	if err != nil {
		writeTunnelResourceError(w, r, fmt.Errorf("%w: %v", tunnelv1.ErrInvalidInput, err))
		return nil, [32]byte{}, false
	}
	return body, hash, true
}

func resourceRequestContext(w http.ResponseWriter, r *http.Request) (previewtunnelapi.RequestContext, bool) {
	request, ok := tunnelRequestFromHTTP(w, r)
	return request, ok
}

func resourceMutationInput(r *http.Request, kind, id string, bodyHash [32]byte, requireETag bool) (tunnelv1.ResourceMutationInput, error) {
	idempotencyKey, err := previewtunnelapi.ParseIdempotencyKey(r.Header)
	if err != nil {
		return tunnelv1.ResourceMutationInput{}, err
	}
	input := tunnelv1.ResourceMutationInput{IdempotencyKey: idempotencyKey, RequestHash: bodyHash}
	if requireETag {
		generation, err := previewtunnelapi.ParseIfMatch(r.Header, kind, id)
		if err != nil {
			return tunnelv1.ResourceMutationInput{}, err
		}
		input.ExpectedGeneration = generation
	}
	return input, nil
}

func resourceIDs(r *http.Request) (string, string) {
	return tunnelIDFromPath(r), strings.TrimSpace(r.PathValue("route_id"))
}

func tunnelResourceRouteCreate(service tunnelv1.ResourceAPI) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, hash, ok := resourceMutationBody(w, r, false)
		if !ok {
			return
		}
		var document tunnelResourceRouteCreateDocument
		if !decodeTunnelJSON(body, &document) {
			writeTunnelResourceError(w, r, fmt.Errorf("%w: invalid route create document", tunnelv1.ErrInvalidInput))
			return
		}
		input, err := resourceMutationInput(r, "", "", hash, false)
		if err != nil {
			writeTunnelResourceError(w, r, err)
			return
		}
		request, ok := resourceRequestContext(w, r)
		if !ok {
			return
		}
		value, err := document.request()
		if err != nil {
			writeTunnelResourceError(w, r, err)
			return
		}
		value.Mutation = input
		result, err := service.CreateRoute(r.Context(), request, tunnelIDFromPath(r), value)
		if err != nil {
			writeTunnelResourceError(w, r, err)
			return
		}
		writeRouteMutation(w, result, true)
	}
}

func tunnelResourceRouteList(service tunnelv1.ResourceAPI) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		request, ok := resourceRequestContext(w, r)
		if !ok {
			return
		}
		limit, err := previewtunnelapi.PageLimit(r.URL.Query().Get("limit"))
		if err != nil {
			writeTunnelResourceError(w, r, fmt.Errorf("%w: %v", tunnelv1.ErrInvalidInput, err))
			return
		}
		page, err := service.ListRoutes(r.Context(), request, tunnelIDFromPath(r), r.URL.Query().Get("cursor"), limit)
		if err != nil {
			writeTunnelResourceError(w, r, err)
			return
		}
		writeResourceJSON(w, http.StatusOK, page)
	}
}

func tunnelResourceRouteGet(service tunnelv1.ResourceAPI) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		request, ok := resourceRequestContext(w, r)
		if !ok {
			return
		}
		value, err := service.GetRoute(r.Context(), request, tunnelIDFromPath(r), strings.TrimSpace(r.PathValue("route_id")))
		if err != nil {
			writeTunnelResourceError(w, r, err)
			return
		}
		w.Header().Set("ETag", value.ETag)
		writeResourceJSON(w, http.StatusOK, value)
	}
}

func tunnelResourceRoutePatch(service tunnelv1.ResourceAPI) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, hash, ok := resourceMutationBody(w, r, false)
		if !ok {
			return
		}
		var document tunnelResourceRoutePatchDocument
		if !decodeTunnelJSON(body, &document) {
			writeTunnelResourceError(w, r, fmt.Errorf("%w: invalid route patch document", tunnelv1.ErrInvalidInput))
			return
		}
		tunnelID, routeID := resourceIDs(r)
		input, err := resourceMutationInput(r, "route", routeID, hash, true)
		if err != nil {
			writeTunnelResourceError(w, r, err)
			return
		}
		request, ok := resourceRequestContext(w, r)
		if !ok {
			return
		}
		value, err := document.request()
		if err != nil {
			writeTunnelResourceError(w, r, err)
			return
		}
		value.Mutation = input
		result, err := service.PatchRoute(r.Context(), request, tunnelID, routeID, value)
		if err != nil {
			writeTunnelResourceError(w, r, err)
			return
		}
		writeRouteMutation(w, result, false)
	}
}

func tunnelResourceRouteDelete(service tunnelv1.ResourceAPI) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, hash, ok := resourceMutationBody(w, r, true)
		if !ok {
			return
		}
		_ = body
		tunnelID, routeID := resourceIDs(r)
		input, err := resourceMutationInput(r, "route", routeID, hash, true)
		if err != nil {
			writeTunnelResourceError(w, r, err)
			return
		}
		request, ok := resourceRequestContext(w, r)
		if !ok {
			return
		}
		result, err := service.DeleteRoute(r.Context(), request, tunnelID, routeID, input)
		if err != nil {
			writeTunnelResourceError(w, r, err)
			return
		}
		writeRouteMutation(w, result, false)
	}
}

func tunnelResourceDomainCreate(service tunnelv1.ResourceAPI) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, hash, ok := resourceMutationBody(w, r, false)
		if !ok {
			return
		}
		var document tunnelResourceDomainCreateDocument
		if !decodeTunnelJSON(body, &document) {
			writeTunnelResourceError(w, r, fmt.Errorf("%w: invalid domain create document", tunnelv1.ErrInvalidInput))
			return
		}
		input, err := resourceMutationInput(r, "", "", hash, false)
		if err != nil {
			writeTunnelResourceError(w, r, err)
			return
		}
		request, ok := resourceRequestContext(w, r)
		if !ok {
			return
		}
		result, err := service.CreateDomain(r.Context(), request, tunnelIDFromPath(r), tunnelv1.DomainCreateRequest{Hostname: document.Hostname, RouteID: document.RouteID, Provider: document.Provider, CertificateStrategy: document.CertificateStrategy, Mutation: input})
		if err != nil {
			writeTunnelResourceError(w, r, err)
			return
		}
		writeDomainMutation(w, result, true)
	}
}

func tunnelResourceDomainList(service tunnelv1.ResourceAPI) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		request, ok := resourceRequestContext(w, r)
		if !ok {
			return
		}
		limit, err := previewtunnelapi.PageLimit(r.URL.Query().Get("limit"))
		if err != nil {
			writeTunnelResourceError(w, r, fmt.Errorf("%w: %v", tunnelv1.ErrInvalidInput, err))
			return
		}
		page, err := service.ListDomains(r.Context(), request, tunnelIDFromPath(r), r.URL.Query().Get("cursor"), limit)
		if err != nil {
			writeTunnelResourceError(w, r, err)
			return
		}
		writeResourceJSON(w, http.StatusOK, page)
	}
}

func tunnelResourceDomainGet(service tunnelv1.ResourceAPI) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		request, ok := resourceRequestContext(w, r)
		if !ok {
			return
		}
		value, err := service.GetDomain(r.Context(), request, tunnelIDFromPath(r), strings.TrimSpace(r.PathValue("domain_id")))
		if err != nil {
			writeTunnelResourceError(w, r, err)
			return
		}
		w.Header().Set("ETag", value.ETag)
		writeResourceJSON(w, http.StatusOK, value)
	}
}

func tunnelResourceDomainDelete(service tunnelv1.ResourceAPI) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, hash, ok := resourceMutationBody(w, r, true)
		if !ok {
			return
		}
		_ = body
		domainID := strings.TrimSpace(r.PathValue("domain_id"))
		input, err := resourceMutationInput(r, "domain_binding", domainID, hash, true)
		if err != nil {
			writeTunnelResourceError(w, r, err)
			return
		}
		request, ok := resourceRequestContext(w, r)
		if !ok {
			return
		}
		result, err := service.DeleteDomain(r.Context(), request, tunnelIDFromPath(r), domainID, input)
		if err != nil {
			writeTunnelResourceError(w, r, err)
			return
		}
		writeDomainMutation(w, result, false)
	}
}

func tunnelResourceDomainVerify(service tunnelv1.ResourceAPI) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, hash, ok := resourceMutationBody(w, r, true)
		if !ok {
			return
		}
		_ = body
		domainID := strings.TrimSpace(r.PathValue("domain_id"))
		input, err := resourceMutationInput(r, "domain_binding", domainID, hash, true)
		if err != nil {
			writeTunnelResourceError(w, r, err)
			return
		}
		request, ok := resourceRequestContext(w, r)
		if !ok {
			return
		}
		result, err := service.VerifyDomain(r.Context(), request, tunnelIDFromPath(r), domainID, input)
		if err != nil {
			writeTunnelResourceError(w, r, err)
			return
		}
		writeDomainMutation(w, result, false)
	}
}

func tunnelResourceDomainInstructions(service tunnelv1.ResourceAPI) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		request, ok := resourceRequestContext(w, r)
		if !ok {
			return
		}
		value, err := service.DomainInstructions(r.Context(), request, tunnelIDFromPath(r), strings.TrimSpace(r.PathValue("domain_id")))
		if err != nil {
			writeTunnelResourceError(w, r, err)
			return
		}
		writeResourceJSON(w, http.StatusOK, value)
	}
}

func tunnelResourceConnectorList(service tunnelv1.ResourceAPI) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		request, ok := resourceRequestContext(w, r)
		if !ok {
			return
		}
		limit, err := previewtunnelapi.PageLimit(r.URL.Query().Get("limit"))
		if err != nil {
			writeTunnelResourceError(w, r, fmt.Errorf("%w: %v", tunnelv1.ErrInvalidInput, err))
			return
		}
		page, err := service.ListConnectors(r.Context(), request, tunnelIDFromPath(r), r.URL.Query().Get("cursor"), limit)
		if err != nil {
			writeTunnelResourceError(w, r, err)
			return
		}
		writeResourceJSON(w, http.StatusOK, page)
	}
}

func tunnelResourceConnectorGet(service tunnelv1.ResourceAPI) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		request, ok := resourceRequestContext(w, r)
		if !ok {
			return
		}
		value, err := service.GetConnector(r.Context(), request, tunnelIDFromPath(r), strings.TrimSpace(r.PathValue("connector_id")))
		if err != nil {
			writeTunnelResourceError(w, r, err)
			return
		}
		w.Header().Set("ETag", value.ETag)
		writeResourceJSON(w, http.StatusOK, value)
	}
}

func tunnelResourceIssueEnrollment(service tunnelv1.ResourceAPI, machineIdentities ...machineRequestVerifier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, hash, ok := resourceMutationBody(w, r, false)
		if !ok {
			return
		}
		var document tunnelResourceEnrollmentDocument
		if !decodeTunnelJSON(body, &document) {
			writeTunnelResourceError(w, r, fmt.Errorf("%w: invalid enrollment document", tunnelv1.ErrInvalidInput))
			return
		}
		input, err := resourceMutationInput(r, "", "", hash, false)
		if err != nil {
			writeTunnelResourceError(w, r, err)
			return
		}
		if document.TTLSeconds < 0 || document.TTLSeconds > 15*60 {
			writeTunnelResourceError(w, r, fmt.Errorf("%w: ttl_seconds is out of range", tunnelv1.ErrInvalidInput))
			return
		}
		var identities machineRequestVerifier
		if len(machineIdentities) > 0 {
			identities = machineIdentities[0]
		}
		request, ok := tunnelEnrollmentRequestContext(w, r, body, input.IdempotencyKey, document.HostID, identities)
		if !ok {
			return
		}
		value, err := service.IssueEnrollment(r.Context(), request, tunnelIDFromPath(r), tunnelv1.EnrollmentRequest{HostID: document.HostID, Capabilities: document.Capabilities, TTL: time.Duration(document.TTLSeconds) * time.Second, Mutation: input})
		if err != nil {
			writeTunnelResourceError(w, r, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusCreated, SuccessResponse{Data: value})
	}
}

// tunnelEnrollmentRequestContext is shared by enrollment issue and exchange.
// Both operations are host-owned and require the renewable machine identity
// to be authenticated over the exact request body and idempotency key.
func tunnelEnrollmentRequestContext(w http.ResponseWriter, r *http.Request, body []byte, idempotencyKey, hostID string, identities machineRequestVerifier) (previewtunnelapi.RequestContext, bool) {
	if !tunnelMachineHeadersPresent(r) {
		writePreviewTunnelError(w, r, http.StatusUnauthorized, "machine_identity_required", "A signed host identity is required for connector enrollment.", "unchanged", false, "run_on_authorized_host")
		return previewtunnelapi.RequestContext{}, false
	}
	authorizationValues := r.Header.Values("Authorization")
	identityValues := r.Header.Values("X-Paperboat-Machine-Identity")
	proofValues := r.Header.Values("X-Paperboat-Machine-Proof")
	if len(authorizationValues) != 1 || len(identityValues) != 1 || len(proofValues) != 1 {
		code := "machine_identity_invalid"
		if len(authorizationValues) == 0 || len(identityValues) == 0 || len(proofValues) == 0 {
			code = "machine_identity_required"
		}
		writePreviewTunnelError(w, r, http.StatusUnauthorized, code, "The signed host identity could not be verified.", "unchanged", false, "run_on_authorized_host")
		return previewtunnelapi.RequestContext{}, false
	}
	request, ok := tunnelMachineRequestContext(w, r, body, idempotencyKey, identities)
	if !ok {
		return previewtunnelapi.RequestContext{}, false
	}
	if hostID == "" || strings.TrimSpace(hostID) != hostID || request.Actor.HostID != hostID {
		writePreviewTunnelError(w, r, http.StatusForbidden, "connector_access_forbidden", "This host is not authorized for connector enrollment.", "unchanged", false, "use_authorized_host")
		return previewtunnelapi.RequestContext{}, false
	}
	return request, true
}

func tunnelResourceExchangeEnrollment(service tunnelv1.ResourceAPI, identities machineRequestVerifier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, hash, ok := resourceMutationBody(w, r, false)
		if !ok {
			return
		}
		var document tunnelResourceEnrollmentExchangeDocument
		if !decodeTunnelJSON(body, &document) {
			writeTunnelResourceError(w, r, fmt.Errorf("%w: invalid enrollment exchange document", tunnelv1.ErrInvalidInput))
			return
		}
		idempotencyKey, err := previewtunnelapi.ParseIdempotencyKey(r.Header)
		if err != nil {
			writeTunnelResourceError(w, r, err)
			return
		}
		request, ok := tunnelEnrollmentRequestContext(w, r, body, idempotencyKey, document.HostID, identities)
		if !ok {
			return
		}
		credentialPublicKey, publicKeyErr := base64.RawURLEncoding.Strict().DecodeString(strings.TrimSpace(document.CredentialVerifierPublicKey))
		credentialProof, credentialProofErr := base64.RawURLEncoding.Strict().DecodeString(strings.TrimSpace(document.CredentialProof))
		if publicKeyErr != nil || credentialProofErr != nil || !tunnelv1.VerifyConnectorCredentialProof(document.CredentialVerifierAlgorithm, credentialPublicKey, credentialProof,
			tunnelIDFromPath(r), document.HostID, document.Token, document.CredentialReference, document.CredentialThumbprint, idempotencyKey) {
			writePreviewTunnelError(w, r, http.StatusUnauthorized, "connector_credential_proof_invalid", "The connector credential proof could not be verified.", "unchanged", false, "retry_with_new_connector_key")
			return
		}
		value, err := service.ExchangeEnrollment(r.Context(), request, tunnelv1.EnrollmentExchangeRequest{
			TunnelID: tunnelIDFromPath(r), Token: document.Token, HostID: document.HostID, ProtocolVersion: document.ProtocolVersion,
			SoftwareVersion: document.SoftwareVersion, CredentialReference: document.CredentialReference, CredentialThumbprint: document.CredentialThumbprint,
			CredentialVerifierAlgorithm: document.CredentialVerifierAlgorithm, CredentialVerifierPublicKey: credentialPublicKey, CredentialProof: credentialProof,
			OperatingSystem: document.OperatingSystem, Architecture: document.Architecture,
			Mutation: tunnelv1.ResourceMutationInput{IdempotencyKey: idempotencyKey, RequestHash: hash},
		})
		if err != nil {
			writeTunnelResourceError(w, r, err)
			return
		}
		writeConnectorActivation(w, value)
	}
}

func tunnelResourceConnectorDrain(service tunnelv1.ResourceAPI) http.HandlerFunc {
	return tunnelResourceConnectorState(service, false)
}

func tunnelResourceConnectorRevoke(service tunnelv1.ResourceAPI) http.HandlerFunc {
	return tunnelResourceConnectorState(service, true)
}

func tunnelResourceConnectorState(service tunnelv1.ResourceAPI, revoke bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, hash, ok := resourceMutationBody(w, r, true)
		if !ok {
			return
		}
		_ = body
		connectorID := strings.TrimSpace(r.PathValue("connector_id"))
		input, err := resourceMutationInput(r, "connector", connectorID, hash, true)
		if err != nil {
			writeTunnelResourceError(w, r, err)
			return
		}
		request, ok := resourceRequestContext(w, r)
		if !ok {
			return
		}
		var value tunnelv1.ConnectorMutationResult
		var mutateErr error
		if revoke {
			value, mutateErr = service.RevokeConnector(r.Context(), request, tunnelIDFromPath(r), connectorID, input)
		} else {
			value, mutateErr = service.DrainConnector(r.Context(), request, tunnelIDFromPath(r), connectorID, input)
		}
		if mutateErr != nil {
			writeTunnelResourceError(w, r, mutateErr)
			return
		}
		writeConnectorMutation(w, value, false)
	}
}

func tunnelResourceRotateCredentials(service tunnelv1.ResourceAPI) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, hash, ok := resourceMutationBody(w, r, true)
		if !ok {
			return
		}
		_ = body
		input, err := resourceMutationInput(r, "tunnel", tunnelIDFromPath(r), hash, true)
		if err != nil {
			writeTunnelResourceError(w, r, err)
			return
		}
		request, ok := resourceRequestContext(w, r)
		if !ok {
			return
		}
		value, err := service.RotateCredentials(r.Context(), request, tunnelIDFromPath(r), input)
		if err != nil {
			writeTunnelResourceError(w, r, err)
			return
		}
		writeResourceJSON(w, http.StatusAccepted, value)
	}
}

func tunnelResourceTunnelLogs(service tunnelv1.ResourceAPI) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		request, ok := resourceRequestContext(w, r)
		if !ok {
			return
		}
		limit, err := previewtunnelapi.PageLimit(r.URL.Query().Get("limit"))
		if err != nil {
			writeTunnelResourceError(w, r, fmt.Errorf("%w: %v", tunnelv1.ErrInvalidInput, err))
			return
		}
		page, err := service.ListTunnelLogs(r.Context(), request, tunnelIDFromPath(r), r.URL.Query().Get("cursor"), limit)
		if err != nil {
			writeTunnelResourceError(w, r, err)
			return
		}
		writeResourceJSON(w, http.StatusOK, page)
	}
}

func tunnelResourcePreviewLogs(service tunnelv1.PreviewLogAPI) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		request, ok := resourceRequestContext(w, r)
		if !ok {
			return
		}
		limit, err := previewtunnelapi.PageLimit(r.URL.Query().Get("limit"))
		if err != nil {
			writeTunnelResourceError(w, r, fmt.Errorf("%w: %v", tunnelv1.ErrInvalidInput, err))
			return
		}
		page, err := service.ListPreviewLogs(r.Context(), request, strings.TrimSpace(r.PathValue("preview_id")), r.URL.Query().Get("cursor"), limit)
		if err != nil {
			writeTunnelResourceError(w, r, err)
			return
		}
		writeResourceJSON(w, http.StatusOK, page)
	}
}

func writeRouteMutation(w http.ResponseWriter, result tunnelv1.RouteMutationResult, create bool) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("ETag", result.Route.ETag)
	if result.Operation.State == "running" {
		writeJSON(w, http.StatusAccepted, SuccessResponse{Data: result.Operation})
		return
	}
	status := http.StatusOK
	if create && !result.Replayed {
		status = http.StatusCreated
	}
	writeJSON(w, status, SuccessResponse{Data: result.Route})
}

func writeDomainMutation(w http.ResponseWriter, result tunnelv1.DomainMutationResult, create bool) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("ETag", result.Domain.ETag)
	if result.Operation.State == "running" {
		writeJSON(w, http.StatusAccepted, SuccessResponse{Data: result.Operation})
		return
	}
	status := http.StatusOK
	if create && !result.Replayed {
		status = http.StatusCreated
	}
	writeJSON(w, status, SuccessResponse{Data: result.Domain})
}

func writeConnectorMutation(w http.ResponseWriter, result tunnelv1.ConnectorMutationResult, create bool) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("ETag", result.Connector.ETag)
	if result.Operation.State == "running" {
		writeJSON(w, http.StatusAccepted, SuccessResponse{Data: result.Operation})
		return
	}
	status := http.StatusOK
	if create && !result.Replayed {
		status = http.StatusCreated
	}
	writeJSON(w, status, SuccessResponse{Data: result.Connector})
}

func writeConnectorActivation(w http.ResponseWriter, result tunnelv1.ConnectorMutationResult) {
	w.Header().Set("Cache-Control", "no-store")
	if result.Activation == nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: APIError{Code: "connector_activation_unavailable", Message: "Connector activation metadata is unavailable."}})
		return
	}
	writeJSON(w, http.StatusAccepted, SuccessResponse{Data: result.Activation})
}

func writeResourceJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, SuccessResponse{Data: value})
}

func writeTunnelResourceError(w http.ResponseWriter, r *http.Request, err error) {
	status, code, message, outcome, retryable, action := http.StatusInternalServerError, "internal_error", "Internal server error.", "uncertain", true, "retry"
	switch {
	case errors.Is(err, previewtunnelapi.ErrIfMatchRequired):
		status, code, message, outcome, retryable, action = http.StatusPreconditionRequired, "if_match_required", "If-Match is required for this resource mutation.", "unchanged", false, "fetch_current_resource"
	case errors.Is(err, previewtunnelapi.ErrInvalidETag):
		status, code, message, outcome, retryable, action = http.StatusBadRequest, "invalid_etag", "If-Match does not identify this resource.", "unchanged", false, "fetch_current_resource"
	case errors.Is(err, previewtunnelapi.ErrInvalidCursor):
		status, code, message, outcome, retryable, action = http.StatusBadRequest, "invalid_cursor", "The resource cursor is invalid.", "unchanged", false, "restart_pagination"
	case errors.Is(err, previewtunnelapi.ErrIdempotencyRequired):
		status, code, message, outcome, retryable, action = http.StatusBadRequest, "idempotency_required", "Idempotency-Key is required.", "unchanged", false, "retry_with_idempotency_key"
	case errors.Is(err, previewtunnelapi.ErrInvalidIdempotency):
		status, code, message, outcome, retryable, action = http.StatusBadRequest, "invalid_idempotency_key", "Idempotency-Key is invalid.", "unchanged", false, "send_valid_idempotency_key"
	case errors.Is(err, previewtunnelapi.ErrForbidden), errors.Is(err, previewtunnelapi.ErrHostActorRequired), errors.Is(err, tunnelv1.ErrHostNotFound):
		status, code, message, outcome, retryable, action = http.StatusForbidden, "forbidden", "You are not allowed to access this resource.", "unchanged", false, "authenticate_with_required_scope"
	case errors.Is(err, tunnelv1.ErrNotFound), errors.Is(err, tunnelv1.ErrRouteNotFound), errors.Is(err, tunnelv1.ErrDomainNotFound), errors.Is(err, tunnelv1.ErrConnectorNotFound):
		status, code, message, outcome, retryable, action = http.StatusNotFound, "resource_not_found", "The resource was not found.", "unchanged", false, "refresh"
	case errors.Is(err, tunnelv1.ErrGenerationConflict):
		status, code, message, outcome, retryable, action = http.StatusPreconditionFailed, "generation_conflict", "The resource changed before this update was applied.", "unchanged", false, "fetch_current_resource"
	case errors.Is(err, tunnelv1.ErrIdempotencyConflict):
		status, code, message, outcome, retryable, action = http.StatusConflict, "idempotency_conflict", "The idempotency key was already used for different input.", "unchanged", false, "retry_with_new_idempotency_key"
	case errors.Is(err, tunnelv1.ErrRouteConflict):
		status, code, message, outcome, retryable, action = http.StatusConflict, "route_conflict", "The route conflicts with an existing route.", "unchanged", false, "choose_different_match"
	case errors.Is(err, tunnelv1.ErrDomainConflict):
		status, code, message, outcome, retryable, action = http.StatusConflict, "domain_conflict", "The domain binding conflicts with an existing binding.", "unchanged", false, "inspect_domain"
	case errors.Is(err, tunnelv1.ErrConnectorConflict):
		status, code, message, outcome, retryable, action = http.StatusConflict, "connector_conflict", "The connector conflicts with current tunnel state.", "unchanged", false, "refresh_and_retry"
	case errors.Is(err, tunnelv1.ErrConflict):
		status, code, message, outcome, retryable, action = http.StatusConflict, "resource_conflict", "The resource conflicts with current state.", "unchanged", false, "refresh_and_retry"
	case errors.Is(err, tunnelv1.ErrEnrollmentAlreadyIssued):
		status, code, message, outcome, retryable, action = http.StatusConflict, "enrollment_token_unrecoverable", "The one-time enrollment token cannot be recovered after issuance. Issue a new enrollment with a new idempotency key.", "changed", false, "issue_new_enrollment"
	case errors.Is(err, tunnelv1.ErrEnrollmentExpired):
		status, code, message, outcome, retryable, action = http.StatusGone, "enrollment_expired", "The connector enrollment has expired. Issue a new enrollment.", "unchanged", false, "issue_new_enrollment"
	case errors.Is(err, tunnelv1.ErrEnrollmentReplay):
		status, code, message, outcome, retryable, action = http.StatusConflict, "enrollment_replay", "The connector enrollment was already consumed. Issue a new enrollment.", "changed", false, "issue_new_enrollment"
	case errors.Is(err, tunnelv1.ErrDNSInstructionsUnavailable):
		status, code, message, outcome, retryable, action = http.StatusNotImplemented, "dns_instructions_unavailable", "Provider-aware instructions for this domain are not available yet.", "unchanged", false, "configure_dns_provider"
	case errors.Is(err, tunnelv1.ErrTerminalState):
		status, code, message, outcome, retryable, action = http.StatusConflict, "resource_deleted", "The resource is terminal and cannot be changed.", "unchanged", false, "create_new_resource"
	case errors.Is(err, tunnelv1.ErrOperationInProgress):
		status, code, message, outcome, retryable, action = http.StatusConflict, "operation_in_progress", "An earlier resource operation is still in progress.", "uncertain", true, "inspect_operation"
	case errors.Is(err, tunnelv1.ErrInvalidInput):
		status, code, message, outcome, retryable, action = http.StatusBadRequest, "invalid_request", "The resource request is invalid.", "unchanged", false, "fix_request"
	}
	writePreviewTunnelError(w, r, status, code, message, outcome, retryable, action)
}
