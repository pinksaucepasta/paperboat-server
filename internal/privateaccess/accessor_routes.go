package privateaccess

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/canonicaljson"
	"github.com/pinksaucepasta/paperboat-server/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

var (
	accessorConfigHashPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	accessorNamePattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
)

const (
	MachineRoutesPath  = "/v1/private-access/routes"
	EdgeAdmissionsPath = "/v1/edge/private-access/carrier-admissions"
	accessorLimit      = 4096
)

// AccessorAdmission is a short-lived, secret-free projection. It authorizes
// one enrolled machine identity to establish a carrier to one exact edge and
// target generation. It is not derived from preview ownership.
type AccessorAdmission struct {
	Schema                               string    `json:"schema"`
	Kind                                 string    `json:"kind"`
	AccountID                            string    `json:"account_id"`
	DeviceID                             string    `json:"device_id"`
	InstallationGeneration               uint64    `json:"installation_generation"`
	AccessorPublicKey                    string    `json:"accessor_public_key"`
	AccessorThumbprint                   string    `json:"accessor_thumbprint"`
	ResourceKind                         string    `json:"resource_kind"`
	ResourceID                           string    `json:"resource_id"`
	TunnelName                           string    `json:"tunnel_name,omitempty"`
	RouteName                            string    `json:"route_name,omitempty"`
	OperationID                          string    `json:"operation_id,omitempty"`
	ConnectorID                          string    `json:"connector_id,omitempty"`
	CarrierSessionID                     string    `json:"carrier_session_id"`
	RouteID                              string    `json:"route_id"`
	RouteGeneration                      uint64    `json:"route_generation"`
	SessionGeneration                    uint64    `json:"session_generation"`
	ProcessGeneration                    uint64    `json:"process_generation"`
	ConfigGeneration                     uint64    `json:"config_generation"`
	AssignmentGeneration                 uint64    `json:"assignment_generation"`
	AssignmentID                         string    `json:"assignment_id"`
	ConfigContentHash                    string    `json:"config_content_hash"`
	EdgeNodeID                           string    `json:"edge_node_id"`
	EdgeProcessEpoch                     string    `json:"edge_process_epoch"`
	Protocol                             string    `json:"protocol"`
	Hostname                             string    `json:"hostname"`
	MatchType                            string    `json:"match_type"`
	WildcardSuffix                       string    `json:"wildcard_suffix,omitempty"`
	EdgeEndpoints                        []string  `json:"edge_endpoints"`
	ExpiresAt                            time.Time `json:"expires_at"`
	TunnelID                             string    `json:"tunnel_id"`
	CarrierConnectorID                   string    `json:"carrier_connector_id"`
	EdgeCarrierServerSPKISHA256          string    `json:"edge_carrier_server_spki_sha256"`
	EdgeCarrierServerCertificateChainPEM string    `json:"edge_carrier_server_certificate_chain_pem"`
}

type AccessorSnapshot struct {
	Schema     string              `json:"schema"`
	Kind       string              `json:"kind"`
	Complete   bool                `json:"complete"`
	Admissions []AccessorAdmission `json:"admissions"`
}

type accessorRows interface {
	ListPrivateAccessRoutesForMachineV1(context.Context, dbsqlc.ListPrivateAccessRoutesForMachineV1Params) ([]dbsqlc.ListPrivateAccessRoutesForMachineV1Row, error)
	ListPrivateAccessCarrierAdmissionsForEdgeV1(context.Context, dbsqlc.ListPrivateAccessCarrierAdmissionsForEdgeV1Params) ([]dbsqlc.ListPrivateAccessCarrierAdmissionsForEdgeV1Row, error)
}

type AccessorRepository struct {
	queries accessorRows
	now     func() time.Time
}

func NewAccessorRepository(database *db.DB) (*AccessorRepository, error) {
	if database == nil || database.Pool() == nil {
		return nil, fmt.Errorf("%w: accessor database is unavailable", ErrInvalid)
	}
	return &AccessorRepository{queries: dbsqlc.New(database.Pool()), now: func() time.Time { return time.Now().UTC() }}, nil
}

func admissionFromValues(now time.Time, accountID, resourceKind, resourceID, tunnelName, routeName, operationID, connectorID, carrierSessionID, routeID string, routeGeneration, sessionGeneration, processGeneration, configGeneration, assignmentGeneration int64, edgeNodeID, edgeEpoch, protocol, hostname string, endpoints []string, expiresAt time.Time, tunnelID, carrierConnectorID, assignmentID, configContentHash, matchType, wildcardSuffix, deviceID string, installationGeneration int64, publicKey, edgeCarrierServerSPKISHA256, edgeCarrierServerCertificateChainPEM string) (AccessorAdmission, error) {
	for _, value := range []string{accountID, resourceID, carrierSessionID, routeID, edgeNodeID, tunnelID, carrierConnectorID, assignmentID, deviceID} {
		if connectorprotocol.ValidateIdentifier(value) != nil {
			return AccessorAdmission{}, ErrInvalid
		}
	}
	if routeGeneration <= 0 || sessionGeneration <= 0 || processGeneration <= 0 || configGeneration <= 0 || assignmentGeneration <= 0 || installationGeneration <= 0 || !expiresAt.After(now.UTC()) || protocol != "http" && protocol != "private_tcp" || !accessorConfigHashPattern.MatchString(configContentHash) || connectorprotocol.ValidateOpaqueEpoch(edgeEpoch) != nil || len(endpoints) != 2 || !accessorConfigHashPattern.MatchString(edgeCarrierServerSPKISHA256) || len(edgeCarrierServerCertificateChainPEM) == 0 || len(edgeCarrierServerCertificateChainPEM) > 64<<10 {
		return AccessorAdmission{}, ErrInvalid
	}
	for index, scheme := range []string{"tls", "quic"} {
		endpoint, err := url.Parse(endpoints[index])
		port, portErr := strconv.Atoi(endpoint.Port())
		if err != nil || endpoint.Scheme != scheme || endpoint.Hostname() == "" || endpoint.User != nil || portErr != nil || port < 1 || port > 65535 || endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" {
			return AccessorAdmission{}, ErrInvalid
		}
	}
	if !validAccessorMatch(protocol, hostname, matchType, wildcardSuffix) {
		return AccessorAdmission{}, ErrInvalid
	}
	if resourceKind == ResourcePreview {
		if tunnelName != "" || routeName != "" || connectorprotocol.ValidateIdentifier(operationID) != nil || connectorID != "" || protocol != "http" {
			return AccessorAdmission{}, ErrInvalid
		}
	} else if resourceKind != ResourceTunnel || !validAccessorName(tunnelName, 63) || !validAccessorName(routeName, 80) || connectorprotocol.ValidateIdentifier(connectorID) != nil || operationID != "" {
		return AccessorAdmission{}, ErrInvalid
	}
	key, err := base64.RawURLEncoding.Strict().DecodeString(publicKey)
	if err != nil {
		return AccessorAdmission{}, ErrInvalid
	}
	thumb, err := connectorprotocol.IdentityThumbprint(key)
	if err != nil {
		return AccessorAdmission{}, ErrInvalid
	}
	return AccessorAdmission{Schema: "paperboat.preview-tunnel/v1", Kind: "private_access_carrier_admission", AccountID: accountID, DeviceID: deviceID, InstallationGeneration: uint64(installationGeneration), AccessorPublicKey: publicKey, AccessorThumbprint: thumb, ResourceKind: resourceKind, ResourceID: resourceID, TunnelName: tunnelName, RouteName: routeName, OperationID: operationID, ConnectorID: connectorID, CarrierSessionID: carrierSessionID, RouteID: routeID, RouteGeneration: uint64(routeGeneration), SessionGeneration: uint64(sessionGeneration), ProcessGeneration: uint64(processGeneration), ConfigGeneration: uint64(configGeneration), AssignmentGeneration: uint64(assignmentGeneration), AssignmentID: assignmentID, ConfigContentHash: configContentHash, EdgeNodeID: edgeNodeID, EdgeProcessEpoch: edgeEpoch, Protocol: protocol, Hostname: hostname, MatchType: matchType, WildcardSuffix: wildcardSuffix, EdgeEndpoints: append([]string(nil), endpoints...), ExpiresAt: expiresAt.UTC(), TunnelID: tunnelID, CarrierConnectorID: carrierConnectorID, EdgeCarrierServerSPKISHA256: edgeCarrierServerSPKISHA256, EdgeCarrierServerCertificateChainPEM: edgeCarrierServerCertificateChainPEM}, nil
}

func validAccessorName(value string, maximum int) bool {
	return value == strings.TrimSpace(value) && len(value) >= 1 && len(value) <= maximum && accessorNamePattern.MatchString(value)
}

func validAccessorMatch(protocol, hostname, matchType, wildcardSuffix string) bool {
	if protocol == "private_tcp" {
		return hostname == "" && matchType == "catch_all" && wildcardSuffix == ""
	}
	if hostname == "" || hostname != strings.ToLower(hostname) {
		return false
	}
	switch matchType {
	case "one_label_wildcard":
		return wildcardSuffix != "" && !strings.Contains(wildcardSuffix, "*") && hostname == "*."+wildcardSuffix && !strings.HasPrefix(wildcardSuffix, ".") && !strings.HasSuffix(wildcardSuffix, ".")
	case "exact", "managed_exact", "catch_all":
		return wildcardSuffix == "" && !strings.Contains(hostname, "*")
	default:
		return false
	}
}

func (r *AccessorRepository) MachineRoutes(ctx context.Context, accountID, machineID string) ([]AccessorAdmission, error) {
	now := r.now().UTC()
	rows, err := r.queries.ListPrivateAccessRoutesForMachineV1(ctx, dbsqlc.ListPrivateAccessRoutesForMachineV1Params{AccountID: accountID, MachineID: machineID, Now: now, RowLimit: accessorLimit + 1})
	if err != nil {
		return nil, err
	}
	if len(rows) > accessorLimit {
		return nil, ErrInvalid
	}
	out := make([]AccessorAdmission, 0, len(rows))
	for _, v := range rows {
		if !v.AccessorPublicKey.Valid {
			return nil, ErrInvalid
		}
		a, err := admissionFromValues(now, v.AccountID, v.ResourceKind, v.ResourceID, v.TunnelName, v.RouteName, v.OperationID, v.ConnectorID, v.CarrierSessionID, v.RouteID, v.RouteGeneration, v.SessionGeneration, v.ProcessGeneration, v.ConfigGeneration, v.AssignmentGeneration, v.EdgeNodeID, v.EdgeProcessEpoch, v.Protocol, v.Hostname, v.EdgeEndpoints, v.ExpiresAt, v.TunnelID, v.CarrierConnectorID, v.AssignmentID, v.ConfigContentHash, v.MatchType, v.WildcardSuffix, v.AccessorDeviceID, v.InstallationGeneration, v.AccessorPublicKey.String, v.EdgeCarrierServerSpkiSha256.String, v.EdgeCarrierServerCertificateChainPem.String)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

func (r *AccessorRepository) EdgeAdmissions(ctx context.Context, nodeID, epoch string) ([]AccessorAdmission, error) {
	now := r.now().UTC()
	rows, err := r.queries.ListPrivateAccessCarrierAdmissionsForEdgeV1(ctx, dbsqlc.ListPrivateAccessCarrierAdmissionsForEdgeV1Params{EdgeNodeID: nodeID, EdgeProcessEpoch: epoch, Now: now, RowLimit: accessorLimit + 1})
	if err != nil {
		return nil, err
	}
	if len(rows) > accessorLimit {
		return nil, ErrInvalid
	}
	out := make([]AccessorAdmission, 0, len(rows))
	for _, v := range rows {
		if !v.AccessorPublicKey.Valid {
			return nil, ErrInvalid
		}
		a, e := admissionFromValues(now, v.AccountID, v.ResourceKind, v.ResourceID, v.TunnelName, v.RouteName, v.OperationID, v.ConnectorID, v.CarrierSessionID, v.RouteID, v.RouteGeneration, v.SessionGeneration, v.ProcessGeneration, v.ConfigGeneration, v.AssignmentGeneration, v.EdgeNodeID, v.EdgeProcessEpoch, v.Protocol, v.Hostname, v.EdgeEndpoints, v.ExpiresAt, v.TunnelID, v.CarrierConnectorID, v.AssignmentID, v.ConfigContentHash, v.MatchType, v.WildcardSuffix, v.AccessorDeviceID, v.InstallationGeneration, v.AccessorPublicKey.String, v.EdgeCarrierServerSpkiSha256.String, v.EdgeCarrierServerCertificateChainPem.String)
		if e != nil {
			return nil, e
		}
		out = append(out, a)
	}
	return out, nil
}

type AccessorHTTPHandler struct {
	repo interface {
		MachineRoutes(context.Context, string, string) ([]AccessorAdmission, error)
		EdgeAdmissions(context.Context, string, string) ([]AccessorAdmission, error)
	}
	machine MachineRequestVerifier
	edge    EdgeVerifier
}

func NewAccessorHTTPHandler(repo interface {
	MachineRoutes(context.Context, string, string) ([]AccessorAdmission, error)
	EdgeAdmissions(context.Context, string, string) ([]AccessorAdmission, error)
}, machine MachineRequestVerifier, edge EdgeVerifier) (*AccessorHTTPHandler, error) {
	if repo == nil || machine == nil || edge == nil {
		return nil, ErrInvalid
	}
	return &AccessorHTTPHandler{repo: repo, machine: machine, edge: edge}, nil
}

type accessorRequest struct {
	EdgeNodeID       string `json:"edge_node_id,omitempty"`
	EdgeProcessEpoch string `json:"edge_process_epoch,omitempty"`
	IdempotencyKey   string `json:"idempotency_key,omitempty"`
}

func (h *AccessorHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r == nil || r.Method != http.MethodPost {
		writeHTTPError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST is required.", false)
		return
	}
	if values := r.Header.Values("Content-Type"); len(values) != 1 || values[0] != "application/json" {
		writeHTTPError(w, http.StatusUnsupportedMediaType, "content_type_required", "application/json is required.", false)
		return
	}
	raw, err := readBody(r)
	if err != nil {
		writeHTTPError(w, 400, "invalid_request", "The request is invalid.", false)
		return
	}
	if canonicaljson.RejectDuplicateFields(raw) != nil {
		writeHTTPError(w, 400, "invalid_request", "The request is invalid.", false)
		return
	}
	var in accessorRequest
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&in) != nil {
		writeHTTPError(w, 400, "invalid_request", "The request is invalid.", false)
		return
	}
	var extra any
	if !errors.Is(d.Decode(&extra), io.EOF) {
		writeHTTPError(w, 400, "invalid_request", "The request is invalid.", false)
		return
	}
	var admissions []AccessorAdmission
	switch r.URL.Path {
	case MachineRoutesPath:
		idempotency, e := singleHeader(r.Header, "Idempotency-Key", false)
		if e != nil || idempotency == "" || idempotency != in.IdempotencyKey {
			writeHTTPError(w, 400, "idempotency_key_invalid", "Idempotency-Key must match the request.", false)
			return
		}
		auth, _ := singleHeader(r.Header, "Authorization", false)
		identity, _ := singleHeader(r.Header, "X-Paperboat-Machine-Identity", false)
		proofText, _ := singleHeader(r.Header, "X-Paperboat-Machine-Proof", false)
		proof, e := base64.RawURLEncoding.Strict().DecodeString(proofText)
		if e != nil || !strings.HasPrefix(auth, "Bearer ") || strings.TrimPrefix(auth, "Bearer ") != identity {
			writeHTTPError(w, 401, "machine_identity_invalid", "Machine authentication is required.", false)
			return
		}
		claims, e := h.machine.VerifyMachineControlRequest(r.Context(), identity, proof, r.Method, r.URL.Path, raw)
		if e != nil || claims.UserID == "" || claims.MachineID == "" || claims.OperationID != in.IdempotencyKey {
			writeHTTPError(w, 401, "machine_identity_invalid", "Machine authentication is required.", false)
			return
		}
		admissions, e = h.repo.MachineRoutes(r.Context(), claims.UserID, claims.MachineID)
		if e != nil {
			writeHTTPError(w, 503, "private_access_unavailable", "Private access discovery is unavailable.", true)
			return
		}
		for _, admission := range admissions {
			if admission.AccountID != claims.UserID || admission.DeviceID != claims.MachineID || admission.InstallationGeneration != uint64(claims.InstallationGeneration) {
				writeHTTPError(w, http.StatusUnauthorized, "machine_identity_stale", "Machine authentication is stale.", false)
				return
			}
		}
	case EdgeAdmissionsPath:
		edge, e := h.edge.VerifyEdgeRequest(r.Context(), r, raw)
		if e != nil || edge.NodeID != in.EdgeNodeID || edge.ProcessEpoch != in.EdgeProcessEpoch {
			writeHTTPError(w, 401, "edge_identity_invalid", "Edge authentication is required.", false)
			return
		}
		admissions, e = h.repo.EdgeAdmissions(r.Context(), edge.NodeID, edge.ProcessEpoch)
		if e != nil {
			writeHTTPError(w, 503, "private_access_unavailable", "Private access discovery is unavailable.", true)
			return
		}
	default:
		writeHTTPError(w, 404, "not_found", "Not found.", false)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(AccessorSnapshot{Schema: "paperboat.preview-tunnel/v1", Kind: "private_access_carrier_snapshot", Complete: true, Admissions: admissions})
}
