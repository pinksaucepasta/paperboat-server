package connectorprotocol

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/tunnelendpoint"
)

const (
	CarrierBootstrapSchema   = "paperboat.connector-bootstrap/v1"
	MaximumBootstrapCarriers = 4
)

var spkiHashPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type CarrierBootstrapRequest struct {
	Schema            string `json:"schema"`
	Kind              string `json:"kind"`
	SessionID         string `json:"session_id"`
	ProcessGeneration uint64 `json:"process_generation"`
	ConfigGeneration  uint64 `json:"config_generation"`
	ConfigContentHash string `json:"config_content_hash"`
}

func (r CarrierBootstrapRequest) Validate() error {
	if r.Schema != CarrierBootstrapSchema || r.Kind != "carrier_bootstrap_request" || ValidateIdentifier(r.SessionID) != nil || r.ProcessGeneration == 0 || r.ConfigGeneration == 0 || !hashPattern.MatchString(r.ConfigContentHash) {
		return ErrInvalidInput
	}
	return nil
}

type CarrierBootstrapNode struct {
	EdgeNodeID                string   `json:"edge_node_id"`
	EdgeProcessEpoch          string   `json:"edge_process_epoch"`
	FailureDomain             string   `json:"failure_domain"`
	Endpoints                 []string `json:"endpoints"`
	ServerSPKISHA256          string   `json:"server_spki_sha256"`
	ServerCertificateChainPEM string   `json:"server_certificate_chain_pem"`
}

func (n CarrierBootstrapNode) Validate() error {
	if ValidateIdentifier(n.EdgeNodeID) != nil || ValidateOpaqueEpoch(n.EdgeProcessEpoch) != nil || ValidateIdentifier(n.FailureDomain) != nil || len(n.Endpoints) != 2 || !spkiHashPattern.MatchString(n.ServerSPKISHA256) || !validCertificateChainPEM(n.ServerCertificateChainPEM) {
		return ErrInvalidInput
	}
	seen := map[string]bool{}
	for _, raw := range n.Endpoints {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Hostname() == "" || parsed.Port() == "" {
			return ErrInvalidInput
		}
		switch parsed.Scheme {
		case "tls", "quic":
			if seen[parsed.Scheme] {
				return ErrInvalidInput
			}
			seen[parsed.Scheme] = true
		default:
			return ErrInvalidInput
		}
	}
	if !seen["tls"] || !seen["quic"] {
		return ErrInvalidInput
	}
	return nil
}

type CarrierBootstrapDescriptor struct {
	Schema               string                 `json:"schema"`
	Kind                 string                 `json:"kind"`
	AccountID            string                 `json:"account_id"`
	TunnelID             string                 `json:"tunnel_id"`
	ConnectorID          string                 `json:"connector_id"`
	HostID               string                 `json:"host_id"`
	StableEndpointID     string                 `json:"stable_endpoint_id"`
	SessionID            string                 `json:"session_id"`
	ProcessGeneration    uint64                 `json:"process_generation"`
	CredentialGeneration uint64                 `json:"credential_generation"`
	ConfigGeneration     uint64                 `json:"config_generation"`
	ConfigContentHash    string                 `json:"config_content_hash"`
	Carriers             []CarrierBootstrapNode `json:"carriers"`
	IssuedAt             time.Time              `json:"issued_at"`
	ExpiresAt            time.Time              `json:"expires_at"`
}

func (d CarrierBootstrapDescriptor) Validate(now time.Time) error {
	if d.Schema != CarrierBootstrapSchema || d.Kind != "carrier_bootstrap_descriptor" || ValidateIdentifier(d.AccountID) != nil || ValidateIdentifier(d.TunnelID) != nil || ValidateIdentifier(d.ConnectorID) != nil || ValidateIdentifier(d.HostID) != nil || tunnelendpoint.ValidateUUID(d.StableEndpointID) != nil || ValidateIdentifier(d.SessionID) != nil || d.ProcessGeneration == 0 || d.CredentialGeneration == 0 || d.ConfigGeneration == 0 || !hashPattern.MatchString(d.ConfigContentHash) || len(d.Carriers) == 0 || len(d.Carriers) > MaximumBootstrapCarriers || d.IssuedAt.IsZero() || d.ExpiresAt.IsZero() || !d.ExpiresAt.After(d.IssuedAt) || d.ExpiresAt.Sub(d.IssuedAt) > 2*time.Minute {
		return ErrInvalidInput
	}
	if !now.IsZero() && (d.IssuedAt.After(now.Add(MaxClockSkew)) || !d.ExpiresAt.After(now)) {
		return ErrInvalidInput
	}
	seenNodes, seenDomains := map[string]bool{}, map[string]bool{}
	for _, carrier := range d.Carriers {
		if carrier.Validate() != nil || seenNodes[carrier.EdgeNodeID+"\x00"+carrier.EdgeProcessEpoch] || seenDomains[carrier.FailureDomain] {
			return ErrInvalidInput
		}
		seenNodes[carrier.EdgeNodeID+"\x00"+carrier.EdgeProcessEpoch] = true
		seenDomains[carrier.FailureDomain] = true
	}
	return nil
}

type CarrierBootstrapSource interface {
	Descriptor(context.Context, ActiveControlSession) (CarrierBootstrapDescriptor, error)
}

type SQLCarrierBootstrapSource struct {
	DB    *db.DB
	Clock Clock
}

func (s SQLCarrierBootstrapSource) Descriptor(ctx context.Context, active ActiveControlSession) (CarrierBootstrapDescriptor, error) {
	if ctx == nil || s.DB == nil || active.validate() != nil {
		return CarrierBootstrapDescriptor{}, ErrInvalidInput
	}
	tunnel, err := s.DB.Queries().GetTunnelManagedEndpointForConnectorBootstrapV1(ctx, dbsqlc.GetTunnelManagedEndpointForConnectorBootstrapV1Params{TunnelID: active.TunnelID, AccountID: active.AccountID})
	if err != nil || tunnelendpoint.ValidateUUID(tunnel.StableEndpointID) != nil {
		return CarrierBootstrapDescriptor{}, ErrInvalidInput
	}
	now := time.Now().UTC()
	if s.Clock != nil {
		now = s.Clock.Now().UTC()
	}
	rows, err := s.DB.Queries().ListReadyConnectorCarrierNodesV1(ctx, dbsqlc.ListReadyConnectorCarrierNodesV1Params{Now: now, RowLimit: MaximumBootstrapCarriers})
	if err != nil {
		return CarrierBootstrapDescriptor{}, err
	}
	carriers := make([]CarrierBootstrapNode, 0, len(rows))
	seenDomains := make(map[string]struct{}, len(rows))
	for _, row := range rows {
		if _, duplicate := seenDomains[row.FailureDomain.String]; duplicate {
			continue
		}
		if !row.CarrierEndpointHost.Valid || !row.CarrierEndpointTcpPort.Valid || !row.CarrierEndpointQuicPort.Valid || !row.CarrierServerSpkiSha256.Valid || !row.CarrierServerCertificateChainPem.Valid || !row.FailureDomain.Valid {
			continue
		}
		host := row.CarrierEndpointHost.String
		if net.ParseIP(host) == nil && (len(host) > 253 || strings.TrimSpace(host) != host || strings.ContainsAny(host, "/\\\r\n")) {
			continue
		}
		carrier := CarrierBootstrapNode{
			EdgeNodeID: row.EdgeNodeID, EdgeProcessEpoch: row.EdgeProcessEpoch, FailureDomain: row.FailureDomain.String,
			Endpoints: []string{
				"tls://" + net.JoinHostPort(host, fmt.Sprint(row.CarrierEndpointTcpPort.Int32)),
				"quic://" + net.JoinHostPort(host, fmt.Sprint(row.CarrierEndpointQuicPort.Int32)),
			},
			ServerSPKISHA256: row.CarrierServerSpkiSha256.String, ServerCertificateChainPEM: row.CarrierServerCertificateChainPem.String,
		}
		if carrier.Validate() != nil {
			continue
		}
		seenDomains[carrier.FailureDomain] = struct{}{}
		carriers = append(carriers, carrier)
	}
	if len(carriers) == 0 {
		return CarrierBootstrapDescriptor{}, codeError(ErrNotReady, ReasonSnapshotRejected, true, nil)
	}
	descriptor := CarrierBootstrapDescriptor{
		Schema: CarrierBootstrapSchema, Kind: "carrier_bootstrap_descriptor",
		AccountID: active.AccountID, TunnelID: active.TunnelID, ConnectorID: active.ConnectorID, HostID: active.HostID,
		StableEndpointID: tunnel.StableEndpointID,
		SessionID:        active.SessionID, ProcessGeneration: active.ProcessGeneration, CredentialGeneration: active.CredentialGeneration,
		ConfigGeneration: active.ConfigGeneration, ConfigContentHash: active.ConfigContentHash, Carriers: carriers,
		IssuedAt: now, ExpiresAt: now.Add(2 * time.Minute),
	}
	if err := descriptor.Validate(now); err != nil {
		return CarrierBootstrapDescriptor{}, err
	}
	return descriptor, nil
}

func validCertificateChainPEM(value string) bool {
	if len(value) == 0 || len(value) > 64<<10 || !strings.HasPrefix(value, "-----BEGIN CERTIFICATE-----") || strings.ContainsRune(value, '\x00') {
		return false
	}
	rest := []byte(value)
	count := 0
	for len(rest) > 0 {
		block, next := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return false
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return false
		}
		count++
		rest = next
	}
	return count > 0
}
