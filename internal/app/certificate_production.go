package app

import (
	"context"
	"crypto/subtle"
	"fmt"
	"os"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/tunnelcert"
	"github.com/pinksaucepasta/paperboat-server/internal/tunnelv1"
)

// newCertificateRuntime is the server's concrete managed-TLS composition.
// Config supplies only public endpoints and opaque references; the environment
// adapter is a narrow deployment boundary for an injected secret manager.
// Hosted deployments can replace that adapter without changing the certificate
// worker, durable store, or edge distribution contract.
func newCertificateRuntime(ctx context.Context, database *db.DB, cfg config.Config) (*tunnelv1.CertificateRuntime, error) {
	certificateConfig := cfg.Certificates
	if !certificateConfig.Enabled {
		return nil, fmt.Errorf("%w: managed certificates are disabled", tunnelv1.ErrCertificateRuntimeUnavailable)
	}
	if err := certificateConfig.Validate(cfg.Environment); err != nil {
		return nil, fmt.Errorf("%w: %v", tunnelv1.ErrCertificateRuntimeUnavailable, err)
	}
	if database == nil {
		return nil, fmt.Errorf("%w: database is required", tunnelv1.ErrCertificateRuntimeUnavailable)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	secrets := tunnelcert.EnvironmentReferenceSource{Prefix: "PAPERBOAT_CERT_SECRET_", LookupEnv: os.LookupEnv}
	distributionCredential, err := secrets.Resolve(ctx, certificateConfig.DistributionCredentialReference)
	if err != nil || len(distributionCredential) == 0 {
		return nil, fmt.Errorf("%w: distribution credential reference is unavailable", tunnelv1.ErrCertificateRuntimeUnavailable)
	}
	defer clear(distributionCredential)
	// The edge distribution client currently authenticates with the same
	// server-issued control credential. Keep the two configuration references
	// explicit, but fail closed if they resolve to different bytes. A second
	// independent bearer would let a misconfigured edge pull a different
	// node's certificate queue.
	edgeCredential := []byte(cfg.Secrets.EdgeControlCredential)
	if subtle.ConstantTimeCompare(edgeCredential, distributionCredential) != 1 {
		clear(edgeCredential)
		return nil, fmt.Errorf("%w: distribution credential must equal edge control credential", tunnelv1.ErrCertificateRuntimeUnavailable)
	}
	clear(edgeCredential)
	signerSource := tunnelcert.EnvironmentSignerSource{EnvironmentReferenceSource: secrets}
	dnsProvider, err := tunnelcert.NewCloudflareDNSProvider(tunnelcert.CloudflareDNSConfig{
		ZoneID:         certificateConfig.DNSZoneID,
		TokenReference: certificateConfig.DNSTokenReference,
		TokenSource:    secrets,
		HTTPClient:     providerHTTPClient("cloudflare-dns", cfg.HTTP.RequestTimeout),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: DNS provider configuration: %v", tunnelv1.ErrCertificateRuntimeUnavailable, err)
	}
	caaInspector, err := tunnelcert.NewDNSCAAInspector(tunnelcert.DNSCAAInspectorConfig{Server: certificateConfig.CAAResolver, Timeout: cfg.HTTP.RequestTimeout})
	if err != nil {
		return nil, fmt.Errorf("%w: CAA resolver configuration: %v", tunnelv1.ErrCertificateRuntimeUnavailable, err)
	}
	issuer, err := tunnelcert.NewACMEIssuer(tunnelcert.ACMEIssuerConfig{
		DirectoryURL:        certificateConfig.DirectoryURL,
		AccountKID:          certificateConfig.AccountKID,
		AccountEmail:        certificateConfig.AccountEmail,
		AccountKeys:         signerSource,
		AccountKeyReference: certificateConfig.AccountKeyReference,
		DNS:                 dnsProvider,
		HTTPClient:          providerHTTPClient("acme", cfg.HTTP.RequestTimeout),
		Timeout:             certificateConfig.ACMETimeout,
		PropagationTimeout:  certificateConfig.PropagationTimeout,
		CleanupTimeout:      certificateConfig.CleanupTimeout,
		PollInterval:        certificateConfig.PollInterval,
		MaxAttempts:         certificateConfig.MaxAttempts,
		RetryBase:           certificateConfig.RetryBase,
		RetryMax:            certificateConfig.RetryMax,
		Issuer:              certificateConfig.Issuer,
		ChallengeZone:       certificateConfig.ChallengeZone,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: ACME issuer configuration: %v", tunnelv1.ErrCertificateRuntimeUnavailable, err)
	}
	platformEdges, err := tunnelv1.NewSQLPlatformEdgeTargetResolver(database, controlplane.ControlTunnelNodeStaleAfter(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: platform edge targets: %v", tunnelv1.ErrCertificateRuntimeUnavailable, err)
	}
	runtime, err := tunnelv1.NewCertificateRuntime(tunnelv1.CertificateRuntimeConfig{
		Database:               database,
		Issuer:                 issuer,
		CAA:                    caaInspector,
		Keys:                   secrets,
		MasterKeyReference:     certificateConfig.MasterKeyReference,
		DistributionCredential: distributionCredential,
		IssuerName:             certificateConfig.Issuer,
		OwnerID:                certificateConfig.OwnerID,
		RenewBefore:            certificateConfig.RenewBefore,
		LockTTL:                certificateConfig.LockTTL,
		DistributionTimeout:    certificateConfig.DistributionTimeout,
		ExpiryAlertWindow:      certificateConfig.ExpiryAlertWindow,
		MaxCertificateLifetime: certificateConfig.MaxCertificateLifetime,
		PlatformBases: tunnelcert.PlatformCertificateBases{
			PreviewBaseDomain: cfg.Preview.BaseDomain,
			TunnelBaseDomain:  cfg.Tunnel.BaseDomain,
			RuntimeBaseDomain: cfg.RuntimeBaseDomain,
		},
		PlatformEdgeTargets: platformEdges.Resolve,
	})
	if err != nil {
		return nil, err
	}
	return runtime, nil
}
