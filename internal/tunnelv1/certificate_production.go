package tunnelv1

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/tunnelcert"
)

// ErrCertificateRuntimeUnavailable identifies a deployment that enabled the
// managed public-certificate lifecycle without supplying every authenticated
// issuer, key, CAA, and edge-distribution dependency.  It is intentionally a
// stable error for startup and readiness callers; no secret value is included.
var ErrCertificateRuntimeUnavailable = errors.New("managed certificate runtime is unavailable")

// CertificateRuntimeConfig is the explicit production composition boundary.
// Secret material is supplied by reference-resolving implementations and is
// held only by the short-lived issuer/distribution component. References are
// persisted in configuration and certificate metadata, never plaintext keys.
type CertificateRuntimeConfig struct {
	Database *db.DB

	Issuer                 tunnelcert.Issuer
	CAA                    tunnelcert.CAAInspector
	Keys                   tunnelcert.MasterKeySource
	MasterKeyReference     string
	DistributionCredential []byte
	DistributionIdentity   tunnelcert.DistributionNodeIdentityResolver
	IssuerName             string
	OwnerID                string

	RenewBefore            time.Duration
	LockTTL                time.Duration
	DistributionTimeout    time.Duration
	ExpiryAlertWindow      time.Duration
	MaxCertificateLifetime time.Duration
	Now                    func() time.Time

	// PlatformBases enables the server-owned preview/tunnel wildcard worker.
	// The edge resolver must return exact current node/process/assignment
	// generations; roots with no platform bases retain the user-domain-only
	// runtime for deterministic tests and migrations before rollout.
	PlatformBases       tunnelcert.PlatformCertificateBases
	PlatformEdgeTargets PlatformEdgeTargetResolver
}

// CertificateRuntime owns the one server-side certificate worker and its
// authenticated pull/ack hub. Closing it wipes queued certificate/key bytes
// and wakes every waiting edge operation. App shutdown owns this component.
type CertificateRuntime struct {
	Worker         *CertificateWorker
	PlatformWorker *PlatformCertificateWorker
	Distribution   *tunnelcert.DistributionHub

	closeOnce sync.Once
	closeErr  error
}

// NewCertificateRuntime constructs the complete durable certificate path:
// SQL certificate state and issuance locks, authenticated distribution hub,
// fenced edge identity lookup, coordinator, operation completer, and worker.
// The caller must provide all provider boundaries explicitly.
func NewCertificateRuntime(config CertificateRuntimeConfig) (*CertificateRuntime, error) {
	if config.Database == nil || config.Issuer == nil || config.CAA == nil || config.Keys == nil || config.MasterKeyReference == "" || config.OwnerID == "" || len(config.DistributionCredential) == 0 {
		return nil, fmt.Errorf("%w: database, issuer, CAA, key source, references, owner, and distribution credential are required", ErrCertificateRuntimeUnavailable)
	}
	store, err := tunnelcert.NewSQLStore(config.Database)
	if err != nil {
		return nil, fmt.Errorf("%w: certificate store: %v", ErrCertificateRuntimeUnavailable, err)
	}
	locks, err := tunnelcert.NewSQLIssuanceLock(config.Database)
	if err != nil {
		return nil, fmt.Errorf("%w: issuance lock: %v", ErrCertificateRuntimeUnavailable, err)
	}
	operations, err := tunnelcert.NewSQLOperationCompleter(config.Database)
	if err != nil {
		return nil, fmt.Errorf("%w: operation completer: %v", ErrCertificateRuntimeUnavailable, err)
	}
	identity := config.DistributionIdentity
	if identity == nil {
		keyLookup, lookupErr := tunnelcert.NewSQLDistributionNodePublicKeyLookup(config.Database, config.Now)
		if lookupErr != nil {
			return nil, fmt.Errorf("%w: edge identity lookup: %v", ErrCertificateRuntimeUnavailable, lookupErr)
		}
		identity, err = tunnelcert.NewSignedDistributionNodeIdentityResolver(keyLookup, config.Now)
		if err != nil {
			return nil, fmt.Errorf("%w: edge identity lookup: %v", ErrCertificateRuntimeUnavailable, err)
		}
	}
	var worker *CertificateWorker
	hub, err := tunnelcert.NewDistributionHub(tunnelcert.DistributionHubConfig{
		Credential: config.DistributionCredential,
		Now:        config.Now,
		Identity:   identity,
		OnDemand: func(ctx context.Context, edge tunnelcert.DistributionNodeIdentity, hostname string) error {
			if worker == nil {
				return tunnelcert.ErrCertificateNotReady
			}
			return worker.RequestExactLeaf(ctx, edge.NodeID, edge.ProcessEpoch, hostname)
		},
	})
	if err != nil {
		return nil, fmt.Errorf("%w: distribution hub: %v", ErrCertificateRuntimeUnavailable, err)
	}
	closeHub := func() {
		if hub != nil {
			_ = hub.Close()
		}
	}
	distributor, err := tunnelcert.NewSQLDistributor(config.Database, hub)
	if err != nil {
		closeHub()
		return nil, fmt.Errorf("%w: SQL distributor: %v", ErrCertificateRuntimeUnavailable, err)
	}
	coordinator, err := tunnelcert.NewCoordinator(tunnelcert.Config{
		Store:                  store,
		Locks:                  locks,
		Keys:                   config.Keys,
		Issuer:                 config.Issuer,
		CAA:                    config.CAA,
		Distributor:            distributor,
		Operations:             operations,
		MasterKeyReference:     config.MasterKeyReference,
		IssuerName:             config.IssuerName,
		OwnerID:                config.OwnerID,
		LockTTL:                config.LockTTL,
		RenewBefore:            config.RenewBefore,
		DistributionTimeout:    config.DistributionTimeout,
		ExpiryAlertWindow:      config.ExpiryAlertWindow,
		MaxCertificateLifetime: config.MaxCertificateLifetime,
		Now:                    config.Now,
	})
	if err != nil {
		closeHub()
		return nil, fmt.Errorf("%w: coordinator: %v", ErrCertificateRuntimeUnavailable, err)
	}
	worker, err = NewCertificateWorker(config.Database, coordinator, config.RenewBefore, config.Now, config.IssuerName)
	if err != nil {
		closeHub()
		return nil, fmt.Errorf("%w: certificate worker: %v", ErrCertificateRuntimeUnavailable, err)
	}
	var platformWorker *PlatformCertificateWorker
	if config.PlatformBases.PreviewBaseDomain != "" || config.PlatformBases.TunnelBaseDomain != "" || config.PlatformEdgeTargets != nil {
		platformWorker, err = NewPlatformCertificateWorker(PlatformCertificateWorkerConfig{
			Database: config.Database, Bases: config.PlatformBases, EdgeTargets: config.PlatformEdgeTargets,
			Issuer: config.Issuer, CAA: config.CAA, Keys: config.Keys,
			MasterKeyReference: config.MasterKeyReference, IssuerName: config.IssuerName,
			OwnerID: config.OwnerID, Distributor: distributor, RenewBefore: config.RenewBefore,
			LockTTL: config.LockTTL, DistributionTimeout: config.DistributionTimeout,
			ExpiryAlertWindow: config.ExpiryAlertWindow, MaxCertificateLifetime: config.MaxCertificateLifetime,
			Now: config.Now,
		})
		if err != nil {
			closeHub()
			return nil, fmt.Errorf("%w: platform certificate worker: %v", ErrCertificateRuntimeUnavailable, err)
		}
	}
	return &CertificateRuntime{Worker: worker, PlatformWorker: platformWorker, Distribution: hub}, nil
}

// Close is idempotent and fail-closed. It is safe to call during partial app
// construction as well as normal shutdown.
func (r *CertificateRuntime) Close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		if r.Distribution != nil {
			r.closeErr = r.Distribution.Close()
		}
	})
	return r.closeErr
}

var _ tunnelcert.CertificateDistributor = (*tunnelcert.DistributionHub)(nil)
