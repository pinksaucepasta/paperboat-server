package app

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/tunnelcert"
)

// DNS publication is part of the existing server reconciliation lifecycle.
// Deployment-owned verified public address metadata is required before the
// first write. Registration/heartbeats cannot populate that metadata.
func newEdgeDNSWorker(database *db.DB, cfg config.Config) (func(context.Context) error, error) {
	admission, err := tunnelcert.NewDatabaseCloudflareAddressAdmission(database, cfg.Certificates.DNSZoneID)
	if err != nil {
		return nil, err
	}
	provider, err := tunnelcert.NewCloudflareDNSProvider(tunnelcert.CloudflareDNSConfig{
		AddressAdmission: admission, ZoneID: cfg.Certificates.DNSZoneID, TokenReference: cfg.Certificates.DNSTokenReference,
		TokenSource: tunnelcert.EnvironmentReferenceSource{Prefix: "PAPERBOAT_CERT_SECRET_", LookupEnv: os.LookupEnv},
		HTTPClient:  providerHTTPClient("cloudflare-edge-dns", 5*time.Second),
	})
	if err != nil {
		return nil, err
	}
	reconciler, err := tunnelcert.NewAddressReconciler(database, provider, net.DefaultResolver)
	if err != nil {
		return nil, err
	}
	return edgeDNSWorker(database, reconciler), nil
}

func edgeDNSWorker(database *db.DB, reconciler *tunnelcert.AddressReconciler) func(context.Context) error {
	return func(ctx context.Context) error {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		cursor := ""
		for {
			rows, err := database.Queries().ListEdgeDNSPublicationResourcesV1(ctx, dbsqlc.ListEdgeDNSPublicationResourcesV1Params{AfterID: cursor, BatchSize: 1})
			if err == nil && len(rows) == 0 {
				cursor = ""
			}
			for _, owner := range rows {
				cursor = owner.ID
				err = reconcileEdgeDNSOwner(ctx, database, reconciler, owner.ID, uint64(owner.Generation))
				if err != nil {
					break
				}
			}
			if err != nil && ctx.Err() == nil {
				slog.WarnContext(ctx, "edge DNS publication pending", "error", err)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
			}
		}
	}
}

func reconcileEdgeDNSOwner(ctx context.Context, database *db.DB, reconciler *tunnelcert.AddressReconciler, owner string, generation uint64) error {
	names, err := database.Queries().ListEdgeDNSPublicationNamesV1(ctx, owner)
	if err != nil {
		return err
	}
	owned, err := reconciler.OwnedHostnames(ctx, owner)
	if err != nil {
		return err
	}
	active, existing := map[string]bool{}, map[string]bool{}
	for _, host := range names {
		active[host] = true
	}
	for _, host := range owned {
		existing[host] = true
		if !active[host] {
			names = append(names, host)
		}
	}
	if len(names) > 128 {
		return errors.New("edge DNS hostname bound exceeded")
	}
	sort.Strings(names)
	for _, host := range names {
		desired := tunnelcert.DesiredAddressPublication{Owner: owner, Hostname: host, ResourceGeneration: generation, ObservedAt: time.Now().UTC()}
		if active[host] {
			rows, err := database.Queries().ListReadyEdgeDNSAddressesV1(ctx, dbsqlc.ListReadyEdgeDNSAddressesV1Params{TunnelID: owner, Hostname: host, Now: sql.NullTime{Time: time.Now().UTC(), Valid: true}})
			if err != nil {
				return err
			}
			desired, err = readyEdgePublication(owner, host, generation, rows)
			if err != nil {
				return err
			}
		}
		if len(desired.Addresses) == 0 && !existing[host] {
			continue
		}
		if active[host] {
			if _, err := database.Queries().TransferWithdrawnEdgeDNSNameV1(ctx, dbsqlc.TransferWithdrawnEdgeDNSNameV1Params{Hostname: host, OwnerID: owner, ResourceGeneration: int64(generation), ObservedAt: desired.ObservedAt}); err != nil {
				return err
			}
		}
		attempt, cancel := context.WithTimeout(ctx, 10*time.Second)
		err = reconciler.Reconcile(attempt, desired)
		cancel()
		if err != nil {
			return err
		}
	}
	return nil
}

func readyEdgePublication(owner, host string, generation uint64, rows []dbsqlc.ListReadyEdgeDNSAddressesV1Row) (tunnelcert.DesiredAddressPublication, error) {
	d := tunnelcert.DesiredAddressPublication{Owner: owner, Hostname: host, ResourceGeneration: generation, ObservedAt: time.Now().UTC()}
	if len(rows) > 2 {
		return d, errors.New("edge DNS placement exceeds two nodes")
	}
	var versions []string
	for _, row := range rows {
		if row.ResourceGeneration != int64(generation) {
			return d, errors.New("edge DNS resource changed during projection")
		}
		d.ObservedAt = row.ObservedAt
		if row.Ipv4 != "" {
			d.Addresses = append(d.Addresses, row.Ipv4)
		}
		if row.Ipv6 != "" {
			d.Addresses = append(d.Addresses, row.Ipv6)
			d.IPv6ReachabilityVerified = true
		}
		versions = append(versions, row.ID+"/"+row.ReadinessVersion)
		if d.ValidUntil.IsZero() || row.ValidUntil.Before(d.ValidUntil) {
			d.ValidUntil = row.ValidUntil
		}
	}
	sort.Strings(versions)
	sum := sha256.Sum256([]byte(strings.Join(versions, "\n")))
	d.ReadinessVersion = hex.EncodeToString(sum[:])
	return d, nil
}
