package tunnelv1

import (
	"database/sql"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

func TestCertificateDomainUsesConfiguredIssuerAndRenewalWindow(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	row := dbsqlc.TunnelDomain{
		ID:                          "dom_01",
		AccountID:                   "acct_01",
		TunnelID:                    "tun_01",
		Hostname:                    "*.example.test",
		OwnershipChallengeReference: "dns-challenge://dom_01",
		OwnershipState:              "verified",
		CertificateStrategy:         "managed",
		CertificateState:            "ready",
		CertificateExpiresAt:        sql.NullTime{Time: now.Add(20 * 24 * time.Hour), Valid: true},
		Generation:                  3,
	}
	for _, test := range []struct {
		name        string
		renewBefore time.Duration
		due         bool
	}{
		{name: "short window", renewBefore: 15 * 24 * time.Hour, due: false},
		{name: "long window", renewBefore: 60 * 24 * time.Hour, due: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			domain, err := certificateDomainWithConfig(row, nil, now, test.renewBefore, "acme.example")
			if err != nil {
				t.Fatal(err)
			}
			if domain.Issuer != "acme.example" {
				t.Fatalf("issuer = %q, want configured issuer", domain.Issuer)
			}
			if domain.RenewalDue != test.due {
				t.Fatalf("renewal due = %v, want %v", domain.RenewalDue, test.due)
			}
		})
	}
}
