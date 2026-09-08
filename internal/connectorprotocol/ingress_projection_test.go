package connectorprotocol

import (
	"context"
	"testing"
	"time"
)

func projectionFixture(now time.Time) IngressDecision {
	return IngressDecision{Binding: IngressBinding{AccountID: "account_1", EnvironmentID: "environment_1", TunnelID: "tunnel_1", ResourceGeneration: 3, RouteID: "route_1", RouteGeneration: 4, HostID: "machine_1", InstallationGeneration: 5, Protocol: "http", Hostname: "app.example.com", PathPrefix: "/", OriginScheme: "http", OriginAddress: "localhost:3000", TLSVerification: "not_applicable"}, EdgeNodeID: "edge_1", EdgeProcessEpoch: "epoch_12345678", ConnectorID: "connector_1", SessionID: "session_1", ProcessGeneration: 6, ConfigGeneration: 7, AssignmentGeneration: 8, ExpiresAt: now.Add(10 * time.Second)}
}

func TestIngressProjectionPreservesExactAuthority(t *testing.T) {
	now := time.Now().UTC()
	d := projectionFixture(now)
	if err := completeIngressProjection(&d, now); err != nil {
		t.Fatal(err)
	}
	b := d.Binding
	if b.OriginAddress != "127.0.0.1:3000" || b.TargetID != b.RouteID || b.TargetGeneration != 4 || b.PublicationID != b.RouteID || b.PublicationGeneration != 4 || b.Lifecycle != TunnelDurable || d.PolicyGeneration != 3 || b.InstallationGeneration != 5 || d.AssignmentGeneration != 8 {
		t.Fatalf("authority mapping incorrect: %+v", d)
	}
	next := projectionFixture(now)
	if err := completeIngressProjection(&next, now); err != nil {
		t.Fatal(err)
	}
	if d.DecisionID == next.DecisionID {
		t.Fatal("refresh reused decision identifier")
	}
}

func TestIngressProjectionRejectsInvalidTargetAndExpiry(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		name   string
		mutate func(*IngressDecision)
	}{
		{"remote target", func(d *IngressDecision) { d.Binding.OriginAddress = "192.0.2.1:3000" }},
		{"dns target", func(d *IngressDecision) { d.Binding.OriginAddress = "origin.example.com:3000" }},
		{"expired", func(d *IngressDecision) { d.ExpiresAt = now }},
		{"excessive authority", func(d *IngressDecision) { d.ExpiresAt = now.Add(time.Minute) }},
		{"missing generation", func(d *IngressDecision) { d.Binding.RouteGeneration = 0 }},
		{"insecure TLS", func(d *IngressDecision) {
			d.Binding.OriginScheme = "https"
			d.Binding.TLSVerification = "insecure_development"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := projectionFixture(now)
			tc.mutate(&d)
			if completeIngressProjection(&d, now) == nil {
				t.Fatal("invalid authority accepted")
			}
		})
	}
	d := projectionFixture(now)
	d.Binding.OriginAddress = "[::1]:443"
	d.Binding.OriginScheme = "https"
	d.Binding.TLSVerification = "custom_ca"
	d.Binding.CAReference = "origin-ca"
	d.Binding.TLSServerName = "origin.example.com"
	if err := completeIngressProjection(&d, now); err != nil {
		t.Fatal(err)
	}
	if d.Binding.CAReference != "origin-ca" || d.Binding.TLSServerName != "origin.example.com" {
		t.Fatal("TLS policy changed")
	}
}

func TestIngressProjectionRejectsUnscopedSelectors(t *testing.T) {
	source := SQLIngressSource{}
	if _, err := source.Daemon(context.Background(), ActiveControlSession{}); err == nil {
		t.Fatal("empty session accepted")
	}
	if _, err := source.Edge(context.Background(), "", ""); err == nil {
		t.Fatal("empty edge accepted")
	}
}
