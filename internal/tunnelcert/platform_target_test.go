package tunnelcert

import (
	"errors"
	"testing"
	"time"
)

func TestPlatformCertificateTargetDefinitionsAreDeterministic(t *testing.T) {
	definitions, err := PlatformCertificateTargetDefinitions(PlatformCertificateBases{
		PreviewBaseDomain: "Preview.Pprbt.dev.",
		TunnelBaseDomain:  "tunnels.pprbt.dev",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(definitions) != 2 {
		t.Fatalf("platform definitions = %d, want 2", len(definitions))
	}
	want := []PlatformCertificateTargetDefinition{
		{ID: PlatformPreviewTargetID, Kind: PlatformPreviewWildcardTarget, Hostname: "*.preview.pprbt.dev", AccountID: PlatformAccountID, ChallengeReference: PlatformPreviewChallengeReference, Generation: 1},
		{ID: PlatformTunnelTargetID, Kind: PlatformTunnelWildcardTarget, Hostname: "*.tunnels.pprbt.dev", AccountID: PlatformAccountID, ChallengeReference: PlatformTunnelChallengeReference, Generation: 1},
	}
	for index := range want {
		if definitions[index] != want[index] {
			t.Fatalf("definition[%d] = %+v, want %+v", index, definitions[index], want[index])
		}
	}
	for _, bases := range []PlatformCertificateBases{
		{PreviewBaseDomain: "*.preview.pprbt.dev", TunnelBaseDomain: "tunnels.pprbt.dev"},
		{PreviewBaseDomain: "preview.pprbt.dev", TunnelBaseDomain: "127.0.0.1"},
		{PreviewBaseDomain: "preview.pprbt.dev", TunnelBaseDomain: ""},
	} {
		if _, err := PlatformCertificateTargetDefinitions(bases); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid platform bases %+v error = %v", bases, err)
		}
	}
}

func TestPlatformCertificateTargetGenerationFitsPostgresBigint(t *testing.T) {
	definition := PlatformCertificateTargetDefinition{
		ID: PlatformPreviewTargetID, Kind: PlatformPreviewWildcardTarget,
		Hostname: "*.preview.pprbt.dev", AccountID: PlatformAccountID,
		ChallengeReference: PlatformPreviewChallengeReference, Generation: maxPlatformGeneration + 1,
	}
	if err := definition.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("generation above BIGINT error = %v", err)
	}
	definition.Generation = maxPlatformGeneration
	if err := definition.Validate(); err != nil {
		t.Fatalf("maximum BIGINT generation rejected: %v", err)
	}
}

func TestPlatformCertificateTargetDefinitionFencesBuiltInIdentity(t *testing.T) {
	definition := PlatformCertificateTargetDefinition{
		ID: PlatformPreviewTargetID, Kind: PlatformPreviewWildcardTarget,
		Hostname: "*.preview.pprbt.dev", AccountID: PlatformAccountID,
		ChallengeReference: PlatformPreviewChallengeReference, Generation: 1,
	}
	for name, mutate := range map[string]func(*PlatformCertificateTargetDefinition){
		"account": func(value *PlatformCertificateTargetDefinition) { value.AccountID = "user-account" },
		"kind":    func(value *PlatformCertificateTargetDefinition) { value.Kind = PlatformTunnelWildcardTarget },
		"id":      func(value *PlatformCertificateTargetDefinition) { value.ID = PlatformTunnelTargetID },
		"challenge": func(value *PlatformCertificateTargetDefinition) {
			value.ChallengeReference = PlatformTunnelChallengeReference
		},
	} {
		invalid := definition
		mutate(&invalid)
		if err := invalid.Validate(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("built-in %s identity error = %v", name, err)
		}
	}
}

func TestPlatformCertificateTargetDefinitionsRejectDuplicateBases(t *testing.T) {
	if _, err := PlatformCertificateTargetDefinitions(PlatformCertificateBases{
		PreviewBaseDomain: "shared.pprbt.dev", TunnelBaseDomain: "shared.pprbt.dev",
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate platform bases error = %v", err)
	}
}

func TestPlatformCertificateTargetValidationFencesRetryAndRevocationState(t *testing.T) {
	definition := PlatformCertificateTargetDefinition{
		ID: PlatformPreviewTargetID, Kind: PlatformPreviewWildcardTarget,
		Hostname: "*.preview.pprbt.dev", AccountID: PlatformAccountID,
		ChallengeReference: PlatformPreviewChallengeReference, Generation: 1,
	}
	for name, mutate := range map[string]func(*PlatformCertificateTarget){
		"retry overflow":      func(value *PlatformCertificateTarget) { value.RetryCount = 31 },
		"revocation mismatch": func(value *PlatformCertificateTarget) { value.DesiredState = "revoked" },
	} {
		invalid := PlatformCertificateTarget{PlatformCertificateTargetDefinition: definition, DesiredState: "active", CertificateState: "pending"}
		mutate(&invalid)
		if err := invalid.Validate(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid %s error = %v", name, err)
		}
	}
}

func TestPlatformStoredCertificateRejectsPEMMaterial(t *testing.T) {
	now := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	value := StoredCertificate{
		ID: "tcert-platform-test", DomainID: PlatformPreviewTargetID, AccountID: PlatformAccountID,
		TargetKind: TargetPlatformWildcard, Hostname: "*.preview.pprbt.dev", DomainGeneration: 1,
		CertificateGeneration: 1, Strategy: StrategyPlatformDNS01, State: StateStaged,
		CertificateReference: "tcert_platform_test", MasterKeyReference: "master/current",
		CertificateCiphertext: []byte("-----BEGIN CERTIFICATE----- plaintext material -----END CERTIFICATE-----"),
		PrivateKeyCiphertext:  []byte("encrypted-placeholder-with-more-than-29-bytes"),
		Fingerprint:           [32]byte{1}, Issuer: "test-ca", NotBefore: now,
		ExpiresAt: now.Add(time.Hour), RenewalAt: now.Add(30 * time.Minute), UpdatedAt: now,
	}
	if err := platformStoredCertificateValid(value); !errors.Is(err, ErrInvalid) {
		t.Fatalf("plaintext platform certificate error = %v", err)
	}
}

func TestPlatformDNSChallengeTargetWritesAuthorizationNameDirectly(t *testing.T) {
	domain := Domain{
		ID: PlatformPreviewTargetID, AccountID: PlatformAccountID,
		TargetKind: TargetPlatformWildcard, Hostname: "*.Preview.Pprbt.dev",
	}
	if _, err := PlatformDNSChallengeTargetForDomain(domain); !errors.Is(err, ErrDNSChallengeUnavailable) {
		// Hostname canonicalization is an explicit storage contract. Keep this
		// check to prevent silently accepting a mixed-case platform projection.
		t.Fatalf("mixed-case platform hostname error = %v", err)
	}
	domain.Hostname = "*.preview.pprbt.dev"
	target, err := PlatformDNSChallengeTargetForDomain(domain)
	if err != nil {
		t.Fatal(err)
	}
	if target != "_acme-challenge.preview.pprbt.dev" {
		t.Fatalf("direct platform challenge target = %q", target)
	}
	delegated, err := DelegatedChallengeTargetForDomain(domain, "not-a-valid-zone")
	if err != nil {
		t.Fatal(err)
	}
	if delegated != target {
		t.Fatalf("platform challenge target through domain helper = %q, want %q", delegated, target)
	}
}

func TestPlatformWildcardDomainRejectsRouteAndLeaseIdentity(t *testing.T) {
	base := Domain{
		ID: PlatformTunnelTargetID, AccountID: PlatformAccountID,
		TargetKind: TargetPlatformWildcard, Hostname: "*.tunnels.pprbt.dev",
		Generation: 1, Strategy: StrategyPlatformDNS01, OwnershipState: "verified",
		CAAState: "not_applicable",
	}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, invalid := range map[string]Domain{
		"route":    func() Domain { value := base; value.RouteID = "route_platform"; return value }(),
		"tunnel":   func() Domain { value := base; value.TunnelID = "tunnel_platform"; return value }(),
		"lease":    func() Domain { value := base; value.PreviewID = "preview_platform"; return value }(),
		"strategy": func() Domain { value := base; value.Strategy = StrategyWildcard; return value }(),
	} {
		if err := invalid.Validate(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("platform %s identity error = %v", name, err)
		}
	}
	user := base
	user.TargetKind = TargetDurableRoute
	user.TunnelID = "tunnel_user"
	user.RouteID = "route_user"
	user.Strategy = StrategyPlatformDNS01
	if err := user.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("platform strategy on user target error = %v", err)
	}
}
