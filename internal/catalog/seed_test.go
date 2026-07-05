package catalog_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/catalog"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

func TestLoadFileParsesCatalogSeed(t *testing.T) {
	seed, err := catalog.LoadFile("../../config/catalogs.example.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(seed.Plans) != 3 {
		t.Fatalf("plans = %d, want 3", len(seed.Plans))
	}
	if len(seed.MachineTypes) == 0 {
		t.Fatal("expected machine type seed data")
	}
	if len(seed.Presets) == 0 {
		t.Fatal("expected preset seed data")
	}
}

func TestSeedValidationRejectsDuplicateCodes(t *testing.T) {
	seed := catalog.Seed{
		Plans: []catalog.Plan{
			{Code: "sailor", Name: "Sailor", IncludedCredits: "0", IncludedStorageGB: 0},
			{Code: "sailor", Name: "Other", IncludedCredits: "0", IncludedStorageGB: 0},
		},
		MachineTypes: []catalog.MachineType{
			{Code: "standard-1x", Name: "Standard 1x", VCPU: 4, MemoryMB: 8192, CreditWeight: "1"},
		},
	}
	err := seed.Validate()
	if err == nil || !strings.Contains(err.Error(), "duplicate plan code") {
		t.Fatalf("expected duplicate code validation error, got %v", err)
	}
}

func TestSeedValidationRejectsNonFiniteDecimals(t *testing.T) {
	seed := catalog.Seed{
		Plans: []catalog.Plan{
			{Code: "sailor", Name: "Sailor", IncludedCredits: "NaN", IncludedStorageGB: 0},
		},
		MachineTypes: []catalog.MachineType{
			{Code: "standard-1x", Name: "Standard 1x", VCPU: 4, MemoryMB: 8192, CreditWeight: "+Inf"},
		},
	}
	err := seed.Validate()
	if err == nil {
		t.Fatal("expected validation error")
	}
	got := err.Error()
	for _, want := range []string{"included_credits", "credit_weight"} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected %q in validation error %q", want, got)
		}
	}
}

func TestSeedValidationRejectsDecimalsOutsideDatabaseScale(t *testing.T) {
	seed := catalog.Seed{
		Plans: []catalog.Plan{
			{Code: "sailor", Name: "Sailor", IncludedCredits: "1.1234567", IncludedStorageGB: 0},
		},
		MachineTypes: []catalog.MachineType{
			{Code: "standard-1x", Name: "Standard 1x", VCPU: 4, MemoryMB: 8192, CreditWeight: "1234567890123"},
		},
	}
	err := seed.Validate()
	if err == nil {
		t.Fatal("expected validation error")
	}
	got := err.Error()
	for _, want := range []string{"included_credits", "credit_weight"} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected %q in validation error %q", want, got)
		}
	}
}

func TestSeedValidationRejectsZeroMachineWeightWithLeadingZeroes(t *testing.T) {
	seed := catalog.Seed{
		Plans: []catalog.Plan{
			{Code: "sailor", Name: "Sailor", IncludedCredits: "0", IncludedStorageGB: 0},
		},
		MachineTypes: []catalog.MachineType{
			{Code: "standard-1x", Name: "Standard 1x", VCPU: 4, MemoryMB: 8192, CreditWeight: "000"},
		},
	}
	err := seed.Validate()
	if err == nil || !strings.Contains(err.Error(), "credit_weight") {
		t.Fatalf("expected credit_weight validation error, got %v", err)
	}
}

func TestCatalogRepositoryListsSeededCatalogs(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run Postgres catalog integration tests")
	}
	ctx := context.Background()
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := db.Migrate(ctx, store); err != nil {
		t.Fatal(err)
	}
	seed, err := catalog.LoadFile("../../config/catalogs.example.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := catalog.Apply(ctx, store, seed); err != nil {
		t.Fatal(err)
	}
	repo := catalog.NewRepository(store.SQL())
	plans, err := repo.ListPlans(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !hasPlan(plans, "sailor") || !hasPlan(plans, "navigator") || !hasPlan(plans, "captain") {
		t.Fatalf("seeded plans missing from %#v", plans)
	}
	machines, err := repo.ListMachineTypes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(machines) < 2 {
		t.Fatalf("machine types = %d, want at least 2", len(machines))
	}
}

func hasPlan(plans []catalog.PlanRecord, code string) bool {
	for _, plan := range plans {
		if plan.Code == code {
			return true
		}
	}
	return false
}

func TestCatalogSeedAppendsImmutableVersionsOnValueChange(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run Postgres catalog integration tests")
	}
	ctx := context.Background()
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := db.Migrate(ctx, store); err != nil {
		t.Fatal(err)
	}
	planCode := uniqueCatalogCode("review-plan")
	machineCode := uniqueCatalogCode("review-1x")
	seed := catalog.Seed{
		Plans: []catalog.Plan{
			{Code: planCode, Name: "Review Plan", IncludedCredits: "1", IncludedStorageGB: 1, Active: true},
		},
		MachineTypes: []catalog.MachineType{
			{Code: machineCode, Name: "Review 1x", VCPU: 4, MemoryMB: 8192, CreditWeight: "1", Active: true},
		},
	}
	if err := catalog.Apply(ctx, store, seed); err != nil {
		t.Fatal(err)
	}
	seed.Plans[0].IncludedCredits = "2"
	if err := catalog.Apply(ctx, store, seed); err != nil {
		t.Fatal(err)
	}
	var versions int
	if err := store.SQL().QueryRowContext(ctx, `
SELECT count(*)
FROM paperboat.plan_versions pv
JOIN paperboat.plans p ON p.id = pv.plan_id
WHERE p.code = $1`, planCode).Scan(&versions); err != nil {
		t.Fatal(err)
	}
	if versions < 2 {
		t.Fatalf("plan versions = %d, want at least 2", versions)
	}
}

func TestCatalogSeedDoesNotAppendVersionsWhenNumericsAreEquivalent(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run Postgres catalog integration tests")
	}
	ctx := context.Background()
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := db.Migrate(ctx, store); err != nil {
		t.Fatal(err)
	}
	planCode := uniqueCatalogCode("review-idempotent-plan")
	machineCode := uniqueCatalogCode("review-idempotent-1x")
	seed := catalog.Seed{
		Plans: []catalog.Plan{
			{Code: planCode, Name: "Review Idempotent Plan", IncludedCredits: "001", IncludedStorageGB: 1, Active: true},
		},
		MachineTypes: []catalog.MachineType{
			{Code: machineCode, Name: "Review Idempotent 1x", VCPU: 4, MemoryMB: 8192, CreditWeight: "001", Active: true},
		},
	}
	if err := catalog.Apply(ctx, store, seed); err != nil {
		t.Fatal(err)
	}
	if err := catalog.Apply(ctx, store, seed); err != nil {
		t.Fatal(err)
	}
	var planVersion int
	if err := store.SQL().QueryRowContext(ctx, `
SELECT version
FROM paperboat.plans
WHERE code = $1`, planCode).Scan(&planVersion); err != nil {
		t.Fatal(err)
	}
	if planVersion != 1 {
		t.Fatalf("plan row version = %d, want 1", planVersion)
	}
	var machineVersion int
	if err := store.SQL().QueryRowContext(ctx, `
SELECT version
FROM paperboat.machine_types
WHERE code = $1`, machineCode).Scan(&machineVersion); err != nil {
		t.Fatal(err)
	}
	if machineVersion != 1 {
		t.Fatalf("machine type row version = %d, want 1", machineVersion)
	}
	var planVersions int
	if err := store.SQL().QueryRowContext(ctx, `
SELECT count(*)
FROM paperboat.plan_versions pv
JOIN paperboat.plans p ON p.id = pv.plan_id
WHERE p.code = $1`, planCode).Scan(&planVersions); err != nil {
		t.Fatal(err)
	}
	if planVersions != 1 {
		t.Fatalf("plan versions = %d, want 1", planVersions)
	}
	var machineVersions int
	if err := store.SQL().QueryRowContext(ctx, `
SELECT count(*)
FROM paperboat.machine_type_versions mtv
JOIN paperboat.machine_types mt ON mt.id = mtv.machine_type_id
WHERE mt.code = $1`, machineCode).Scan(&machineVersions); err != nil {
		t.Fatal(err)
	}
	if machineVersions != 1 {
		t.Fatalf("machine type versions = %d, want 1", machineVersions)
	}
}

func uniqueCatalogCode(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}
