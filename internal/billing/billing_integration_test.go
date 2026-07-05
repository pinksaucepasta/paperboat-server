package billing_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/billing"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

func TestPolarWebhookAppliesPlanResourcesIdempotently(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := "usr_billing_plan_" + suffix
	insertUser(t, store, userID, "plan-"+suffix+"@example.com")
	planCode := "plan-" + suffix
	productID := "prod_plan_" + suffix
	insertPlanProduct(t, store, planCode, productID, "price_plan_"+suffix, "12.5", 42)

	service := billing.NewService(billing.NewRepository(store), billing.FakePolarClient{}, audit.NewWriter(store))
	body := []byte(fmt.Sprintf(`{"id":"evt_plan_%[1]s","type":"subscription.active","data":{"customer":{"external_id":"%[2]s"},"product_id":"%[3]s","price_id":"price_plan_%[1]s","subscription":{"id":"sub_%[1]s"},"status":"active","current_period_end":"2026-08-05T12:00:00Z"}}`, suffix, userID, productID))
	inserted, err := service.HandleWebhook(ctx, body)
	if err != nil {
		t.Fatal(err)
	}
	if !inserted {
		t.Fatal("first webhook was not inserted")
	}
	inserted, err = service.HandleWebhook(ctx, body)
	if err != nil {
		t.Fatal(err)
	}
	if inserted {
		t.Fatal("duplicate webhook inserted")
	}
	usage, err := billing.NewRepository(store).Usage(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if usage.CreditsBalance != "12.500000" || usage.IncludedStorageGB != 42 {
		t.Fatalf("usage = %+v", usage)
	}
	var state string
	if err := store.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.subscriptions WHERE user_id = $1`, userID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "active" {
		t.Fatalf("subscription state = %q", state)
	}
}

func TestPolarRefundReversesTopupWithoutNegativeCredits(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := "usr_billing_refund_" + suffix
	insertUser(t, store, userID, "refund-"+suffix+"@example.com")
	productCode := "topup-" + suffix
	productID := "prod_topup_" + suffix
	priceID := "price_topup_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.billing_products (id, code, provider, provider_product_id, provider_price_id, catalog_type, catalog_ref, active)
VALUES ($1, $2, 'polar', $3, $4, 'credit_topup', '5', true)`, "bp_"+productCode, productCode, productID, priceID); err != nil {
		t.Fatal(err)
	}
	service := billing.NewService(billing.NewRepository(store), billing.FakePolarClient{}, audit.NewWriter(store))
	purchase := []byte(fmt.Sprintf(`{"id":"evt_topup_%[1]s","type":"order.paid","data":{"external_user_id":"%[2]s","product_id":"%[3]s","price_id":"%[4]s"}}`, suffix, userID, productID, priceID))
	if _, err := service.HandleWebhook(ctx, purchase); err != nil {
		t.Fatal(err)
	}
	refund := []byte(fmt.Sprintf(`{"id":"evt_refund_%[1]s","type":"order.refunded","data":{"external_user_id":"%[2]s","product_id":"%[3]s","price_id":"%[4]s"}}`, suffix, userID, productID, priceID))
	if _, err := service.HandleWebhook(ctx, refund); err != nil {
		t.Fatal(err)
	}
	if _, err := service.HandleWebhook(ctx, []byte(fmt.Sprintf(`{"id":"evt_refund_again_%[1]s","type":"order.refunded","data":{"external_user_id":"%[2]s","product_id":"%[3]s","price_id":"%[4]s"}}`, suffix, userID, productID, priceID))); err != nil {
		if err != billing.ErrInsufficientCredits {
			t.Fatal(err)
		}
	}
	usage, err := billing.NewRepository(store).Usage(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if usage.CreditsBalance != "0.000000" {
		t.Fatalf("credit balance = %s, want zero", usage.CreditsBalance)
	}
}

func TestCreditDebitRetryIgnoresLaterBalance(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := "usr_billing_debit_" + suffix
	insertUser(t, store, userID, "debit-"+suffix+"@example.com")
	repo := billing.NewRepository(store)
	if err := repo.GrantCredits(ctx, userID, "cled_grant_"+suffix, "grant-"+suffix, "test", suffix, "5", nil); err != nil {
		t.Fatal(err)
	}
	if err := repo.DebitCredits(ctx, userID, "cled_debit_"+suffix, "debit-"+suffix, "metering", suffix, "5", nil); err != nil {
		t.Fatal(err)
	}
	if err := repo.DebitCredits(ctx, userID, "cled_debit_retry_"+suffix, "debit-"+suffix, "metering", suffix, "5", nil); err != nil {
		t.Fatalf("idempotent debit retry returned error: %v", err)
	}
	var balance string
	if err := store.SQL().QueryRowContext(ctx, `SELECT balance::text FROM paperboat.credit_accounts WHERE user_id = $1`, userID).Scan(&balance); err != nil {
		t.Fatal(err)
	}
	if balance != "0.000000" {
		t.Fatalf("balance = %s, want zero", balance)
	}
}

func TestNegativeAdminAdjustmentRetryIgnoresLaterBalance(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := "usr_billing_admin_debit_" + suffix
	insertUser(t, store, userID, "admin-debit-"+suffix+"@example.com")
	repo := billing.NewRepository(store)
	if err := repo.GrantCredits(ctx, userID, "cled_admin_grant_"+suffix, "admin-grant-"+suffix, "test", suffix, "5", nil); err != nil {
		t.Fatal(err)
	}
	if err := repo.AdjustCredits(ctx, userID, "cled_admin_debit_"+suffix, "admin-debit-"+suffix, "-5", map[string]any{"reason": "test"}); err != nil {
		t.Fatal(err)
	}
	if err := repo.AdjustCredits(ctx, userID, "cled_admin_debit_retry_"+suffix, "admin-debit-"+suffix, "-5", map[string]any{"reason": "test"}); err != nil {
		t.Fatalf("idempotent admin debit retry returned error: %v", err)
	}
	var balance string
	if err := store.SQL().QueryRowContext(ctx, `SELECT balance::text FROM paperboat.credit_accounts WHERE user_id = $1`, userID).Scan(&balance); err != nil {
		t.Fatal(err)
	}
	if balance != "0.000000" {
		t.Fatalf("balance = %s, want zero", balance)
	}
}

func TestPolarWebhookRequiresExactPriceMapping(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := "usr_billing_price_" + suffix
	insertUser(t, store, userID, "price-"+suffix+"@example.com")
	productID := "prod_shared_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.billing_products (id, code, provider, provider_product_id, provider_price_id, catalog_type, catalog_ref, active)
VALUES ($1, $2, 'polar', $3, $4, 'credit_topup', '5', true)`, "bp_price_"+suffix, "topup-price-"+suffix, productID, "price_known_"+suffix); err != nil {
		t.Fatal(err)
	}
	service := billing.NewService(billing.NewRepository(store), billing.FakePolarClient{}, audit.NewWriter(store))
	_, err := service.HandleWebhook(ctx, []byte(fmt.Sprintf(`{"id":"evt_missing_price_%[1]s","type":"order.paid","data":{"external_user_id":"%[2]s","product_id":"%[3]s"}}`, suffix, userID, productID)))
	if err == nil {
		t.Fatal("webhook without exact price mapping succeeded")
	}
}

func TestPolarWebhookWithMappedProductRequiresUserMapping(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	productID := "prod_no_user_" + suffix
	priceID := "price_no_user_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.billing_products (id, code, provider, provider_product_id, provider_price_id, catalog_type, catalog_ref, active)
VALUES ($1, $2, 'polar', $3, $4, 'credit_topup', '5', true)`, "bp_no_user_"+suffix, "topup-no-user-"+suffix, productID, priceID); err != nil {
		t.Fatal(err)
	}
	service := billing.NewService(billing.NewRepository(store), billing.FakePolarClient{}, audit.NewWriter(store))
	_, err := service.HandleWebhook(ctx, []byte(fmt.Sprintf(`{"id":"evt_no_user_%[1]s","type":"order.paid","data":{"product_id":"%[2]s","price_id":"%[3]s"}}`, suffix, productID, priceID)))
	if err == nil {
		t.Fatal("webhook without user mapping succeeded")
	}
}

func TestExtraStorageCancellationCannotOverallocate(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := "usr_billing_storage_" + suffix
	insertUser(t, store, userID, "storage-"+suffix+"@example.com")
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.storage_accounts (id, user_id, included_gb, purchased_gb, allocated_gb)
VALUES ($1, $2, 5, 5, 10)`, "stor_"+suffix, userID); err != nil {
		t.Fatal(err)
	}
	productID := "prod_storage_" + suffix
	priceID := "price_storage_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.billing_products (id, code, provider, provider_product_id, provider_price_id, catalog_type, catalog_ref, active)
VALUES ($1, $2, 'polar', $3, $4, 'extra_storage', '0', true)`, "bp_storage_"+suffix, "storage-"+suffix, productID, priceID); err != nil {
		t.Fatal(err)
	}
	service := billing.NewService(billing.NewRepository(store), billing.FakePolarClient{}, audit.NewWriter(store))
	_, err := service.HandleWebhook(ctx, []byte(fmt.Sprintf(`{"id":"evt_storage_refund_%[1]s","type":"order.refunded","data":{"external_user_id":"%[2]s","product_id":"%[3]s","price_id":"%[4]s"}}`, suffix, userID, productID, priceID)))
	if err != billing.ErrInsufficientStorage {
		t.Fatalf("error = %v, want insufficient storage", err)
	}
}

func testStore(t *testing.T) *db.DB {
	t.Helper()
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run billing integration tests")
	}
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := db.Migrate(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	return store
}

func insertUser(t *testing.T, store *db.DB, userID, email string) {
	t.Helper()
	if _, err := store.SQL().ExecContext(context.Background(), `
INSERT INTO paperboat.users (id, workos_subject, primary_email, status)
VALUES ($1, $2, $3, 'active')`, userID, "workos_"+userID, email); err != nil {
		t.Fatal(err)
	}
}

func insertPlanProduct(t *testing.T, store *db.DB, planCode, productID, priceID, credits string, storageGB int) {
	t.Helper()
	ctx := context.Background()
	planID := "plan_" + planCode
	versionID := "pv_" + planCode
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.plans (id, code, name, active, current_version_id)
VALUES ($1, $2, $3, true, $4)`, planID, planCode, planCode, versionID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.plan_versions (id, plan_id, version_number, included_credits, included_storage_gb)
VALUES ($1, $2, 1, $3::numeric, $4)`, versionID, planID, credits, storageGB); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.billing_products (id, code, provider, provider_product_id, provider_price_id, catalog_type, catalog_ref, active)
VALUES ($1, $2, 'polar', $3, $4, 'plan', $5, true)`, "bp_"+planCode, "product-"+planCode, productID, priceID, planCode); err != nil {
		t.Fatal(err)
	}
}
