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
	body := []byte(fmt.Sprintf(`{"type":"subscription.created","data":{"id":"sub_%[1]s","customer":{"external_id":"%[2]s"},"product_id":"%[3]s","price_id":"price_plan_%[1]s","status":"active","current_period_start":"2026-07-05T12:00:00Z","current_period_end":"2026-08-05T12:00:00Z"}}`, suffix, userID, productID))
	inserted, err := service.HandleWebhookWithID(ctx, "evt_plan_created_"+suffix, body)
	if err != nil {
		t.Fatal(err)
	}
	if !inserted {
		t.Fatal("first webhook was not inserted")
	}
	body = []byte(fmt.Sprintf(`{"type":"subscription.active","data":{"id":"sub_%[1]s","customer":{"external_id":"%[2]s"},"product_id":"%[3]s","price_id":"price_plan_%[1]s","status":"active","current_period_start":"2026-07-05T12:00:00Z","current_period_end":"2026-08-05T12:00:00Z"}}`, suffix, userID, productID))
	inserted, err = service.HandleWebhookWithID(ctx, "evt_plan_active_"+suffix, body)
	if err != nil {
		t.Fatal(err)
	}
	if !inserted {
		t.Fatal("second lifecycle webhook was not inserted")
	}
	body = []byte(fmt.Sprintf(`{"type":"order.paid","data":{"id":"order_%[1]s","customer":{"external_id":"%[2]s"},"product_id":"%[3]s","product_price_id":"price_plan_%[1]s","status":"paid","subscription":{"id":"sub_%[1]s","status":"active","current_period_start":"2026-07-05T12:00:00Z","current_period_end":"2026-08-05T12:00:00Z"}}}`, suffix, userID, productID))
	inserted, err = service.HandleWebhookWithID(ctx, "evt_order_paid_"+suffix, body)
	if err != nil {
		t.Fatal(err)
	}
	if !inserted {
		t.Fatal("order.paid webhook was not inserted")
	}
	body = []byte(fmt.Sprintf(`{"type":"subscription.active","data":{"id":"sub_%[1]s","customer":{"external_id":"%[2]s"},"product_id":"%[3]s","price_id":"price_plan_%[1]s","status":"active","current_period_start":"2026-07-05T12:00:00Z","current_period_end":"2026-08-05T12:00:00Z"}}`, suffix, userID, productID))
	inserted, err = service.HandleWebhookWithID(ctx, "evt_plan_active_"+suffix, body)
	if err != nil {
		t.Fatal(err)
	}
	if inserted {
		t.Fatal("duplicate provider event was inserted")
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

func TestPolarWebhookProratesPlanSwitchCredits(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := "usr_billing_switch_" + suffix
	insertUser(t, store, userID, "switch-"+suffix+"@example.com")
	oldPlan := "switch-old-" + suffix
	newPlan := "switch-new-" + suffix
	oldProductID := "prod_switch_old_" + suffix
	newProductID := "prod_switch_new_" + suffix
	oldPriceID := "price_switch_old_" + suffix
	newPriceID := "price_switch_new_" + suffix
	insertPlanProduct(t, store, oldPlan, oldProductID, oldPriceID, "100", 30)
	insertPlanProduct(t, store, newPlan, newProductID, newPriceID, "300", 100)

	service := billing.NewService(billing.NewRepository(store), billing.FakePolarClient{}, audit.NewWriter(store))
	subscriptionID := "sub_switch_" + suffix
	periodStart := "2026-07-01T00:00:00Z"
	periodEnd := "2026-07-31T00:00:00Z"
	initial := []byte(fmt.Sprintf(`{"type":"subscription.active","data":{"id":%q,"customer":{"external_id":%q},"product_id":%q,"price_id":%q,"status":"active","current_period_start":%q,"current_period_end":%q}}`, subscriptionID, userID, oldProductID, oldPriceID, periodStart, periodEnd))
	if _, err := service.HandleWebhookWithID(ctx, "evt_switch_initial_"+suffix, initial); err != nil {
		t.Fatal(err)
	}

	upgrade := []byte(fmt.Sprintf(`{"type":"subscription.updated","data":{"id":%q,"customer":{"external_id":%q},"product_id":%q,"price_id":%q,"status":"active","current_period_start":%q,"current_period_end":%q,"modified_at":"2026-07-16T00:00:00Z"}}`, subscriptionID, userID, newProductID, newPriceID, periodStart, periodEnd))
	if _, err := service.HandleWebhookWithID(ctx, "evt_switch_upgrade_"+suffix, upgrade); err != nil {
		t.Fatal(err)
	}
	upgradeFollowup := []byte(fmt.Sprintf(`{"type":"subscription.active","data":{"id":%q,"customer":{"external_id":%q},"product_id":%q,"price_id":%q,"status":"active","current_period_start":%q,"current_period_end":%q,"modified_at":"2026-07-16T00:00:01Z"}}`, subscriptionID, userID, newProductID, newPriceID, periodStart, periodEnd))
	if _, err := service.HandleWebhookWithID(ctx, "evt_switch_upgrade_followup_"+suffix, upgradeFollowup); err != nil {
		t.Fatal(err)
	}

	downgrade := []byte(fmt.Sprintf(`{"type":"subscription.updated","data":{"id":%q,"customer":{"external_id":%q},"product_id":%q,"price_id":%q,"status":"active","current_period_start":%q,"current_period_end":%q,"modified_at":"2026-07-23T12:00:00Z"}}`, subscriptionID, userID, oldProductID, oldPriceID, periodStart, periodEnd))
	if _, err := service.HandleWebhookWithID(ctx, "evt_switch_downgrade_"+suffix, downgrade); err != nil {
		t.Fatal(err)
	}

	usage, err := billing.NewRepository(store).Usage(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if usage.CreditsBalance != "150.000000" {
		t.Fatalf("credit balance = %s, want 150.000000", usage.CreditsBalance)
	}
	if usage.IncludedStorageGB != 30 {
		t.Fatalf("included storage = %d, want 30", usage.IncludedStorageGB)
	}
	var switchEntries int
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.credit_ledger_entries cle JOIN paperboat.credit_accounts ca ON ca.id=cle.account_id WHERE ca.user_id=$1 AND cle.idempotency_key LIKE 'subscription:%:plan-switch:%'`, userID).Scan(&switchEntries); err != nil {
		t.Fatal(err)
	}
	if switchEntries != 2 {
		t.Fatalf("plan switch ledger entries = %d, want 2", switchEntries)
	}
}

func TestListPlanProductsReturnsActiveCatalogPlans(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	activeCode := "active-plan-" + suffix
	inactiveCode := "inactive-plan-" + suffix
	insertPlanProduct(t, store, activeCode, "prod_active_"+suffix, "price_active_"+suffix, "25", 50)
	insertPlanProduct(t, store, inactiveCode, "prod_inactive_"+suffix, "price_inactive_"+suffix, "100", 200)
	cleanupPlanProducts(t, store, activeCode, inactiveCode)
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.plans SET active = false WHERE code = $1`, inactiveCode); err != nil {
		t.Fatal(err)
	}

	products, err := billing.NewRepository(store).ListPlanProducts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var foundActive, foundInactive bool
	for _, product := range products {
		switch product.PlanCode {
		case activeCode:
			foundActive = true
			if product.IncludedCredits != "25.000000" || product.IncludedStorageGB != 50 {
				t.Fatalf("active plan product = %+v", product)
			}
		case inactiveCode:
			foundInactive = true
		}
	}
	if !foundActive {
		t.Fatal("active plan product was not listed")
	}
	if foundInactive {
		t.Fatal("inactive catalog plan product was listed")
	}
}

func TestCheckoutRejectsInactiveCatalogPlan(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	planCode := "inactive-checkout-plan-" + suffix
	insertPlanProduct(t, store, planCode, "prod_inactive_checkout_"+suffix, "price_inactive_checkout_"+suffix, "100", 200)
	cleanupPlanProducts(t, store, planCode)
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.plans SET active = false WHERE code = $1`, planCode); err != nil {
		t.Fatal(err)
	}

	service := billing.NewService(billing.NewRepository(store), billing.FakePolarClient{}, audit.NewWriter(store))
	_, err := service.CreateCheckout(ctx, "usr_unused", "user@example.test", "product-"+planCode, "checkout-"+suffix, "https://example.test/success")
	if err != billing.ErrUnknownProduct {
		t.Fatalf("checkout error = %v, want unknown product", err)
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
	cleanupPlanProducts(t, store, planCode)
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

func cleanupPlanProducts(t *testing.T, store *db.DB, planCodes ...string) {
	t.Helper()
	t.Cleanup(func() {
		ctx := context.Background()
		if _, err := store.SQL().ExecContext(ctx, `DELETE FROM paperboat.subscriptions WHERE active_plan_version_id IN (SELECT pv.id FROM paperboat.plan_versions pv JOIN paperboat.plans p ON p.id = pv.plan_id WHERE p.code = ANY($1))`, planCodes); err != nil {
			t.Errorf("clean subscriptions: %v", err)
			return
		}
		if _, err := store.SQL().ExecContext(ctx, `DELETE FROM paperboat.billing_products WHERE catalog_type = 'plan' AND catalog_ref = ANY($1)`, planCodes); err != nil {
			t.Errorf("clean billing products: %v", err)
			return
		}
		if _, err := store.SQL().ExecContext(ctx, `DELETE FROM paperboat.plan_versions WHERE plan_id IN (SELECT id FROM paperboat.plans WHERE code = ANY($1))`, planCodes); err != nil {
			t.Errorf("clean plan versions: %v", err)
			return
		}
		if _, err := store.SQL().ExecContext(ctx, `DELETE FROM paperboat.plans WHERE code = ANY($1)`, planCodes); err != nil {
			t.Errorf("clean plans: %v", err)
		}
	})
}
