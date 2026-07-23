package billing_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/billing"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

func TestBillingUncertainRecoveryIsAuditedIdempotentAndKindBound(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := "usr_billing_recovery_" + suffix
	insertUser(t, store, userID, "billing-recovery-"+suffix+"@example.com")
	operations := map[string]string{
		"checkout":            "checkout_recovery_" + suffix,
		"portal":              "portal_recovery_" + suffix,
		"subscription_update": "subscription_recovery_" + suffix,
		"auto_topup":          "auto_topup_recovery_" + suffix,
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.billing_checkout_reservations (id,user_id,product_code,idempotency_key,state,expires_at,last_error,uncertain_at) VALUES ($1,$2,'product-test',$3,'uncertain',now()+interval '5 minutes','provider_outcome_unknown',now())`, "bcr_"+suffix, userID, operations["checkout"]); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.billing_portal_operations (idempotency_key,user_id,request_hash,state,last_error) VALUES ($1,$2,$3,'uncertain','provider_outcome_unknown')`, operations["portal"], userID, bytes.Repeat([]byte{1}, 32)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.billing_subscription_update_operations (idempotency_key,user_id,provider_subscription_id,request_hash,state,last_error) VALUES ($1,$2,$3,$4,'uncertain','provider_outcome_unknown')`, operations["subscription_update"], userID, "sub_"+suffix, bytes.Repeat([]byte{2}, 32)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.credit_auto_topup_attempts (id,user_id,idempotency_key,state,last_error) VALUES ($1,$2,$3,'uncertain','provider_outcome_unknown')`, "ata_"+suffix, userID, operations["auto_topup"]); err != nil {
		t.Fatal(err)
	}
	recovery := billing.NewRecoveryService(store, audit.NewWriter(store))
	for kind, operationID := range operations {
		recoveryKey := "billing-recovery-" + kind + "-" + suffix
		evidence := "polar:event:no-mutation:" + kind + ":" + suffix
		if err := recovery.Recover(ctx, userID, recoveryKey, kind, operationID, evidence); err != nil {
			t.Fatalf("recover %s: %v", kind, err)
		}
		if err := recovery.Recover(ctx, userID, recoveryKey, kind, operationID, evidence); err != nil {
			t.Fatalf("replay %s: %v", kind, err)
		}
		if err := recovery.Recover(ctx, userID, recoveryKey, kind, operationID, evidence+"-different"); !errors.Is(err, billing.ErrBillingRecoveryConflict) {
			t.Fatalf("conflict %s: %v", kind, err)
		}
	}
	checks := []struct{ table, operation string }{
		{"billing_checkout_reservations", operations["checkout"]},
		{"billing_portal_operations", operations["portal"]},
		{"billing_subscription_update_operations", operations["subscription_update"]},
		{"credit_auto_topup_attempts", operations["auto_topup"]},
	}
	for _, check := range checks {
		var state string
		if err := store.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.`+check.table+` WHERE idempotency_key=$1`, check.operation).Scan(&state); err != nil || state != "failed" {
			t.Fatalf("%s state=%q err=%v", check.table, state, err)
		}
	}
	var recoveryCount, auditCount int
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.billing_uncertain_recoveries WHERE operation_id LIKE '%' || $1`, suffix).Scan(&recoveryCount); err != nil || recoveryCount != 4 {
		t.Fatalf("recoveries=%d err=%v", recoveryCount, err)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.audit_events WHERE event_type='billing.uncertain_operation_recovered' AND actor_user_id=$1`, userID).Scan(&auditCount); err != nil || auditCount != 4 {
		t.Fatalf("audits=%d err=%v", auditCount, err)
	}
	if err := recovery.Recover(ctx, userID, "billing-recovery-not-uncertain-"+suffix, "portal", operations["portal"], "polar:event:no-mutation:retry:"+suffix); !errors.Is(err, billing.ErrBillingOperationNotUncertain) {
		t.Fatalf("non-uncertain recovery=%v", err)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.billing_uncertain_recoveries WHERE idempotency_key=$1`, "billing-recovery-not-uncertain-"+suffix).Scan(&recoveryCount); err != nil || recoveryCount != 0 {
		t.Fatalf("rolled-back recovery count=%d err=%v", recoveryCount, err)
	}
}

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

func TestPolarTrialConvertsSameSubscriptionToSailor(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := "usr_trial_" + suffix
	insertUser(t, store, userID, "trial-"+suffix+"@example.com")
	trialCode, sailorCode := "trial-"+suffix, "sailor-"+suffix
	productID, priceID := "prod_trial_"+suffix, "price_trial_"+suffix
	insertPlanProduct(t, store, trialCode, productID, priceID, "10", 5)
	insertPlanProduct(t, store, sailorCode, "prod_sailor_"+suffix, "price_sailor_"+suffix, "100", 30)
	cleanupPlanProducts(t, store, trialCode, sailorCode)
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.plan_versions SET metadata=jsonb_build_object('billing', jsonb_build_object('converts_to_plan', $2::text)) WHERE id=(SELECT current_version_id FROM paperboat.plans WHERE code=$1)`, trialCode, sailorCode); err != nil {
		t.Fatal(err)
	}
	service := billing.NewService(billing.NewRepository(store), billing.FakePolarClient{}, audit.NewWriter(store))
	subscriptionID := "sub_trial_" + suffix
	trial := []byte(fmt.Sprintf(`{"type":"subscription.created","data":{"id":%q,"customer":{"external_id":%q},"product_id":%q,"price_id":%q,"status":"trialing","current_period_start":"2026-07-01T00:00:00Z","current_period_end":"2026-07-08T00:00:00Z"}}`, subscriptionID, userID, productID, priceID))
	if _, err := service.HandleWebhookWithID(ctx, "evt_trial_"+suffix, trial); err != nil {
		t.Fatal(err)
	}
	active := []byte(fmt.Sprintf(`{"type":"subscription.active","data":{"id":%q,"customer":{"external_id":%q},"product_id":%q,"price_id":%q,"status":"active","current_period_start":"2026-07-08T00:00:00Z","current_period_end":"2026-08-08T00:00:00Z"}}`, subscriptionID, userID, productID, priceID))
	if _, err := service.HandleWebhookWithID(ctx, "evt_trial_active_"+suffix, active); err != nil {
		t.Fatal(err)
	}
	var subscriptions int
	var planCode string
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*), max(p.code) FROM paperboat.subscriptions s JOIN paperboat.plan_versions pv ON pv.id=s.active_plan_version_id JOIN paperboat.plans p ON p.id=pv.plan_id WHERE s.user_id=$1`, userID).Scan(&subscriptions, &planCode); err != nil {
		t.Fatal(err)
	}
	if subscriptions != 1 || planCode != sailorCode {
		t.Fatalf("subscriptions/plan = %d/%q", subscriptions, planCode)
	}
	if _, err := service.CreateCheckout(ctx, userID, "trial@example.com", "product-"+trialCode, "trial-again-"+suffix, "https://example.test/success"); !errors.Is(err, billing.ErrTrialUnavailable) {
		t.Fatalf("repeat trial error = %v", err)
	}
}

func TestCheckoutReservationPreventsConcurrentSubscriptions(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := "usr_checkout_guard_" + suffix
	insertUser(t, store, userID, "guard-"+suffix+"@example.com")
	planCode := "guard-plan-" + suffix
	insertPlanProduct(t, store, planCode, "prod_guard_"+suffix, "price_guard_"+suffix, "10", 5)
	cleanupPlanProducts(t, store, planCode)
	service := billing.NewService(billing.NewRepository(store), billing.FakePolarClient{}, audit.NewWriter(store))
	first, err := service.CreateCheckout(ctx, userID, "guard@example.com", "product-"+planCode, "guard-key-"+suffix, "https://example.test/success")
	if err != nil {
		t.Fatal(err)
	}
	retry, err := service.CreateCheckout(ctx, userID, "guard@example.com", "product-"+planCode, "guard-key-"+suffix, "https://example.test/success")
	if err != nil || retry.URL != first.URL {
		t.Fatalf("same-key retry = %+v, %v", retry, err)
	}
	if _, err := service.CreateCheckout(ctx, userID, "guard@example.com", "product-"+planCode, "different-key-"+suffix, "https://example.test/success"); !errors.Is(err, billing.ErrCheckoutPending) {
		t.Fatalf("concurrent checkout error = %v", err)
	}
}

type uncertainPolarClient struct{ billing.FakePolarClient }

func (uncertainPolarClient) CreateCheckout(context.Context, billing.CheckoutInput) (billing.CheckoutSession, error) {
	return billing.CheckoutSession{}, context.DeadlineExceeded
}

type countingPortalClient struct {
	billing.FakePolarClient
	calls int
	fail  error
}

func (c *countingPortalClient) CreateCustomerPortal(ctx context.Context, input billing.CustomerPortalInput) (billing.CustomerPortalSession, error) {
	c.calls++
	if c.fail != nil {
		return billing.CustomerPortalSession{}, c.fail
	}
	return c.FakePolarClient.CreateCustomerPortal(ctx, input)
}

func TestCustomerPortalOperationReplayAndUncertainState(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := "usr_portal_operation_" + suffix
	insertUser(t, store, userID, "portal-"+suffix+"@example.com")
	key := "portal-key-" + suffix
	client := &countingPortalClient{}
	service := billing.NewService(billing.NewRepository(store), client, audit.NewWriter(store))
	service.SetEncryptionKey("portal-test-encryption-key")
	first, err := service.CreateCustomerPortal(ctx, userID, "portal@example.com", key, "https://example.test/return")
	if err != nil {
		t.Fatal(err)
	}
	replay, err := service.CreateCustomerPortal(ctx, userID, "portal@example.com", key, "https://example.test/return")
	if err != nil || replay.URL != first.URL || client.calls != 1 {
		t.Fatalf("replay = %#v, err=%v, calls=%d", replay, err, client.calls)
	}
	var ciphertext []byte
	if err := store.SQL().QueryRowContext(ctx, `SELECT result_ciphertext FROM paperboat.billing_portal_operations WHERE idempotency_key=$1`, key).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if len(ciphertext) == 0 || string(ciphertext) == first.URL {
		t.Fatal("portal result was not encrypted at rest")
	}
	if _, err := service.CreateCustomerPortal(ctx, userID, "portal@example.com", key, "https://example.test/different"); !errors.Is(err, billing.ErrIdempotencyConflict) {
		t.Fatalf("conflicting replay = %v, want ErrIdempotencyConflict", err)
	}

	uncertainKey := "portal-uncertain-" + suffix
	uncertainClient := &countingPortalClient{fail: context.DeadlineExceeded}
	uncertainService := billing.NewService(billing.NewRepository(store), uncertainClient, audit.NewWriter(store))
	uncertainService.SetEncryptionKey("portal-test-encryption-key")
	if _, err := uncertainService.CreateCustomerPortal(ctx, userID, "portal@example.com", uncertainKey, "https://example.test/return"); !errors.Is(err, billing.ErrProviderOutcomeUnknown) {
		t.Fatalf("uncertain portal error = %v, want ErrProviderOutcomeUnknown", err)
	}
	if _, err := uncertainService.CreateCustomerPortal(ctx, userID, "portal@example.com", uncertainKey, "https://example.test/return"); !errors.Is(err, billing.ErrProviderOutcomeUnknown) || uncertainClient.calls != 1 {
		t.Fatalf("uncertain replay = %v, calls=%d", err, uncertainClient.calls)
	}
	recovery := billing.NewRecoveryService(store, audit.NewWriter(store))
	if err := recovery.Recover(ctx, userID, "portal-recovery-"+suffix, "portal", uncertainKey, "polar:event:no-mutation:portal:"+suffix); err != nil {
		t.Fatal(err)
	}
	retryClient := &countingPortalClient{}
	retryService := billing.NewService(billing.NewRepository(store), retryClient, audit.NewWriter(store))
	retryService.SetEncryptionKey("portal-test-encryption-key")
	if retried, err := retryService.CreateCustomerPortal(ctx, userID, "portal@example.com", uncertainKey, "https://example.test/return"); err != nil || retried.URL == "" || retryClient.calls != 1 {
		t.Fatalf("recovered portal = %#v, err=%v, calls=%d", retried, err, retryClient.calls)
	}
}

type uncertainSubscriptionClient struct {
	billing.FakePolarClient
	calls *int
}

func (c uncertainSubscriptionClient) UpdateSubscription(context.Context, billing.SubscriptionUpdateInput) error {
	*c.calls++
	return context.DeadlineExceeded
}

func TestSubscriptionDowngradeTimeoutPreservesPendingIntent(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := "usr_subscription_uncertain_" + suffix
	insertUser(t, store, userID, "subscription-uncertain-"+suffix+"@example.com")
	highPlan, lowPlan := "uncertain-high-"+suffix, "uncertain-low-"+suffix
	highProduct, lowProduct := "prod_uncertain_high_"+suffix, "prod_uncertain_low_"+suffix
	insertPlanProduct(t, store, highPlan, highProduct, "price_uncertain_high_"+suffix, "100", 100)
	insertPlanProduct(t, store, lowPlan, lowProduct, "price_uncertain_low_"+suffix, "10", 10)
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.plan_versions SET metadata=jsonb_build_object('billing',jsonb_build_object('rank',CASE WHEN id=$1 THEN 2 ELSE 1 END)) WHERE id IN ($1,$2)`, "pv_"+highPlan, "pv_"+lowPlan); err != nil {
		t.Fatal(err)
	}
	seed := billing.NewService(billing.NewRepository(store), billing.FakePolarClient{}, audit.NewWriter(store))
	initial := []byte(fmt.Sprintf(`{"type":"subscription.active","data":{"id":%q,"customer":{"external_id":%q},"product_id":%q,"status":"active","current_period_start":"2026-07-01T00:00:00Z","current_period_end":"2099-08-01T00:00:00Z"}}`, "sub_uncertain_"+suffix, userID, highProduct))
	if _, err := seed.HandleWebhookWithID(ctx, "evt_subscription_uncertain_"+suffix, initial); err != nil {
		t.Fatal(err)
	}
	calls := 0
	service := billing.NewService(billing.NewRepository(store), uncertainSubscriptionClient{calls: &calls}, audit.NewWriter(store))
	key := "downgrade-" + suffix
	if _, err := service.CreateCheckout(ctx, userID, "subscription-uncertain@example.com", "product-"+lowPlan, key, "https://example.test/success"); !errors.Is(err, billing.ErrProviderOutcomeUnknown) {
		t.Fatalf("downgrade error = %v, want ErrProviderOutcomeUnknown", err)
	}
	if _, err := service.CreateCheckout(ctx, userID, "subscription-uncertain@example.com", "product-"+lowPlan, key, "https://example.test/success"); !errors.Is(err, billing.ErrProviderOutcomeUnknown) || calls != 1 {
		t.Fatalf("downgrade replay error = %v, calls=%d", err, calls)
	}
	if _, err := service.CreateCheckout(ctx, userID, "subscription-uncertain@example.com", "product-"+lowPlan, key, "https://example.test/different"); !errors.Is(err, billing.ErrIdempotencyConflict) || calls != 1 {
		t.Fatalf("conflicting downgrade replay error = %v, calls=%d", err, calls)
	}
	var operationState string
	if err := store.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.billing_subscription_update_operations WHERE idempotency_key=$1`, key).Scan(&operationState); err != nil {
		t.Fatal(err)
	}
	if operationState != "uncertain" {
		t.Fatalf("operation state = %q, want uncertain", operationState)
	}
	var pending string
	if err := store.SQL().QueryRowContext(ctx, `SELECT pending_plan_version_id FROM paperboat.subscriptions WHERE user_id=$1`, userID).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending != "pv_"+lowPlan {
		t.Fatalf("pending plan = %q, want %q", pending, "pv_"+lowPlan)
	}
}

func TestCheckoutProviderTimeoutPersistsUncertainOutcome(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := "usr_checkout_uncertain_" + suffix
	insertUser(t, store, userID, "uncertain-"+suffix+"@example.com")
	planCode := "uncertain-plan-" + suffix
	insertPlanProduct(t, store, planCode, "prod_uncertain_"+suffix, "price_uncertain_"+suffix, "10", 5)
	cleanupPlanProducts(t, store, planCode)
	service := billing.NewService(billing.NewRepository(store), uncertainPolarClient{}, audit.NewWriter(store))
	key := "uncertain-key-" + suffix

	if _, err := service.CreateCheckout(ctx, userID, "uncertain@example.com", "product-"+planCode, key, "https://example.test/success"); !errors.Is(err, billing.ErrProviderOutcomeUnknown) {
		t.Fatalf("initial checkout error = %v, want ErrProviderOutcomeUnknown", err)
	}
	if _, err := service.CreateCheckout(ctx, userID, "uncertain@example.com", "product-"+planCode, key, "https://example.test/success"); !errors.Is(err, billing.ErrProviderOutcomeUnknown) {
		t.Fatalf("replay checkout error = %v, want ErrProviderOutcomeUnknown", err)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.billing_checkout_reservations SET expires_at=now()-interval '1 hour' WHERE user_id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateCheckout(ctx, userID, "uncertain@example.com", "product-"+planCode, "different-"+key, "https://example.test/success"); !errors.Is(err, billing.ErrCheckoutPending) {
		t.Fatalf("different-key checkout error = %v, want ErrCheckoutPending", err)
	}
	var state, lastError string
	var uncertainAt time.Time
	if err := store.SQL().QueryRowContext(ctx, `SELECT state,last_error,uncertain_at FROM paperboat.billing_checkout_reservations WHERE user_id=$1`, userID).Scan(&state, &lastError, &uncertainAt); err != nil {
		t.Fatal(err)
	}
	if state != "uncertain" || lastError != "provider_outcome_unknown" || uncertainAt.IsZero() {
		t.Fatalf("reservation = %q/%q/%s, want uncertain/provider_outcome_unknown/timestamp", state, lastError, uncertainAt)
	}
}

func TestSubscriptionSeatsReconcilePurchasedStorage(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := "usr_storage_seats_" + suffix
	insertUser(t, store, userID, "seats-"+suffix+"@example.com")
	planCode, productID, priceID := "seat-plan-"+suffix, "prod_seat_"+suffix, "price_seat_"+suffix
	insertPlanProduct(t, store, planCode, productID, priceID, "10", 5)
	cleanupPlanProducts(t, store, planCode)
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.plan_versions SET metadata='{"billing":{"storage_unit_gb":10,"storage_seat_offset":1}}'::jsonb WHERE id=(SELECT current_version_id FROM paperboat.plans WHERE code=$1)`, planCode); err != nil {
		t.Fatal(err)
	}
	service := billing.NewService(billing.NewRepository(store), billing.FakePolarClient{}, audit.NewWriter(store))
	body := []byte(fmt.Sprintf(`{"type":"subscription.active","data":{"id":"sub_seats_%[1]s","customer":{"external_id":%q},"product_id":%q,"price_id":%q,"status":"active","seats":3,"current_period_start":"2026-07-01T00:00:00Z","current_period_end":"2026-08-01T00:00:00Z"}}`, suffix, userID, productID, priceID))
	if _, err := service.HandleWebhookWithID(ctx, "evt_seats_"+suffix, body); err != nil {
		t.Fatal(err)
	}
	usage, err := billing.NewRepository(store).Usage(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if usage.PurchasedStorageGB != 20 {
		t.Fatalf("purchased storage = %d", usage.PurchasedStorageGB)
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

func TestPolarWebhookUsesStableProductMappingWithoutLegacyPriceField(t *testing.T) {
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
	if _, err := service.HandleWebhook(ctx, []byte(fmt.Sprintf(`{"id":"evt_missing_price_%[1]s","type":"order.paid","data":{"external_user_id":"%[2]s","product_id":"%[3]s"}}`, suffix, userID, productID))); err != nil {
		t.Fatalf("product-mapped webhook failed: %v", err)
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

func TestConnectedMachineSubscriptionAllocatesPeriodsAndRevokesOnCancellation(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := "usr_connected_subscription_" + suffix
	machineID := "cm_" + suffix
	insertUser(t, store, userID, "connected-subscription-"+suffix+"@example.com")
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.connected_machines (id, user_id, environment_id, display_name, platform, architecture, workspace_root, state, seat_state)
VALUES ($1, $2, $3, $4, 'darwin', 'arm64', '/Users/example', 'offline', 'occupied')`, machineID, userID, "env_"+suffix, "Mac "+suffix); err != nil {
		t.Fatal(err)
	}
	productID, priceID := "prod_connected_sub_"+suffix, "price_connected_sub_"+suffix
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.billing_products (id, code, provider, provider_product_id, provider_price_id, catalog_type, catalog_ref, active)
VALUES ($1, $2, 'polar', $3, $4, 'connected_machine_subscription', '{"allowance_bytes":1048576}', true)`, "bp_connected_sub_"+suffix, "connected-subscription-"+suffix, productID, priceID); err != nil {
		t.Fatal(err)
	}
	service := billing.NewService(billing.NewRepository(store), billing.FakePolarClient{}, audit.NewWriter(store))
	subscriptionID := "sub_connected_" + suffix
	created := []byte(fmt.Sprintf(`{"id":%q,"type":"subscription.active","data":{"id":%q,"customer":{"external_id":%q},"product_id":%q,"price_id":%q,"status":"active","seats":2,"current_period_start":"2026-07-01T00:00:00Z","current_period_end":"2026-08-01T00:00:00Z"}}`, "evt_connected_created_"+suffix, subscriptionID, userID, productID, priceID))
	if _, err := service.HandleWebhook(ctx, created); err != nil {
		t.Fatal(err)
	}
	var seats int
	var allowance int64
	if err := store.SQL().QueryRowContext(ctx, `SELECT seat_quantity, allowance_bytes FROM paperboat.connected_machine_entitlements WHERE user_id = $1`, userID).Scan(&seats, &allowance); err != nil {
		t.Fatal(err)
	}
	if seats != 2 || allowance != 1048576 {
		t.Fatalf("entitlement seats/allowance = %d/%d", seats, allowance)
	}
	var included int64
	if err := store.SQL().QueryRowContext(ctx, `SELECT included_bytes FROM paperboat.connected_machine_bandwidth_periods WHERE connected_machine_id = $1`, machineID).Scan(&included); err != nil {
		t.Fatal(err)
	}
	if included != 1048576 {
		t.Fatalf("included period bytes = %d", included)
	}
	canceled := []byte(fmt.Sprintf(`{"id":%q,"type":"subscription.canceled","data":{"id":%q,"customer":{"external_id":%q},"product_id":%q,"price_id":%q,"status":"canceled"}}`, "evt_connected_canceled_"+suffix, subscriptionID, userID, productID, priceID))
	if _, err := service.HandleWebhook(ctx, canceled); err != nil {
		t.Fatal(err)
	}
	var entitlementState, machineState, seatState string
	if err := store.SQL().QueryRowContext(ctx, `SELECT state FROM paperboat.connected_machine_entitlements WHERE user_id = $1`, userID).Scan(&entitlementState); err != nil {
		t.Fatal(err)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT state, seat_state FROM paperboat.connected_machines WHERE id = $1`, machineID).Scan(&machineState, &seatState); err != nil {
		t.Fatal(err)
	}
	if entitlementState != "canceled" || machineState != "revoked" || seatState != "released" {
		t.Fatalf("states entitlement/machine/seat = %q/%q/%q", entitlementState, machineState, seatState)
	}
}

func TestConnectedMachineBandwidthTopupGrantAndRefund(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID := "usr_connected_topup_" + suffix
	insertUser(t, store, userID, "connected-topup-"+suffix+"@example.com")
	productID, priceID := "prod_connected_topup_"+suffix, "price_connected_topup_"+suffix
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.billing_products (id, code, provider, provider_product_id, provider_price_id, catalog_type, catalog_ref, active)
VALUES ($1, $2, 'polar', $3, $4, 'connected_machine_bandwidth_topup', '{"bytes":4194304}', true)`, "bp_connected_topup_"+suffix, "connected-topup-"+suffix, productID, priceID); err != nil {
		t.Fatal(err)
	}
	service := billing.NewService(billing.NewRepository(store), billing.FakePolarClient{}, audit.NewWriter(store))
	orderID := "order_connected_topup_" + suffix
	paid := []byte(fmt.Sprintf(`{"id":%q,"type":"order.paid","data":{"id":%q,"customer":{"external_id":%q},"product_id":%q,"price_id":%q,"order":{"id":%q}}}`, "evt_connected_topup_paid_"+suffix, orderID, userID, productID, priceID, orderID))
	if _, err := service.HandleWebhook(ctx, paid); err != nil {
		t.Fatal(err)
	}
	var remaining int64
	if err := store.SQL().QueryRowContext(ctx, `SELECT remaining_bytes FROM paperboat.connected_machine_bandwidth_topups WHERE provider_order_id = $1`, orderID).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 4194304 {
		t.Fatalf("remaining top-up bytes = %d", remaining)
	}
	refunded := []byte(fmt.Sprintf(`{"id":%q,"type":"order.refunded","data":{"id":%q,"customer":{"external_id":%q},"product_id":%q,"price_id":%q,"order":{"id":%q}}}`, "evt_connected_topup_refund_"+suffix, "refund_"+suffix, userID, productID, priceID, orderID))
	if _, err := service.HandleWebhook(ctx, refunded); err != nil {
		t.Fatal(err)
	}
	var state string
	if err := store.SQL().QueryRowContext(ctx, `SELECT state, remaining_bytes FROM paperboat.connected_machine_bandwidth_topups WHERE provider_order_id = $1`, orderID).Scan(&state, &remaining); err != nil {
		t.Fatal(err)
	}
	if state != "void" || remaining != 0 {
		t.Fatalf("top-up state/remaining = %q/%d", state, remaining)
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
		if _, err := store.SQL().ExecContext(ctx, `DELETE FROM paperboat.subscriptions WHERE active_plan_version_id IN (SELECT pv.id FROM paperboat.plan_versions pv JOIN paperboat.plans p ON p.id = pv.plan_id WHERE p.code = ANY($1)) OR pending_plan_version_id IN (SELECT pv.id FROM paperboat.plan_versions pv JOIN paperboat.plans p ON p.id = pv.plan_id WHERE p.code = ANY($1))`, planCodes); err != nil {
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
