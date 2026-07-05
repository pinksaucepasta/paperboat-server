package billing

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

var (
	ErrIdempotencyConflict = errors.New("idempotency key conflicts with existing billing operation")
	ErrInsufficientCredits = errors.New("insufficient credits")
	ErrInsufficientStorage = errors.New("insufficient storage available")
	ErrInvalidSignature    = errors.New("invalid polar webhook signature")
	ErrUnknownProduct      = errors.New("billing product is not active or mapped")
	ErrRetryableWebhook    = errors.New("webhook could not be processed yet")
)

type PolarClient interface {
	CreateCheckout(ctx context.Context, input CheckoutInput) (CheckoutSession, error)
	CreateCustomerPortal(ctx context.Context, input CustomerPortalInput) (CustomerPortalSession, error)
}

type CheckoutInput struct {
	UserID            string
	UserEmail         string
	ProductCode       string
	ProviderProductID string
	ProviderPriceID   string
	IdempotencyKey    string
	SuccessURL        string
}

type CheckoutSession struct {
	URL                string
	ProviderSessionID  string
	ProviderCustomerID string
}

type CustomerPortalInput struct {
	UserID         string
	UserEmail      string
	IdempotencyKey string
	ReturnURL      string
}

type CustomerPortalSession struct {
	URL string
}

type Repository struct {
	db *db.DB
}

func NewRepository(store *db.DB) *Repository {
	return &Repository{db: store}
}

type Entitlement struct {
	State              string     `json:"state"`
	PlanCode           string     `json:"plan_code,omitempty"`
	PlanName           string     `json:"plan_name,omitempty"`
	CurrentPeriodStart *time.Time `json:"current_period_start,omitempty"`
	CurrentPeriodEnd   *time.Time `json:"current_period_end,omitempty"`
	Active             bool       `json:"active"`
}

type Usage struct {
	CreditsBalance     string `json:"credits_balance"`
	IncludedStorageGB  int    `json:"included_storage_gb"`
	PurchasedStorageGB int    `json:"purchased_storage_gb"`
	AllocatedStorageGB int    `json:"allocated_storage_gb"`
	AvailableStorageGB int    `json:"available_storage_gb"`
}

type Product struct {
	Code              string
	CatalogType       string
	CatalogRef        string
	ProviderProductID string
	ProviderPriceID   string
}

func (r *Repository) Entitlement(ctx context.Context, userID string) (Entitlement, error) {
	var e Entitlement
	var start, end sql.NullTime
	err := r.db.SQL().QueryRowContext(ctx, `
SELECT s.state, p.code, p.name, s.current_period_start, s.current_period_end
FROM paperboat.subscriptions s
LEFT JOIN paperboat.plan_versions pv ON pv.id = s.active_plan_version_id
LEFT JOIN paperboat.plans p ON p.id = pv.plan_id
WHERE s.user_id = $1
ORDER BY s.updated_at DESC, s.created_at DESC
LIMIT 1`, userID).Scan(&e.State, &e.PlanCode, &e.PlanName, &start, &end)
	if errors.Is(err, sql.ErrNoRows) {
		return Entitlement{State: "none", Active: false}, nil
	}
	if err != nil {
		return Entitlement{}, fmt.Errorf("query entitlement: %w", err)
	}
	if start.Valid {
		e.CurrentPeriodStart = &start.Time
	}
	if end.Valid {
		e.CurrentPeriodEnd = &end.Time
	}
	e.Active = entitlementActive(e.State, e.CurrentPeriodEnd, time.Now().UTC())
	return e, nil
}

func (r *Repository) Usage(ctx context.Context, userID string) (Usage, error) {
	var usage Usage
	err := r.db.SQL().QueryRowContext(ctx, `
SELECT coalesce(ca.balance::text, '0'),
       coalesce(sa.included_gb, 0),
       coalesce(sa.purchased_gb, 0),
       coalesce(sa.allocated_gb, 0),
       coalesce(sa.included_gb + sa.purchased_gb - sa.allocated_gb, 0)
FROM paperboat.users u
LEFT JOIN paperboat.credit_accounts ca ON ca.user_id = u.id
LEFT JOIN paperboat.storage_accounts sa ON sa.user_id = u.id
WHERE u.id = $1`, userID).Scan(&usage.CreditsBalance, &usage.IncludedStorageGB, &usage.PurchasedStorageGB, &usage.AllocatedStorageGB, &usage.AvailableStorageGB)
	if err != nil {
		return Usage{}, fmt.Errorf("query billing usage: %w", err)
	}
	return usage, nil
}

func (r *Repository) ProductByCode(ctx context.Context, code string) (Product, error) {
	var product Product
	err := r.db.SQL().QueryRowContext(ctx, `
SELECT code, catalog_type, catalog_ref, provider_product_id, provider_price_id
FROM paperboat.billing_products
WHERE code = $1 AND provider = 'polar' AND active`, code).Scan(&product.Code, &product.CatalogType, &product.CatalogRef, &product.ProviderProductID, &product.ProviderPriceID)
	if errors.Is(err, sql.ErrNoRows) {
		return Product{}, ErrUnknownProduct
	}
	if err != nil {
		return Product{}, fmt.Errorf("query billing product: %w", err)
	}
	return product, nil
}

func (r *Repository) ProductByProviderIDs(ctx context.Context, tx *db.Tx, providerProductID, providerPriceID string) (Product, error) {
	if strings.TrimSpace(providerPriceID) == "" {
		return Product{}, ErrUnknownProduct
	}
	var product Product
	err := tx.QueryRow(ctx, `
SELECT code, catalog_type, catalog_ref, provider_product_id, provider_price_id
FROM billing_products
WHERE provider = 'polar'
  AND active
  AND ($1 = '' OR provider_product_id = $1)
  AND provider_price_id = $2
ORDER BY updated_at DESC
LIMIT 1`, providerProductID, providerPriceID).Scan(&product.Code, &product.CatalogType, &product.CatalogRef, &product.ProviderProductID, &product.ProviderPriceID)
	if errors.Is(err, sql.ErrNoRows) {
		return Product{}, ErrUnknownProduct
	}
	if err != nil {
		return Product{}, fmt.Errorf("query billing product by provider ids: %w", err)
	}
	return product, nil
}

func (r *Repository) GrantCredits(ctx context.Context, userID, entryID, idempotencyKey, sourceType, sourceID, amount string, metadata map[string]any) error {
	if strings.TrimSpace(amount) == "" || strings.HasPrefix(strings.TrimSpace(amount), "-") {
		return fmt.Errorf("credit amount must be positive")
	}
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		accountID, err := ensureCreditAccount(ctx, tx, userID)
		if err != nil {
			return err
		}
		return insertCreditLedger(ctx, tx, accountID, entryID, "grant", amount, sourceType, sourceID, idempotencyKey, metadata, true)
	})
}

func (r *Repository) DebitCredits(ctx context.Context, userID, entryID, idempotencyKey, sourceType, sourceID, amount string, metadata map[string]any) error {
	if strings.TrimSpace(amount) == "" || strings.HasPrefix(strings.TrimSpace(amount), "-") {
		return fmt.Errorf("credit amount must be positive")
	}
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		return debitCreditsTx(ctx, tx, userID, entryID, "debit", idempotencyKey, sourceType, sourceID, amount, metadata)
	})
}

func (r *Repository) AdjustCredits(ctx context.Context, userID, entryID, idempotencyKey, amount string, metadata map[string]any) error {
	amount = strings.TrimSpace(amount)
	if amount == "" || amount == "0" || amount == "0.000000" {
		return fmt.Errorf("credit adjustment amount must be nonzero")
	}
	if strings.HasPrefix(amount, "-") {
		debitAmount := strings.TrimPrefix(amount, "-")
		return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
			return debitCreditsTx(ctx, tx, userID, entryID, "adjustment", idempotencyKey, "admin", userID, debitAmount, metadata)
		})
	}
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		accountID, err := ensureCreditAccount(ctx, tx, userID)
		if err != nil {
			return err
		}
		return insertCreditLedger(ctx, tx, accountID, entryID, "adjustment", amount, "admin", userID, idempotencyKey, metadata, true)
	})
}

func (r *Repository) ApplyIncludedStorage(ctx context.Context, userID, entryID, idempotencyKey, sourceType, sourceID string, amountGB int, metadata map[string]any) error {
	if amountGB < 0 {
		return fmt.Errorf("included storage amount must be nonnegative")
	}
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		accountID, err := ensureStorageAccount(ctx, tx, userID)
		if err != nil {
			return err
		}
		return setIncludedStorageTx(ctx, tx, accountID, entryID, "included_set", amountGB, sourceType, sourceID, idempotencyKey, metadata)
	})
}

func (r *Repository) ApplyPurchasedStorage(ctx context.Context, userID, entryID, idempotencyKey, sourceType, sourceID string, amountGB int, metadata map[string]any) error {
	if amountGB < 0 {
		return fmt.Errorf("purchased storage amount must be nonnegative")
	}
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		accountID, err := ensureStorageAccount(ctx, tx, userID)
		if err != nil {
			return err
		}
		return setPurchasedStorageTx(ctx, tx, accountID, entryID, "purchased_set", amountGB, sourceType, sourceID, idempotencyKey, metadata)
	})
}

func (r *Repository) AdjustPurchasedStorage(ctx context.Context, userID, entryID, idempotencyKey string, purchasedGB int, metadata map[string]any) error {
	if purchasedGB < 0 {
		return fmt.Errorf("purchased storage amount must be nonnegative")
	}
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		accountID, err := ensureStorageAccount(ctx, tx, userID)
		if err != nil {
			return err
		}
		return setPurchasedStorageTx(ctx, tx, accountID, entryID, "adjustment", purchasedGB, "admin", userID, idempotencyKey, metadata)
	})
}

func (r *Repository) ReleaseStorage(ctx context.Context, accountID, projectID, entryID, idempotencyKey string, amountGB int, metadata map[string]any) error {
	if amountGB <= 0 {
		return fmt.Errorf("amount_gb must be positive")
	}
	return r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		return releaseStorageTx(ctx, tx, accountID, projectID, entryID, idempotencyKey, amountGB, metadata)
	})
}

func (r *Repository) RecordPolarEvent(ctx context.Context, providerEventID, eventType string, payload []byte, process func(context.Context, *db.Tx) error) (bool, error) {
	inserted := false
	err := r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		result, err := tx.Exec(ctx, `
INSERT INTO polar_events (id, provider_event_id, event_type, processed_state, payload)
VALUES ($1, $2, $3, 'processing', $4::jsonb)
ON CONFLICT (provider_event_id) DO NOTHING`, newID("pevt"), providerEventID, eventType, string(payload))
		if err != nil {
			return err
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if rows == 0 {
			return nil
		}
		inserted = true
		if process != nil {
			if err := process(ctx, tx); err != nil {
				_, _ = tx.Exec(ctx, `UPDATE polar_events SET processed_state = 'failed', processed_at = now() WHERE provider_event_id = $1`, providerEventID)
				return err
			}
		}
		_, err = tx.Exec(ctx, `UPDATE polar_events SET processed_state = 'processed', processed_at = now() WHERE provider_event_id = $1`, providerEventID)
		return err
	})
	return inserted, err
}

type Service struct {
	repo   *Repository
	client PolarClient
	audit  *audit.Writer
}

func NewService(repo *Repository, client PolarClient, auditWriter *audit.Writer) *Service {
	return &Service{repo: repo, client: client, audit: auditWriter}
}

func (s *Service) Entitlement(ctx context.Context, userID string) (Entitlement, error) {
	return s.repo.Entitlement(ctx, userID)
}

func (s *Service) Usage(ctx context.Context, userID string) (Usage, error) {
	return s.repo.Usage(ctx, userID)
}

func (s *Service) CreateCheckout(ctx context.Context, userID, email, productCode, idempotencyKey, successURL string) (CheckoutSession, error) {
	product, err := s.repo.ProductByCode(ctx, productCode)
	if err != nil {
		return CheckoutSession{}, err
	}
	session, err := s.client.CreateCheckout(ctx, CheckoutInput{UserID: userID, UserEmail: email, ProductCode: productCode, ProviderProductID: product.ProviderProductID, ProviderPriceID: product.ProviderPriceID, IdempotencyKey: idempotencyKey, SuccessURL: successURL})
	if err != nil {
		return CheckoutSession{}, err
	}
	_ = s.audit.Write(ctx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "billing.checkout_created", ResourceType: "billing_product", ResourceID: product.Code, IdempotencyKey: "billing.checkout:" + idempotencyKey, Metadata: map[string]any{"catalog_type": product.CatalogType}})
	return session, nil
}

func (s *Service) CreateCustomerPortal(ctx context.Context, userID, email, idempotencyKey, returnURL string) (CustomerPortalSession, error) {
	session, err := s.client.CreateCustomerPortal(ctx, CustomerPortalInput{UserID: userID, UserEmail: email, IdempotencyKey: idempotencyKey, ReturnURL: returnURL})
	if err != nil {
		return CustomerPortalSession{}, err
	}
	_ = s.audit.Write(ctx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "billing.customer_portal_created", ResourceType: "user", ResourceID: userID, IdempotencyKey: "billing.portal:" + idempotencyKey, Metadata: map[string]any{}})
	return session, nil
}

func (s *Service) AdjustCredits(ctx context.Context, adminUserID, targetUserID, amount, idempotencyKey, reason string) error {
	if strings.TrimSpace(reason) == "" {
		return fmt.Errorf("reason is required")
	}
	if err := s.repo.AdjustCredits(ctx, targetUserID, newID("cled"), idempotencyKey, amount, map[string]any{"reason": reason, "admin_user_id": adminUserID}); err != nil {
		return err
	}
	_ = s.audit.Write(ctx, audit.Event{ActorUserID: adminUserID, ActorType: audit.ActorAdmin, EventType: "billing.credits_adjusted", ResourceType: "user", ResourceID: targetUserID, IdempotencyKey: "billing.admin.credits:" + idempotencyKey, Metadata: map[string]any{"reason": reason, "amount": amount}})
	return nil
}

func (s *Service) AdjustPurchasedStorage(ctx context.Context, adminUserID, targetUserID, idempotencyKey, reason string, purchasedGB int) error {
	if strings.TrimSpace(reason) == "" {
		return fmt.Errorf("reason is required")
	}
	if err := s.repo.AdjustPurchasedStorage(ctx, targetUserID, newID("sled"), idempotencyKey, purchasedGB, map[string]any{"reason": reason, "admin_user_id": adminUserID}); err != nil {
		return err
	}
	_ = s.audit.Write(ctx, audit.Event{ActorUserID: adminUserID, ActorType: audit.ActorAdmin, EventType: "billing.storage_adjusted", ResourceType: "user", ResourceID: targetUserID, IdempotencyKey: "billing.admin.storage:" + idempotencyKey, Metadata: map[string]any{"reason": reason, "purchased_gb": purchasedGB}})
	return nil
}

type WebhookEvent struct {
	ID   string          `json:"id"`
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

func (s *Service) HandleWebhook(ctx context.Context, body []byte) (bool, error) {
	var event WebhookEvent
	if err := json.Unmarshal(body, &event); err != nil {
		return false, fmt.Errorf("parse polar webhook: %w", err)
	}
	if strings.TrimSpace(event.ID) == "" || strings.TrimSpace(event.Type) == "" {
		return false, fmt.Errorf("polar webhook missing id or type")
	}
	return s.repo.RecordPolarEvent(ctx, event.ID, event.Type, body, func(ctx context.Context, tx *db.Tx) error {
		return s.processWebhookEvent(ctx, tx, event)
	})
}

func (s *Service) processWebhookEvent(ctx context.Context, tx *db.Tx, event WebhookEvent) error {
	payload := webhookPayload(event)
	userID := payload.firstString("external_user_id", "external_customer_id", "customer.external_id", "customer.external_user_id", "metadata.paperboat_user_id", "metadata.user_id")
	productID := payload.firstString("product_id", "product.id", "product", "price.product_id", "items.0.product_id")
	priceID := payload.firstString("price_id", "price.id", "price", "items.0.price_id")
	product, err := s.repo.ProductByProviderIDs(ctx, tx, productID, priceID)
	if errors.Is(err, ErrUnknownProduct) {
		return fmt.Errorf("%w: polar product_id=%q price_id=%q", ErrRetryableWebhook, productID, priceID)
	}
	if err != nil {
		return err
	}
	if userID == "" {
		return fmt.Errorf("%w: missing paperboat user mapping for polar product_id=%q price_id=%q", ErrRetryableWebhook, productID, priceID)
	}
	if refundLikeEvent(event.Type) {
		return s.applyRefundWebhook(ctx, tx, event, payload, userID, product)
	}
	switch product.CatalogType {
	case "plan":
		return s.applyPlanWebhook(ctx, tx, event, payload, userID, product)
	case "credit_topup":
		return grantCreditsTx(ctx, tx, userID, newID("cled"), event.ID+":credits:"+product.Code, "polar_event", event.ID, product.CatalogRef, map[string]any{"event_type": event.Type, "product_code": product.Code})
	case "extra_storage":
		gb, err := strconv.Atoi(product.CatalogRef)
		if err != nil || gb < 0 {
			return fmt.Errorf("extra storage product %q catalog_ref must be nonnegative GB", product.Code)
		}
		accountID, err := ensureStorageAccount(ctx, tx, userID)
		if err != nil {
			return err
		}
		return setPurchasedStorageTx(ctx, tx, accountID, newID("sled"), "purchased_set", gb, "polar_event", event.ID, event.ID+":storage:"+product.Code, map[string]any{"event_type": event.Type, "product_code": product.Code})
	default:
		return nil
	}
}

func (s *Service) applyRefundWebhook(ctx context.Context, tx *db.Tx, event WebhookEvent, payload webhookMap, userID string, product Product) error {
	switch product.CatalogType {
	case "plan":
		subscriptionID := payload.firstString("subscription_id", "subscription.id", "id")
		if subscriptionID == "" {
			return nil
		}
		_, err := tx.Exec(ctx, `
UPDATE subscriptions
SET state = $3, version = version + 1, updated_at = now()
WHERE provider = 'polar' AND provider_subscription_id = $1 AND user_id = $2`, subscriptionID, userID, subscriptionState("", event.Type))
		return err
	case "credit_topup":
		return debitCreditsTx(ctx, tx, userID, newID("cled"), "refund", event.ID+":refund-credits:"+product.Code, "polar_event", event.ID, product.CatalogRef, map[string]any{"event_type": event.Type, "product_code": product.Code})
	case "extra_storage":
		accountID, err := ensureStorageAccount(ctx, tx, userID)
		if err != nil {
			return err
		}
		return setPurchasedStorageTx(ctx, tx, accountID, newID("sled"), "cancellation", 0, "polar_event", event.ID, event.ID+":refund-storage:"+product.Code, map[string]any{"event_type": event.Type, "product_code": product.Code})
	default:
		return nil
	}
}

func (s *Service) applyPlanWebhook(ctx context.Context, tx *db.Tx, event WebhookEvent, payload webhookMap, userID string, product Product) error {
	var planVersionID, includedCredits string
	var includedStorageGB int
	if err := tx.QueryRow(ctx, `
SELECT pv.id, pv.included_credits::text, pv.included_storage_gb
FROM plans p
JOIN plan_versions pv ON pv.id = p.current_version_id
WHERE p.code = $1 AND p.active`, product.CatalogRef).Scan(&planVersionID, &includedCredits, &includedStorageGB); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	subscriptionID := payload.firstString("subscription_id", "subscription.id", "id")
	if subscriptionID == "" {
		subscriptionID = event.ID
	}
	state := subscriptionState(payload.firstString("status", "state"), event.Type)
	start := payload.firstTime("current_period_start", "period_start")
	end := payload.firstTime("current_period_end", "period_end", "ends_at")
	if _, err := tx.Exec(ctx, `
INSERT INTO subscriptions (id, user_id, provider, provider_subscription_id, state, active_plan_version_id, current_period_start, current_period_end)
VALUES ($1, $2, 'polar', $3, $4, $5, $6, $7)
ON CONFLICT (provider_subscription_id) DO UPDATE SET
	user_id = EXCLUDED.user_id,
	state = EXCLUDED.state,
	active_plan_version_id = EXCLUDED.active_plan_version_id,
	current_period_start = EXCLUDED.current_period_start,
	current_period_end = EXCLUDED.current_period_end,
	version = subscriptions.version + 1,
	updated_at = now()`, newID("sub"), userID, subscriptionID, state, planVersionID, start, end); err != nil {
		return err
	}
	if state == "active" || state == "trialing" {
		if err := grantCreditsTx(ctx, tx, userID, newID("cled"), event.ID+":plan-credits:"+product.Code, "polar_event", event.ID, includedCredits, map[string]any{"event_type": event.Type, "plan_code": product.CatalogRef}); err != nil {
			return err
		}
		accountID, err := ensureStorageAccount(ctx, tx, userID)
		if err != nil {
			return err
		}
		storageKey := event.ID + ":included-storage:" + product.Code
		return setIncludedStorageTx(ctx, tx, accountID, newID("sled"), "included_set", includedStorageGB, "polar_event", event.ID, storageKey, map[string]any{"event_type": event.Type, "plan_code": product.CatalogRef})
	}
	return nil
}

type HTTPPolarClient struct {
	BaseURL string
	APIKey  string
	Client  *http.Client
}

func (c HTTPPolarClient) CreateCheckout(ctx context.Context, input CheckoutInput) (CheckoutSession, error) {
	if c.Client == nil {
		c.Client = http.DefaultClient
	}
	payload := map[string]any{
		"products":             []string{input.ProviderProductID},
		"customer_email":       input.UserEmail,
		"success_url":          input.SuccessURL,
		"external_customer_id": input.UserID,
	}
	var out struct {
		URL        string `json:"url"`
		ID         string `json:"id"`
		CustomerID string `json:"customer_id"`
	}
	if err := c.post(ctx, "/v1/checkouts/", input.IdempotencyKey, payload, &out); err != nil {
		return CheckoutSession{}, err
	}
	return CheckoutSession{URL: out.URL, ProviderSessionID: out.ID, ProviderCustomerID: out.CustomerID}, nil
}

func (c HTTPPolarClient) CreateCustomerPortal(ctx context.Context, input CustomerPortalInput) (CustomerPortalSession, error) {
	if c.Client == nil {
		c.Client = http.DefaultClient
	}
	payload := map[string]any{"external_customer_id": input.UserID, "return_url": input.ReturnURL}
	var out struct {
		URL string `json:"customer_portal_url"`
	}
	if err := c.post(ctx, "/v1/customer-sessions/", input.IdempotencyKey, payload, &out); err != nil {
		return CustomerPortalSession{}, err
	}
	return CustomerPortalSession{URL: out.URL}, nil
}

func (c HTTPPolarClient) post(ctx context.Context, path, idempotencyKey string, payload, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.BaseURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", idempotencyKey)
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("polar api returned status %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

type FakePolarClient struct{}

func (FakePolarClient) CreateCheckout(_ context.Context, input CheckoutInput) (CheckoutSession, error) {
	return CheckoutSession{URL: "https://polar.example.test/checkout/" + input.IdempotencyKey, ProviderSessionID: "fake_checkout_" + input.IdempotencyKey}, nil
}

func (FakePolarClient) CreateCustomerPortal(_ context.Context, input CustomerPortalInput) (CustomerPortalSession, error) {
	return CustomerPortalSession{URL: "https://polar.example.test/portal/" + input.IdempotencyKey}, nil
}

func VerifyWebhookSignature(body []byte, webhookID, timestamp, signatures, secret string, tolerance time.Duration) error {
	return VerifyWebhookSignatureAt(body, webhookID, timestamp, signatures, secret, tolerance, time.Now().UTC())
}

func VerifyWebhookSignatureAt(body []byte, webhookID, timestamp, signatures, secret string, tolerance time.Duration, now time.Time) error {
	webhookID = strings.TrimSpace(webhookID)
	timestamp = strings.TrimSpace(timestamp)
	signatures = strings.TrimSpace(signatures)
	secret = strings.TrimSpace(secret)
	if webhookID == "" || timestamp == "" || signatures == "" || secret == "" || tolerance <= 0 {
		return ErrInvalidSignature
	}
	sentAtUnix, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return ErrInvalidSignature
	}
	sentAt := time.Unix(sentAtUnix, 0).UTC()
	if now.UTC().Sub(sentAt) > tolerance || sentAt.Sub(now.UTC()) > tolerance {
		return ErrInvalidSignature
	}

	key, err := standardWebhookSecret(secret)
	if err != nil {
		return ErrInvalidSignature
	}
	signedContent := []byte(webhookID + "." + timestamp + ".")
	signedContent = append(signedContent, body...)
	expectedMAC := hmac.New(sha256.New, key)
	_, _ = expectedMAC.Write(signedContent)
	expected := base64.StdEncoding.EncodeToString(expectedMAC.Sum(nil))

	for _, candidate := range standardWebhookSignatures(signatures) {
		if hmac.Equal([]byte(expected), []byte(candidate)) {
			return nil
		}
	}
	return ErrInvalidSignature
}

func standardWebhookSecret(secret string) ([]byte, error) {
	secret = strings.TrimSpace(secret)
	if strings.HasPrefix(secret, "whsec_") {
		return decodeWebhookSecret(strings.TrimPrefix(secret, "whsec_"))
	}
	if decoded, err := decodeWebhookSecret(secret); err == nil {
		return decoded, nil
	}
	return []byte(secret), nil
}

func decodeWebhookSecret(secret string) ([]byte, error) {
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(secret)
		if err == nil {
			return decoded, nil
		}
	}
	return nil, ErrInvalidSignature
}

func standardWebhookSignatures(header string) []string {
	parts := strings.Fields(header)
	signatures := make([]string, 0, len(parts))
	for _, part := range parts {
		version, signature, ok := strings.Cut(part, ",")
		if !ok {
			signatures = append(signatures, strings.TrimSpace(part))
			continue
		}
		if strings.TrimSpace(version) == "v1" && strings.TrimSpace(signature) != "" {
			signatures = append(signatures, strings.TrimSpace(signature))
		}
	}
	if len(signatures) == 0 {
		return nil
	}
	return signatures
}

func ReadWebhookBody(r *http.Request) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r.Body, 1<<20))
}

func entitlementActive(state string, periodEnd *time.Time, now time.Time) bool {
	if state != "active" && state != "trialing" {
		return false
	}
	return periodEnd == nil || periodEnd.After(now)
}

func ensureCreditAccount(ctx context.Context, tx *db.Tx, userID string) (string, error) {
	id := newID("cred")
	var accountID string
	err := tx.QueryRow(ctx, `
INSERT INTO credit_accounts (id, user_id)
VALUES ($1, $2)
ON CONFLICT (user_id) DO UPDATE SET updated_at = credit_accounts.updated_at
RETURNING id`, id, userID).Scan(&accountID)
	return accountID, err
}

func ensureStorageAccount(ctx context.Context, tx *db.Tx, userID string) (string, error) {
	id := newID("stor")
	var accountID string
	err := tx.QueryRow(ctx, `
INSERT INTO storage_accounts (id, user_id)
VALUES ($1, $2)
ON CONFLICT (user_id) DO UPDATE SET updated_at = storage_accounts.updated_at
RETURNING id`, id, userID).Scan(&accountID)
	return accountID, err
}

func grantCreditsTx(ctx context.Context, tx *db.Tx, userID, entryID, idempotencyKey, sourceType, sourceID, amount string, metadata map[string]any) error {
	if strings.TrimSpace(amount) == "" || strings.HasPrefix(strings.TrimSpace(amount), "-") {
		return fmt.Errorf("credit amount must be positive")
	}
	accountID, err := ensureCreditAccount(ctx, tx, userID)
	if err != nil {
		return err
	}
	return insertCreditLedger(ctx, tx, accountID, entryID, "grant", amount, sourceType, sourceID, idempotencyKey, metadata, true)
}

func debitCreditsTx(ctx context.Context, tx *db.Tx, userID, entryID, entryType, idempotencyKey, sourceType, sourceID, amount string, metadata map[string]any) error {
	if strings.TrimSpace(amount) == "" || strings.HasPrefix(strings.TrimSpace(amount), "-") {
		return fmt.Errorf("credit amount must be positive")
	}
	accountID, err := ensureCreditAccount(ctx, tx, userID)
	if err != nil {
		return err
	}
	if seen, err := creditLedgerEntryMatches(ctx, tx, accountID, entryType, amount, sourceType, sourceID, idempotencyKey); err != nil || seen {
		return err
	}
	if err := ensureCreditBalance(ctx, tx, accountID, amount); err != nil {
		return err
	}
	return insertCreditLedger(ctx, tx, accountID, entryID, entryType, amount, sourceType, sourceID, idempotencyKey, metadata, false)
}

func ensureCreditBalance(ctx context.Context, tx *db.Tx, accountID, amount string) error {
	var balance string
	if err := tx.QueryRow(ctx, `SELECT balance::text FROM credit_accounts WHERE id = $1 FOR UPDATE`, accountID).Scan(&balance); err != nil {
		return err
	}
	var enough bool
	if err := tx.QueryRow(ctx, `SELECT $1::numeric >= $2::numeric`, balance, amount).Scan(&enough); err != nil {
		return err
	}
	if !enough {
		return ErrInsufficientCredits
	}
	return nil
}

func insertCreditLedger(ctx context.Context, tx *db.Tx, accountID, entryID, entryType, amount, sourceType, sourceID, idempotencyKey string, metadata map[string]any, add bool) error {
	if seen, err := creditLedgerEntryMatches(ctx, tx, accountID, entryType, amount, sourceType, sourceID, idempotencyKey); err != nil || seen {
		return err
	}
	if metadata == nil {
		metadata = map[string]any{}
	}
	b, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	result, err := tx.Exec(ctx, `
INSERT INTO credit_ledger_entries (id, account_id, entry_type, amount, source_type, source_id, idempotency_key, metadata)
VALUES ($1, $2, $3, $4::numeric, $5, $6, $7, $8::jsonb)
ON CONFLICT (idempotency_key) DO NOTHING`, entryID, accountID, entryType, amount, sourceType, sourceID, idempotencyKey, string(b))
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil || rows == 0 {
		return err
	}
	op := "-"
	if add {
		op = "+"
	}
	_, err = tx.Exec(ctx, `UPDATE credit_accounts SET balance = balance `+op+` $2::numeric, version = version + 1, updated_at = now() WHERE id = $1`, accountID, amount)
	return err
}

func creditLedgerEntryMatches(ctx context.Context, tx *db.Tx, accountID, entryType, amount, sourceType, sourceID, idempotencyKey string) (bool, error) {
	var existing struct {
		accountID  string
		entryType  string
		amount     string
		sourceType string
		sourceID   string
	}
	err := tx.QueryRow(ctx, `
SELECT account_id, entry_type, amount::text, source_type, source_id
FROM credit_ledger_entries
WHERE idempotency_key = $1`, idempotencyKey).Scan(&existing.accountID, &existing.entryType, &existing.amount, &existing.sourceType, &existing.sourceID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var sameAmount bool
	if err := tx.QueryRow(ctx, `SELECT $1::numeric = $2::numeric`, existing.amount, amount).Scan(&sameAmount); err != nil {
		return false, err
	}
	if existing.accountID == accountID &&
		existing.entryType == entryType &&
		sameAmount &&
		existing.sourceType == sourceType &&
		existing.sourceID == sourceID {
		return true, nil
	}
	return false, ErrIdempotencyConflict
}

func releaseStorageTx(ctx context.Context, tx *db.Tx, accountID, projectID, entryID, idempotencyKey string, amountGB int, metadata map[string]any) error {
	if seen, err := storageLedgerExists(ctx, tx, idempotencyKey); err != nil || seen {
		return err
	}
	var allocated int
	if err := tx.QueryRow(ctx, `SELECT allocated_gb FROM storage_accounts WHERE id = $1 FOR UPDATE`, accountID).Scan(&allocated); err != nil {
		return err
	}
	if allocated < amountGB {
		return fmt.Errorf("storage release exceeds allocated storage")
	}
	if _, err := tx.Exec(ctx, `UPDATE storage_accounts SET allocated_gb = allocated_gb - $2, version = version + 1, updated_at = now() WHERE id = $1`, accountID, amountGB); err != nil {
		return err
	}
	return insertStorageLedger(ctx, tx, accountID, entryID, "release", amountGB, "project", projectID, idempotencyKey, metadata)
}

func setIncludedStorageTx(ctx context.Context, tx *db.Tx, accountID, entryID, entryType string, includedGB int, sourceType, sourceID, idempotencyKey string, metadata map[string]any) error {
	if seen, err := storageLedgerExists(ctx, tx, idempotencyKey); err != nil || seen {
		return err
	}
	var purchased, allocated int
	if err := tx.QueryRow(ctx, `SELECT purchased_gb, allocated_gb FROM storage_accounts WHERE id = $1 FOR UPDATE`, accountID).Scan(&purchased, &allocated); err != nil {
		return err
	}
	if allocated > includedGB+purchased {
		return ErrInsufficientStorage
	}
	if _, err := tx.Exec(ctx, `UPDATE storage_accounts SET included_gb = $2, version = version + 1, updated_at = now() WHERE id = $1`, accountID, includedGB); err != nil {
		return err
	}
	return insertStorageLedger(ctx, tx, accountID, entryID, entryType, includedGB, sourceType, sourceID, idempotencyKey, metadata)
}

func setPurchasedStorageTx(ctx context.Context, tx *db.Tx, accountID, entryID, entryType string, purchasedGB int, sourceType, sourceID, idempotencyKey string, metadata map[string]any) error {
	if seen, err := storageLedgerExists(ctx, tx, idempotencyKey); err != nil || seen {
		return err
	}
	var included, allocated int
	if err := tx.QueryRow(ctx, `SELECT included_gb, allocated_gb FROM storage_accounts WHERE id = $1 FOR UPDATE`, accountID).Scan(&included, &allocated); err != nil {
		return err
	}
	if allocated > included+purchasedGB {
		return ErrInsufficientStorage
	}
	if _, err := tx.Exec(ctx, `UPDATE storage_accounts SET purchased_gb = $2, version = version + 1, updated_at = now() WHERE id = $1`, accountID, purchasedGB); err != nil {
		return err
	}
	return insertStorageLedger(ctx, tx, accountID, entryID, entryType, purchasedGB, sourceType, sourceID, idempotencyKey, metadata)
}

func storageLedgerExists(ctx context.Context, tx *db.Tx, idempotencyKey string) (bool, error) {
	var exists bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM storage_ledger_entries WHERE idempotency_key = $1)`, idempotencyKey).Scan(&exists)
	return exists, err
}

func insertStorageLedger(ctx context.Context, tx *db.Tx, accountID, entryID, entryType string, amountGB int, sourceType, sourceID, idempotencyKey string, metadata map[string]any) error {
	if metadata == nil {
		metadata = map[string]any{}
	}
	b, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
INSERT INTO storage_ledger_entries (id, account_id, entry_type, amount_gb, source_type, source_id, idempotency_key, metadata)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)`, entryID, accountID, entryType, amountGB, sourceType, sourceID, idempotencyKey, string(b))
	return err
}

func newID(prefix string) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return prefix + "_" + hex.EncodeToString(b[:])
}

type webhookMap map[string]any

func webhookPayload(event WebhookEvent) webhookMap {
	var root map[string]any
	_ = json.Unmarshal(event.Data, &root)
	if root == nil {
		root = map[string]any{}
	}
	return webhookMap(root)
}

func (m webhookMap) firstString(paths ...string) string {
	for _, path := range paths {
		if value := valueAtPath(map[string]any(m), path); value != nil {
			switch typed := value.(type) {
			case string:
				if strings.TrimSpace(typed) != "" {
					return strings.TrimSpace(typed)
				}
			case float64:
				return strconv.FormatInt(int64(typed), 10)
			}
		}
	}
	return ""
}

func (m webhookMap) firstTime(paths ...string) any {
	for _, path := range paths {
		value := m.firstString(path)
		if value == "" {
			continue
		}
		if parsed, err := time.Parse(time.RFC3339, value); err == nil {
			return parsed
		}
		if unix, err := strconv.ParseInt(value, 10, 64); err == nil {
			return time.Unix(unix, 0).UTC()
		}
	}
	return nil
}

func valueAtPath(root map[string]any, path string) any {
	var current any = root
	for _, part := range strings.Split(path, ".") {
		switch typed := current.(type) {
		case map[string]any:
			current = typed[part]
		case []any:
			index, err := strconv.Atoi(part)
			if err != nil || index < 0 || index >= len(typed) {
				return nil
			}
			current = typed[index]
		default:
			return nil
		}
	}
	return current
}

func subscriptionState(status, eventType string) string {
	normalized := strings.ToLower(strings.TrimSpace(status))
	switch normalized {
	case "active", "trialing", "past_due", "canceled", "incomplete", "expired":
		return normalized
	case "cancelled":
		return "canceled"
	}
	eventType = strings.ToLower(eventType)
	switch {
	case strings.Contains(eventType, "trial"):
		return "trialing"
	case strings.Contains(eventType, "cancel"):
		return "canceled"
	case strings.Contains(eventType, "past_due"):
		return "past_due"
	case strings.Contains(eventType, "incomplete"):
		return "incomplete"
	case strings.Contains(eventType, "expire"):
		return "expired"
	default:
		return "active"
	}
}

func refundLikeEvent(eventType string) bool {
	eventType = strings.ToLower(eventType)
	return strings.Contains(eventType, "refund") ||
		strings.Contains(eventType, "chargeback") ||
		strings.Contains(eventType, "dispute")
}
