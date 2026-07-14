package billing

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestVerifyWebhookSignature(t *testing.T) {
	body := []byte(`{"id":"evt_test","type":"subscription.active"}`)
	secret := "whsec_test-webhook-secret"
	webhookID := "msg_test"
	now := time.Date(2026, 7, 5, 12, 0, 0, 0, time.UTC)
	timestamp := strconv.FormatInt(now.Unix(), 10)
	mac := hmac.New(sha256.New, []byte(strings.TrimPrefix(secret, "whsec_")))
	_, _ = mac.Write([]byte(webhookID + "." + timestamp + "."))
	_, _ = mac.Write(body)
	wrongSignature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	mac = hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(webhookID + "." + timestamp + "."))
	_, _ = mac.Write(body)
	signature := "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))

	if err := VerifyWebhookSignatureAt(body, webhookID, timestamp, signature, secret, 5*time.Minute, now); err != nil {
		t.Fatalf("VerifyWebhookSignature returned error: %v", err)
	}
	if err := VerifyWebhookSignatureAt(body, webhookID, timestamp, "v1,bad", secret, 5*time.Minute, now); err != ErrInvalidSignature {
		t.Fatalf("invalid signature error = %v, want ErrInvalidSignature", err)
	}
	if err := VerifyWebhookSignatureAt(body, webhookID, timestamp, "v1,"+wrongSignature, secret, 5*time.Minute, now); err != ErrInvalidSignature {
		t.Fatalf("invalid signature error = %v, want ErrInvalidSignature", err)
	}
}

func TestVerifyWebhookSignatureRejectsOutsideTolerance(t *testing.T) {
	body := []byte(`{"id":"evt_test","type":"subscription.active"}`)
	secret := "whsec_test-webhook-secret"
	webhookID := "msg_test"
	now := time.Date(2026, 7, 5, 12, 0, 0, 0, time.UTC)
	oldTimestamp := strconv.FormatInt(now.Add(-10*time.Minute).Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(webhookID + "." + oldTimestamp + "."))
	_, _ = mac.Write(body)
	signature := "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))

	if err := VerifyWebhookSignatureAt(body, webhookID, oldTimestamp, signature, secret, 5*time.Minute, now); err != ErrInvalidSignature {
		t.Fatalf("stale signature error = %v, want ErrInvalidSignature", err)
	}
	if err := VerifyWebhookSignatureAt(body, webhookID, "not-a-timestamp", signature, secret, 5*time.Minute, now); err != ErrInvalidSignature {
		t.Fatalf("bad timestamp error = %v, want ErrInvalidSignature", err)
	}
	if err := VerifyWebhookSignatureAt(body, webhookID, oldTimestamp, signature, secret, 0, now); err != ErrInvalidSignature {
		t.Fatalf("zero tolerance error = %v, want ErrInvalidSignature", err)
	}
}

func TestFakePolarClientUsesIdempotencyKey(t *testing.T) {
	client := FakePolarClient{}
	session, err := client.CreateCheckout(context.Background(), CheckoutInput{
		IdempotencyKey:    "checkout-key",
		ProviderProductID: "prod_test",
		ProviderPriceID:   "price_test",
		UserID:            "usr_test",
		UserEmail:         "user@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if session.URL != "https://polar.example.test/checkout/checkout-key" {
		t.Fatalf("checkout URL = %q", session.URL)
	}
}

func TestHTTPPolarClientCreateCheckoutUsesPolarPayload(t *testing.T) {
	var gotPath, gotIDKey string
	var gotPayload map[string]any
	client := HTTPPolarClient{
		BaseURL: "https://polar.example.test",
		APIKey:  "polar_oat_test",
		Client: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			gotPath = req.URL.Path
			gotIDKey = req.Header.Get("Idempotency-Key")
			if err := json.NewDecoder(req.Body).Decode(&gotPayload); err != nil {
				t.Fatal(err)
			}
			return jsonResponse(`{"id":"checkout_test","url":"https://polar.example.test/checkout","customer_id":"customer_test"}`), nil
		}).client(),
	}
	session, err := client.CreateCheckout(context.Background(), CheckoutInput{
		UserID:            "usr_test",
		UserEmail:         "user@example.com",
		ProviderProductID: "prod_test",
		ProviderPriceID:   "price_test",
		IdempotencyKey:    "checkout-key",
		SuccessURL:        "https://paperboat.example/paid",
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/v1/checkouts/" || gotIDKey != "checkout-key" {
		t.Fatalf("path/idempotency = %q/%q", gotPath, gotIDKey)
	}
	products, ok := gotPayload["products"].([]any)
	if !ok || len(products) != 1 || products[0] != "prod_test" {
		t.Fatalf("products payload = %#v", gotPayload["products"])
	}
	if gotPayload["external_customer_id"] != "usr_test" {
		t.Fatalf("external_customer_id = %#v", gotPayload["external_customer_id"])
	}
	if gotPayload["currency"] != "usd" {
		t.Fatalf("currency = %#v", gotPayload["currency"])
	}
	if _, ok := gotPayload["price_id"]; ok {
		t.Fatalf("unexpected price_id in payload: %#v", gotPayload)
	}
	if session.URL != "https://polar.example.test/checkout" || session.ProviderSessionID != "checkout_test" || session.ProviderCustomerID != "customer_test" {
		t.Fatalf("session = %+v", session)
	}
}

func TestHTTPPolarClientCreateCustomerPortalUsesCustomerSession(t *testing.T) {
	var gotPath string
	var gotPayload map[string]any
	client := HTTPPolarClient{
		BaseURL: "https://polar.example.test",
		APIKey:  "polar_oat_test",
		Client: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			gotPath = req.URL.Path
			if err := json.NewDecoder(req.Body).Decode(&gotPayload); err != nil {
				t.Fatal(err)
			}
			return jsonResponse(`{"customer_portal_url":"https://polar.example.test/portal"}`), nil
		}).client(),
	}
	session, err := client.CreateCustomerPortal(context.Background(), CustomerPortalInput{
		UserID:         "usr_test",
		UserEmail:      "user@example.com",
		IdempotencyKey: "portal-key",
		ReturnURL:      "https://paperboat.example/account",
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/v1/customer-sessions/" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotPayload["external_customer_id"] != "usr_test" || gotPayload["return_url"] != "https://paperboat.example/account" {
		t.Fatalf("payload = %#v", gotPayload)
	}
	if _, ok := gotPayload["external_user_id"]; ok {
		t.Fatalf("unexpected external_user_id in payload: %#v", gotPayload)
	}
	if session.URL != "https://polar.example.test/portal" {
		t.Fatalf("portal URL = %q", session.URL)
	}
}

func TestHTTPPolarClientUpdateSubscriptionUsesInvoiceProration(t *testing.T) {
	var gotMethod, gotPath, gotIDKey string
	var gotPayload map[string]any
	client := HTTPPolarClient{
		BaseURL: "https://polar.example.test",
		APIKey:  "polar_oat_test",
		Client: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			gotMethod = req.Method
			gotPath = req.URL.Path
			gotIDKey = req.Header.Get("Idempotency-Key")
			if err := json.NewDecoder(req.Body).Decode(&gotPayload); err != nil {
				t.Fatal(err)
			}
			return jsonResponse(`{"id":"sub_test","status":"active"}`), nil
		}).client(),
	}
	if err := client.UpdateSubscription(context.Background(), SubscriptionUpdateInput{
		ProviderSubscriptionID: "sub_test",
		ProviderProductID:      "prod_navigator",
		ProrationBehavior:      "invoice",
		IdempotencyKey:         "switch-key",
	}); err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPatch || gotPath != "/v1/subscriptions/sub_test" || gotIDKey != "switch-key" {
		t.Fatalf("method/path/idempotency = %q/%q/%q", gotMethod, gotPath, gotIDKey)
	}
	if gotPayload["product_id"] != "prod_navigator" || gotPayload["proration_behavior"] != "invoice" {
		t.Fatalf("payload = %#v", gotPayload)
	}
}

func TestHTTPPolarClientUpdatesStorageSeatsWithoutChangingProduct(t *testing.T) {
	var gotPayload map[string]any
	client := HTTPPolarClient{BaseURL: "https://polar.example.test", Client: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if err := json.NewDecoder(req.Body).Decode(&gotPayload); err != nil {
			t.Fatal(err)
		}
		return jsonResponse(`{"id":"sub_test"}`), nil
	}).client()}
	seats := 3
	if err := client.UpdateSubscription(context.Background(), SubscriptionUpdateInput{ProviderSubscriptionID: "sub_test", Seats: &seats, ProrationBehavior: "next_period", IdempotencyKey: "storage-key"}); err != nil {
		t.Fatal(err)
	}
	if gotPayload["seats"] != float64(3) || gotPayload["proration_behavior"] != "next_period" {
		t.Fatalf("payload = %#v", gotPayload)
	}
	if _, exists := gotPayload["product_id"]; exists {
		t.Fatalf("storage update changed product: %#v", gotPayload)
	}
}

func TestHTTPPolarClientReadsSeatPricing(t *testing.T) {
	client := HTTPPolarClient{BaseURL: "https://polar.example.test", Client: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return jsonResponse(`{"current_period_start":"2026-07-01T00:00:00Z","current_period_end":"2026-08-01T00:00:00Z","product":{"prices":[{"amount_type":"fixed","price_currency":"usd"},{"amount_type":"seat_based","price_currency":"usd","seat_tiers":{"seat_tier_type":"volume","tiers":[{"min_seats":1,"max_seats":null,"price_per_seat":250}]}}]}}`), nil
	}).client()}
	pricing, err := client.GetSubscriptionPricing(context.Background(), "sub_test")
	if err != nil {
		t.Fatal(err)
	}
	if pricing.Currency != "usd" || pricing.TierType != "volume" || len(pricing.Tiers) != 1 || pricing.Tiers[0].PricePerSeat != 250 {
		t.Fatalf("pricing = %+v", pricing)
	}
}

func TestSeatPriceTotal(t *testing.T) {
	maxTwo := 2
	volume := SubscriptionPricing{TierType: "volume", Tiers: []SeatPriceTier{{MinSeats: 1, MaxSeats: &maxTwo, PricePerSeat: 100}, {MinSeats: 3, PricePerSeat: 80}}}
	if got := seatPriceTotal(3, volume); got != 240 {
		t.Fatalf("volume total = %d", got)
	}
	graduated := SubscriptionPricing{TierType: "graduated", Tiers: []SeatPriceTier{{MinSeats: 1, MaxSeats: &maxTwo, PricePerSeat: 100}, {MinSeats: 3, PricePerSeat: 80}}}
	if got := seatPriceTotal(3, graduated); got != 280 {
		t.Fatalf("graduated total = %d", got)
	}
}

func TestEntitlementActiveStates(t *testing.T) {
	now := time.Date(2026, 7, 5, 12, 0, 0, 0, time.UTC)
	future := now.Add(time.Hour)
	past := now.Add(-time.Hour)
	cases := []struct {
		name      string
		state     string
		periodEnd *time.Time
		want      bool
	}{
		{name: "active without end", state: "active", want: true},
		{name: "trialing future end", state: "trialing", periodEnd: &future, want: true},
		{name: "active past end", state: "active", periodEnd: &past, want: false},
		{name: "past due", state: "past_due", periodEnd: &future, want: false},
		{name: "canceled", state: "canceled", periodEnd: &future, want: false},
		{name: "paused", state: "paused", periodEnd: &future, want: false},
		{name: "revoked", state: "revoked", periodEnd: &future, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := entitlementActive(tc.state, tc.periodEnd, now); got != tc.want {
				t.Fatalf("entitlementActive() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestBillingRelevantEvent(t *testing.T) {
	cases := map[string]bool{
		"subscription.created":  true,
		"subscription.active":   true,
		"subscription.canceled": true,
		"order.paid":            true,
		"order.refunded":        true,
		"refund.created":        true,
		"checkout.created":      false,
		"customer.updated":      false,
		"member.created":        false,
	}
	for eventType, want := range cases {
		if got := billingRelevantEvent(eventType); got != want {
			t.Errorf("billingRelevantEvent(%q) = %t, want %t", eventType, got, want)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func (f roundTripFunc) client() *http.Client {
	return &http.Client{Transport: f}
}

func jsonResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusCreated,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Header:     make(http.Header),
	}
}

func TestWebhookPayloadExtractsNestedFields(t *testing.T) {
	event := WebhookEvent{
		ID:   "evt_payload",
		Type: "subscription.updated",
		Data: []byte(`{
			"customer": {"external_id": "usr_123"},
			"items": [{"product_id": "prod_123", "price_id": "price_123"}],
			"current_period_end": "2026-08-05T12:00:00Z"
		}`),
	}
	payload := webhookPayload(event)
	if got := payload.firstString("customer.external_id"); got != "usr_123" {
		t.Fatalf("user id = %q", got)
	}
	if got := payload.firstString("items.0.product_id"); got != "prod_123" {
		t.Fatalf("product id = %q", got)
	}
	if got := payload.firstTime("current_period_end"); got == nil {
		t.Fatal("period end was not parsed")
	}
}

func TestSubscriptionStateMapping(t *testing.T) {
	cases := map[string]string{
		"active":     "active",
		"trialing":   "trialing",
		"past_due":   "past_due",
		"cancelled":  "canceled",
		"incomplete": "incomplete",
		"expired":    "expired",
		"paused":     "paused",
		"unpaid":     "unpaid",
		"revoked":    "revoked",
	}
	for input, want := range cases {
		if got := subscriptionState(input, ""); got != want {
			t.Fatalf("subscriptionState(%q) = %q, want %q", input, got, want)
		}
	}
	if got := subscriptionState("", "subscription.canceled"); got != "canceled" {
		t.Fatalf("event-derived state = %q", got)
	}
}

func TestProratedCreditDelta(t *testing.T) {
	start := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(30 * 24 * time.Hour)
	tests := []struct {
		name      string
		old       string
		new       string
		effective time.Time
		want      string
	}{
		{name: "half-period upgrade", old: "100", new: "300", effective: start.Add(15 * 24 * time.Hour), want: "100.000000"},
		{name: "quarter-period downgrade", old: "300", new: "100", effective: start.Add(22*24*time.Hour + 12*time.Hour), want: "-50.000000"},
		{name: "after period", old: "100", new: "300", effective: end.Add(time.Hour), want: "0.000000"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := proratedCreditDelta(tc.old, tc.new, start, end, tc.effective)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("delta = %s, want %s", got, tc.want)
			}
		})
	}
}
