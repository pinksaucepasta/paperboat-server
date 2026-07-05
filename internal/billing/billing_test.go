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
	"testing"
	"time"
)

func TestVerifyWebhookSignature(t *testing.T) {
	body := []byte(`{"id":"evt_test","type":"subscription.active"}`)
	key := []byte("test-webhook-secret")
	secret := "whsec_" + base64.StdEncoding.EncodeToString(key)
	webhookID := "msg_test"
	now := time.Date(2026, 7, 5, 12, 0, 0, 0, time.UTC)
	timestamp := strconv.FormatInt(now.Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(webhookID + "." + timestamp + "."))
	_, _ = mac.Write(body)
	wrongSignature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	mac = hmac.New(sha256.New, key)
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
	key := []byte("test-webhook-secret")
	secret := "whsec_" + base64.StdEncoding.EncodeToString(key)
	webhookID := "msg_test"
	now := time.Date(2026, 7, 5, 12, 0, 0, 0, time.UTC)
	oldTimestamp := strconv.FormatInt(now.Add(-10*time.Minute).Unix(), 10)
	mac := hmac.New(sha256.New, key)
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
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := entitlementActive(tc.state, tc.periodEnd, now); got != tc.want {
				t.Fatalf("entitlementActive() = %v, want %v", got, tc.want)
			}
		})
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
