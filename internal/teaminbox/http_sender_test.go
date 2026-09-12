package teaminbox

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPReceiptSenderUsesIdempotencyAndMinimalBody(t *testing.T) {
	var body map[string]string
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" || r.Header.Get("Idempotency-Key") != "tir_1" {
			t.Errorf("headers=%v", r.Header)
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"message_id": "sink_1"})
	}))
	defer sink.Close()
	sender, err := NewHTTPReceiptSender(sink.URL, "test-token", "receipts@example.invalid", sink.Client())
	if err != nil {
		t.Fatal(err)
	}
	id, err := sender.SendReceipt(context.Background(), ReceiptMessage{IdempotencyKey: "tir_1", To: "recipient@example.invalid", Subject: "Files received", Text: "Paperboat received 2 files."})
	if err != nil || id != "sink_1" {
		t.Fatalf("id=%q err=%v", id, err)
	}
	if len(body) != 4 || body["to"] != "recipient@example.invalid" || body["text"] != "Paperboat received 2 files." {
		t.Fatalf("body=%v", body)
	}
}

func TestHTTPReceiptSenderRejectsRemotePlaintextAndHeaderInjection(t *testing.T) {
	if _, err := NewHTTPReceiptSender("http://email.example.test/send", "test-token", "receipts@example.invalid", nil); err == nil {
		t.Fatal("remote plaintext endpoint accepted")
	}
	sender, err := NewHTTPReceiptSender("https://email.example.test/send", "test-token", "receipts@example.invalid", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = sender.SendReceipt(context.Background(), ReceiptMessage{IdempotencyKey: "tir_1", To: "victim@example.invalid\r\nBcc: other@example.invalid", Subject: "x", Text: "x"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("injection error=%v", err)
	}
}
