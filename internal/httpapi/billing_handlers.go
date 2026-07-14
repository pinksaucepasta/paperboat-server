package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/billing"
)

func billingEntitlement(service *billing.Service) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		entitlement, err := service.Entitlement(r.Context(), p.User.ID)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: entitlement})
	})
}

func billingUsage(service *billing.Service) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		usage, err := service.Usage(r.Context(), p.User.ID)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal server error.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: usage})
	})
}

func billingPlanProducts(service *billing.Service) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		products, err := service.ListPlanProducts(r.Context())
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Billing plans could not be loaded.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: products})
	})
}

func billingStorage(service *billing.Service) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		storage, err := service.StorageSubscription(r.Context(), p.User.ID)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "billing_unavailable", "Storage subscription is unavailable.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: storage})
	})
}

func billingStorageUpdate(service *billing.Service) http.Handler {
	type request struct {
		StorageGB int `json:"storage_gb"`
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		var body request
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, r, http.StatusBadRequest, "validation_failed", "Request body must be valid JSON.")
			return
		}
		key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
		if key == "" {
			writeError(w, r, http.StatusBadRequest, "validation_failed", "Idempotency-Key is required.")
			return
		}
		storage, err := service.UpdateStorageSubscription(r.Context(), p.User.ID, body.StorageGB, key)
		if errors.Is(err, billing.ErrInsufficientStorage) {
			writeError(w, r, http.StatusConflict, "quota_exceeded", "Storage cannot be reduced below current allocation.")
			return
		}
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "validation_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: storage})
	})
}

func billingStoragePreview(service *billing.Service) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		storageGB, err := strconv.Atoi(r.URL.Query().Get("storage_gb"))
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "validation_failed", "storage_gb must be an integer.")
			return
		}
		preview, err := service.PreviewStorageSubscription(r.Context(), p.User.ID, storageGB)
		if errors.Is(err, billing.ErrInsufficientStorage) {
			writeError(w, r, http.StatusConflict, "quota_exceeded", "Storage cannot be reduced below current allocation.")
			return
		}
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "validation_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: preview})
	})
}

func billingAutoTopup(service *billing.Service) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		policy, err := service.AutoTopupPolicy(r.Context(), p.User.ID)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Auto top-up policy is unavailable.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: policy})
	})
}

func billingAutoTopupUpdate(service *billing.Service) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		var policy billing.AutoTopupPolicy
		if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
			writeError(w, r, http.StatusBadRequest, "validation_failed", "Request body must be valid JSON.")
			return
		}
		updated, err := service.SetAutoTopupPolicy(r.Context(), p.User.ID, policy)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "validation_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: updated})
	})
}

func billingCheckout(service *billing.Service) http.Handler {
	type request struct {
		ProductCode string `json:"product_code"`
		SuccessURL  string `json:"success_url"`
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		var body request
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, r, http.StatusBadRequest, "validation_failed", "Request body must be valid JSON.")
			return
		}
		idempotencyKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
		if idempotencyKey == "" || strings.TrimSpace(body.ProductCode) == "" {
			writeError(w, r, http.StatusBadRequest, "validation_failed", "Idempotency-Key and product_code are required.")
			return
		}
		session, err := service.CreateCheckout(r.Context(), p.User.ID, p.User.PrimaryEmail, body.ProductCode, idempotencyKey, body.SuccessURL)
		if errors.Is(err, billing.ErrUnknownProduct) {
			writeError(w, r, http.StatusBadRequest, "validation_failed", "Billing product is not available.")
			return
		}
		if errors.Is(err, billing.ErrSamePlan) {
			writeError(w, r, http.StatusBadRequest, "validation_failed", "You are already subscribed to this plan.")
			return
		}
		if errors.Is(err, billing.ErrTrialUnavailable) {
			writeError(w, r, http.StatusConflict, "trial_unavailable", "The free trial is only available once per account.")
			return
		}
		if errors.Is(err, billing.ErrCheckoutPending) {
			writeError(w, r, http.StatusConflict, "checkout_pending", "Another billing checkout is already pending.")
			return
		}
		if errors.Is(err, billing.ErrInsufficientStorage) {
			writeError(w, r, http.StatusConflict, "quota_exceeded", "Reduce allocated storage before changing to this plan.")
			return
		}
		if err != nil {
			writeError(w, r, http.StatusServiceUnavailable, "provider_unavailable", "Billing provider is unavailable.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]any{
			"url": session.URL,
		}})
	})
}

func billingCustomerPortal(service *billing.Service) http.Handler {
	type request struct {
		ReturnURL string `json:"return_url"`
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		var body request
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, r, http.StatusBadRequest, "validation_failed", "Request body must be valid JSON.")
			return
		}
		idempotencyKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
		if idempotencyKey == "" {
			writeError(w, r, http.StatusBadRequest, "validation_failed", "Idempotency-Key is required.")
			return
		}
		session, err := service.CreateCustomerPortal(r.Context(), p.User.ID, p.User.PrimaryEmail, idempotencyKey, body.ReturnURL)
		if err != nil {
			writeError(w, r, http.StatusServiceUnavailable, "provider_unavailable", "Billing provider is unavailable.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]any{
			"url": session.URL,
		}})
	})
}

func polarWebhook(service *billing.Service, secret string, tolerance time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := billing.ReadWebhookBody(r)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "validation_failed", "Webhook body could not be read.")
			return
		}
		if err := billing.VerifyWebhookSignature(body, r.Header.Get("Webhook-Id"), r.Header.Get("Webhook-Timestamp"), r.Header.Get("Webhook-Signature"), secret, tolerance); err != nil {
			writeError(w, r, http.StatusUnauthorized, "forbidden", "Webhook signature is invalid.")
			return
		}
		inserted, err := service.HandleWebhookWithID(r.Context(), r.Header.Get("Webhook-Id"), body)
		if err != nil {
			if errors.Is(err, billing.ErrRetryableWebhook) {
				writeError(w, r, http.StatusServiceUnavailable, "provider_unavailable", "Webhook event could not be processed yet.")
				return
			}
			writeError(w, r, http.StatusBadRequest, "validation_failed", "Webhook event could not be processed.")
			return
		}
		status := "processed"
		if !inserted {
			status = "duplicate"
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]any{"status": status}})
	}
}

func adminAdjustCredits(service *billing.Service) http.Handler {
	type request struct {
		Amount string `json:"amount"`
		Reason string `json:"reason"`
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		var body request
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, r, http.StatusBadRequest, "validation_failed", "Request body must be valid JSON.")
			return
		}
		idempotencyKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
		if idempotencyKey == "" || strings.TrimSpace(body.Amount) == "" || strings.TrimSpace(body.Reason) == "" {
			writeError(w, r, http.StatusBadRequest, "validation_failed", "Idempotency-Key, amount, and reason are required.")
			return
		}
		err := service.AdjustCredits(r.Context(), p.User.ID, r.PathValue("user_id"), body.Amount, idempotencyKey, body.Reason)
		if errors.Is(err, billing.ErrInsufficientCredits) {
			writeError(w, r, http.StatusConflict, "credits_exhausted", "Credit adjustment would make the balance negative.")
			return
		}
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "validation_failed", "Credit adjustment could not be applied.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]any{"status": "adjusted"}})
	})
}

func adminAdjustStorage(service *billing.Service) http.Handler {
	type request struct {
		PurchasedGB int    `json:"purchased_gb"`
		Reason      string `json:"reason"`
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromContext(r.Context())
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "Authentication is required.")
			return
		}
		var body request
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, r, http.StatusBadRequest, "validation_failed", "Request body must be valid JSON.")
			return
		}
		idempotencyKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
		if idempotencyKey == "" || strings.TrimSpace(body.Reason) == "" || body.PurchasedGB < 0 {
			writeError(w, r, http.StatusBadRequest, "validation_failed", "Idempotency-Key, nonnegative purchased_gb, and reason are required.")
			return
		}
		err := service.AdjustPurchasedStorage(r.Context(), p.User.ID, r.PathValue("user_id"), idempotencyKey, body.Reason, body.PurchasedGB)
		if errors.Is(err, billing.ErrInsufficientStorage) {
			writeError(w, r, http.StatusConflict, "quota_exceeded", "Storage adjustment would over-allocate the account.")
			return
		}
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "validation_failed", "Storage adjustment could not be applied.")
			return
		}
		writeJSON(w, http.StatusOK, SuccessResponse{Data: map[string]any{"status": "adjusted"}})
	})
}
