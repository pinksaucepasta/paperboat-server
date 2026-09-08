package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pinksaucepasta/paperboat-server/internal/accessdescriptor"
	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
	"github.com/pinksaucepasta/paperboat-server/internal/usermachines"
)

func TestRuntimeObservationReturnsConfiguredTransferPolicyAfterAuthentication(t *testing.T) {
	machines := &usermachines.Service{}
	policy := accessdescriptor.FileTransferPolicy{Revision: "task24", MaxFileBytes: 1024, MaxBatchFiles: 2, MaxBatchBytes: 2048, MaxConcurrentTransfers: 1, RetentionSeconds: 60, DeliveryTimeoutSeconds: 30, MaxPendingSpoolBytes: 4096}
	machines.ConfigureFileTransfer(policy)
	for _, denied := range []bool{false, true} {
		identity := &fakeRuntimeIdentity{}
		if denied {
			identity.err = controlplane.ErrHelperProof
		}
		r := httptest.NewRequest(http.MethodPost, "/v1/runtime-observations", strings.NewReader(`{"environment_id":"environment_1","resource_id":"machine_1","sampled_at":"2026-09-08T12:00:00Z"}`))
		r.Header.Set("Authorization", "Bearer machine-token")
		r.Header.Set("X-Paperboat-Machine-Proof", base64.RawURLEncoding.EncodeToString([]byte("machine-proof")))
		w := httptest.NewRecorder()
		runtimeObservation(&fakeRuntimeObservationRepository{}, identity, 10, machines).ServeHTTP(w, r)
		if denied {
			if w.Code != http.StatusUnauthorized || strings.Contains(w.Body.String(), "file_transfer_policy") {
				t.Fatal("unauthorized policy response")
			}
			continue
		}
		var got struct {
			Data struct {
				Policy accessdescriptor.FileTransferPolicy `json:"file_transfer_policy"`
			} `json:"data"`
		}
		if w.Code != http.StatusAccepted || json.Unmarshal(w.Body.Bytes(), &got) != nil || got.Data.Policy != policy {
			t.Fatalf("configured policy response status=%d", w.Code)
		}
	}
}
