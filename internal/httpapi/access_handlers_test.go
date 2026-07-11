package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pinksaucepasta/paperboat-server/internal/agentunnel"
)

func TestWriteAccessErrorDistinguishesMachineFailure(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/projects/prj_1/cli-connect", nil)
	if !writeAccessError(recorder, request, agentunnel.ErrMachineFailed) {
		t.Fatal("machine failure was not handled")
	}
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), `"code":"machine_failed"`) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
