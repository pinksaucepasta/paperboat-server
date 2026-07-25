package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pinksaucepasta/paperboat-server/internal/access"
)

func TestWriteAccessErrorDistinguishesMachineFailure(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/projects/prj_1/connection-descriptor", nil)
	if !writeAccessError(recorder, request, access.ErrMachineFailed) {
		t.Fatal("machine failure was not handled")
	}
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), `"code":"machine_failed"`) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
