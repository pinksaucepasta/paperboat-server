package httpapi

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
	"github.com/pinksaucepasta/paperboat-server/internal/lazyaccess"
)

type lazyRuntimeSink struct {
	calls                int
	environment, machine string
	observation          lazyaccess.RuntimeObservation
}

func (s *lazyRuntimeSink) RecordLazyRuntimeObservation(_ context.Context, environment, machine string, in lazyaccess.RuntimeObservation) error {
	s.calls++
	s.environment = environment
	s.machine = machine
	s.observation = in
	return nil
}

func TestLazyRuntimeRegistrationRequiresSignedCurrentMachine(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	body := fmt.Sprintf(`{"environment_id":"prj_test","resource_id":"machine_test","reporter_version":"test","sampled_at":%q,"lazy_runtime":{"schema":"paperboat.lazy-runtime/v1","boot_id":"0123456789abcdef","installation_generation":4,"started_at":%q}}`, now, now)
	for _, tc := range []struct {
		name    string
		proof   bool
		authErr error
		status  int
	}{
		{"signed", true, nil, 202}, {"bad proof", true, controlplane.ErrHelperProof, 401}, {"legacy heartbeat", false, nil, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &fakeRuntimeObservationRepository{}
			identity := &fakeRuntimeIdentity{err: tc.authErr}
			sink := &lazyRuntimeSink{}
			r := httptest.NewRequest(http.MethodPost, "/v1/runtime-observations", strings.NewReader(body))
			r.Header.Set("Authorization", "Bearer fixture-machine-token")
			if tc.proof {
				r.Header.Set("X-Paperboat-Machine-Proof", base64.RawURLEncoding.EncodeToString([]byte("fixture-proof")))
			}
			w := httptest.NewRecorder()
			runtimeObservation(repo, identity, 10, sink).ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status=%d want=%d", w.Code, tc.status)
			}
			if tc.status == 202 {
				if sink.calls != 1 || sink.environment != "prj_test" || sink.machine != "machine_test" || sink.observation.InstallationGeneration != 4 || string(identity.body) != body {
					t.Fatal("signed exact machine registration not preserved")
				}
			} else if sink.calls != 0 {
				t.Fatal("unauthorized heartbeat registered a lazy runtime")
			}
		})
	}
}
