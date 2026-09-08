package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/auth"
	"github.com/pinksaucepasta/paperboat-server/internal/mint"
	"github.com/pinksaucepasta/paperboat-server/internal/nativeprivateaccess"
)

type nativePrivateResolverFunc func(context.Context, nativeprivateaccess.Request) (nativeprivateaccess.Target, error)

func (f nativePrivateResolverFunc) ResolveNativePrivate(ctx context.Context, request nativeprivateaccess.Request) (nativeprivateaccess.Target, error) {
	return f(ctx, request)
}

func TestNativePrivateGrantUsesAuthenticatedDeviceIdentity(t *testing.T) {
	now := time.Now().UTC()
	signer, err := mint.NewEphemeral(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	service := &nativeprivateaccess.Service{Signer: signer, Issuer: "https://api.example.test", Now: func() time.Time { return now }}
	service.Resolver = nativePrivateResolverFunc(func(_ context.Context, request nativeprivateaccess.Request) (nativeprivateaccess.Target, error) {
		if request.AccountID != "account_01" || request.UserID != "account_01" || request.CLIClientSessionID != "cli_session_01" || request.OperationID != "operation_native_1" {
			t.Fatalf("request=%+v", request)
		}
		return nativeprivateaccess.Target{AccountID: request.AccountID, UserID: request.UserID, EnvironmentID: "env_1", MachineID: "mch_1", AccessSessionID: "umas_1", ResourceKind: "preview", ResourceID: "prv_1", ResourceGeneration: 2, RouteID: "prv_1", RouteGeneration: 2, TargetGeneration: 2, Protocol: "http", TargetScheme: "http", TargetAddress: "127.0.0.1:3000"}, nil
	})
	request := httptest.NewRequest(http.MethodPost, "/v1/native-private-access/grants", strings.NewReader(`{"operation_id":"operation_native_1","resource_kind":"preview","resource_id":"prv_1","route_id":"prv_1","protocol":"http"}`))
	request = request.WithContext(context.WithValue(request.Context(), authContextKey{}, principal{User: auth.User{ID: "account_01"}, Client: &auth.ClientPrincipal{SessionID: "cli_session_01"}}))
	recorder := httptest.NewRecorder()
	nativePrivateGrant(service).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" || !strings.Contains(recorder.Body.String(), `"credential"`) {
		t.Fatalf("status=%d cache=%q body=%s", recorder.Code, recorder.Header().Get("Cache-Control"), recorder.Body.String())
	}
}

func TestNativePrivateGrantRequiresDevicePrincipalAndStrictBody(t *testing.T) {
	signer, _ := mint.NewEphemeral(time.Hour)
	service := &nativeprivateaccess.Service{Signer: signer, Issuer: "https://api.example.test", Resolver: nativePrivateResolverFunc(func(context.Context, nativeprivateaccess.Request) (nativeprivateaccess.Target, error) {
		return nativeprivateaccess.Target{}, nativeprivateaccess.ErrDenied
	})}
	for name, testCase := range map[string]struct {
		request *http.Request
		want    int
	}{
		"no device principal": {httptest.NewRequest(http.MethodPost, "/v1/native-private-access/grants", strings.NewReader(`{}`)), http.StatusUnauthorized},
		"unknown field":       {httptest.NewRequest(http.MethodPost, "/v1/native-private-access/grants", strings.NewReader(`{"operation_id":"operation_native_1","unknown":true}`)).WithContext(context.WithValue(context.Background(), authContextKey{}, principal{User: auth.User{ID: "account_01"}, Client: &auth.ClientPrincipal{SessionID: "cli_session_01"}})), http.StatusBadRequest},
	} {
		t.Run(name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			nativePrivateGrant(service).ServeHTTP(recorder, testCase.request)
			if recorder.Code != testCase.want {
				t.Fatalf("status=%d want=%d body=%s", recorder.Code, testCase.want, recorder.Body.String())
			}
		})
	}
}
