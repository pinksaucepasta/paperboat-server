package nativeprivateaccess

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/mint"
)

type resolverFunc func(context.Context, Request) (Target, error)

func (f resolverFunc) ResolveNativePrivate(c context.Context, r Request) (Target, error) {
	return f(c, r)
}
func TestIssueAndRevalidateUseAuthoritativeExactTarget(t *testing.T) {
	now := time.Now().UTC()
	signer, _ := mint.NewEphemeral(time.Hour)
	req := Request{AccountID: "acct_1", UserID: "usr_1", CLIClientSessionID: "cli_1", OperationID: "operation_native_1", ResourceKind: "tunnel", ResourceID: "tun_1", RouteID: "route_1", Protocol: "tcp"}
	target := Target{AccountID: req.AccountID, UserID: req.UserID, EnvironmentID: "env_1", MachineID: "machine_1", AccessSessionID: "umas_1", ResourceKind: req.ResourceKind, ResourceID: req.ResourceID, RouteID: req.RouteID, Protocol: req.Protocol, TargetScheme: "tcp", TargetAddress: "127.0.0.1:22", ResourceGeneration: 2, RouteGeneration: 3, TargetGeneration: 4}
	current := target
	service := Service{Resolver: resolverFunc(func(context.Context, Request) (Target, error) { return current, nil }), Signer: signer, Issuer: "https://api.example.test", Now: func() time.Time { return now }}
	grant, err := service.Issue(context.Background(), req)
	if err != nil || grant.Credential == "" || grant.Target != target {
		t.Fatalf("grant=%+v err=%v", grant, err)
	}
	if err = service.Revalidate(context.Background(), req, target); err != nil {
		t.Fatal(err)
	}
	current.TargetGeneration++
	if !errors.Is(service.Revalidate(context.Background(), req, target), ErrDenied) {
		t.Fatal("stale generation accepted")
	}
	current = target
	current.TargetAddress = "192.0.2.1:22"
	if _, err = service.Issue(context.Background(), req); !errors.Is(err, ErrDenied) {
		t.Fatal("non-loopback target issued")
	}
}

func TestIssueResolvesSelectorToExactSignedTarget(t *testing.T) {
	now := time.Now().UTC()
	signer, _ := mint.NewEphemeral(time.Hour)
	request := Request{AccountID: "usr_1", UserID: "usr_1", CLIClientSessionID: "cli_1", OperationID: "operation_selector_1", Selector: "database"}
	target := Target{AccountID: "usr_1", UserID: "usr_1", EnvironmentID: "env_1", MachineID: "machine_1", AccessSessionID: "umas_1", ResourceKind: "tunnel", ResourceID: "tun_1", RouteID: "route_1", Protocol: "tcp", TargetScheme: "tcp", TargetAddress: "127.0.0.1:5432", ResourceGeneration: 2, RouteGeneration: 3, TargetGeneration: 4}
	service := Service{Resolver: resolverFunc(func(_ context.Context, got Request) (Target, error) {
		if got.Selector != request.Selector {
			t.Fatalf("request=%+v", got)
		}
		return target, nil
	}), Signer: signer, Issuer: "https://api.example.test", Now: func() time.Time { return now }}
	grant, err := service.Issue(context.Background(), request)
	if err != nil || grant.Target != target || grant.Credential == "" {
		t.Fatalf("grant=%+v err=%v", grant, err)
	}
}
