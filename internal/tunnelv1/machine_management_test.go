package tunnelv1

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"os"
	"testing"

	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

func TestSharedTunnelManagementOnPostgres(t *testing.T) {
	f := newTRK07PostgresFixture(t)
	ctx := context.Background()
	owner, host := f.addAccount(t, "tunnel_owner")
	member, _ := f.addAccount(t, "tunnel_member")
	team, tunnel := "team_"+f.suffix, "tun_shared_"+f.suffix
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := f.database.SQL().ExecContext(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	f.createTunnel(t, owner, host, tunnel, "shared-tunnel")
	exec(`INSERT INTO paperboat.teams(team_id,owner_account,generation) VALUES($1,$2,1)`, team, owner)
	t.Cleanup(func() {
		exec(`UPDATE paperboat.user_machines SET owner_team_id=NULL WHERE id=$1`, host)
		exec(`DELETE FROM paperboat.teams WHERE team_id=$1`, team)
	})
	exec(`INSERT INTO paperboat.team_members(team_id,account_id,membership_generation,role,active) VALUES($1,$2,1,'member',true)`, team, member)
	exec(`INSERT INTO paperboat.team_resource_bindings(team_id,resource_kind,resource_id,owner_account) VALUES($1,'machine',$2,$3)`, team, host, owner)
	exec(`INSERT INTO paperboat.team_machine_grants(team_id,machine_id,audience,capabilities) VALUES($1,$2,'all_members',ARRAY['preview_manage'])`, team, host)
	check := func(want bool) {
		t.Helper()
		account, shared, err := f.repository.ResolveManagementAccount(ctx, member, tunnel)
		if want {
			if err != nil || account != owner || !shared {
				t.Fatalf("shared resolution: %q %v %v", account, shared, err)
			}
		} else if !errors.Is(err, ErrNotFound) {
			t.Fatalf("expected denied, got %v", err)
		}
	}
	check(false)
	exec(`UPDATE paperboat.tunnels SET access_mode='private' WHERE id=$1`, tunnel)
	check(false) // A preview grant is not tunnel management.
	exec(`UPDATE paperboat.team_machine_grants SET capabilities=ARRAY['tunnel_manage'] WHERE team_id=$1`, team)
	check(true)
	request := testRequest(false)
	request.Actor.AccountID = member
	request.Actor.ActorID = member
	scoped, mapped, shared, err := scopeTunnelManagement(ctx, f.repository, request, tunnel)
	if err != nil || !shared || mapped.Actor.AccountID != owner || mapped.Actor.ActorID != member {
		t.Fatalf("resource/actor mapping: %+v %v", mapped, err)
	}
	if _, err = f.repository.Get(scoped, mapped.Actor.AccountID, tunnel); err != nil {
		t.Fatal(err)
	}
	if err = f.database.InTx(scoped, authorizeTunnelManagementTx); err != nil {
		t.Fatal(err)
	}

	name := "shared-updated"
	patch := PatchRecord{OperationID: "op_shared_" + f.suffix, AuditEventID: "aud_shared_" + f.suffix, TunnelID: tunnel, AccountID: owner, Name: &name, ExpectedGeneration: 1, IdempotencyKey: "shared-patch", RequestHash: testHash(), ActorID: member, AuditActorID: member, ActorType: "user", CorrelationID: "shared-test", Now: f.now}
	result, err := f.repository.Patch(scoped, patch)
	if err != nil || result.Tunnel.Name != name || result.Tunnel.AccountID != owner {
		t.Fatalf("shared patch: %+v %v", result, err)
	}

	if path := os.Getenv("PAPERBOAT_SHARED_TUNNEL_FIXTURE"); path != "" {
		before, err := f.database.Queries().GetTunnelConfigGenerationV1(ctx, dbsqlc.GetTunnelConfigGenerationV1Params{TunnelID: tunnel, Generation: 2})
		if err != nil {
			t.Fatal(err)
		}
		paused, err := f.repository.Transition(scoped, StateRecord{OperationID: "op_pause_" + f.suffix, AuditEventID: "aud_pause_" + f.suffix, TunnelID: tunnel, AccountID: owner, DesiredState: DesiredPaused, ExpectedGeneration: 2, IdempotencyKey: "shared-pause", RequestHash: testHash(), ActorID: member, AuditActorID: member, ActorType: "user", CorrelationID: "shared-pause"})
		if err != nil {
			t.Fatal(err)
		}
		after, err := f.database.Queries().GetTunnelConfigGenerationV1(ctx, dbsqlc.GetTunnelConfigGenerationV1Params{TunnelID: tunnel, Generation: paused.Tunnel.Generation})
		if err != nil {
			t.Fatal(err)
		}
		if before.CreatedByActorID != member || after.CreatedByActorID != member {
			t.Fatal("shared config loses authenticated actor")
		}
		payload, err := json.Marshal(struct {
			Owner, Actor, Machine, Tunnel, Endpoint string
			Before, After                           json.RawMessage
		}{owner, member, host, tunnel, result.Tunnel.StableEndpointID, before.Snapshot, after.Snapshot})
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, payload, 0600); err != nil {
			t.Fatal(err)
		}
	}
	listed, err := f.repository.List(ctx, member, nil, 10)
	if err != nil || len(listed) != 1 || listed[0].ID != tunnel {
		t.Fatalf("shared list: %+v %v", listed, err)
	}
	exec(`UPDATE paperboat.team_machine_grants SET active=false WHERE team_id=$1`, team)
	if err = f.database.InTx(scoped, func(ctx context.Context, tx *db.Tx) error { return authorizeTunnelManagementTx(ctx, tx) }); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stale resolved authority survives revocation: %v", err)
	}
	if _, err = f.repository.Patch(scoped, patch); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked mutation replay: %v", err)
	}
	check(false)
	exec(`UPDATE paperboat.team_machine_grants SET active=true WHERE team_id=$1`, team)
	exec(`UPDATE paperboat.user_machines SET configured_capabilities='{}' WHERE id=$1`, host)
	check(false)
	exec(`UPDATE paperboat.user_machines SET configured_capabilities=ARRAY['preview_launch'],owner_team_id=$2 WHERE id=$1`, host, team)
	check(true)
	if _, _, err = f.repository.ResolveManagementAccount(ctx, owner, tunnel); !errors.Is(err, ErrNotFound) {
		t.Fatalf("team ownership left issuer access: %v", err)
	}
	exec(`UPDATE paperboat.team_members SET active=false WHERE team_id=$1`, team)
	check(false)
	exec(`UPDATE paperboat.team_members SET active=true WHERE team_id=$1`, team)
	exec(`UPDATE paperboat.tunnels SET access_mode='public' WHERE id=$1`, tunnel)
	check(false)
}

func TestSharedTunnelManagementKeepsActorAndDeniesPublication(t *testing.T) {
	repo := &fakeTunnelRepository{managementOwner: "owner_other", managementShared: true}
	service := testService(t, repo, sequentialID())
	public := AccessPublic
	if _, err := service.PatchTunnel(context.Background(), testRequest(false), "tun_1", PatchTunnelRequest{AccessMode: &public}); !errors.Is(err, ErrMachinePublicationDenied) {
		t.Fatalf("public patch: %v", err)
	}
	name := "new-name"
	_, err := service.PatchTunnel(context.Background(), testRequest(false), "tun_1", PatchTunnelRequest{Name: &name, MutationInput: MutationInput{ExpectedGeneration: 1, IdempotencyKey: "shared-patch", RequestHash: testHash()}})
	if err != nil {
		t.Fatal(err)
	}
	if repo.patch.AccountID != "owner_other" || repo.patch.ActorID != "user_1" || repo.patch.AuditActorID != "user_1" {
		t.Fatalf("shared patch identity: %+v", repo.patch)
	}
	resources := &fakeResourceRepository{managementOwner: "owner_other", managementShared: true}
	resourceService := resourceServiceForTest(t, resources, 0)
	if _, err = resourceService.CreateDomain(context.Background(), testRequest(false), "tun_1", DomainCreateRequest{}); !errors.Is(err, ErrMachinePublicationDenied) {
		t.Fatalf("domain publication: %v", err)
	}
	if _, err = resourceService.IssueEnrollment(context.Background(), testRequest(false), "tun_1", EnrollmentRequest{}); !errors.Is(err, ErrMachinePublicationDenied) {
		t.Fatalf("connector enrollment: %v", err)
	}
	if _, err = resourceService.ListRoutes(context.Background(), testRequest(false), "tun_1", "", 10); err != nil {
		t.Fatal(err)
	}
	if resources.listRoutesAccount != "owner_other" || resources.listRoutesTunnel != "tun_1" {
		t.Fatal("shared routes did not resolve exact resource owner")
	}
	resources.managementErr = ErrNotFound
	if _, err = resourceService.ListRoutes(context.Background(), testRequest(false), "tun_1", "", 10); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked management: %v", err)
	}
}
