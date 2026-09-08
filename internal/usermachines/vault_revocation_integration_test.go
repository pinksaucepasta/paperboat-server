package usermachines

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
)

func TestExplicitMachineRevocationFencesVaultAndTeams(t *testing.T) {
	store := testStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, deletion := range []bool{false, true} {
		t.Run(fmt.Sprintf("delete_%t", deletion), func(t *testing.T) {
			suffix := fmt.Sprintf("%d", time.Now().UnixNano())
			account, machine, team := "vraccount_"+suffix, "vrmachine_"+suffix, "vrteam_"+suffix
			// Successful revocation creates immutable audit history. Retain its
			// unique fixture account until the isolated test database is dropped.

			if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users(id,workos_subject,primary_email,status) VALUES($1,$1,$1||'@invalid.test','active')`, account); err != nil {
				t.Fatal(err)
			}
			if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machines(id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,setup_mode,setup_roles) VALUES($1,$2,$3,'revoke vault','linux','amd64','/revoke-test','online','released','client',ARRAY['interactive'])`, machine, account, "env_"+suffix); err != nil {
				t.Fatal(err)
			}
			// The revocation hook only observes custody existence; no cryptographic claim
			// is made about this opaque storage fixture.
			if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.environment_password_vaults(account_id,generation,document_id,envelope) VALUES($1,1,'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','opaque-test-envelope')`, account); err != nil {
				t.Fatal(err)
			}
			for _, q := range []string{`INSERT INTO paperboat.teams(team_id,owner_account,generation) VALUES($1,$2,1)`, `INSERT INTO paperboat.team_members(team_id,account_id,membership_generation,role,active) VALUES($1,$2,1,'member',true)`} {
				if _, err := store.SQL().ExecContext(ctx, q, team, account); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.environment_vault_teams(team_id,key_epoch) SELECT $1,1 WHERE $2<>''`, team, account); err != nil {
				t.Fatal(err)
			}
			if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.environment_vault_team_members(team_id,account_id,grant_epoch) VALUES($1,$2,1)`, team, account); err != nil {
				t.Fatal(err)
			}
			service := New(store, audit.NewWriter(store), Policy{}, testSeatAuthorizer{})
			if err := service.Disconnect(ctx, "other_account", machine); err == nil {
				t.Fatal("cross-account disconnect accepted")
			}
			var count int
			if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.environment_vault_personal_epochs WHERE account_id=$1`, account).Scan(&count); err != nil || count != 0 {
				t.Fatal("failed revocation changed vault state", err)
			}
			var err error
			if deletion {
				err = service.Delete(ctx, account, machine)
			} else {
				err = service.Disconnect(ctx, account, machine)
			}
			if err != nil {
				t.Fatal(err)
			}
			var personalRequired, teamRequired bool
			var fence uint64
			if err := store.SQL().QueryRowContext(ctx, `SELECT rotation_required FROM paperboat.environment_vault_personal_epochs WHERE account_id=$1`, account).Scan(&personalRequired); err != nil {
				t.Fatal(err)
			}
			if err := store.SQL().QueryRowContext(ctx, `SELECT rotation_required FROM paperboat.environment_vault_teams WHERE team_id=$1`, team).Scan(&teamRequired); err != nil {
				t.Fatal(err)
			}
			if err := store.SQL().QueryRowContext(ctx, `SELECT generation FROM paperboat.environment_vault_projection_fences WHERE machine_id=$1`, machine).Scan(&fence); err != nil {
				t.Fatal(err)
			}
			if !personalRequired || !teamRequired || fence == 0 {
				t.Fatal("explicit machine revocation omitted atomic key/projection fences")
			}
		})
	}
}
