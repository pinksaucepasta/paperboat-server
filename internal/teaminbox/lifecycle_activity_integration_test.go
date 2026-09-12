package teaminbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/observability"
	"github.com/pinksaucepasta/paperboat-server/internal/teams"
)

func TestPostgresInboxLifecycleActivityAndCurrentAuthority(t *testing.T) {
	store := inboxTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	ctx = observability.WithRequestID(ctx, "http-correlation-must-not-replace-inbox-id")
	suffix := fmt.Sprint(time.Now().UnixNano())
	sender, recipient, team := "tila_sender_"+suffix, "tila_recipient_"+suffix, "tila_team_"+suffix
	source, ownDestination, destination := "tila_source_"+suffix, "tila_own_"+suffix, "tila_destination_"+suffix
	for _, account := range []string{sender, recipient} {
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users(id,workos_subject,primary_email,status) VALUES($1,$1,$1||'@invalid.test','active')`, account); err != nil {
			t.Fatal(err)
		}
	}
	for _, machine := range []struct{ id, owner string }{{source, sender}, {ownDestination, sender}, {destination, recipient}} {
		if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machines(id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online,configured_capabilities,observed_capabilities) VALUES($1,$2,$3,$1,'linux','amd64','/workspace','online','occupied',true,ARRAY['file_receive'],ARRAY['file_receive'])`, machine.id, machine.owner, "env_"+machine.id); err != nil {
			t.Fatal(err)
		}
	}
	authority := teams.NewService(store)
	current, err := authority.Create(ctx, recipient, teams.CreateRequest{OperationID: "create_" + suffix, TeamID: team})
	if err != nil {
		t.Fatal(err)
	}
	invite, err := authority.Invite(ctx, recipient, team, teams.InviteRequest{OperationID: "invite_" + suffix, ExpectedGeneration: current.Generation, AccountID: sender})
	if err != nil {
		t.Fatal(err)
	}
	current, err = authority.Accept(ctx, sender, invite.InvitationID, teams.AcceptRequest{OperationID: "accept_" + suffix})
	if err != nil {
		t.Fatal(err)
	}
	current, err = authority.Machine(ctx, recipient, team, teams.MachineRequest{OperationID: "share_" + suffix, ExpectedGeneration: current.Generation, MachineID: destination, Action: "share"})
	if err != nil {
		t.Fatal(err)
	}
	grant := func(active bool, operation string) {
		t.Helper()
		current, err = authority.GrantMachine(ctx, recipient, team, teams.MachineGrantRequest{OperationID: operation + suffix, ExpectedGeneration: current.Generation, MachineID: destination, Audience: "selected_member", AccountID: sender, Capabilities: []string{"files"}, Active: active})
		if err != nil {
			t.Fatal(err)
		}
	}
	grant(true, "grant_")

	service, err := New(store)
	if err != nil {
		t.Fatal(err)
	}
	files := []File{{Basename: "must-not-appear.txt", Size: 3, SHA256: strings.Repeat("b", 64)}}
	request, err := service.Create(ctx, RequestInput{RequestID: "tila_request_" + suffix, OperationID: "tila_operation_" + suffix, SenderAccount: sender, SourceMachineID: source, DestinationMachineID: destination, BatchID: "tila_batch_" + suffix, Files: files, ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	request, err = service.Decide(ctx, recipient, request.RequestID, "approved", request.DecisionGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.Consume(ctx, sender, request.RequestID, request.ManifestDigest); err != nil {
		t.Fatal(err)
	}
	if _, err = service.Consume(ctx, sender, request.RequestID, request.ManifestDigest); err != nil {
		t.Fatalf("consume retry: %v", err)
	}
	if _, err = service.Complete(ctx, sender, request.RequestID, request.ManifestDigest); !errors.Is(err, ErrNotFound) {
		t.Fatalf("sender completed recipient publication: %v", err)
	}
	statusAfterDeniedComplete, err := service.Get(ctx, recipient, request.RequestID)
	if err != nil || statusAfterDeniedComplete.Status != "consumed" {
		t.Fatalf("denied completion changed request: status=%s err=%v", statusAfterDeniedComplete.Status, err)
	}
	if _, err = service.Complete(ctx, recipient, request.RequestID, request.ManifestDigest); err != nil {
		t.Fatal(err)
	}
	if _, err = service.Complete(ctx, recipient, request.RequestID, request.ManifestDigest); err != nil {
		t.Fatalf("complete retry: %v", err)
	}

	rows, err := store.SQL().QueryContext(ctx, `SELECT event_type,metadata FROM paperboat.audit_events WHERE resource_type='team' AND resource_id=$1 AND event_type LIKE 'team.inbox_%' ORDER BY cursor_sequence`, team)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	want := []string{"team.inbox_request", "team.inbox_decide", "team.inbox_consume", "team.inbox_complete"}
	var got []string
	for rows.Next() {
		var eventType string
		var raw []byte
		if err = rows.Scan(&eventType, &raw); err != nil {
			t.Fatal(err)
		}
		var metadata map[string]any
		if err = json.Unmarshal(raw, &metadata); err != nil {
			t.Fatal(err)
		}
		if len(metadata) != 3 || metadata["request_id"] != request.RequestID || metadata["status"] == nil || metadata["target_account"] == nil {
			t.Fatalf("unsafe lifecycle metadata for %s: %s", eventType, raw)
		}
		if strings.Contains(string(raw), files[0].Basename) || strings.Contains(string(raw), files[0].SHA256) || strings.Contains(string(raw), request.ManifestDigest) {
			t.Fatalf("payload metadata leaked for %s: %s", eventType, raw)
		}
		got = append(got, eventType)
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("lifecycle events = %v, want %v", got, want)
	}

	stale, err := service.Create(ctx, RequestInput{RequestID: "tila_stale_" + suffix, OperationID: "tila_stale_op_" + suffix, SenderAccount: sender, SourceMachineID: source, DestinationMachineID: destination, BatchID: "tila_stale_batch_" + suffix, Files: files, ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	grant(false, "revoke_")
	if _, err = service.Decide(ctx, recipient, stale.RequestID, "approved", stale.DecisionGeneration); !errors.Is(err, ErrRevoked) {
		t.Fatalf("stale sender authority decision: %v", err)
	}
	status, err := service.Get(ctx, recipient, stale.RequestID)
	if err != nil || status.Status != "revoked" {
		t.Fatalf("stale request status=%s err=%v", status.Status, err)
	}

	// A team-owned machine survives its original enroller leaving, but that
	// departed account must not remain the Inbox recipient or be replaced by the
	// new team owner. Existing consumed authorization is revoked on retry.
	grant(true, "restore_")
	consumed, err := service.Create(ctx, RequestInput{RequestID: "tila_departed_" + suffix, OperationID: "tila_departed_op_" + suffix, SenderAccount: sender, SourceMachineID: source, DestinationMachineID: destination, BatchID: "tila_departed_batch_" + suffix, Files: files, ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	consumed, err = service.Decide(ctx, recipient, consumed.RequestID, "approved", consumed.DecisionGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.Consume(ctx, sender, consumed.RequestID, consumed.ManifestDigest); err != nil {
		t.Fatal(err)
	}
	current, err = authority.Machine(ctx, recipient, team, teams.MachineRequest{OperationID: "transfer_machine_" + suffix, ExpectedGeneration: current.Generation, MachineID: destination, Action: "transfer_to_team", Confirmation: destination})
	if err != nil {
		t.Fatal(err)
	}
	current, err = authority.Mutate(ctx, recipient, team, teams.MutationRequest{OperationID: "transfer_owner_" + suffix, ExpectedGeneration: current.Generation, Action: "transfer", AccountID: sender})
	if err != nil {
		t.Fatal(err)
	}
	current, err = authority.Mutate(ctx, sender, team, teams.MutationRequest{OperationID: "remove_enroller_" + suffix, ExpectedGeneration: current.Generation, Action: "remove", AccountID: recipient})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = authority.Authorize(ctx, sender, team, "machine", destination, "files"); err != nil {
		t.Fatalf("unrelated current team machine access was lost: %v", err)
	}
	denied, err := service.Create(ctx, RequestInput{RequestID: "tila_after_leave_" + suffix, OperationID: "tila_after_leave_op_" + suffix, SenderAccount: sender, SourceMachineID: source, DestinationMachineID: destination, BatchID: "tila_after_leave_batch_" + suffix, Files: files, ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if !errors.Is(err, ErrForbidden) || denied.RequestID != "" {
		t.Fatalf("departed enroller received new request: request=%+v err=%v", denied, err)
	}
	if _, err = service.Consume(ctx, sender, consumed.RequestID, consumed.ManifestDigest); !errors.Is(err, ErrRevoked) {
		t.Fatalf("departed enroller retained consumed authorization: %v", err)
	}
	personal, err := service.Create(ctx, RequestInput{RequestID: "tila_personal_" + suffix, OperationID: "tila_personal_op_" + suffix, SenderAccount: sender, SourceMachineID: source, DestinationMachineID: ownDestination, BatchID: "tila_personal_batch_" + suffix, Files: files, ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil || personal.Status != "not_required" || personal.RecipientAccount != sender {
		t.Fatalf("personal same-account flow changed: request=%+v err=%v", personal, err)
	}
}
