package teaminbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/teams"
)

func inboxTestStore(t *testing.T) *db.DB {
	t.Helper()
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run Team Inbox integration tests")
	}
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
	}
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err = db.Migrate(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	return store
}

type receiptSink struct {
	mu    sync.Mutex
	calls []ReceiptMessage
	fail  int
}

func (s *receiptSink) SendReceipt(_ context.Context, message ReceiptMessage) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, message)
	if s.fail > 0 {
		s.fail--
		return "", errors.New("test sink unavailable")
	}
	return "test-message-" + message.IdempotencyKey, nil
}

func TestPostgresExactApprovalRevocationAndReceiptDelivery(t *testing.T) {
	store := inboxTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	suffix := fmt.Sprint(time.Now().UnixNano())
	sender, recipient, team := "ti_sender_"+suffix, "ti_recipient_"+suffix, "ti_team_"+suffix
	source, ownDestination, destination := "ti_source_"+suffix, "ti_own_destination_"+suffix, "ti_destination_"+suffix
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
	current, err = authority.GrantMachine(ctx, recipient, team, teams.MachineGrantRequest{OperationID: "grant_" + suffix, ExpectedGeneration: current.Generation, MachineID: destination, Audience: "selected_member", AccountID: sender, Capabilities: []string{"files"}, Active: true})
	if err != nil {
		t.Fatal(err)
	}

	service, _ := New(store)
	service.ConfigureEncryptionKey("task41-team-smtp-encryption-key")
	smtpConfig, err := service.TeamSMTP(ctx, recipient, team)
	if err != nil || smtpConfig.Generation != 1 || smtpConfig.PasswordStored {
		t.Fatalf("default team SMTP=%+v err=%v", smtpConfig, err)
	}
	smtpConfig, err = service.SetTeamSMTP(ctx, recipient, team, SMTPConfig{Host: "smtp.example.test", Port: 587, Username: "team-user", Password: "team-password-secret", FromAddress: "receipts@example.test", TLSMode: "starttls"}, smtpConfig.Generation)
	if err != nil || !smtpConfig.PasswordStored || smtpConfig.Password != "" {
		t.Fatalf("set team SMTP=%+v err=%v", smtpConfig, err)
	}
	if _, err = service.TeamSMTP(ctx, sender, team); !errors.Is(err, ErrForbidden) {
		t.Fatalf("member read team SMTP=%v", err)
	}
	var encrypted []byte
	if err = store.SQL().QueryRowContext(ctx, `SELECT password_ciphertext FROM paperboat.team_receipt_smtp WHERE team_id=$1`, team).Scan(&encrypted); err != nil || strings.Contains(string(encrypted), "team-password-secret") {
		t.Fatalf("SMTP password storage err=%v", err)
	}
	files := []File{{Basename: "proof.txt", Size: 5, SHA256: strings.Repeat("a", 64)}}
	if _, err = store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machines SET state='offline',online=false WHERE id=$1`, destination); err != nil {
		t.Fatal(err)
	}
	if offline, createErr := service.Create(ctx, RequestInput{RequestID: "tir_offline_" + suffix, OperationID: "op_offline_" + suffix, SenderAccount: sender, SourceMachineID: source, DestinationMachineID: destination, BatchID: "fb_offline_" + suffix, Files: files, ExpiresAt: time.Now().UTC().Add(time.Hour)}); !errors.Is(createErr, ErrOffline) || offline.RequestID != "" {
		t.Fatalf("offline request=%+v err=%v", offline, createErr)
	}
	if _, err = store.SQL().ExecContext(ctx, `UPDATE paperboat.user_machines SET state='online',online=true WHERE id=$1`, destination); err != nil {
		t.Fatal(err)
	}
	request, err := service.Create(ctx, RequestInput{RequestID: "tir_" + suffix, OperationID: "op_" + suffix, SenderAccount: sender, SourceMachineID: source, DestinationMachineID: destination, BatchID: "fb_" + suffix, Files: files, ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil || request.Status != "pending" {
		t.Fatalf("create=%+v err=%v", request, err)
	}
	results := make(chan error, 2)
	for range 2 {
		go func() {
			_, decideErr := service.Decide(ctx, recipient, request.RequestID, "approved", request.DecisionGeneration)
			results <- decideErr
		}()
	}
	var successes, conflicts int
	for range 2 {
		if decideErr := <-results; decideErr == nil {
			successes++
		} else if errors.Is(decideErr, ErrConflict) {
			conflicts++
		} else {
			t.Fatal(decideErr)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent decisions successes=%d conflicts=%d", successes, conflicts)
	}
	if _, err = service.Consume(ctx, sender, request.RequestID, strings.Repeat("0", 64)); !errors.Is(err, ErrConflict) {
		t.Fatalf("substitution error=%v", err)
	}
	if _, err = service.Consume(ctx, sender, request.RequestID, request.ManifestDigest); err != nil {
		t.Fatal(err)
	}
	if _, err = service.Consume(ctx, sender, request.RequestID, request.ManifestDigest); err != nil {
		t.Fatalf("exact resume=%v", err)
	}
	policy, err := service.Policy(ctx, recipient)
	if err != nil || policy.Generation != 1 || policy.Acceptance != "manual" {
		t.Fatalf("default policy=%+v err=%v", policy, err)
	}
	policy, err = service.SetPolicy(ctx, recipient, Policy{Acceptance: "manual", ReceiptEmail: true}, policy.Generation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.SetPolicy(ctx, recipient, Policy{Acceptance: "automatic"}, policy.Generation+1); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale policy update=%v", err)
	}
	consumed, err := service.Get(ctx, recipient, request.RequestID)
	if err != nil || consumed.Status != "consumed" {
		t.Fatalf("pre-completion status=%q error=%v", consumed.Status, err)
	}
	completed, err := service.Complete(ctx, recipient, request.RequestID, request.ManifestDigest)
	if err != nil || completed.Status != "completed" || completed.DecisionGeneration != consumed.DecisionGeneration+1 {
		t.Fatalf("completion response status=%q generation=%d want=%d error=%v", completed.Status, completed.DecisionGeneration, consumed.DecisionGeneration+1, err)
	}
	storedCompletion, err := service.Get(ctx, recipient, request.RequestID)
	if err != nil || storedCompletion.Status != completed.Status || storedCompletion.DecisionGeneration != completed.DecisionGeneration {
		t.Fatalf("completion response differs from stored status/generation: %v", err)
	}
	repeatedCompletion, err := service.Complete(ctx, recipient, request.RequestID, request.ManifestDigest)
	if err != nil || repeatedCompletion.Status != "completed" || repeatedCompletion.DecisionGeneration != completed.DecisionGeneration {
		t.Fatalf("completion retry status=%q generation=%d want=%d error=%v", repeatedCompletion.Status, repeatedCompletion.DecisionGeneration, completed.DecisionGeneration, err)
	}
	sink := &receiptSink{fail: 1}
	service.smtpFactory = func(config SMTPConfig) (ReceiptSender, error) {
		if config.Password != "team-password-secret" || config.Host != "smtp.example.test" {
			t.Fatalf("decrypted SMTP config=%+v", config)
		}
		return sink, nil
	}
	worker, _ := NewReceiptWorker(service, sink, time.Millisecond)
	if err = worker.DeliverOne(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = store.SQL().ExecContext(ctx, `UPDATE paperboat.team_inbox_receipt_outbox SET next_attempt_at=now() WHERE request_id=$1`, request.RequestID); err != nil {
		t.Fatal(err)
	}
	if err = worker.DeliverOne(ctx); err != nil {
		t.Fatal(err)
	}
	sink.mu.Lock()
	calls := append([]ReceiptMessage(nil), sink.calls...)
	sink.mu.Unlock()
	if len(calls) != 2 || calls[0].IdempotencyKey != request.RequestID || calls[0].Text != calls[1].Text || strings.Contains(calls[0].Text, "proof.txt") || strings.Contains(calls[0].Text, files[0].SHA256) {
		t.Fatalf("unsafe or non-idempotent receipts: %+v", calls)
	}
	status, err := service.Get(ctx, recipient, request.RequestID)
	if err != nil || status.ReceiptNotification != "delivered" {
		t.Fatalf("receipt status=%+v err=%v", status, err)
	}
	if err = service.DeleteTeamSMTP(ctx, recipient, team, smtpConfig.Generation); err != nil {
		t.Fatal(err)
	}
	if senderAfterDelete, senderErr := service.teamSMTPSender(ctx, team); senderErr != nil || senderAfterDelete != nil {
		t.Fatalf("team SMTP removal did not restore fallback: sender=%T err=%v", senderAfterDelete, senderErr)
	}

	declined, err := service.Create(ctx, RequestInput{RequestID: "tir_decline_" + suffix, OperationID: "op_decline_" + suffix, SenderAccount: sender, SourceMachineID: source, DestinationMachineID: destination, BatchID: "fb_decline_" + suffix, Files: files, ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.Decide(ctx, recipient, declined.RequestID, "declined", declined.DecisionGeneration); err != nil {
		t.Fatal(err)
	}
	if _, err = service.Consume(ctx, sender, declined.RequestID, declined.ManifestDigest); !errors.Is(err, ErrDeclined) {
		t.Fatalf("declined consume=%v", err)
	}

	base := time.Now().UTC()
	service.now = func() time.Time { return base }
	expired, err := service.Create(ctx, RequestInput{RequestID: "tir_expire_" + suffix, OperationID: "op_expire_" + suffix, SenderAccount: sender, SourceMachineID: source, DestinationMachineID: destination, BatchID: "fb_expire_" + suffix, Files: files, ExpiresAt: base.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return base.Add(2 * time.Minute) }
	if _, err = service.Decide(ctx, recipient, expired.RequestID, "approved", expired.DecisionGeneration); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired decision=%v", err)
	}
	service.now = func() time.Time { return time.Now().UTC() }

	policy, err = service.SetPolicy(ctx, recipient, Policy{Acceptance: "automatic", ReceiptEmail: false}, policy.Generation)
	if err != nil {
		t.Fatal(err)
	}
	automatic, err := service.Create(ctx, RequestInput{RequestID: "tir_auto_" + suffix, OperationID: "op_auto_" + suffix, SenderAccount: sender, SourceMachineID: source, DestinationMachineID: destination, BatchID: "fb_auto_" + suffix, Files: files, ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil || automatic.Status != "approved" {
		t.Fatalf("automatic=%+v err=%v", automatic, err)
	}
	policy, err = service.SetPolicy(ctx, recipient, Policy{Acceptance: "manual", ReceiptEmail: false}, policy.Generation)
	if err != nil {
		t.Fatal(err)
	}
	automatic, err = service.Get(ctx, recipient, automatic.RequestID)
	if err != nil || automatic.Status != "pending" {
		t.Fatalf("policy change did not invalidate automatic approval: %+v err=%v", automatic, err)
	}
	if _, err = service.Decide(ctx, recipient, automatic.RequestID, "approved", automatic.DecisionGeneration); err != nil {
		t.Fatal(err)
	}
	if _, err = service.Consume(ctx, sender, automatic.RequestID, automatic.ManifestDigest); err != nil {
		t.Fatal(err)
	}
	if _, err = service.Complete(ctx, recipient, automatic.RequestID, automatic.ManifestDigest); err != nil {
		t.Fatal(err)
	}
	var optedOutReceipts int
	if err = store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.team_inbox_receipt_outbox WHERE request_id=$1`, automatic.RequestID).Scan(&optedOutReceipts); err != nil || optedOutReceipts != 0 {
		t.Fatalf("opt-out receipts=%d err=%v", optedOutReceipts, err)
	}

	second, err := service.Create(ctx, RequestInput{RequestID: "tir_revoked_" + suffix, OperationID: "op_revoked_" + suffix, SenderAccount: sender, SourceMachineID: source, DestinationMachineID: destination, BatchID: "fb_revoked_" + suffix, Files: files, ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	second, err = service.Decide(ctx, recipient, second.RequestID, "approved", second.DecisionGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.Consume(ctx, sender, second.RequestID, second.ManifestDigest); err != nil {
		t.Fatal(err)
	}
	current, err = authority.GrantMachine(ctx, recipient, team, teams.MachineGrantRequest{OperationID: "revoke_" + suffix, ExpectedGeneration: current.Generation, MachineID: destination, Audience: "selected_member", AccountID: sender, Capabilities: []string{"files"}, Active: false})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.Consume(ctx, sender, second.RequestID, second.ManifestDigest); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked retry error=%v", err)
	}
	third, err := service.Create(ctx, RequestInput{RequestID: "tir_denied_" + suffix, OperationID: "op_denied_" + suffix, SenderAccount: sender, SourceMachineID: source, DestinationMachineID: destination, BatchID: "fb_denied_" + suffix, Files: files, ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if !errors.Is(err, ErrForbidden) || third.RequestID != "" {
		t.Fatalf("revoked create=%+v err=%v", third, err)
	}

	same, err := service.Create(ctx, RequestInput{RequestID: "tir_same_" + suffix, OperationID: "op_same_" + suffix, SenderAccount: sender, SourceMachineID: source, DestinationMachineID: ownDestination, BatchID: "fb_same_" + suffix, Files: files, ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil || same.Status != "not_required" {
		t.Fatalf("same-account request=%+v err=%v", same, err)
	}
}
