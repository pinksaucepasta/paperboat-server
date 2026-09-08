package environment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/teams"
)

func TestPostgresVaultScopesTeamRotationAndReconciliation(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_DATABASE_DSN"))
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN for isolated vault scope transactions")
	}
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(dsn), "_test") {
		t.Fatal("isolated test database required")
	}
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	// Fresh-schema setup crosses the remote database link for historical migrations;
	// it does not consume the bounded behavior scenario below.
	setup, setupCancel := context.WithTimeout(context.Background(), 5*time.Minute)
	err = db.Migrate(setup, store)
	setupCancel()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	suffix := strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	owner, member, team, machine := "vsowner_"+suffix, "vsmember_"+suffix, "vsteam_"+suffix, "vshost_"+suffix
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		// Only the validated isolated fixture database is eligible for audit cleanup.
		err := store.InTx(cleanup, func(ctx context.Context, tx *db.Tx) error {
			if _, err := tx.Exec(ctx, `ALTER TABLE audit_events DISABLE TRIGGER audit_events_append_only`); err != nil {
				return err
			}
			for _, q := range []string{`DELETE FROM audit_events WHERE actor_user_id IN($1,$2) AND resource_id=$3`, `DELETE FROM environment_vault_scopes WHERE owner_id IN($1,$2,$3)`, `DELETE FROM teams WHERE team_id=$3 AND owner_account IN($1,$2)`, `DELETE FROM users WHERE id IN($1,$2) AND $3<>''`} {
				if _, err := tx.Exec(ctx, q, owner, member, team); err != nil {
					return err
				}
			}
			_, err := tx.Exec(ctx, `ALTER TABLE audit_events ENABLE TRIGGER audit_events_append_only`)
			return err
		})
		if err != nil {
			t.Errorf("cleanup exact test fixtures: %v", err)
		}
	}()
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users(id,workos_subject,primary_email,status) VALUES($1,$1,$1||'@invalid.test','active'),($2,$2,$2||'@invalid.test','active')`, owner, member); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machines(id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,setup_mode,setup_roles) VALUES($1,$2,$3,'vault scopes','linux','amd64','/vault-test','online','released','host',ARRAY['host'])`, machine, owner, "env_"+suffix); err != nil {
		t.Fatal(err)
	}
	service := NewService(store, nil, nil, "https://control.example")
	first := passwordVaultFixture(t, "https://control.example", owner, 1, make([]byte, 32))
	memberRaw := passwordVaultFixture(t, "https://control.example", member, 1, make([]byte, 32))
	if _, err := service.PutPasswordVault(ctx, owner, first); err != nil {
		t.Fatal(err)
	}
	if _, err := service.PutPasswordVault(ctx, member, memberRaw); err != nil {
		t.Fatal(err)
	}
	writer, _ := ParsePasswordVaultMetadata(first, "https://control.example", owner)
	recipient, _ := ParsePasswordVaultMetadata(memberRaw, "https://control.example", member)
	firstDigest := sha256.Sum256(first)
	nextRaw := passwordVaultFixtureByte(t, "https://control.example", owner, 2, firstDigest[:], 9)
	next, _ := ParsePasswordVaultMetadata(nextRaw, "https://control.example", owner)
	scopeRaw := vaultScopeFixture(t, fixtureScopeHeader(team, "team", owner, 1, 1, 1, make([]byte, 32)), 11)
	create := VaultTeamCreate{OperationID: "create_" + suffix, TeamID: team, VaultEnvelope: b64Vault(nextRaw), ScopeEnvelope: b64Vault(scopeRaw)}
	create.GrantEnvelope = b64Vault(vaultGrantFixture(t, fixtureGrantClaims(team, create.OperationID, 1, 1, writer, next), 11))
	created, err := service.CreateVaultTeam(ctx, owner, create)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateVaultTeam(ctx, owner, create); err != nil {
		t.Fatal("exact initialize retry failed", err)
	}
	if created.Generation != 1 {
		t.Fatal("new team generation", created.Generation)
	}
	if _, err := service.GetVaultScope(ctx, member, "team", team, ""); !errors.Is(err, ErrKeyAuthorizationRequired) {
		t.Fatal("ungranted account read team", err)
	}
	authority := teams.NewService(store)
	invitation, err := authority.Invite(ctx, owner, team, teams.InviteRequest{OperationID: "invite_" + suffix, ExpectedGeneration: 1, AccountID: member})
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := authority.Accept(ctx, member, invitation.InvitationID, teams.AcceptRequest{OperationID: "accept_" + suffix})
	if err != nil {
		t.Fatal(err)
	}
	permitted, err := authority.Grant(ctx, owner, team, teams.GrantRequest{OperationID: "permission_" + suffix, ExpectedGeneration: accepted.Generation, AccountID: member, ResourceKind: "env", ResourceID: team, Permission: "read", Active: true})
	if err != nil {
		t.Fatal(err)
	}
	grant := VaultMemberGrant{OperationID: "grant_" + suffix, AccountID: member, ExpectedTeamGeneration: permitted.Generation, ExpectedMembershipGeneration: 1}
	grant.GrantEnvelope = b64Vault(vaultGrantFixture(t, fixtureGrantClaims(team, grant.OperationID, 1, 1, next, recipient), 11))
	granted, err := service.GrantVaultTeamMember(ctx, owner, team, grant)
	if err != nil {
		t.Fatal(err)
	}
	if granted.Generation != permitted.Generation+1 {
		t.Fatal("membership generation did not commit")
	}
	// Older snapshots must not resurrect stale authority after a later team mutation.
	if _, err := service.CreateVaultTeam(ctx, owner, create); !errors.Is(err, ErrVersionConflict) {
		t.Fatal("stale initialization replay accepted", err)
	}
	inbox, err := service.ListVaultGrants(ctx, member)
	if err != nil || len(inbox) != 1 {
		t.Fatal("missing individual grant", err)
	}
	if _, err := service.GetVaultScope(ctx, member, "team", team, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := service.PutVaultScope(ctx, member, "team", team, "", VaultScopePut{OperationID: "denied_write_" + suffix, Envelope: b64Vault(scopeRaw)}); !errors.Is(err, ErrKeyAuthorizationRequired) {
		t.Fatal("read-only member wrote scope", err)
	}
	deniedGrant := grant
	deniedGrant.OperationID = "denied_grant_" + suffix
	deniedGrant.ExpectedTeamGeneration = granted.Generation
	if _, err := service.GrantVaultTeamMember(ctx, member, team, deniedGrant); !errors.Is(err, ErrKeyAuthorizationRequired) {
		t.Fatal("member regranted key", err)
	}
	if _, err := service.RotateVaultTeam(ctx, member, team, VaultTeamRotate{OperationID: "denied_rotate_" + suffix, ExpectedTeamGeneration: granted.Generation, RemoveAccountIDs: []string{}, GrantEnvelopes: []string{}, ScopeEnvelope: b64Vault(scopeRaw)}); !errors.Is(err, ErrKeyAuthorizationRequired) {
		t.Fatal("member rotated key", err)
	}
	writable, err := authority.Grant(ctx, owner, team, teams.GrantRequest{OperationID: "write_permission_" + suffix, ExpectedGeneration: granted.Generation, AccountID: member, ResourceKind: "env", ResourceID: team, Permission: "write", Active: true})
	if err != nil {
		t.Fatal(err)
	}
	initialDigest := sha256.Sum256(scopeRaw)
	memberScope := vaultScopeFixture(t, fixtureScopeHeader(team, "team", member, 1, 1, 2, initialDigest[:]), 11)
	if _, err := service.PutVaultScope(ctx, member, "team", team, "", VaultScopePut{OperationID: "member_write_" + suffix, Envelope: b64Vault(memberScope)}); err != nil {
		t.Fatal("explicit write-granted member denied", err)
	}
	scopeRaw = memberScope
	granted.Generation = writable.Generation
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.environment_vault_projection_sources(machine_id,owner_kind,owner_id) VALUES($1,'team',$2)`, machine, team); err != nil {
		t.Fatal(err)
	}
	if err := store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error { return RequirePersonalRotationTx(ctx, tx, member) }); err != nil {
		t.Fatal(err)
	}
	memberInventory, err := service.GetVaultPersonalScopes(ctx, member)
	if err != nil || !memberInventory.RotationRequired {
		t.Fatal("device revocation omitted personal fence", err)
	}
	fencedTeam, err := service.GetVaultTeam(ctx, owner, team)
	if err != nil || !fencedTeam.RotationRequired || fencedTeam.Generation != granted.Generation+1 {
		t.Fatal("device revocation omitted team fence", err)
	}
	if _, err := service.PutVaultScope(ctx, owner, "team", team, "", VaultScopePut{OperationID: "blocked_" + suffix, Envelope: b64Vault(scopeRaw)}); !errors.Is(err, ErrVaultRotationRequired) {
		t.Fatal("unrotated team write accepted", err)
	}
	removedTeam, err := authority.Mutate(ctx, owner, team, teams.MutationRequest{OperationID: "remove_before_rekey_" + suffix, ExpectedGeneration: fencedTeam.Generation, Action: "remove", AccountID: member})
	if err != nil {
		t.Fatal("shared membership removal failed", err)
	}
	fencedTeam, err = service.GetVaultTeam(ctx, owner, team)
	if err != nil || !fencedTeam.RotationRequired || fencedTeam.Generation != removedTeam.Generation {
		t.Fatal("shared removal lost pending rekey", err)
	}
	nextDigest := sha256.Sum256(nextRaw)
	thirdRaw := passwordVaultFixtureByte(t, "https://control.example", owner, 3, nextDigest[:], 10)
	third, _ := ParsePasswordVaultMetadata(thirdRaw, "https://control.example", owner)
	scopeDigest := sha256.Sum256(scopeRaw)
	rotatedRaw := vaultScopeFixture(t, fixtureScopeHeader(team, "team", owner, 2, 2, 3, scopeDigest[:]), 11)
	rotation := VaultTeamRotate{OperationID: "rotate_" + suffix, ExpectedTeamGeneration: fencedTeam.Generation, RemoveAccountIDs: []string{member}, ScopeEnvelope: b64Vault(rotatedRaw), VaultEnvelope: b64Vault(thirdRaw), GrantEnvelopes: []string{}}
	if _, err := service.RotateVaultTeam(ctx, owner, team, rotation); !errors.Is(err, ErrPrecondition) {
		t.Fatal("missing exact recipient set accepted", err)
	}
	head, err := service.GetPasswordVault(ctx, owner)
	if err != nil || head.Generation != 2 {
		t.Fatal("failed rotation advanced vault", err)
	}
	rotation.GrantEnvelopes = []string{b64Vault(vaultGrantFixture(t, fixtureGrantClaims(team, rotation.OperationID, 2, 1, next, third), 11))}
	rotated, err := service.RotateVaultTeam(ctx, owner, team, rotation)
	if err != nil || rotated.KeyEpoch != 2 {
		t.Fatal("rotation failed", err)
	}
	head, err = service.GetPasswordVault(ctx, owner)
	if err != nil || head.Generation != 3 {
		t.Fatal("rotation omitted key custody", err)
	}
	if _, err := service.GetVaultScope(ctx, member, "team", team, ""); !errors.Is(err, ErrKeyAuthorizationRequired) {
		t.Fatal("removed member read new scope", err)
	}
	if _, err := service.GrantVaultTeamMember(ctx, owner, team, grant); !errors.Is(err, ErrKeyAuthorizationRequired) {
		t.Fatal("removed member regrant replay accepted", err)
	}
	inbox, err = service.ListVaultGrants(ctx, member)
	if err != nil || len(inbox) != 0 {
		t.Fatal("removed member received grant", err)
	}
	var fence uint64
	if err := store.SQL().QueryRowContext(ctx, `SELECT generation FROM paperboat.environment_vault_projection_fences WHERE machine_id=$1`, machine).Scan(&fence); err != nil || fence != 3 {
		t.Fatalf("projection fence=%d, want revocation + member removal + ciphertext commit (3): %v", fence, err)
	}
	removedMember, ok := vaultMember(rotated, member)
	if !ok || removedMember.Active || removedMember.MembershipGeneration != 2 {
		t.Fatal("rekey repeated membership removal")
	}
	if _, err := service.RotateVaultTeam(ctx, owner, team, rotation); err != nil {
		t.Fatal("exact rotation retry failed", err)
	}
	rotation.RemoveAccountIDs = []string{}
	if _, err := service.RotateVaultTeam(ctx, owner, team, rotation); !errors.Is(err, ErrOperationConflict) {
		t.Fatal("operation substitution accepted", err)
	}

	// Existing machine installations may initialize ENV custody for the first
	// time after installation generation one; machine-control auth binds that
	// exact installation, independently of ENV recipient generation numbering.
	laterMachine := "vslater_" + suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machines(id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,setup_mode,setup_roles,installation_generation) VALUES($1,$2,$3,'later vault','linux','amd64','/vault-test','online','released','host',ARRAY['host'],3)`, laterMachine, owner, "later_env_"+suffix); err != nil {
		t.Fatal(err)
	}
	laterRequest := VaultHostKeyRequest{OperationID: "later_host_" + suffix, InstallationGeneration: 3, HostKeyGeneration: 3, HostPublic: b64Vault(bytes.Repeat([]byte{75}, 32))}
	if later, err := service.RegisterVaultHostKey(ctx, owner, laterMachine, laterRequest); err != nil || later.InstallationGeneration != 3 || later.HostKeyGeneration != 3 {
		t.Fatal("later installation could not initialize ENV", err)
	}
	laterRequest.InstallationGeneration = 2
	if _, err := service.RegisterVaultHostKey(ctx, owner, laterMachine, laterRequest); !errors.Is(err, ErrVersionConflict) {
		t.Fatal("wrong installation registered ENV recipient", err)
	}

	hostPublic := bytes.Repeat([]byte{74}, 32)
	hostRequest := VaultHostKeyRequest{OperationID: "hostkey_" + suffix, InstallationGeneration: 1, HostKeyGeneration: 1, HostPublic: b64Vault(hostPublic)}
	binding, err := service.RegisterVaultHostKey(ctx, owner, machine, hostRequest)
	if err != nil || binding.State != "pending" {
		t.Fatal("authenticated host key registration failed", err)
	}
	pc := vaultProjectionClaims{Domain: "paperboat.environment.host-projection", Version: 1, Issuer: "https://control.example", OwnerAccount: owner, MachineID: machine, InstallationGeneration: 1, HostKeyGeneration: 1, HostPublic: hostPublic, SelectionGeneration: 1, Revision: 1, Previous: make([]byte, 32), Sources: []vaultProjectionSource{}, WriterVaultGeneration: 3, WriterPublic: third.WriterPublicKey[:]}
	projectionRaw := vaultProjectionFixture(t, pc, 11)
	provision := VaultHostProvision{OperationID: "provision_" + suffix, Selection: []VaultHostSelection{}, Envelope: b64Vault(projectionRaw)}
	provisioned, err := service.ProvisionVaultHost(ctx, owner, machine, provision)
	if err != nil || provisioned.State != "ready" {
		t.Fatal("explicit empty projection failed", err)
	}
	observation := VaultProjectionObservation{Schema: VaultProjectionObservationSchema, ObservationSeq: 1, HostRecipientKeyID: vaultHostKeyID(hostPublic), Projection: &VaultProjectionCursor{Revision: 1, DocumentID: provisioned.DocumentID}, FenceGeneration: provisioned.FenceGeneration, State: "applied", ObservedAt: time.Now().UTC()}
	if _, err := service.RecordVaultProjectionObservation(ctx, "env_"+suffix, machine, &observation); err != nil {
		t.Fatal("valid projection observation rejected", err)
	}
	// Personal writes use one account epoch and concurrent successors have one winner.
	personalRaw := vaultScopeFixture(t, fixtureScopeHeader(owner, "personal", owner, 3, 1, 1, make([]byte, 32)), 11)
	personal, err := service.PutVaultScope(ctx, owner, "personal", owner, "", VaultScopePut{OperationID: "personal_" + suffix, Envelope: b64Vault(personalRaw)})
	if err != nil {
		t.Fatal(err)
	}
	pd := sha256.Sum256(personalRaw)
	successor := vaultScopeFixture(t, fixtureScopeHeader(owner, "personal", owner, 3, 1, 2, pd[:]), 11)
	results := make(chan error, 2)
	start := make(chan struct{})
	for _, op := range []string{"race_a_", "race_b_"} {
		go func(op string) {
			<-start
			_, err := service.PutVaultScope(ctx, owner, "personal", owner, "", VaultScopePut{OperationID: op + suffix, Envelope: b64Vault(successor)})
			results <- err
		}(op)
	}
	close(start)
	wins, conflicts := 0, 0
	for range 2 {
		err := <-results
		if err == nil {
			wins++
		} else if errors.Is(err, ErrVersionConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if wins != 1 || conflicts != 1 {
		t.Fatal("concurrent scope CAS failed")
	}
	inventory, err := service.GetVaultPersonalScopes(ctx, owner)
	if err != nil || inventory.KeyEpoch != 1 || len(inventory.Scopes) != 1 {
		t.Fatal("personal inventory invalid", err)
	}
	personal = inventory.Scopes[0]
	// Explicit total loss starts a fresh writer, sharing identity and personal epoch.
	thirdDigest := sha256.Sum256(thirdRaw)
	resetRaw := passwordVaultFixtureWith(t, "https://control.example", owner, 4, thirdDigest[:], vaultFixtureOptions{writerSeedByte: 12, passwordEpoch: 2, recoveryEpoch: 2})
	var resetEnvelope passwordVaultEnvelope
	var resetBody passwordVaultBody
	var resetHeader passwordVaultHeader
	_ = strictDecoding.Unmarshal(resetRaw, &resetEnvelope)
	_ = strictDecoding.Unmarshal(resetEnvelope.UnsignedBody, &resetBody)
	_ = strictDecoding.Unmarshal(resetBody.Header, &resetHeader)
	resetHeader.SharingPublic = bytes.Repeat([]byte{73}, 32)
	resetBody.Header, _ = EncodeCanonical(resetHeader)
	resetEnvelope.UnsignedBody, _ = EncodeCanonical(resetBody)
	message, _ := EncodeCanonical([]any{"paperboat.environment.vault-signature", uint64(1), resetEnvelope.UnsignedBody})
	resetEnvelope.Signature = ed25519.Sign(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{12}, 32)), message)
	resetRaw, _ = EncodeCanonical(resetEnvelope)
	successorDigest := sha256.Sum256(successor)
	replacement := vaultScopeFixture(t, fixtureScopeHeader(owner, "personal", owner, 4, 2, personal.Revision+1, successorDigest[:]), 12)
	reset := VaultPersonalReset{OperationID: "reset_" + suffix, ExpectedVaultDocumentID: third.Head.DocumentID, VaultEnvelope: b64Vault(resetRaw), ScopeEnvelopes: []string{}, ConfirmTotalLoss: true}
	if _, err := service.ResetPersonalVault(ctx, owner, reset); !errors.Is(err, ErrPrecondition) {
		t.Fatal("incomplete reset accepted", err)
	}
	reset.ScopeEnvelopes = []string{b64Vault(replacement)}
	if _, err := service.ResetPersonalVault(ctx, owner, reset); err != nil {
		t.Fatal(err)
	}
	inventory, err = service.GetVaultPersonalScopes(ctx, owner)
	if err != nil || inventory.KeyEpoch != 2 || inventory.Scopes[0].KeyEpoch != 2 {
		t.Fatal("reset failed to advance personal epoch", err)
	}
	if _, err := service.ResetPersonalVault(ctx, owner, reset); err != nil {
		t.Fatal("reset exact retry failed", err)
	}
	currentTeam, err := service.GetVaultTeam(ctx, owner, team)
	if err != nil || currentTeam.Scope.WriterPublic != "" || currentTeam.Scope.Envelope != "" {
		t.Fatal("reset account retained ungranted ciphertext access", err)
	}
	var storedSigner []byte
	if err := store.SQL().QueryRowContext(ctx, `SELECT writer_public FROM paperboat.environment_vault_scopes WHERE owner_kind='team' AND owner_id=$1`, team).Scan(&storedSigner); err != nil || b64Vault(storedSigner) != rotated.Scope.WriterPublic {
		t.Fatal("reset replaced historical committed team signer", err)
	}
	if _, err := service.GetVaultScope(ctx, owner, "team", team, ""); !errors.Is(err, ErrKeyAuthorizationRequired) {
		t.Fatal("reset silently restored team keys", err)
	}

	if _, err := service.CreateVaultTeam(ctx, owner, create); !errors.Is(err, ErrKeyAuthorizationRequired) {
		t.Fatal("reset owner initialization replay exposed ciphertext", err)
	}
	// Old applied reports must receive the reset fence, not loop on a rejected heartbeat.
	observation.ObservationSeq++
	observation.ObservedAt = time.Now().UTC()
	pendingBundle, err := service.RecordVaultProjectionObservation(ctx, "env_"+suffix, machine, &observation)
	if err != nil || pendingBundle.State != "pending" || pendingBundle.FenceGeneration <= provisioned.FenceGeneration {
		t.Fatal("reset did not deliver pending fence", err)
	}
	sameBinding, err := service.RegisterVaultHostKey(ctx, owner, machine, hostRequest)
	if err != nil || sameBinding.WriterPublic != binding.WriterPublic {
		t.Fatal("reset silently changed pinned host writer", err)
	}
	resetMetadata, err := ParsePasswordVaultMetadata(resetRaw, "https://control.example", owner)
	if err != nil {
		t.Fatal(err)
	}
	projectionDigest := sha256.Sum256(projectionRaw)
	pc.SelectionGeneration = 2
	pc.Revision = 2
	pc.Previous = projectionDigest[:]
	pc.WriterVaultGeneration = 4
	pc.WriterPublic = resetMetadata.WriterPublicKey[:]
	reprovision := VaultHostProvision{OperationID: "reprovision_" + suffix, ExpectedSelectionGeneration: 1, Selection: []VaultHostSelection{}, Envelope: b64Vault(vaultProjectionFixture(t, pc, 12))}
	reprovisioned, err := service.ProvisionVaultHost(ctx, owner, machine, reprovision)
	if err != nil || reprovisioned.State != "ready" || reprovisioned.WriterPublic == binding.WriterPublic {
		t.Fatal("explicit reset reprovision failed", err)
	}
	overrideHeader := fixtureScopeHeader(owner, "personal", owner, 4, 2, 1, make([]byte, 32))
	overrideHeader.MachineID = machine
	if _, err := service.PutVaultScope(ctx, owner, "personal", owner, machine, VaultScopePut{OperationID: "override_" + suffix, Envelope: b64Vault(vaultScopeFixture(t, overrideHeader, 12))}); err != nil {
		t.Fatal(err)
	}
	finalHost, err := service.GetVaultHost(ctx, owner, machine)
	if err != nil || finalHost.Bundle.State != "pending" {
		t.Fatal("first machine override did not invalidate projection", err)
	}

	// Staged personal rotation retains usable committed ciphertext until all scopes
	// and the replacement vault can commit together.
	if err := store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error { return RequirePersonalRotationTx(ctx, tx, owner) }); err != nil {
		t.Fatal(err)
	}
	rotationInventory, err := service.GetVaultPersonalScopes(ctx, owner)
	if err != nil || !rotationInventory.RotationRequired || len(rotationInventory.Scopes) != 2 {
		t.Fatal("rotation inventory invalid", err)
	}
	resetDigest := sha256.Sum256(resetRaw)
	resetHeader.Generation = 5
	resetHeader.Previous = resetDigest[:]
	resetBody.Header, _ = EncodeCanonical(resetHeader)
	resetBody.Ciphertext = bytes.Repeat([]byte{19}, 17)
	resetEnvelope.UnsignedBody, _ = EncodeCanonical(resetBody)
	message, _ = EncodeCanonical([]any{"paperboat.environment.vault-signature", uint64(1), resetEnvelope.UnsignedBody})
	resetEnvelope.Signature = ed25519.Sign(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{12}, 32)), message)
	fifthRaw, _ := EncodeCanonical(resetEnvelope)
	rotatePersonal := VaultPersonalRotate{OperationID: "personalrotate_" + suffix, ExpectedVaultDocumentID: resetMetadata.Head.DocumentID, VaultEnvelope: b64Vault(fifthRaw), ScopeDocuments: []VaultScopeDocument{}}
	for _, old := range rotationInventory.Scopes {
		oldDigest, err := hex.DecodeString(strings.TrimPrefix(old.DocumentID, "sha256:"))
		if err != nil {
			t.Fatal(err)
		}
		header := fixtureScopeHeader(owner, "personal", owner, 5, 3, old.Revision+1, oldDigest)
		header.MachineID = old.MachineID
		encoded := b64Vault(vaultScopeFixture(t, header, 12))
		stage := VaultPersonalScopeStage{ExpectedVaultDocumentID: rotatePersonal.ExpectedVaultDocumentID, MachineID: old.MachineID, Envelope: encoded}
		document, err := service.StagePersonalVaultScope(ctx, owner, rotatePersonal.OperationID, stage)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.StagePersonalVaultScope(ctx, owner, rotatePersonal.OperationID, stage); err != nil {
			t.Fatal("stage retry failed", err)
		}
		rotatePersonal.ScopeDocuments = append(rotatePersonal.ScopeDocuments, document)
	}
	partial := rotatePersonal
	partial.ScopeDocuments = partial.ScopeDocuments[:1]
	if _, err := service.RotatePersonalVault(ctx, owner, partial); !errors.Is(err, ErrPrecondition) {
		t.Fatal("incomplete staged rotation accepted", err)
	}
	rotatedHead, err := service.RotatePersonalVault(ctx, owner, rotatePersonal)
	if err != nil || rotatedHead.Generation != 5 {
		t.Fatal("staged rotation failed", err)
	}
	if _, err := service.RotatePersonalVault(ctx, owner, rotatePersonal); err != nil {
		t.Fatal("committed staged retry failed", err)
	}
	rotationInventory, err = service.GetVaultPersonalScopes(ctx, owner)
	if err != nil || rotationInventory.RotationRequired || rotationInventory.KeyEpoch != 3 {
		t.Fatal("rotation did not release personal fence", err)
	}
	var stagedCount int
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.environment_vault_personal_rotation_scopes WHERE account_id=$1`, owner).Scan(&stagedCount); err != nil || stagedCount != 0 {
		t.Fatal("rotation leaked staging", err)
	}

}
