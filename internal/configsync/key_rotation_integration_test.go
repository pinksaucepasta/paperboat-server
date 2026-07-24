package configsync

import (
	"bytes"
	"context"
	"database/sql"
	"io"
	"os"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

func TestKeyRotationWaitsForOfflineCanonicalAssignment(t *testing.T) {
	store := openConfigSyncTestDB(t)
	ctx := context.Background()
	suffix := strings.NewReplacer("/", "_", " ", "_").Replace(t.Name())
	userID := "rotation_user_" + suffix
	repositoryID := "rotation_repo_" + suffix
	onlineEnvironment := "rotation_online_" + suffix
	offlineEnvironment := "rotation_offline_" + suffix
	seedRotationScope(t, store, userID, repositoryID, onlineEnvironment, offlineEnvironment)

	repository := NewRepository(store, config.ConfigSync{}, "rotation-test-encryption-key-32-bytes", audit.NewWriter(store))
	original, err := repository.EnsureAccountKey(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	oldCiphertext := encryptForRecipient(t, original.Recipient, []byte("old-key-overlap-proof"))

	rotated, err := repository.RotateAccountKey(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Version != original.Version+1 || !strings.Contains(rotated.Identity, original.Identity) {
		t.Fatalf("rotated key does not retain prior identity")
	}
	if got := decryptWithIdentities(t, rotated.Identity, oldCiphertext); got != "old-key-overlap-proof" {
		t.Fatalf("overlap decrypt = %q", got)
	}
	if _, err := repository.RotateAccountKey(ctx, userID); err != ErrRotationPending {
		t.Fatalf("second rotation error = %v, want ErrRotationPending", err)
	}

	setRotationStatus(t, store, onlineEnvironment, repositoryID, "rotation_assignment_online_"+suffix, "rotation_helper_online_"+suffix, int64(rotated.Version))
	if err := repository.RetireCompletedRotations(ctx); err != nil {
		t.Fatal(err)
	}
	assertPreviousKeyPresent(t, store, userID, true)

	setRotationStatus(t, store, offlineEnvironment, repositoryID, "rotation_assignment_offline_"+suffix, "rotation_helper_offline_"+suffix, int64(rotated.Version))
	if err := repository.RetireCompletedRotations(ctx); err != nil {
		t.Fatal(err)
	}
	assertPreviousKeyPresent(t, store, userID, false)
	current, err := repository.EnsureAccountKey(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(current.Identity, original.Identity) {
		t.Fatal("retired identity remains in the active key bundle")
	}
}

func seedRotationScope(t *testing.T, store *db.DB, userID, repositoryID, onlineEnvironment, offlineEnvironment string) {
	t.Helper()
	ctx := context.Background()
	t.Cleanup(func() {
		_, _ = store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.users WHERE id=$1`, userID)
	})
	if _, err := store.SQL().ExecContext(ctx, `
		INSERT INTO paperboat.users (id,workos_subject,primary_email,status)
		VALUES ($1,$2,$3,'active')
	`, userID, "workos_"+userID, userID+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `
		INSERT INTO paperboat.control_config_repositories
		  (id,owner_user_id,provider,external_ref,display_name,state)
		VALUES ($1,$2,'github',$1,'rotation test','active')
	`, repositoryID, userID); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		environmentID, assignmentID, helperID string
	}{
		{onlineEnvironment, "rotation_assignment_online_" + strings.TrimPrefix(onlineEnvironment, "rotation_online_"), "rotation_helper_online_" + strings.TrimPrefix(onlineEnvironment, "rotation_online_")},
		{offlineEnvironment, "rotation_assignment_offline_" + strings.TrimPrefix(offlineEnvironment, "rotation_offline_"), "rotation_helper_offline_" + strings.TrimPrefix(offlineEnvironment, "rotation_offline_")},
	} {
		if _, err := store.SQL().ExecContext(ctx, `
			INSERT INTO paperboat.control_environments
			  (id,workspace_id,owner_user_id,desired_state)
			VALUES ($1,$2,$3,'active')
		`, item.environmentID, "workspace_"+item.environmentID, userID); err != nil {
			t.Fatal(err)
		}
		if _, err := store.SQL().ExecContext(ctx, `
			INSERT INTO paperboat.control_helpers
			  (id,environment_id,state,generation)
			VALUES ($1,$2,'active',1)
		`, item.helperID, item.environmentID); err != nil {
			t.Fatal(err)
		}
		if _, err := store.SQL().ExecContext(ctx, `
			INSERT INTO paperboat.control_config_assignments
			  (id,environment_id,repository_id,consent_state,warning_revision,accepted_at)
			VALUES ($1,$2,$3,'accepted','warning-1',now())
		`, item.assignmentID, item.environmentID, repositoryID); err != nil {
			t.Fatal(err)
		}
	}
}

func setRotationStatus(t *testing.T, store *db.DB, environmentID, repositoryID, assignmentID, helperID string, keyVersion int64) {
	t.Helper()
	if _, err := store.SQL().ExecContext(context.Background(), `
		INSERT INTO paperboat.control_config_sync_statuses
		  (environment_id,repository_id,assignment_id,helper_id,helper_generation,
		   warning_revision,policy_revision,key_version,sync_revision,state,helper_updated_at)
		VALUES ($1,$2,$3,$4,1,'warning-1','policy-1',$5,1,'healthy',now())
		ON CONFLICT (environment_id) DO UPDATE
		SET assignment_id=EXCLUDED.assignment_id, helper_id=EXCLUDED.helper_id,
		    key_version=EXCLUDED.key_version, sync_revision=control_config_sync_statuses.sync_revision+1,
		    state='healthy', helper_updated_at=now()
	`, environmentID, repositoryID, assignmentID, helperID, keyVersion); err != nil {
		t.Fatal(err)
	}
}

func assertPreviousKeyPresent(t *testing.T, store *db.DB, userID string, want bool) {
	t.Helper()
	var previous sql.NullInt32
	if err := store.SQL().QueryRowContext(context.Background(), `
		SELECT previous_key_version FROM paperboat.account_config_keys WHERE user_id=$1
	`, userID).Scan(&previous); err != nil {
		t.Fatal(err)
	}
	if previous.Valid != want {
		t.Fatalf("previous key present = %t, want %t", previous.Valid, want)
	}
}

func encryptForRecipient(t *testing.T, recipientValue string, plaintext []byte) []byte {
	t.Helper()
	recipient, err := age.ParseX25519Recipient(recipientValue)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	writer, err := age.Encrypt(&output, recipient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func decryptWithIdentities(t *testing.T, identitiesValue string, ciphertext []byte) string {
	t.Helper()
	identities, err := age.ParseIdentities(strings.NewReader(identitiesValue))
	if err != nil {
		t.Fatal(err)
	}
	reader, err := age.Decrypt(bytes.NewReader(ciphertext), identities...)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return string(plaintext)
}

func openConfigSyncTestDB(t *testing.T) *db.DB {
	t.Helper()
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run config-sync PostgreSQL integration tests")
	}
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := db.Migrate(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	return store
}
