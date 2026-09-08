package peersessions

import (
	"context"
	"testing"

	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

// A newly granted resource must refresh configuration without withdrawing the
// previously issued, narrower authority. Actual withdrawal still fences both
// sides, including when an access lease is shortened.
func exerciseAdditiveAccessRelayAuthority(t *testing.T, store *db.DB, account, cli string) {
	t.Helper()
	ctx := context.Background()
	tx, err := store.SQL().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var machine, original string
	if err := tx.QueryRowContext(ctx, `SELECT id,user_machine_id FROM paperboat.user_machine_access_sessions WHERE user_id=$1 AND cli_client_session_id=$2 AND state='active' LIMIT 1`, account, cli).Scan(&original, &machine); err != nil {
		t.Fatal(err)
	}
	read := func() [4]int64 {
		t.Helper()
		var values [4]int64
		for i, endpoint := range []string{cli, machine} {
			if err := tx.QueryRowContext(ctx, `SELECT config_generation,relay_revocation_generation FROM paperboat.peer_network_identities WHERE user_id=$1 AND endpoint_id=$2`, account, endpoint).Scan(&values[2*i], &values[2*i+1]); err != nil {
				t.Fatal(err)
			}
		}
		return values
	}
	before := read()
	for _, suffix := range []string{"_new_file", "_resume_file"} {
		id := original + suffix
		if _, err := tx.ExecContext(ctx, `INSERT INTO paperboat.user_machine_access_sessions(id,user_machine_id,user_id,environment_id,cli_client_session_id,http_base_url,helper_file_session_id,expires_at) SELECT $2,user_machine_id,user_id,environment_id,cli_client_session_id,http_base_url,$2,expires_at FROM paperboat.user_machine_access_sessions WHERE id=$1`, original, id); err != nil {
			t.Fatal(err)
		}
		after := read()
		for i := range 2 {
			if after[2*i] != before[2*i]+1 || after[2*i+1] != before[2*i+1] {
				t.Fatalf("additive access revoked existing endpoint %d authority: before=%v after=%v", i, before, after)
			}
		}
		before = after
	}
	for _, change := range []string{"expires_at=expires_at-interval '1 second'", "state='revoked',revoked_at=now(),revocation_reason='test'"} {
		if _, err := tx.ExecContext(ctx, "UPDATE paperboat.user_machine_access_sessions SET "+change+" WHERE id=$1", original+"_new_file"); err != nil {
			t.Fatal(err)
		}
		after := read()
		for i := range 2 {
			if after[2*i] != before[2*i]+1 || after[2*i+1] != after[2*i] || after[2*i+1] <= before[2*i+1] {
				t.Fatalf("access withdrawal did not fence endpoint %d: before=%v after=%v", i, before, after)
			}
		}
		before = after
	}
}
