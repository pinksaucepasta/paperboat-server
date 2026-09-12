package httpapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/github"
	"github.com/pinksaucepasta/paperboat-server/internal/mint"
	"github.com/pinksaucepasta/paperboat-server/internal/secrets"
)

// Two synthetic PB accounts use one explicitly authorized provider principal.
// Only credential provisioning is a fixture: identity/repository discovery and
// directional access issuance call GitHub through its production client/service.
func task44ConfigProvider(t *testing.T, ctx context.Context, store *db.DB, cfg config.Config, assignments *controlplane.ConfigAssignmentService, actors ...string) *github.Service {
	t.Helper()
	token := os.Getenv("PAPERBOAT_TASK44_GITHUB_TOKEN")
	external := os.Getenv("PAPERBOAT_TASK44_GITHUB_REPOSITORY_ID")
	if token == "" || external == "" {
		t.Fatal("real private config repository and provider credential are required")
	}
	if _, err := strconv.ParseInt(external, 10, 64); err != nil {
		t.Fatal("numeric GitHub repository ID required")
	}
	cfg.Secrets.EncryptionKey = "task44-isolated-encryption-key"
	client := github.HTTPClient{BaseURL: "https://api.github.com", Client: &http.Client{Timeout: 15 * time.Second}}
	user, err := client.CurrentUser(ctx, token)
	if err != nil || user.Login == "" {
		t.Fatal("real GitHub principal verification failed")
	}
	encrypted, err := secrets.Encrypt(cfg.Secrets.EncryptionKey, token)
	if err != nil {
		t.Fatal("fixture credential encryption failed")
	}
	defer clear(encrypted)
	for _, actor := range actors {
		if err := store.Queries().UpsertGitHubOAuthToken(ctx, dbsqlc.UpsertGitHubOAuthTokenParams{ID: "task44_github_" + actor, UserID: actor, TokenCiphertext: encrypted, Scopes: []string{"repo", "read:org", "gist", "workflow", "delete_repo"}, ProviderAccountLogin: user.Login}); err != nil {
			t.Fatal("encrypted provider fixture provisioning failed")
		}
	}
	service := github.NewService(store, audit.NewWriter(store), client, cfg)
	assignments.SetRepositoryResolver(controlplane.ConfigRepositoryResolverFunc(func(ctx context.Context, actor, provider, id string) (controlplane.ConfigRepositoryConnection, error) {
		if provider != "github" || id != external {
			return controlplane.ConfigRepositoryConnection{}, controlplane.ErrAssignmentForbidden
		}
		repository, account, err := service.ResolvePrivateRepository(ctx, actor, id)
		if err != nil {
			return controlplane.ConfigRepositoryConnection{}, err
		}
		return controlplane.ConfigRepositoryConnection{ProviderAccountID: account, ExternalRepositoryID: repository.ID, DisplayName: repository.Owner + "/" + repository.Name, CloneURL: repository.CloneURL, PublishURL: repository.CloneURL, DefaultBranch: repository.DefaultBranch, AuthorizationRef: "github-user:" + actor, CredentialCapability: "provider_user_repository"}, nil
	}))
	return service
}

func task44QualifyConfigWorker(t *testing.T, ctx context.Context, store *db.DB, cfg config.Config, signer *mint.Provider, enrollment *controlplane.EnrollmentService, assignments *controlplane.ConfigAssignmentService, provider *github.Service, member, machine, environment, repository, team string, defaultVersion int64, action func(string, string, map[string]string)) {
	t.Helper()
	writer := audit.NewWriter(store)
	const issuer = "https://task44.invalid"
	const encryptionKey = "task44-isolated-encryption-key"
	// Preserve production scheduling policy; explicit stop/start drives each
	// approved assignment transition without a synthetic synchronization loop.
	policy := cfg.ConfigSync
	policy.Mode = "leased_writes"
	policy.BYODEnabled = true
	policy.WarningRevision = "task44"
	credentials := controlplane.NewConfigCredentialService(store, signer, issuer, encryptionKey)
	credentials.SetAuditWriter(writer)
	credentials.SetWarningRevision(policy.WarningRevision)
	credentials.SetRollout(policy.Mode, true, []string{environment})
	leases := controlplane.NewConfigLeaseService(store, writer)
	leases.ConfigureAuthentication(enrollment, signer, issuer, policy.WarningRevision)
	leases.ConfigureRollout(policy.Mode, true, []string{environment})
	statuses := controlplane.NewConfigStatusService(store, enrollment, writer, policy.SummaryLimit)
	statuses.SetAccountPolicy(policy)
	access := controlplane.NewConfigRepositoryAccessService(store, leases, controlplane.ConfigRepositoryAccessIssuerFuncs{Issue: func(ctx context.Context, actor, id, permission string) (controlplane.ScopedRepositoryCredential, error) {
		issued, err := provider.IssueUserRepositoryAccess(ctx, actor, id, permission)
		return controlplane.ScopedRepositoryCredential{Token: issued.Token, ExpiresAt: issued.ExpiresAt}, err
	}}, encryptionKey, writer)
	conflicts := controlplane.NewConfigConflictService(store, leases, writer)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/config/credentials", configCredentialIssue(credentials))
	mux.HandleFunc("POST /v1/config/runtime", configRuntimeGet(controlplane.NewConfigRuntimeService(store, leases, policy)))
	mux.HandleFunc("POST /v1/config/repository-access", configRepositoryAccessIssue(access))
	mux.HandleFunc("POST /v1/config/leases/acquire", configLeaseAcquire(leases))
	mux.HandleFunc("POST /v1/config/leases/renew", configLeaseRenew(leases))
	mux.HandleFunc("POST /v1/config/leases/release", configLeaseRelease(leases))
	mux.HandleFunc("POST /v1/config/status", configStatusRecord(statuses, slog.New(slog.NewTextHandler(io.Discard, nil))))
	mux.HandleFunc("POST /v1/config/conflict-resolutions/pending", configConflictPending(conflicts))
	mux.HandleFunc("POST /v1/config/conflict-resolutions/acknowledge", configConflictAcknowledge(conflicts))
	endpoint := httptest.NewTLSServer(mux)
	defer endpoint.Close()
	grant, err := enrollment.Issue(ctx, member, "task44-config-enrollment", environment, 5*time.Minute)
	if err != nil {
		t.Fatal("member config enrollment failed")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	identity, err := enrollment.Exchange(ctx, grant.Credential, public)
	if err != nil || identity.MachineID != machine {
		t.Fatal("member config identity binding failed")
	}
	start := map[string]string{"config_endpoint": endpoint.URL, "config_ca_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: endpoint.Certificate().Raw})), "config_environment_id": environment, "config_machine_id": machine, "config_identity_token": identity.Credential, "config_proof_private_key_base64": base64.RawURLEncoding.EncodeToString(private), "config_proof_helper_id": identity.HelperID, "config_installation_generation": "1", "config_home_relative_path": "task44-config.txt"}
	if binary := os.Getenv("PAPERBOAT_TASK44_CHEZMOI_BIN"); binary != "" {
		start["chezmoi_binary"] = binary
	}
	assignment, err := assignments.Assignment(ctx, member, machine)
	if err != nil || assignment.AdoptedTeamID.String != team {
		t.Fatal("member adopted config assignment missing")
	}
	if assignment.ConsentState == "pending" {
		assignment, err = assignments.AcceptConsent(ctx, member, machine, "task44", assignment.Version)
		if err != nil {
			t.Fatal("member config consent failed")
		}
	}
	waitStatus := func(label string, match func(controlplane.ConfigAccountEnvironment) bool) controlplane.ConfigAccountEnvironment {
		t.Helper()
		deadline, done := context.WithTimeout(ctx, 60*time.Second)
		defer done()
		tick := time.NewTicker(200 * time.Millisecond)
		defer tick.Stop()
		var last controlplane.ConfigAccountEnvironment
		for {
			account, err := statuses.Account(deadline, member)
			if err != nil {
				if deadline.Err() != nil {
					t.Fatalf("config %s not observed: state=%s mode=%s reviewed=%d applied=%t published=%t", label, last.State, last.Mode, len(last.Review), last.LastAppliedRevision != "", last.LastPublishedRevision != "")
				}
				t.Fatal("real config status query failed")
			}
			for _, item := range account.Environments {
				if item.MachineID == machine {
					last = item
					if match(item) {
						return item
					}
				}
			}
			select {
			case <-deadline.Done():
				t.Fatalf("config %s not observed: state=%s mode=%s reviewed=%d applied=%t published=%t", label, last.State, last.Mode, len(last.Review), last.LastAppliedRevision != "", last.LastPublishedRevision != "")
			case <-tick.C:
			}
		}
	}
	action("config-pull-start", "config_start", start)
	reviewed := waitStatus("review", func(item controlplane.ConfigAccountEnvironment) bool {
		return len(item.Review) > 0 && item.RemoteRevision != "" && item.LastAppliedRevision == ""
	})
	action("config-before-approval-absent", "config_expect_absent", map[string]string{"config_home_relative_path": "task44-config.txt"})
	action("config-review-stop", "config_stop", map[string]string{"expected_error": "review_required"})
	assignment, err = assignments.Assignment(ctx, member, machine)
	if err != nil {
		t.Fatal(err)
	}
	assignment, err = assignments.ApprovePullRevision(ctx, member, machine, reviewed.RemoteRevision, assignment.Version)
	if err != nil {
		t.Fatal("exact reviewed config revision approval failed")
	}
	action("config-approved-start", "config_start", start)
	waitStatus("approved pull", func(item controlplane.ConfigAccountEnvironment) bool {
		return item.LastAppliedRevision == reviewed.RemoteRevision
	})
	action("config-pull-bytes", "config_expect", map[string]string{"config_home_relative_path": "task44-config.txt", "content": "task44-config-initial\n"})
	action("config-pull-stop", "config_stop", nil)
	assignment, err = assignments.Assignment(ctx, member, machine)
	if err != nil {
		t.Fatal(err)
	}
	assignment, err = assignments.AssignTargets(ctx, member, machine, "", repository, controlplane.ConfigModePushOnly, false, "task44", assignment.Version)
	if err != nil {
		t.Fatal("explicit personal pull/push assignment failed")
	}
	if assignment.ConsentState == "pending" {
		assignment, err = assignments.AcceptConsent(ctx, member, machine, "task44", assignment.Version)
		if err != nil {
			t.Fatal("personal config consent failed")
		}
	}
	action("config-personal-start", "config_start", start)
	waitStatus("personal push baseline", func(item controlplane.ConfigAccountEnvironment) bool {
		return item.Mode == controlplane.ConfigModePushOnly && item.State == "healthy"
	})
	action("config-personal-edit", "config_edit", map[string]string{"config_home_relative_path": "task44-config.txt", "content": "task44-config-updated\n"})
	// The production bounded shutdown flush publishes this intentional edit
	// without shortening the normal minimum push interval.
	action("config-push-stop", "config_stop", nil)
	published := waitStatus("provider publication", func(item controlplane.ConfigAccountEnvironment) bool {
		return item.Mode == controlplane.ConfigModePushOnly && item.LastPublishedRevision != "" && item.LastPublishedRevision != reviewed.RemoteRevision
	})
	if len(published.LastPublishedRevision) != 40 {
		t.Fatal("publication did not report a real Git revision")
	}
	t.Logf("Task44 provider published revision %s", published.LastPublishedRevision)
	// Restore an actually adopted assignment before the scenario removes membership;
	// personal overrides are intentionally not revoked merely by leaving a team.
	if err = assignments.Clear(ctx, member, machine, assignment.Version); err != nil {
		t.Fatal("personal assignment cleanup failed")
	}
	if _, err = assignments.AdoptTeamDefault(ctx, member, team, defaultVersion); err != nil {
		t.Fatalf("re-adoption before membership revocation failed: %v", err)
	}
	restored, err := assignments.Assignment(ctx, member, machine)
	if err != nil || restored.AdoptedTeamID.String != team {
		t.Fatal("restored adopted assignment missing")
	}
	t.Log("real provider discovery and directional access -> adopted review/approve/apply -> explicit personal Git publication; same member helper, signed status, and restored adoption")
}
