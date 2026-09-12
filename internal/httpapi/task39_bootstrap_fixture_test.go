package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/accessdescriptor"
	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/auth"
	"github.com/pinksaucepasta/paperboat-server/internal/billing"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/lazyaccess"
	"github.com/pinksaucepasta/paperboat-server/internal/metering"
	"github.com/pinksaucepasta/paperboat-server/internal/mint"
	"github.com/pinksaucepasta/paperboat-server/internal/peeridentity"
	"github.com/pinksaucepasta/paperboat-server/internal/peersessions"
	"github.com/pinksaucepasta/paperboat-server/internal/usermachines"
)

// Run only on the designated Hetzner test host. The client machines exercise
// actual one-shot bootstrap against this private router and isolated database.
// Only the upstream identity provider is substituted; no principal or machine
// credential is forged, and all enrollment, signatures and observations are real.
func TestTask39ServeAuthenticatedEnrollment(t *testing.T) {
	directory := os.Getenv("PAPERBOAT_TASK39_BOOTSTRAP_DIR")
	if directory == "" {
		t.Skip("private native enrollment fixture is opt-in")
	}
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(directory) {
		t.Fatal("absolute protected fixture directory required")
	}
	address, base := os.Getenv("PAPERBOAT_TASK39_BOOTSTRAP_LISTEN"), os.Getenv("PAPERBOAT_TASK39_BOOTSTRAP_URL")
	host, _, err := net.SplitHostPort(address)
	if err != nil || net.ParseIP(host) == nil || !strings.HasPrefix(host, "100.") || !strings.HasPrefix(base, "https://") {
		t.Fatal("private Tailscale listener and HTTPS origin required")
	}
	database, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	ctx := context.Background()
	if err := db.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	secret := base64.RawURLEncoding.EncodeToString(key)
	clear(key)
	cfg := config.Default()
	cfg.HTTP.PublicBaseURL = base
	writer := audit.NewWriter(database)
	signer, err := mint.NewEphemeral(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	accounts := auth.NewService(database, writer, auth.FakeWorkOSVerifier{}, []string{secret}, true, "https://login.pprbt.dev")
	devices := auth.NewDeviceService(database, writer, cfg.CLIAuth, []string{secret})
	billingService := billing.NewService(billing.NewRepository(database), billing.FakePolarClient{}, writer)
	machines := usermachines.New(database, writer, usermachines.Policy{PairingLifetime: cfg.UserMachines.PairingLifetime, OfflineAfter: cfg.UserMachines.OfflineAfter, AllowedPlatforms: cfg.UserMachines.AllowedPlatforms}, billingService)
	machines.ConfigureProvisioning(nil, secret)
	machines.ConfigureAccess(nil, base, cfg.CLIAuth.AccessTokenLifetime)
	machines.ConfigureFileTransfer(accessdescriptor.FileTransferPolicy{
		Revision: cfg.Access.FileTransfer.Revision, MaxFileBytes: cfg.Access.FileTransfer.MaxFileBytes,
		MaxBatchFiles: cfg.Access.FileTransfer.MaxBatchFiles, MaxBatchBytes: cfg.Access.FileTransfer.MaxBatchBytes,
		MaxConcurrentTransfers: cfg.Access.FileTransfer.MaxConcurrentTransfers, RetentionSeconds: int64(cfg.Access.FileTransfer.Retention / time.Second),
		DeliveryTimeoutSeconds: int64(cfg.Access.FileTransfer.DeliveryTimeout / time.Second), MaxPendingSpoolBytes: cfg.Access.FileTransfer.MaxPendingSpoolBytes,
	})
	machines.ConfigureOneShotCLIAuth(cfg.CLIAuth.ClientID, cfg.CLIAuth.AllowedScopes, cfg.CLIAuth.AccessTokenLifetime, cfg.CLIAuth.RefreshTokenLifetime, secret)
	machines.ConfigureMachineControl(signer, base)
	if err := machines.ConfigureRuntimeRoute("task39.invalid", 38080); err != nil {
		t.Fatal(err)
	}
	if err := machines.ConfigureMachineArtifacts(os.Getenv("PAPERBOAT_TASK39_BOOTSTRAP_REPOSITORY"), "2026.09.08.390"); err != nil {
		t.Fatal(err)
	}
	enrollment := controlplane.NewEnrollmentService(database, signer, writer, base, secret)
	machines.ConfigureHelperEnrollment(func(ctx context.Context, actor, operation, environment string, lifetime time.Duration) (usermachines.HelperEnrollmentGrant, error) {
		grant, err := enrollment.Issue(ctx, actor, operation, environment, lifetime)
		return usermachines.HelperEnrollmentGrant{EnrollmentID: grant.EnrollmentID, HelperID: grant.HelperID, Credential: grant.Credential, ExpiresAt: grant.ExpiresAt}, err
	})
	machines.ConfigureHelperRecovery(func(ctx context.Context, actor, operation, environment, helper string, lifetime time.Duration) (usermachines.HelperEnrollmentGrant, error) {
		grant, err := enrollment.RecoverHelper(ctx, actor, operation, environment, helper, lifetime)
		return usermachines.HelperEnrollmentGrant{EnrollmentID: grant.EnrollmentID, HelperID: grant.HelperID, Credential: grant.Credential, ExpiresAt: grant.ExpiresAt}, err
	})
	identityRepo, err := peeridentity.NewSQLRepository(database, writer)
	if err != nil {
		t.Fatal(err)
	}
	identities, err := peeridentity.NewService(identityRepo)
	if err != nil {
		t.Fatal(err)
	}
	network, err := peersessions.NewNetworkService(database, signer, base)
	if err != nil {
		t.Fatal(err)
	}
	router := authTestOriginHandler{next: NewRouter(Options{Config: cfg, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Auth: accounts, DeviceAuth: devices, Billing: billingService, Machines: machines, MintKeys: signer, Enrollment: enrollment, RuntimeIdentity: enrollment, PeerIdentity: identities, PeerNetwork: network, LazyActivation: &lazyaccess.Activator{DB: database}, MeteringRepo: metering.NewRuntimeRepository(database, secret, cfg.ConfigSync.StaleHeartbeatAfter)})}
	type user struct {
		Name         string `json:"name"`
		AccountID    string `json:"account_id"`
		EnrollmentID string `json:"enrollment_id"`
		Token        string `json:"token"`
	}
	var users []user
	for _, name := range []string{"pb39a", "pb39b"} {
		email := name + "-" + time.Now().UTC().Format("20060102150405.000000000") + "@example.test"
		cookies := loginCookies(t, router, "bootstrap_"+email+":"+email+":"+name)
		account := userIDByEmail(t, database, email)
		if _, err := database.SQL().ExecContext(ctx, `INSERT INTO paperboat.user_machine_entitlements (id,user_id,provider_subscription_id,product_code,state,seat_quantity,allowance_bytes,current_period_start,current_period_end) VALUES ($1,$2,$3,'connected-test','active',1,1048576,now()-interval '1 hour',now()+interval '1 hour')`, "ume_bootstrap_"+account, account, "sub_bootstrap_"+account); err != nil {
			t.Fatal(err)
		}
		// An authenticated account issues the one-shot token through the same
		// service used by the already-tested HTTP enrollment endpoint.
		started, err := machines.StartEnrollment(ctx, account, "bootstrap_"+name)
		if err != nil {
			t.Fatal(err)
		}
		if len(cookies) == 0 {
			t.Fatal("authenticated account session missing")
		}
		users = append(users, user{Name: name, AccountID: account, EnrollmentID: started.ID, Token: started.BootstrapToken})
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No external test-provider sign-in is exposed after fixture accounts exist.
		if strings.HasPrefix(r.URL.Path, "/v1/auth/workos/") {
			http.NotFound(w, r)
			return
		}
		router.ServeHTTP(w, r)
	}), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second}
	finished := make(chan error, 1)
	go func() {
		finished <- server.ServeTLS(listener, os.Getenv("PAPERBOAT_TASK39_TLS_CERT"), os.Getenv("PAPERBOAT_TASK39_TLS_KEY"))
	}()
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	payload, err := json.Marshal(users)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "enrollments.json"), payload, 0600); err != nil {
		t.Fatal(err)
	}
	clear(payload)
	t.Log("private authenticated enrollment fixture ready")
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case err := <-finished:
			t.Fatalf("private enrollment listener stopped: %v", err)
		case <-ticker.C:
			if _, err := os.Stat(filepath.Join(directory, "stop")); err == nil {
				for _, user := range users {
					var count int
					if err := database.Pool().QueryRow(ctx, `SELECT count(*) FROM paperboat.user_machines WHERE user_id=$1 AND online AND deleted_at IS NULL AND revoked_at IS NULL`, user.AccountID).Scan(&count); err != nil || count != 1 {
						t.Fatalf("expected one ready enrolled machine for %s: count=%d err=%v", user.Name, count, err)
					}
				}
				return
			}
		}
	}
}
