package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/app"
	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/catalog"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/fly"
	"github.com/pinksaucepasta/paperboat-server/internal/orchestrator"
	"github.com/pinksaucepasta/paperboat-server/internal/projects"
)

func main() {
	if err := run(os.Args, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) < 2 {
		printUsage(stdout)
		return nil
	}

	switch args[1] {
	case "serve":
		return runServe(args[2:], stdout, stderr)
	case "migrate":
		return runMigrate(args[2:], stdout, stderr)
	case "seed-catalogs":
		return runSeedCatalogs(args[2:], stdout, stderr)
	case "reconcile":
		return runReconcile(args[2:], stdout, stderr)
	case "admin":
		return runAdmin(args[2:], stdout, stderr)
	case "help", "-h", "--help":
		printUsage(stdout)
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[1])
	}
}

func runAdmin(args []string, stdout, stderr io.Writer) error {
	if len(args) < 2 {
		return errors.New("usage: paperboat-server admin <usage-key provision|project delete> [flags]")
	}
	switch args[0] + " " + args[1] {
	case "usage-key provision":
		return runAdminProvisionUsageKey(args[2:], stdout, stderr)
	case "project delete":
		return runAdminDeleteProject(args[2:], stdout, stderr)
	default:
		return errors.New("usage: paperboat-server admin <usage-key provision|project delete> [flags]")
	}
}

func runAdminDeleteProject(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("admin project delete", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "path to JSON config file")
	userID := fs.String("user-id", "", "owning user ID")
	projectID := fs.String("project-id", "", "project ID")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || strings.TrimSpace(*userID) == "" || strings.TrimSpace(*projectID) == "" {
		return errors.New("admin project delete requires --user-id and --project-id")
	}
	cfg, err := config.Load(context.Background(), config.LoadOptions{Environment: os.Getenv("PAPERBOAT_ENV"), FilePath: *configPath, LookupEnv: os.LookupEnv, ReadFile: os.ReadFile})
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	store, err := db.Open(cfg.Database)
	if err != nil {
		return err
	}
	defer store.Close()
	project, err := projects.NewService(store, audit.NewWriter(store), cfg).Delete(context.Background(), strings.TrimSpace(*userID), strings.TrimSpace(*projectID))
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "project %s deletion state: %s\n", project.ID, project.State)
	return err
}

func runAdminProvisionUsageKey(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("admin usage-key provision", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "path to JSON config file")
	actorID := fs.String("actor-user-id", "", "administrator user ID")
	idempotencyKey := fs.String("idempotency-key", "", "unique operation key")
	keyID := fs.String("key-id", "", "usage signing key ID")
	nodeID := fs.String("edge-node-id", "", "edge node ID")
	publicKeyValue := fs.String("public-key", "", "base64url Ed25519 public key")
	notBeforeValue := fs.String("not-before", "", "RFC3339 validity start")
	expiresAtValue := fs.String("expires-at", "", "RFC3339 validity end")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("admin usage-key provision does not accept positional arguments")
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(*publicKeyValue))
	if err != nil {
		return errors.New("public-key must be unpadded base64url")
	}
	notBefore, err := time.Parse(time.RFC3339, strings.TrimSpace(*notBeforeValue))
	if err != nil {
		return errors.New("not-before must be RFC3339")
	}
	expiresAt, err := time.Parse(time.RFC3339, strings.TrimSpace(*expiresAtValue))
	if err != nil {
		return errors.New("expires-at must be RFC3339")
	}
	cfg, err := config.Load(context.Background(), config.LoadOptions{Environment: os.Getenv("PAPERBOAT_ENV"), FilePath: *configPath, LookupEnv: os.LookupEnv, ReadFile: os.ReadFile})
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	store, err := db.Open(cfg.Database)
	if err != nil {
		return err
	}
	defer store.Close()
	service := controlplane.NewEdgeService(store, cfg.Secrets.EdgeControlCredential)
	service.SetAuditWriter(audit.NewWriter(store))
	if err := service.ProvisionUsageKey(context.Background(), strings.TrimSpace(*actorID), strings.TrimSpace(*idempotencyKey), strings.TrimSpace(*keyID), strings.TrimSpace(*nodeID), publicKey, notBefore.UTC(), expiresAt.UTC()); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "usage verification key %s provisioned for %s\n", strings.TrimSpace(*keyID), strings.TrimSpace(*nodeID))
	return err
}

func runReconcile(args []string, stdout, stderr io.Writer) error {
	cfg, err := loadCommandConfig(args, stderr)
	if err != nil {
		return err
	}
	store, err := db.Open(cfg.Database)
	if err != nil {
		return err
	}
	defer store.Close()
	var flyClient fly.Client
	if cfg.Providers.FakeMode {
		flyClient = fly.NewFakeClient()
	} else {
		flyClient = &fly.SDKClient{APIToken: cfg.Secrets.FlyAPIToken, AppName: cfg.Fly.AppName, OrgSlug: cfg.Fly.OrgSlug, BaseURL: cfg.Providers.Fly.BaseURL}
	}
	run, err := orchestrator.NewService(store, flyClient, cfg).Reconcile(context.Background())
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(run, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, string(b))
	return err
}

func runMigrate(args []string, stdout, stderr io.Writer) error {
	cfg, err := loadCommandConfig(args, stderr)
	if err != nil {
		return err
	}
	store, err := db.Open(cfg.Database)
	if err != nil {
		return err
	}
	defer store.Close()
	if err := db.Migrate(context.Background(), store); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, "database migrations applied")
	return err
}

func runSeedCatalogs(args []string, stdout, stderr io.Writer) error {
	cfg, err := loadCommandConfig(args, stderr)
	if err != nil {
		return err
	}
	seed, err := catalog.LoadFile(cfg.Catalogs.SeedFile)
	if err != nil {
		return err
	}
	store, err := db.Open(cfg.Database)
	if err != nil {
		return err
	}
	defer store.Close()
	if err := catalog.Apply(context.Background(), store, seed); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, "catalog seed applied")
	return err
}

func loadCommandConfig(args []string, stderr io.Writer) (config.Config, error) {
	fs := flag.NewFlagSet("command", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "path to JSON config file")
	if err := fs.Parse(args); err != nil {
		return config.Config{}, err
	}
	cfg, err := config.Load(context.Background(), config.LoadOptions{
		Environment: os.Getenv("PAPERBOAT_ENV"),
		FilePath:    *configPath,
		LookupEnv:   os.LookupEnv,
		ReadFile:    os.ReadFile,
	})
	if err != nil {
		return config.Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return config.Config{}, err
	}
	return cfg, nil
}

func runServe(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "path to JSON config file")
	dumpConfig := fs.Bool("dump-config", false, "print redacted config and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(context.Background(), config.LoadOptions{
		Environment: os.Getenv("PAPERBOAT_ENV"),
		FilePath:    *configPath,
		LookupEnv:   os.LookupEnv,
		ReadFile:    os.ReadFile,
	})
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	if *dumpConfig {
		_, err := fmt.Fprintln(stdout, cfg.RedactedJSON())
		return err
	}

	handler := slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo})
	logger := slog.New(handler)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	server, err := app.New(app.Options{
		Config: cfg,
		Logger: logger,
	})
	if err != nil {
		return err
	}
	if err := server.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, `paperboat-server controls the Paperboat backend.

Usage:
  paperboat-server serve [-config path] [-dump-config]
  paperboat-server migrate
  paperboat-server seed-catalogs
  paperboat-server reconcile
  paperboat-server admin usage-key provision [flags]
  paperboat-server admin project delete --user-id <id> --project-id <id> [flags]
`)
}
