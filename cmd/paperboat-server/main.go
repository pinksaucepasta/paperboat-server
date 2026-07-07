package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/pinksaucepasta/paperboat-server/internal/agentunnel"
	"github.com/pinksaucepasta/paperboat-server/internal/app"
	"github.com/pinksaucepasta/paperboat-server/internal/catalog"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/fly"
	"github.com/pinksaucepasta/paperboat-server/internal/orchestrator"
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
		return fmt.Errorf("%s: command is defined for the production CLI surface but blocked until its phase implementation", args[1])
	case "help", "-h", "--help":
		printUsage(stdout)
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[1])
	}
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
	run, err := orchestrator.NewServiceWithAgentunnel(store, flyClient, cfg, commandAgentunnelClient(cfg)).Reconcile(context.Background())
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

func commandAgentunnelClient(cfg config.Config) agentunnel.Client {
	if cfg.Providers.FakeMode {
		return agentunnel.FakeClient{BaseURL: cfg.Providers.Agentunnel.BaseURL}
	}
	return agentunnel.HTTPClient{
		BaseURL:              cfg.Providers.Agentunnel.BaseURL,
		APIKey:               cfg.Secrets.AgentunnelAPIKey,
		PapercodeLocalURL:    cfg.Providers.Agentunnel.PapercodeLocalURL,
		RouteExpiresIn:       cfg.Providers.Agentunnel.RouteExpiresIn,
		RouteSubdomainPrefix: cfg.Providers.Agentunnel.RouteSubdomainPrefix,
	}
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
  paperboat-server admin
`)
}
