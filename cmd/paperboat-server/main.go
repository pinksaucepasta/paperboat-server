package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/pinksaucepasta/paperboat-server/internal/app"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
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
	case "migrate", "seed-catalogs", "reconcile", "admin":
		return fmt.Errorf("%s: command is defined for the production CLI surface but blocked until its phase implementation", args[1])
	case "help", "-h", "--help":
		printUsage(stdout)
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[1])
	}
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
