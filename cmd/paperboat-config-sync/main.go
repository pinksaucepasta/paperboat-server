package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/pinksaucepasta/paperboat-server/internal/configsync"
)

func main() {
	cfg, err := configsync.ConfigFromEnv()
	if err != nil {
		fail(err)
	}
	engine, err := configsync.New(cfg)
	if err != nil {
		fail(err)
	}
	mode := "restore"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch mode {
	case "restore":
		err = engine.Restore(ctx)
	case "save", "flush":
		flushCtx, cancel := context.WithTimeout(ctx, cfg.Policy.ShutdownFlushTimeout)
		err = engine.Flush(flushCtx, mode)
		cancel()
	case "daemon":
		err = engine.RunDaemon(ctx)
	default:
		fail(fmt.Errorf("unknown config sync mode %q", mode))
	}
	if err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "{\"component\":\"config-sync\",\"level\":\"error\",\"message\":%q}\n", err.Error())
	os.Exit(1)
}
