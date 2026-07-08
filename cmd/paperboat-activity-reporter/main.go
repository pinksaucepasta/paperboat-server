package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/pinksaucepasta/paperboat-server/internal/activity"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	reporter, err := activity.NewReporter(activity.FromEnv())
	if err != nil {
		fmt.Fprintf(os.Stderr, `{"component":"activity","level":"error","message":%q}`+"\n", err.Error())
		os.Exit(64)
	}
	if err := reporter.Run(ctx); err != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, `{"component":"activity","level":"error","message":%q}`+"\n", err.Error())
		os.Exit(1)
	}
}
