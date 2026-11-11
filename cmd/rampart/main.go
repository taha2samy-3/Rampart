package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"rampart/internal/config"
	"rampart/internal/targets"
	"rampart/internal/telemetry"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "rampart: fatal error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	handled, err := handleCLI(args)
	if err != nil {
		return err
	}
	if handled {
		return nil
	}

	cfg, err := config.Load(args)
	if err != nil {
		return err
	}

	logger := telemetry.SetupLogger(cfg.Telemetry.LogLevel, cfg.Telemetry.LogFormat, os.Stdout)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	runner := targets.NewRunner(cfg, logger)
	return runner.Run(ctx)
}
