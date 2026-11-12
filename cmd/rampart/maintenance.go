package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"rampart/internal/config"
	"rampart/internal/retention"
)

// runMaintenance is `rampart maintenance`: it creates the coming months' event and audit partitions and drops
// the months past retention (docs/16 D4, D53). It needs the owner role, so it runs where the migrations run: the
// Helm CronJob, or by hand. Tenant data is removed by the server's own retention sweep, as the application role.
func runMaintenance(args []string) error {
	fs := flag.NewFlagSet("maintenance", flag.ContinueOnError)
	dbURL := fs.String("db-url", "", "PostgreSQL URL of rampart_owner (default: RAMPART_DATABASE_MIGRATE_URL)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	connURL := *dbURL
	if connURL == "" {
		connURL = os.Getenv("RAMPART_DATABASE_MIGRATE_URL")
	}
	if connURL == "" {
		return fmt.Errorf("maintenance: the owner's PostgreSQL URL is required (--db-url or RAMPART_DATABASE_MIGRATE_URL)")
	}
	// The retention days come from the same configuration as the server's (file and RAMPART_RETENTION_*), and
	// are validated the same way, so a CronJob cannot drop a month the server would keep.
	cfg, err := config.Load(nil)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	pool, err := pgxpool.New(ctx, connURL)
	if err != nil {
		return fmt.Errorf("maintenance: connecting: %w", err)
	}
	defer pool.Close()
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	policy := cfg.Retention.RetentionPolicy
	if !cfg.Retention.Enabled {
		policy.EventsDays, policy.AuditDays = 0, 0 // retention off: partitions are still created, nothing is dropped
	}
	if err := retention.MaintainLogs(ctx, pool, policy, time.Now().UTC(), log); err != nil {
		return fmt.Errorf("maintenance: %w", err)
	}
	fmt.Println("Event and audit partitions are in place; months past retention were dropped.")
	return nil
}
