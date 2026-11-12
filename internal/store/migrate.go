package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
)

// RiverSchema is the PostgreSQL schema holding River's tables (doc 12).
const RiverSchema = "river"

// CurrentExpectedSchemaVersion defines the baseline schema version expected by this binary.
const CurrentExpectedSchemaVersion int64 = 10

// MigrateUp executes Goose migrations, River migrations, and initial range partitions (normative D4).
func MigrateUp(ctx context.Context, directURL string) error {
	db, err := sql.Open("pgx", directURL)
	if err != nil {
		return fmt.Errorf("store: failed to open migration database: %w", err)
	}
	defer func() { _ = db.Close() }()

	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("store: goose set dialect failed: %w", err)
	}
	goose.SetBaseFS(MigrationsFS)

	// 1. Run Goose schema migrations
	if err := goose.UpContext(ctx, db, "migrations"); err != nil {
		return fmt.Errorf("store: goose up migrations failed: %w", err)
	}

	// 2. Run River queue migrations
	poolCfg, err := pgxpool.ParseConfig(directURL)
	if err != nil {
		return fmt.Errorf("store: failed to parse direct URL for river migrations: %w", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return fmt.Errorf("store: failed to create pool for river migrations: %w", err)
	}
	defer pool.Close()

	// doc 12: River's tables live in their own schema. The owner creates it and grants
	// the runtime roles; River itself runs as rampart_app / rampart_system.
	if _, err := pool.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS `+RiverSchema); err != nil {
		return fmt.Errorf("store: creating river schema failed: %w", err)
	}
	migrator, err := rivermigrate.New(riverpgxv5.New(pool), &rivermigrate.Config{Schema: RiverSchema})
	if err != nil {
		return fmt.Errorf("store: failed to initialize river migrator: %w", err)
	}
	if _, err := migrator.Migrate(ctx, rivermigrate.DirectionUp, &rivermigrate.MigrateOpts{}); err != nil {
		return fmt.Errorf("store: river migration failed: %w", err)
	}

	for _, stmt := range []string{
		`GRANT USAGE ON SCHEMA river TO rampart_app, rampart_system`,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA river TO rampart_app, rampart_system`,
		`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA river TO rampart_app, rampart_system`,
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("store: granting river privileges failed: %w", err)
		}
	}

	// 3. Ensure partition maintenance runs for upcoming months
	if err := MaintainPartitions(ctx, pool, time.Now().UTC()); err != nil {
		return fmt.Errorf("store: initial partition creation failed: %w", err)
	}

	return nil
}

// MigrateWait blocks until the database schema version is at least minVersion (normative D4).
// Used primarily by Kubernetes init containers.
func MigrateWait(ctx context.Context, dbURL string, minVersion int64, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		db, err := sql.Open("pgx", dbURL)
		if err == nil {
			_ = goose.SetDialect("postgres")
			ver, errVer := goose.GetDBVersion(db)
			_ = db.Close()
			if errVer == nil && ver >= minVersion {
				return nil
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if time.Now().After(deadline) {
				return fmt.Errorf("store: timed out waiting for schema version >= %d", minVersion)
			}
		}
	}
}
