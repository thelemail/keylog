package cmd

import (
	"context"
	"fmt"
	"io/fs"

	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
	"github.com/spf13/cobra"

	"github.com/thelemail/keylog/db"
	"github.com/thelemail/keylog/internal/pkg/postgres"
)

const migrationsDir = "migrations/postgres"

func newMigrateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Apply / roll back / inspect database migrations",
	}
	cmd.AddCommand(newMigrateUpCmd(), newMigrateDownCmd(), newMigrateStatusCmd())
	return cmd
}

func newMigrateUpCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "up",
		Short: "Apply all pending migrations",
		RunE: func(c *cobra.Command, _ []string) error {
			return runMigrate(c.Context(), func(ctx context.Context, p *goose.Provider) error {
				_, err := p.Up(ctx)
				return err
			})
		},
	}
}

func newMigrateDownCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "down",
		Short: "Roll back the most recent migration",
		RunE: func(c *cobra.Command, _ []string) error {
			return runMigrate(c.Context(), func(ctx context.Context, p *goose.Provider) error {
				_, err := p.Down(ctx)
				return err
			})
		},
	}
}

func newMigrateStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show applied and pending migrations",
		RunE: func(c *cobra.Command, _ []string) error {
			return runMigrate(c.Context(), func(ctx context.Context, p *goose.Provider) error {
				sources, err := p.Status(ctx)
				if err != nil {
					return err
				}
				for _, s := range sources {
					state := "pending"
					if s.State == goose.StateApplied {
						state = "applied"
					}
					fmt.Fprintf(c.OutOrStdout(), "%-12s %s\n", state, s.Source.Path)
				}
				return nil
			})
		},
	}
}

func runMigrate(ctx context.Context, op func(context.Context, *goose.Provider) error) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	pg, err := postgres.New(ctx, cfg.Postgres)
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	defer func() { _ = pg.Close() }()

	sub, err := fs.Sub(db.Migrations, migrationsDir)
	if err != nil {
		return fmt.Errorf("migrations fs: %w", err)
	}
	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		return fmt.Errorf("goose locker: %w", err)
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, pg.DB, sub, goose.WithSessionLocker(locker))
	if err != nil {
		return fmt.Errorf("goose provider: %w", err)
	}
	return op(ctx, provider)
}
