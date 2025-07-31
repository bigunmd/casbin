package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/bigunmd/casbin/pgx/adapter"
	"github.com/casbin/casbin/v2"
	"github.com/jackc/pgx/v5"
)

func main() {
	sigCtx, stop := signal.NotifyContext(
		context.Background(),
		syscall.SIGTERM,
		syscall.SIGINT,
	)
	defer stop()

	conn, err := pgx.Connect(sigCtx, "postgresql://postgres:postgres@localhost:5432/postgres?sslmode=disable")
	if err != nil {
		slog.Error("failed to open connection", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer func() {
		if err := conn.Close(sigCtx); err != nil {
			slog.Error("failed to close connection", slog.String("error", err.Error()))
		}
	}()

	a, err := adapter.NewFiltered(
		sigCtx,
		conn,
		adapter.WithTableName("casbin_rule_test"),
		adapter.WithBatchSize(3),
	)
	if err != nil {
		slog.Error("failed to create adapter", slog.String("error", err.Error()))
		os.Exit(1)
	}

	e, err := casbin.NewEnforcer("examples/rbac_model.conf", a)
	if err != nil {
		slog.Error("failed to create enforcer", slog.String("error", err.Error()))
		os.Exit(1)
	}

	if _, err := e.AddNamedPolicy(
		"p",
		[]string{"alice", "data1", "read"},
	); err != nil {
		slog.Error("failed to add named policy", slog.String("error", err.Error()))
		os.Exit(1)
	}

	if _, err := e.RemoveNamedPolicy(
		"p",
		[]string{"alice", "data1", "read"},
	); err != nil {
		slog.Error("failed to remove named policy", slog.String("error", err.Error()))
		os.Exit(1)
	}

	if _, err := e.AddNamedPolicies(
		"p",
		[][]string{
			{"alice", "data1", "read"},
			{"bob", "data2", "write"},
			{"data2_admin", "data2", "read"},
			{"data2_admin", "data2", "write"},
		}); err != nil {
		slog.Error("failed to add named policies", slog.String("error", err.Error()))
		os.Exit(1)
	}

	ok, err := e.Enforce("alice", "data1", "read")
	if err != nil {
		slog.Error("failed to enforce policy", slog.String("error", err.Error()))
		os.Exit(1)
	}
	slog.Info("alice can read data1", slog.Bool("ok", ok))
}
