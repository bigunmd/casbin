# Casbin PGX adapter
- [Casbin PGX adapter](#casbin-pgx-adapter)
  - [Description](#description)
  - [API support](#api-support)
  - [How to use](#how-to-use)
  - [Other similar implementations](#other-similar-implementations)

## Description

The idea behind this adapter is to be able to use `pgx.Tx` transaction interface seamlessly while working with Casbin official golang package.

**THERE ARE NO UNDERLYING TRANSACTIONS** inside Casbin adapter interface implementations and it highly depends on passing transaction instance while working with API that modifies existing policies (UPDATE\DELETE). **So keep that in mind!**

## API support

- Adapter
- Batch Adapter
- Filtered Adapter
- Updatable Adapter

## How to use

```golang
package main

import (
	"context"
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

	conn, _ := pgx.Connect(sigCtx, "postgresql://postgres:postgres@localhost:5432/postgres?sslmode=disable")
	defer func() {
		_ = conn.Close(sigCtx)
	}()

	tx, _ := conn.Begin(sigCtx)
	defer func() {
		_ := tx.Rollback(sigCtx)
	}()

	a, _ := adapter.NewFiltered(
		sigCtx,
		tx, // Can use pgx.Tx, pgx.Conn, pgxpool.Pool
		adapter.WithTableName("casbin_rule_test"), // Use custom table name
		adapter.WithBatchSize(3000), // Adjust policy insert batching
        adapter.WithTimeout(4 * time.Second) // Custom timeout for underlying operations
	)

	e, _ := casbin.NewEnforcer("examples/rbac_model.conf", a)

	e.AddNamedPolicy("p", []string{"alice", "data1", "read"})

	e.AddNamedPolicies(
		"p",
		[][]string{
			{"alice", "data1", "read"},
			{"bob", "data2", "write"},
			{"data2_admin", "data2", "read"},
			{"data2_admin", "data2", "write"},
		},
    )

	e.Enforce("alice", "data1", "read")

	e.UpdateNamedPolicy(
		"p",
		[]string{"alice", "data1", "read"},
		[]string{"alice", "data3", "read"},
	)

	e.Enforce("alice", "data1", "read")

	e.RemoveNamedPolicy("p", []string{"alice", "data3", "read"})

	_ = tx.Commit(sigCtx)
}
```

## Other similar implementations

- [Filtered pgx adapter](https://github.com/pckhoi/casbin-pgx-adapter)
- [Pgx Adapter](https://github.com/cychiuae/casbin-pg-adapter)

Some of the inspiration comes from the projects above and also the official Casbin [GORM Adapter](https://github.com/casbin/gorm-adapter).