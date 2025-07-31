package adapter

import (
	"context"
	"errors"
	"fmt"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

const (
	defaultTableName = "casbin_rule"
	defaultTimeout   = 4 * time.Second
)

type casbinRule struct {
	ID    uint        `db:"id"`
	Ptype pgtype.Text `db:"ptype"`
	V0    pgtype.Text `db:"v0"`
	V1    pgtype.Text `db:"v1"`
	V2    pgtype.Text `db:"v2"`
	V3    pgtype.Text `db:"v3"`
	V4    pgtype.Text `db:"v4"`
	V5    pgtype.Text `db:"v5"`
}

type PgConn interface {
	CopyFrom(ctx context.Context, tableName pgx.Identifier, columnNames []string, rowSrc pgx.CopyFromSource) (int64, error)
	Exec(ctx context.Context, sql string, arguments ...any) (commandTag pgconn.CommandTag, err error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

var _ persist.Adapter = (*Adapter)(nil)
var _ persist.ContextAdapter = (*Adapter)(nil)

// var _ persist.BatchAdapter = (*Adapter)(nil)

type Option func(*Adapter) error

func WithTableName(tableName string) Option {
	return func(a *Adapter) error {
		if tableName == "" {
			return errors.New("must provide valid table name")
		}
		a.tableName = tableName

		return nil
	}
}

func WithTimeout(timeout time.Duration) Option {
	return func(a *Adapter) error {
		if timeout == 0 {
			return errors.New("must provide valid timeout")
		}
		a.timeout = timeout

		return nil
	}
}

type Adapter struct {
	conn       PgConn
	tableName  string
	timeout    time.Duration
	isFiltered bool
}

// AddPolicyCtx implements persist.ContextAdapter.
func (a *Adapter) AddPolicyCtx(ctx context.Context, sec string, ptype string, rule []string) error {
	return a.addPolicy(ctx, sec, ptype, rule)
}

// LoadPolicyCtx implements persist.ContextAdapter.
func (a *Adapter) LoadPolicyCtx(ctx context.Context, model model.Model) error {
	return a.loadPolicy(ctx, model)
}

// RemoveFilteredPolicyCtx implements persist.ContextAdapter.
func (a *Adapter) RemoveFilteredPolicyCtx(ctx context.Context, sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	panic("unimplemented")
}

// RemovePolicyCtx implements persist.ContextAdapter.
func (a *Adapter) RemovePolicyCtx(ctx context.Context, sec string, ptype string, rule []string) error {
	panic("unimplemented")
}

// SavePolicyCtx implements persist.ContextAdapter.
func (a *Adapter) SavePolicyCtx(ctx context.Context, model model.Model) error {
	return a.savePolicy(ctx, model)
}

func (a *Adapter) addPolicy(ctx context.Context, sec string, ptype string, rule []string) error {
	line := a.savePolicyLine(ptype, rule)
	sql, arguments, err := sq.Insert(a.tableName).
		Columns(
			"ptype",
			"v0",
			"v1",
			"v2",
			"v3",
			"v4",
			"v5",
		).Values(
		line.Ptype,
		line.V0,
		line.V1,
		line.V2,
		line.V3,
		line.V4,
		line.V5,
	).Suffix("ON CONFLICT DO NOTHING").
		PlaceholderFormat(sq.Dollar).ToSql()
	if err != nil {
		return fmt.Errorf("cannot create insert policy rule query: %w", err)
	}
	if _, err := a.conn.Exec(ctx, sql, arguments...); err != nil {
		return fmt.Errorf("cannot execute insert policy rule query: %w", err)
	}

	return nil
}

// AddPolicy implements persist.Adapter.
func (a *Adapter) AddPolicy(sec string, ptype string, rule []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()
	return a.addPolicy(ctx, sec, ptype, rule)
}

func (a *Adapter) preview(rules []casbinRule, model model.Model) error {
	j := 0
	for i, rule := range rules {
		r := []string{
			rule.Ptype.String,
			rule.V0.String,
			rule.V1.String,
			rule.V2.String,
			rule.V3.String,
			rule.V4.String,
			rule.V5.String,
		}
		index := len(r) - 1
		for r[index] == "" {
			index--
		}
		index += 1
		p := r[:index]
		key := p[0]
		sec := key[:1]
		ok, err := model.HasPolicyEx(sec, key, p[1:])
		if err != nil {
			return fmt.Errorf("cannot check if model has policy rule: %w", err)
		}
		if ok {
			rules[j], rules[i] = rule, rules[j]
			j++
		}
	}
	rules = rules[j:]

	return nil
}

func loadPolicyLine(r casbinRule, model model.Model) error {
	var p = []string{
		r.Ptype.String,
		r.V0.String,
		r.V1.String,
		r.V2.String,
		r.V3.String,
		r.V4.String,
		r.V5.String,
	}

	index := len(p) - 1
	for p[index] == "" {
		index--
	}
	index += 1
	p = p[:index]
	if err := persist.LoadPolicyArray(p, model); err != nil {
		return fmt.Errorf("cannot load policy array: %w", err)
	}

	return nil
}

func (a *Adapter) loadPolicy(ctx context.Context, model model.Model) error {
	sql, arguments, err := sq.Select(
		"id",
		"ptype",
		"v0",
		"v1",
		"v2",
		"v3",
		"v4",
		"v5",
	).From(a.tableName).
		OrderBy("id").
		PlaceholderFormat(sq.Dollar).ToSql()
	if err != nil {
		return fmt.Errorf("cannot create select casbin rule query: %w", err)
	}
	rows, err := a.conn.Query(ctx, sql, arguments...)
	if err != nil {
		return fmt.Errorf("cannot execute select casbin rule query: %w", err)
	}
	rules, err := pgx.CollectRows(rows, pgx.RowToStructByName[casbinRule])
	if err != nil {
		return fmt.Errorf("cannot collect rows: %w", err)
	}
	if err := a.preview(rules, model); err != nil {
		return fmt.Errorf("cannot preview policy rules: %w", err)
	}
	for _, r := range rules {
		if err := loadPolicyLine(r, model); err != nil {
			return fmt.Errorf("cannot load policy line: %w", err)
		}
	}

	return nil
}

// LoadPolicy implements persist.Adapter.
func (a *Adapter) LoadPolicy(model model.Model) error {
	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()
	return a.loadPolicy(ctx, model)
}

// RemoveFilteredPolicy implements persist.Adapter.
func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	panic("unimplemented")
}

// RemovePolicy implements persist.Adapter.
func (a *Adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	panic("unimplemented")
}

func (a *Adapter) truncateTable(ctx context.Context) error {
	if _, err := a.conn.Exec(ctx, fmt.Sprintf("TRUNCATE TABLE %s", a.tableName)); err != nil {
		return fmt.Errorf("cannot execute truncate table '%s' query: %w", a.tableName, err)
	}

	return nil
}

func (a *Adapter) savePolicyLine(ptype string, rule []string) casbinRule {
	var line casbinRule
	line.Ptype = pgtype.Text{
		String: ptype,
		Valid:  true,
	}
	if len(rule) > 0 {
		line.V0 = pgtype.Text{
			String: rule[0],
			Valid:  true,
		}
	}
	if len(rule) > 1 {
		line.V1 = pgtype.Text{
			String: rule[1],
			Valid:  true,
		}
	}
	if len(rule) > 2 {
		line.V2 = pgtype.Text{
			String: rule[2],
			Valid:  true,
		}
	}
	if len(rule) > 3 {
		line.V3 = pgtype.Text{
			String: rule[3],
			Valid:  true,
		}
	}
	if len(rule) > 4 {
		line.V4 = pgtype.Text{
			String: rule[4],
			Valid:  true,
		}
	}
	if len(rule) > 5 {
		line.V5 = pgtype.Text{
			String: rule[5],
			Valid:  true,
		}
	}

	return line
}

func (a *Adapter) savePolicy(ctx context.Context, model model.Model) error {
	if err := a.truncateTable(ctx); err != nil {
		return fmt.Errorf("cannot truncate table: %w", err)
	}

	var lines []casbinRule
	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			lines = append(lines, a.savePolicyLine(ptype, rule))
		}
	}
	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			lines = append(lines, a.savePolicyLine(ptype, rule))
		}
	}

	var rows [][]any
	for _, line := range lines {
		rows = append(rows, []any{
			line.Ptype.String,
			line.V0.String,
			line.V1.String,
			line.V2.String,
			line.V3.String,
			line.V4.String,
			line.V5.String,
		})
	}

	if _, err := a.conn.CopyFrom(ctx, pgx.Identifier{a.tableName}, []string{
		"ptype",
		"v0",
		"v1",
		"v2",
		"v3",
		"v4",
		"v5",
	}, pgx.CopyFromRows(rows)); err != nil {
		return fmt.Errorf("cannot batch insert rows: %w", err)
	}

	return nil
}

// SavePolicy implements persist.Adapter.
func (a *Adapter) SavePolicy(model model.Model) error {
	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()
	return a.savePolicy(ctx, model)
}

func (a *Adapter) createTable(ctx context.Context) error {
	if _, err := a.conn.Exec(ctx, fmt.Sprintf(`
	CREATE TABLE IF NOT EXISTS %s (
		id BIGSERIAL,
		ptype VARCHAR(32),
		v0 VARCHAR(255), 
		v1 VARCHAR(255), 
		v2 VARCHAR(255), 
		v3 VARCHAR(255), 
		v4 VARCHAR(255), 
		v5 VARCHAR(255),
		PRIMARY KEY (id)
	);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_%s ON %s (ptype,v0,v1,v2,v3,v4,v5);
	`, a.tableName, a.tableName, a.tableName)); err != nil {
		return fmt.Errorf("cannot execute create '%s' table query: %w", a.tableName, err)
	}

	return nil
}

func New(ctx context.Context, conn PgConn, opts ...Option) (*Adapter, error) {
	a := &Adapter{
		conn:      conn,
		tableName: defaultTableName,
		timeout:   defaultTimeout,
	}

	for _, opt := range opts {
		if err := opt(a); err != nil {
			return nil, fmt.Errorf("cannot apply option: %w", err)
		}
	}

	if err := a.createTable(ctx); err != nil {
		return nil, fmt.Errorf("cannot create table: %w", err)
	}

	return a, nil
}
