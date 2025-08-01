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
)

const (
	defaultTableName = "casbin_rule"
	defaultTimeout   = 4 * time.Second
	defaultBatchSize = 1000
)

type casbinRule struct {
	ID    uint   `db:"id"`
	Ptype string `db:"ptype"`
	V0    string `db:"v0"`
	V1    string `db:"v1"`
	V2    string `db:"v2"`
	V3    string `db:"v3"`
	V4    string `db:"v4"`
	V5    string `db:"v5"`
}

func (c *casbinRule) slice() []string {
	policy := make([]string, 0)
	if c.Ptype != "" {
		policy = append(policy, c.Ptype)
	}
	if c.V0 != "" {
		policy = append(policy, c.V0)
	}
	if c.V1 != "" {
		policy = append(policy, c.V1)
	}
	if c.V2 != "" {
		policy = append(policy, c.V2)
	}
	if c.V3 != "" {
		policy = append(policy, c.V3)
	}
	if c.V4 != "" {
		policy = append(policy, c.V4)
	}
	if c.V5 != "" {
		policy = append(policy, c.V5)
	}
	return policy
}

type filter struct {
	Ptype []string
	V0    []string
	V1    []string
	V2    []string
	V3    []string
	V4    []string
	V5    []string
}

type batchFilter struct {
	filters []filter
}

type PgConn interface {
	CopyFrom(ctx context.Context, tableName pgx.Identifier, columnNames []string, rowSrc pgx.CopyFromSource) (int64, error)
	Exec(ctx context.Context, sql string, arguments ...any) (commandTag pgconn.CommandTag, err error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

var _ persist.Adapter = (*Adapter)(nil)
var _ persist.ContextAdapter = (*Adapter)(nil)
var _ persist.BatchAdapter = (*Adapter)(nil)
var _ persist.ContextBatchAdapter = (*Adapter)(nil)
var _ persist.FilteredAdapter = (*Adapter)(nil)
var _ persist.ContextFilteredAdapter = (*Adapter)(nil)
var _ persist.UpdatableAdapter = (*Adapter)(nil)
var _ persist.ContextUpdatableAdapter = (*Adapter)(nil)

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

func WithBatchSize(batchSize uint) Option {
	return func(a *Adapter) error {
		if batchSize == 0 {
			return errors.New("must provide valid batch size")
		}
		a.batchSize = batchSize

		return nil
	}
}

type Adapter struct {
	conn       PgConn
	tableName  string
	timeout    time.Duration
	batchSize  uint
	isFiltered bool
}

// UpdateFilteredPoliciesCtx implements persist.ContextUpdatableAdapter.
func (a *Adapter) UpdateFilteredPoliciesCtx(ctx context.Context, sec string, ptype string, newRules [][]string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	return a.updateFilteredPolicies(ctx, sec, ptype, newRules, fieldIndex, fieldValues...)
}

// UpdatePoliciesCtx implements persist.ContextUpdatableAdapter.
func (a *Adapter) UpdatePoliciesCtx(ctx context.Context, sec string, ptype string, oldRules [][]string, newRules [][]string) error {
	return a.updatePolicies(ctx, sec, ptype, oldRules, newRules)
}

// UpdatePolicyCtx implements persist.ContextUpdatableAdapter.
func (a *Adapter) UpdatePolicyCtx(ctx context.Context, sec string, ptype string, oldRule []string, newRule []string) error {
	return a.updatePolicy(ctx, sec, ptype, oldRule, newRule)
}

func (a *Adapter) updateFilteredPolicies(ctx context.Context, sec string, ptype string, newRules [][]string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	line := casbinRule{Ptype: ptype}
	if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
		line.V0 = fieldValues[0-fieldIndex]
	}
	if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
		line.V1 = fieldValues[1-fieldIndex]
	}
	if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
		line.V2 = fieldValues[2-fieldIndex]
	}
	if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
		line.V3 = fieldValues[3-fieldIndex]
	}
	if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
		line.V4 = fieldValues[4-fieldIndex]
	}
	if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
		line.V5 = fieldValues[5-fieldIndex]
	}

	// Selecting old rules matching filter
	sqb := sq.Select(
		"id",
		"ptype",
		"v0",
		"v1",
		"v2",
		"v3",
		"v4",
		"v5",
	).
		From(a.tableName).
		Where(sq.Eq{"ptype": line.Ptype})
	if line.V0 != "" {
		sqb = sqb.Where(sq.Eq{"v0": line.V0})
	}
	if line.V1 != "" {
		sqb = sqb.Where(sq.Eq{"v1": line.V1})
	}
	if line.V2 != "" {
		sqb = sqb.Where(sq.Eq{"v2": line.V2})
	}
	if line.V3 != "" {
		sqb = sqb.Where(sq.Eq{"v3": line.V3})
	}
	if line.V4 != "" {
		sqb = sqb.Where(sq.Eq{"v4": line.V4})
	}
	if line.V5 != "" {
		sqb = sqb.Where(sq.Eq{"v5": line.V5})
	}
	sql, arguments, err := sqb.PlaceholderFormat(sq.Dollar).ToSql()
	if err != nil {
		return nil, fmt.Errorf("cannot build select policy rule query: %w", err)
	}
	rows, err := a.conn.Query(ctx, sql, arguments...)
	if err != nil {
		return nil, fmt.Errorf("cannot query select policy rule query: %w", err)
	}
	oldLines, err := pgx.CollectRows(rows, pgx.RowToStructByName[casbinRule])
	if err != nil {
		return nil, fmt.Errorf("cannot collect rows: %w", err)
	}

	// Deleting old rules matching filter
	if err := a.rawDelete(ctx, line); err != nil {
		return nil, fmt.Errorf("cannot raw delete policy rule: %w", err)
	}

	// Inserting new rules
	if err := a.addPolicies(ctx, sec, ptype, newRules); err != nil {
		return nil, fmt.Errorf("cannot add policies: %w", err)
	}

	var oldPolicies [][]string
	for _, oldLine := range oldLines {
		oldPolicies = append(oldPolicies, oldLine.slice())
	}

	return oldPolicies, nil
}

// UpdateFilteredPolicies implements persist.UpdatableAdapter.
func (a *Adapter) UpdateFilteredPolicies(sec string, ptype string, newRules [][]string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()
	return a.updateFilteredPolicies(ctx, sec, ptype, newRules, fieldIndex, fieldValues...)
}

func (a *Adapter) updatePolicies(ctx context.Context, sec string, ptype string, oldRules [][]string, newRules [][]string) error {
	if len(oldRules) != len(newRules) {
		return errors.New("must provide equal number of old and new rules")
	}
	for idx, oldRule := range oldRules {
		if err := a.updatePolicy(ctx, sec, ptype, oldRule, newRules[idx]); err != nil {
			return fmt.Errorf("cannot update policy: %w", err)
		}
	}

	return nil
}

// UpdatePolicies implements persist.UpdatableAdapter.
func (a *Adapter) UpdatePolicies(sec string, ptype string, oldRules [][]string, newRules [][]string) error {
	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()
	return a.updatePolicies(ctx, sec, ptype, oldRules, newRules)
}

func (a *Adapter) updatePolicy(ctx context.Context, sec string, ptype string, oldRule []string, newRule []string) error {
	oldLine := a.savePolicyLine(ptype, oldRule)
	newLine := a.savePolicyLine(ptype, newRule)
	sql, arguments, err := sq.Update(a.tableName).
		Set("ptype", newLine.Ptype).
		Set("v0", newLine.V0).
		Set("v1", newLine.V1).
		Set("v2", newLine.V2).
		Set("v3", newLine.V3).
		Set("v4", newLine.V4).
		Set("v5", newLine.V5).
		Where(sq.Eq{"ptype": oldLine.Ptype}).
		Where(sq.Eq{"v0": oldLine.V0}).
		Where(sq.Eq{"v1": oldLine.V1}).
		Where(sq.Eq{"v2": oldLine.V2}).
		Where(sq.Eq{"v3": oldLine.V3}).
		Where(sq.Eq{"v4": oldLine.V4}).
		Where(sq.Eq{"v5": oldLine.V5}).
		PlaceholderFormat(sq.Dollar).ToSql()
	if err != nil {
		return fmt.Errorf("cannot create update policy rule query: %w", err)
	}
	if _, err := a.conn.Exec(ctx, sql, arguments...); err != nil {
		return fmt.Errorf("cannot execute update policy rule query: %w", err)
	}

	return nil
}

// UpdatePolicy implements persist.UpdatableAdapter.
func (a *Adapter) UpdatePolicy(sec string, ptype string, oldRule []string, newRule []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()
	return a.updatePolicy(ctx, sec, ptype, oldRule, newRule)
}

// IsFilteredCtx implements persist.ContextFilteredAdapter.
func (a *Adapter) IsFilteredCtx(ctx context.Context) bool {
	return a.isFiltered
}

// LoadFilteredPolicyCtx implements persist.ContextFilteredAdapter.
func (a *Adapter) LoadFilteredPolicyCtx(ctx context.Context, model model.Model, filter interface{}) error {
	return a.loadFilteredPolicy(ctx, model, filter)
}

// IsFiltered implements persist.FilteredAdapter.
func (a *Adapter) IsFiltered() bool {
	return a.isFiltered
}

func (a *Adapter) loadFilteredPolicy(ctx context.Context, model model.Model, filt interface{}) error {
	bf := batchFilter{
		filters: []filter{},
	}
	switch filterValue := filt.(type) {
	case filter:
		bf.filters = []filter{filterValue}
	case *filter:
		bf.filters = []filter{*filterValue}
	case []filter:
		bf.filters = filterValue
	case batchFilter:
		bf = filterValue
	case *batchFilter:
		bf = *filterValue
	default:
		return errors.New("unsupported filter type")
	}

	for _, f := range bf.filters {
		sqb := sq.Select(
			"id",
			"ptype",
			"v0",
			"v1",
			"v2",
			"v3",
			"v4",
			"v5",
		).From(a.tableName).OrderBy("id")
		if len(f.Ptype) > 0 {
			sqb = sqb.Where(sq.Eq{"ptype": f.Ptype})
		}
		if len(f.V0) > 0 {
			sqb = sqb.Where(sq.Eq{"v0": f.V0})
		}
		if len(f.V1) > 0 {
			sqb = sqb.Where(sq.Eq{"v1": f.V1})
		}
		if len(f.V2) > 0 {
			sqb = sqb.Where(sq.Eq{"v2": f.V2})
		}
		if len(f.V3) > 0 {
			sqb = sqb.Where(sq.Eq{"v3": f.V3})
		}
		if len(f.V4) > 0 {
			sqb = sqb.Where(sq.Eq{"v4": f.V4})
		}
		if len(f.V5) > 0 {
			sqb = sqb.Where(sq.Eq{"v5": f.V5})
		}
		sql, arguments, err := sqb.PlaceholderFormat(sq.Dollar).ToSql()
		if err != nil {
			return fmt.Errorf("cannot create select filtered casbin rule query: %w", err)
		}
		rows, err := a.conn.Query(ctx, sql, arguments...)
		if err != nil {
			return fmt.Errorf("cannot execute select filtered casbin rule query: %w", err)
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
	}
	a.isFiltered = true

	return nil
}

// LoadFilteredPolicy implements persist.FilteredAdapter.
func (a *Adapter) LoadFilteredPolicy(model model.Model, filter interface{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()
	return a.loadFilteredPolicy(ctx, model, filter)
}

// AddPoliciesCtx implements persist.ContextBatchAdapter.
func (a *Adapter) AddPoliciesCtx(ctx context.Context, sec string, ptype string, rules [][]string) error {
	return a.addPolicies(ctx, sec, ptype, rules)
}

// RemovePoliciesCtx implements persist.ContextBatchAdapter.
func (a *Adapter) RemovePoliciesCtx(ctx context.Context, sec string, ptype string, rules [][]string) error {
	return a.removePolicies(ctx, sec, ptype, rules)
}

func (a *Adapter) addPolicies(ctx context.Context, sec string, ptype string, rules [][]string) error {
	var lines []casbinRule
	for _, rule := range rules {
		lines = append(lines, a.savePolicyLine(ptype, rule))
	}

	for i := 0; i < len(lines); i += int(a.batchSize) {
		end := i + int(a.batchSize)
		if end > len(lines) {
			end = len(lines)
		}
		batch := lines[i:end]

		sqb := sq.Insert(a.tableName).
			Columns(
				"ptype",
				"v0",
				"v1",
				"v2",
				"v3",
				"v4",
				"v5",
			).Suffix("ON CONFLICT DO NOTHING")
		for _, line := range batch {
			sqb = sqb.Values(
				line.Ptype,
				line.V0,
				line.V1,
				line.V2,
				line.V3,
				line.V4,
				line.V5,
			)
		}
		sql, arguments, err := sqb.PlaceholderFormat(sq.Dollar).ToSql()
		if err != nil {
			return fmt.Errorf("cannot create insert policy rules query: %w", err)
		}
		if _, err := a.conn.Exec(ctx, sql, arguments...); err != nil {
			return fmt.Errorf("cannot execute insert policy rules query: %w", err)
		}
	}

	return nil
}

// AddPolicies implements persist.BatchAdapter.
func (a *Adapter) AddPolicies(sec string, ptype string, rules [][]string) error {
	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()
	return a.addPolicies(ctx, sec, ptype, rules)
}

func (a *Adapter) removePolicies(ctx context.Context, sec string, ptype string, rules [][]string) error {
	for _, rule := range rules {
		if err := a.removePolicy(ctx, sec, ptype, rule); err != nil {
			return fmt.Errorf("cannot remove policy: %w", err)
		}
	}

	return nil
}

// RemovePolicies implements persist.BatchAdapter.
func (a *Adapter) RemovePolicies(sec string, ptype string, rules [][]string) error {
	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()
	return a.removePolicies(ctx, sec, ptype, rules)
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
	return a.removeFilteredPolicy(ctx, sec, ptype, fieldIndex, fieldValues...)
}

// RemovePolicyCtx implements persist.ContextAdapter.
func (a *Adapter) RemovePolicyCtx(ctx context.Context, sec string, ptype string, rule []string) error {
	return a.removePolicy(ctx, sec, ptype, rule)
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
			rule.Ptype,
			rule.V0,
			rule.V1,
			rule.V2,
			rule.V3,
			rule.V4,
			rule.V5,
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
		r.Ptype,
		r.V0,
		r.V1,
		r.V2,
		r.V3,
		r.V4,
		r.V5,
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

func checkFieldValues(fieldValues ...string) error {
	for _, fv := range fieldValues {
		if fv != "" {
			return nil
		}
	}

	return errors.New("must provide at least one non empty field value")
}

func (a *Adapter) removeFilteredPolicy(ctx context.Context, sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	var line casbinRule
	line.Ptype = ptype

	if fieldIndex == -1 {
		return a.rawDelete(ctx, line)
	}

	if err := checkFieldValues(fieldValues...); err != nil {
		return fmt.Errorf("cannot check field values: %w", err)
	}

	if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
		line.V0 = fieldValues[0-fieldIndex]
	}
	if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
		line.V1 = fieldValues[1-fieldIndex]
	}
	if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
		line.V2 = fieldValues[2-fieldIndex]
	}
	if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
		line.V3 = fieldValues[3-fieldIndex]
	}
	if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
		line.V4 = fieldValues[4-fieldIndex]
	}
	if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
		line.V5 = fieldValues[5-fieldIndex]
	}

	if err := a.rawDelete(ctx, line); err != nil {
		return fmt.Errorf("cannot raw delete line: %w", err)
	}

	return nil
}

// RemoveFilteredPolicy implements persist.Adapter.
func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()
	return a.removeFilteredPolicy(ctx, sec, ptype, fieldIndex, fieldValues...)
}

func (a *Adapter) rawDelete(ctx context.Context, line casbinRule) error {
	sqb := sq.Delete(a.tableName).Where(sq.Eq{"ptype": line.Ptype})
	if line.V0 != "" {
		sqb = sqb.Where(sq.Eq{"v0": line.V0})
	}
	if line.V1 != "" {
		sqb = sqb.Where(sq.Eq{"v1": line.V1})
	}
	if line.V2 != "" {
		sqb = sqb.Where(sq.Eq{"v2": line.V2})
	}
	if line.V3 != "" {
		sqb = sqb.Where(sq.Eq{"v3": line.V3})
	}
	if line.V4 != "" {
		sqb = sqb.Where(sq.Eq{"v4": line.V4})
	}
	if line.V5 != "" {
		sqb = sqb.Where(sq.Eq{"v5": line.V5})
	}
	sql, arguments, err := sqb.PlaceholderFormat(sq.Dollar).ToSql()
	if err != nil {
		return fmt.Errorf("cannot build delete policy rule query: %w", err)
	}
	if _, err := a.conn.Exec(ctx, sql, arguments...); err != nil {
		return fmt.Errorf("cannot execute delete policy rule query: %w", err)
	}

	return nil
}

func (a *Adapter) removePolicy(ctx context.Context, sec string, ptype string, rule []string) error {
	line := a.savePolicyLine(ptype, rule)
	if err := a.rawDelete(ctx, line); err != nil {
		return fmt.Errorf("cannot raw delete line: %w", err)
	}

	return nil
}

// RemovePolicy implements persist.Adapter.
func (a *Adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()
	return a.removePolicy(ctx, sec, ptype, rule)
}

func (a *Adapter) truncateTable(ctx context.Context) error {
	if _, err := a.conn.Exec(ctx, fmt.Sprintf("TRUNCATE TABLE %s", a.tableName)); err != nil {
		return fmt.Errorf("cannot execute truncate table '%s' query: %w", a.tableName, err)
	}

	return nil
}

func (a *Adapter) savePolicyLine(ptype string, rule []string) casbinRule {
	var line casbinRule
	line.Ptype = ptype
	if len(rule) > 0 {
		line.V0 = rule[0]
	}
	if len(rule) > 1 {
		line.V1 = rule[1]
	}
	if len(rule) > 2 {
		line.V2 = rule[2]
	}
	if len(rule) > 3 {
		line.V3 = rule[3]
	}
	if len(rule) > 4 {
		line.V4 = rule[4]
	}
	if len(rule) > 5 {
		line.V5 = rule[5]
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
			line.Ptype,
			line.V0,
			line.V1,
			line.V2,
			line.V3,
			line.V4,
			line.V5,
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
		ptype VARCHAR(32) NOT NULL,
		v0 VARCHAR(255) NOT NULL DEFAULT '', 
		v1 VARCHAR(255) NOT NULL DEFAULT '', 
		v2 VARCHAR(255) NOT NULL DEFAULT '', 
		v3 VARCHAR(255) NOT NULL DEFAULT '', 
		v4 VARCHAR(255) NOT NULL DEFAULT '', 
		v5 VARCHAR(255) NOT NULL DEFAULT '',
		PRIMARY KEY (id),
		UNIQUE (ptype,v0,v1,v2,v3,v4,v5)
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
		batchSize: defaultBatchSize,
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

func NewFiltered(ctx context.Context, conn PgConn, opts ...Option) (*Adapter, error) {
	a, err := New(ctx, conn, opts...)
	if err != nil {
		return nil, fmt.Errorf("cannot create adapter: %w", err)
	}
	a.isFiltered = true

	return a, nil
}
