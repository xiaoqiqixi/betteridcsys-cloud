package controllerbackup

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"regexp"
	"sort"
	"strings"
)

// Database files are typed byte records, never SQL programs. The restore side
// must compare this metadata to a freshly migrated empty target before INSERT.
type Column struct {
	Name      string  `json:"name"`
	Type      string  `json:"type"`
	Nullable  string  `json:"nullable"`
	Charset   *string `json:"charset"`
	Collation *string `json:"collation"`
	Extra     string  `json:"extra"`
	Key       string  `json:"key"`
}
type Table struct {
	Schema  int      `json:"schema"`
	Name    string   `json:"table"`
	Columns []Column `json:"columns"`
	NextID  *string  `json:"next_id"`
}

var sqlName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func tableNames() []string {
	var names []string
	for name := range requiredFiles() {
		if strings.HasPrefix(name, "database/") {
			names = append(names, strings.TrimSuffix(strings.TrimPrefix(name, "database/"), ".jsonl"))
		}
	}
	sort.Strings(names)
	return names
}

// SnapshotDatabase is a single read-only REPEATABLE READ transaction. The
// caller supplies private bounded writers, keeps the source fenced, and has
// already checked the embedded migration checksums. No source rows are written.
func SnapshotDatabase(ctx context.Context, db *sql.DB, write func(string, func(io.Writer) error) error) (int64, error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return 0, ErrInvalid
	}
	defer conn.Close()
	var locked int
	if conn.QueryRowContext(ctx, "SELECT GET_LOCK('aster_controller_schema_v1',5)").Scan(&locked) != nil || locked != 1 {
		return 0, ErrInvalid
	}
	defer func() {
		release, cancel := context.WithTimeout(context.Background(), 5_000_000_000)
		defer cancel()
		_, _ = conn.ExecContext(release, "DO RELEASE_LOCK('aster_controller_schema_v1')")
	}()
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return 0, ErrInvalid
	}
	defer tx.Rollback()
	names := tableNames()
	rows, err := tx.QueryContext(ctx, "SELECT TABLE_NAME,ENGINE,TABLE_TYPE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME")
	if err != nil {
		return 0, ErrInvalid
	}
	index := 0
	for rows.Next() {
		var name, engine, kind string
		if rows.Scan(&name, &engine, &kind) != nil || index >= len(names) || name != names[index] || engine != "InnoDB" || kind != "BASE TABLE" {
			rows.Close()
			return 0, ErrInvalid
		}
		index++
	}
	err = rows.Err()
	rows.Close()
	if err != nil || index != len(names) {
		return 0, ErrInvalid
	}
	for _, query := range []string{
		"SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=DATABASE()",
		"SELECT COUNT(*) FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA=DATABASE()",
		"SELECT COUNT(*) FROM information_schema.EVENTS WHERE EVENT_SCHEMA=DATABASE()",
	} {
		var n int
		if tx.QueryRowContext(ctx, query).Scan(&n) != nil || n != 0 {
			return 0, ErrInvalid
		}
	}
	// Obtain metadata locks on every approved table before taking column
	// definitions. These transaction locks remain held through the final read.
	for _, name := range names {
		r, e := tx.QueryContext(ctx, "SELECT * FROM `"+name+"` LIMIT 0")
		if e != nil {
			return 0, ErrInvalid
		}
		r.Close()
	}
	var count int64
	for _, name := range names {
		table := Table{Schema: 1, Name: name}
		r, e := tx.QueryContext(ctx, "SELECT COLUMN_NAME,COLUMN_TYPE,IS_NULLABLE,CHARACTER_SET_NAME,COLLATION_NAME,EXTRA,COLUMN_KEY FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? ORDER BY ORDINAL_POSITION", name)
		if e != nil {
			return 0, ErrInvalid
		}
		var selectColumns, primary []string
		for r.Next() {
			var c Column
			if r.Scan(&c.Name, &c.Type, &c.Nullable, &c.Charset, &c.Collation, &c.Extra, &c.Key) != nil || !sqlName.MatchString(c.Name) || len(table.Columns) >= 128 || (c.Extra != "" && c.Extra != "auto_increment") {
				r.Close()
				return 0, ErrInvalid
			}
			table.Columns = append(table.Columns, c)
			selectColumns = append(selectColumns, "CAST(`"+c.Name+"` AS BINARY)")
			if c.Key == "PRI" {
				primary = append(primary, "`"+c.Name+"`")
			}
		}
		e = r.Err()
		r.Close()
		if e != nil || len(table.Columns) == 0 || len(primary) == 0 {
			return 0, ErrInvalid
		}
		if tx.QueryRowContext(ctx, "SELECT CAST(AUTO_INCREMENT AS CHAR) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=?", name).Scan(&table.NextID) != nil {
			return 0, ErrInvalid
		}
		e = write("database/"+name+".jsonl", func(w io.Writer) error {
			enc := json.NewEncoder(w)
			if enc.Encode(table) != nil {
				return ErrInvalid
			}
			data, e := tx.QueryContext(ctx, "SELECT "+strings.Join(selectColumns, ",")+" FROM `"+name+"` ORDER BY "+strings.Join(primary, ","))
			if e != nil {
				return ErrInvalid
			}
			defer data.Close()
			values := make([][]byte, len(table.Columns))
			destinations := make([]any, len(values))
			for i := range values {
				destinations[i] = &values[i]
			}
			for data.Next() {
				if data.Scan(destinations...) != nil {
					return ErrInvalid
				}
				var bytes int64
				for _, value := range values {
					bytes += int64(len(value))
				}
				if bytes > 48<<20 || enc.Encode(values) != nil {
					return ErrInvalid
				}
				count++
			}
			return data.Err()
		})
		if e != nil {
			return 0, ErrInvalid
		}
	}
	if tx.Commit() != nil {
		return 0, ErrInvalid
	}
	return count, nil
}
