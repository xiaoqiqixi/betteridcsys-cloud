package networking

import (
	"database/sql"
	"errors"
	"fmt"
	"testing"

	"github.com/go-sql-driver/mysql"
)

type ingressNamespaceRow struct {
	used int
	err  error
}

func (r ingressNamespaceRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	*dest[0].(*int) = r.used
	return nil
}
func TestPublicIngressNamespaceOnlyExplicitMissingTableRetainsStandaloneSchema(t *testing.T) {
	for _, tc := range []struct {
		name string
		row  ingressNamespaceRow
		want error
	}{
		{"unused", ingressNamespaceRow{}, nil},
		{"occupied", ingressNamespaceRow{used: 1}, ErrConflict},
		{"schema5_missing_table", ingressNamespaceRow{err: &mysql.MySQLError{Number: 1146}}, nil},
		{"wrapped_missing_table", ingressNamespaceRow{err: fmt.Errorf("query: %w", &mysql.MySQLError{Number: 1146})}, nil},
		{"permission_denied", ingressNamespaceRow{err: &mysql.MySQLError{Number: 1142}}, ErrUnavailable},
		{"credentials_denied", ingressNamespaceRow{err: &mysql.MySQLError{Number: 1045}}, ErrUnavailable},
		{"database_absent", ingressNamespaceRow{err: &mysql.MySQLError{Number: 1049}}, ErrUnavailable},
		{"table_without_result", ingressNamespaceRow{err: sql.ErrNoRows}, ErrUnavailable},
		{"network_failure", ingressNamespaceRow{err: errors.New("connection lost")}, ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := publicIngressNamespaceRow(tc.row); !errors.Is(got, tc.want) {
				t.Fatal("namespace error relaxed", got, tc.want)
			}
		})
	}
}
