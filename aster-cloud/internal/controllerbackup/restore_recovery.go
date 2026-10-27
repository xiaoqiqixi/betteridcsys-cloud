package controllerbackup

import (
	"aster/cloud/internal/control"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"reflect"
	"sort"
	"strings"
)

type preparedTable struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}
type databasePreparation struct {
	Schema          int             `json:"schema"`
	OperationID     string          `json:"operation_id"`
	Database        string          `json:"database"`
	ServerUUID      string          `json:"server_uuid"`
	OwnershipSHA256 string          `json:"ownership_sha256"`
	ManifestSHA256  string          `json:"manifest_sha256"`
	Tables          []preparedTable `json:"tables"`
}

func restoreOwner(receipt []byte, runtimeDSN string) (*databaseOwnership, error) {
	if len(receipt) > 65536 || len(runtimeDSN) > 4096 {
		return nil, ErrInvalid
	}
	runtimeDSN = strings.TrimSpace(runtimeDSN)
	owner, e := decodeDatabaseOwnership(receipt, runtimeDSN)
	if e != nil {
		return nil, ErrInvalid
	}
	store, e := control.OpenDSN(runtimeDSN) // validation only, never connect
	if e != nil {
		return nil, ErrInvalid
	}
	store.DB.Close()
	return owner, nil
}

// RestoreRecoverableDatabase adds a durable pre-write proof to the marked-empty
// restore. persist MUST atomically retain the bytes in the protected target
// operation before returning nil. Its failure prevents all data-row changes;
// already created DDL remains sealed and is never automatically reimported.
func (a *Archive) RestoreRecoverableDatabase(ctx context.Context, target *sql.DB, receipt []byte, runtimeDSN string, persist func([]byte) error) (DatabaseRestoreReport, error) {
	if persist == nil {
		return DatabaseRestoreReport{}, ErrInvalid
	}
	owner, e := restoreOwner(receipt, runtimeDSN)
	if e != nil {
		return DatabaseRestoreReport{}, e
	}
	return a.restoreDatabase(ctx, target, owner, persist)
}

func structure(ctx context.Context, q sqlReader) ([]preparedTable, error) {
	names := append(tableNames(), installerOwnershipTable)
	sort.Strings(names)
	var proof []preparedTable
	for _, name := range names {
		var have, ddl string
		if q.QueryRowContext(ctx, "SHOW CREATE TABLE `"+name+"`").Scan(&have, &ddl) != nil || have != name || len(ddl) < 1 || len(ddl) > 1<<20 {
			return nil, ErrInvalid
		}
		proof = append(proof, preparedTable{name, digestBytes([]byte(ddl))})
	}
	return proof, nil
}

func (a *Archive) preparation(owner *databaseOwnership) databasePreparation {
	owned, _ := json.Marshal(owner)
	manifest, _ := json.Marshal(a.manifest)
	return databasePreparation{Schema: 1, OperationID: a.manifest.OperationID, Database: owner.Database, ServerUUID: owner.ServerUUID,
		OwnershipSHA256: digestBytes(owned), ManifestSHA256: digestBytes(manifest)}
}
func (a *Archive) prepareStructure(ctx context.Context, q sqlReader, owner *databaseOwnership) ([]byte, error) {
	if owner == nil {
		return nil, ErrInvalid
	}
	p := a.preparation(owner)
	var e error
	p.Tables, e = structure(ctx, q)
	if e != nil {
		return nil, e
	}
	raw, e := json.Marshal(p)
	if e != nil {
		return nil, ErrInvalid
	}
	return append(raw, '\n'), nil
}

// VerifyRestoredDatabase resolves an unknown commit response using read-only
// verification, never INSERT replay. Every authenticated table byte, encoding,
// auto-increment and full CREATE TABLE definition (including FKs/indexes) must
// match. The proof is from the protected pre-write target journal, NOT a backup
// entry, user upload, caller-supplied SQL or a previously saved success flag.
// Root ownership/grants, admission sealing and later session/node authority
// transfer remain the fixed host coordinator's responsibility.
func (a *Archive) VerifyRestoredDatabase(ctx context.Context, target *sql.DB, receipt []byte, runtimeDSN string, proof []byte) (DatabaseRestoreReport, error) {
	plan, _, _, e := a.parseDatabase(ctx)
	if e != nil || target == nil || len(proof) > 65536 || !bytes.HasSuffix(proof, []byte("\n")) {
		return DatabaseRestoreReport{}, ErrInvalid
	}
	owner, e := restoreOwner(receipt, runtimeDSN)
	if e != nil || owner.Database != "aster_cloud_restore_"+a.manifest.OperationID {
		return DatabaseRestoreReport{}, ErrInvalid
	}
	var p databasePreparation
	if !canonicalRecord(bytes.TrimSuffix(proof, []byte("\n")), &p) {
		return DatabaseRestoreReport{}, ErrInvalid
	}
	want := a.preparation(owner)
	want.Tables = p.Tables
	if !reflect.DeepEqual(p, want) || len(p.Tables) != len(tableNames())+1 {
		return DatabaseRestoreReport{}, ErrInvalid
	}
	names := append(tableNames(), installerOwnershipTable)
	sort.Strings(names)
	for i, t := range p.Tables {
		if t.Name != names[i] || !shaPattern.MatchString(t.SHA256) {
			return DatabaseRestoreReport{}, ErrInvalid
		}
	}
	expected := map[string]string{}
	for _, f := range a.manifest.Files {
		expected[f.Name] = f.SHA256
	}
	total, e := snapshotDatabaseChecked(ctx, target, owner, func(name string, emit func(io.Writer) error) error {
		h := sha256.New()
		if emit(h) != nil || hex.EncodeToString(h.Sum(nil)) != expected[name] {
			return ErrInvalid
		}
		return nil
	}, func(q sqlReader) error {
		var account string
		if q.QueryRowContext(ctx, "SELECT CURRENT_USER()").Scan(&account) != nil || account != owner.MigrationUser+"@localhost" {
			return ErrInvalid
		}
		have, e := structure(ctx, q)
		if e != nil || !reflect.DeepEqual(have, p.Tables) {
			return ErrInvalid
		}
		return nil
	})
	if e != nil || total != plan.Rows {
		return DatabaseRestoreReport{}, ErrInvalid
	}
	return DatabaseRestoreReport{Tables: len(plan.Tables), Rows: total, ExactRowsVerified: true, DeclaredConstraintsVerified: true, ProvisioningMarkerPreserved: true}, nil
}
