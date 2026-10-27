// Package controllerbackup handles the authenticated migration container. A
// verified container is NOT a database restore approval or a takeover lease.
package controllerbackup

import (
	"archive/tar"
	"aster/cloud/migrations"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"filippo.io/age"
)

const Protocol = "aster.controller-backup/1"
const KeyPrefix = "ASTER-CONTROLLER-RECOVERY-1:"
const MaxDataBytes int64 = 8 << 30
const MaxCipherBytes int64 = MaxDataBytes + (64 << 20)
const MaxManifestBytes int64 = 2 << 20

var ErrInvalid = errors.New("migration archive unconfirmed")
var controllerID = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
var operationID = regexp.MustCompile(`^[0-9a-f]{32}$`)
var sourceSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)
var shaPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var materialName = regexp.MustCompile(`^materials/([0-9a-f]{64})\.bin$`)

type Entry struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}
type Manifest struct {
	Schema           int     `json:"schema"`
	Protocol         string  `json:"protocol"`
	ControllerID     string  `json:"controller_id"`
	OperationID      string  `json:"operation_id"`
	SourceCommit     string  `json:"source_commit"`
	SchemaVersion    int     `json:"schema_version"`
	SourcePlanSHA256 string  `json:"source_plan_sha256"`
	Files            []Entry `json:"files"`
}
type Report struct {
	Schema                   int    `json:"schema"`
	Protocol                 string `json:"protocol"`
	ControllerID             string `json:"controller_id"`
	OperationID              string `json:"operation_id"`
	SourceCommit             string `json:"source_commit"`
	Entries                  int    `json:"entries"`
	DataBytes                int64  `json:"data_bytes"`
	Authenticated            bool   `json:"authenticated"`
	ContentIntegrityVerified bool   `json:"content_integrity_verified"`
	DataSemanticsVerified    bool   `json:"data_semantics_verified"`
	TargetRestoreApproved    bool   `json:"target_restore_approved"`
	MigrationReady           bool   `json:"migration_ready"`
}

// SQL identifiers come only from this binary's immutable embedded migrations,
// never from the archive. This inventory does not authorize executing SQL from
// a backup, nor establish row/foreign-key correctness for a target database.
func requiredFiles() map[string]bool {
	names := map[string]bool{"controller/config.json": true, "controller/materials.json": true, "database/schema.json": true, "source/installation.json": true,
		"source/plan.json": true, "source/isolated.json": true}
	pattern := regexp.MustCompile(`(?i)CREATE TABLE (?:IF NOT EXISTS )?(controller_[a-z0-9_]+)\s*\(`)
	for _, migration := range migrations.All() {
		for _, found := range pattern.FindAllStringSubmatch(migration.SQL, -1) {
			names["database/"+found[1]+".jsonl"] = true
		}
	}
	return names
}

func validManifest(m Manifest, expectedController, expectedOperation string) (int64, bool) {
	if m.Schema != 1 || m.Protocol != Protocol || m.ControllerID != expectedController ||
		m.OperationID != expectedOperation || !sourceSHA.MatchString(m.SourceCommit) ||
		m.SchemaVersion != len(migrations.All()) || !shaPattern.MatchString(m.SourcePlanSHA256) {
		return 0, false
	}
	required := requiredFiles()
	if len(m.Files) < len(required) || len(m.Files) > 256 {
		return 0, false
	}
	var total int64
	previous := ""
	for _, entry := range m.Files {
		if entry.Name <= previous || entry.Size < 0 || entry.Size > MaxDataBytes-total || !shaPattern.MatchString(entry.SHA256) {
			return 0, false
		}
		previous = entry.Name
		if entry.Name == "source/plan.json" && entry.SHA256 != m.SourcePlanSHA256 {
			return 0, false
		}
		if required[entry.Name] {
			delete(required, entry.Name)
		} else if match := materialName.FindStringSubmatch(entry.Name); len(match) != 2 || match[1] != entry.SHA256 || entry.Size == 0 || entry.Size > 1<<20 {
			return 0, false
		}
		total += entry.Size
	}
	return total, len(required) == 0
}

// Reject duplicate keys and case-insensitive aliases before Go's permissive
// struct decoder. Size, nesting and token bounds apply before any data restore.
func decodeManifest(raw []byte) (Manifest, error) {
	allowed := map[string]bool{}
	for _, key := range strings.Fields("schema protocol controller_id operation_id source_commit schema_version source_plan_sha256 files name size sha256") {
		allowed[key] = true
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	tokens := 0
	var visit func(int) error
	visit = func(depth int) error {
		tokens++
		if depth > 16 || tokens > 20000 {
			return ErrInvalid
		}
		token, err := d.Token()
		if err != nil {
			return ErrInvalid
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					key, e := d.Token()
					name, ok := key.(string)
					if e != nil || !ok || !allowed[name] || seen[name] {
						return ErrInvalid
					}
					seen[name] = true
					if visit(depth+1) != nil {
						return ErrInvalid
					}
				}
				end, e := d.Token()
				if e != nil || end != json.Delim('}') {
					return ErrInvalid
				}
			case '[':
				for d.More() {
					if visit(depth+1) != nil {
						return ErrInvalid
					}
				}
				end, e := d.Token()
				if e != nil || end != json.Delim(']') {
					return ErrInvalid
				}
			default:
				return ErrInvalid
			}
		}
		return nil
	}
	if visit(0) != nil {
		return Manifest{}, ErrInvalid
	}
	if _, err := d.Token(); err != io.EOF {
		return Manifest{}, ErrInvalid
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var result Manifest
	if d.Decode(&result) != nil {
		return Manifest{}, ErrInvalid
	}
	return result, nil
}

func regularHeader(header *tar.Header, name string, size int64) bool {
	return header != nil && header.Name == name && header.Size == size && header.Mode == 0600 &&
		header.Typeflag == tar.TypeReg && header.Format == tar.FormatUSTAR && header.Linkname == "" &&
		header.Uid == 0 && header.Gid == 0 && header.Uname == "" && header.Gname == "" &&
		len(header.PAXRecords) == 0 && len(header.Xattrs) == 0
}

type countedReader struct {
	reader  io.Reader
	bytes   int64
	padding int
	failed  bool
}

func (r *countedReader) Read(p []byte) (int, error) {
	if r.failed {
		return 0, ErrInvalid
	}
	n, err := r.reader.Read(p)
	r.bytes += int64(n)
	check := min(n, r.padding)
	for _, b := range p[:check] {
		if b != 0 {
			r.failed = true
			return 0, ErrInvalid
		}
	}
	r.padding -= check
	return n, err
}

func (r *countedReader) padAfter(size int64) { r.padding = int((512 - size%512) % 512) }

func tarSpan(size int64) int64 { return 512 + ((size+511)/512)*512 }

func inspect(reader io.Reader, key, expectedController, expectedOperation string, stage func(Entry) (io.WriteCloser, error), authenticated func(Manifest)) (Report, error) {
	identity, err := age.NewScryptIdentity(key)
	if err != nil {
		return Report{}, ErrInvalid
	}
	identity.SetMaxWorkFactor(18)
	clear, err := age.Decrypt(reader, identity)
	if err != nil {
		return Report{}, ErrInvalid
	}
	counted := &countedReader{reader: clear}
	tr := tar.NewReader(counted)
	header, err := tr.Next()
	if err != nil || header.Size < 1 || header.Size > MaxManifestBytes || !regularHeader(header, "manifest.json", header.Size) {
		return Report{}, ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(tr, MaxManifestBytes+1))
	if err != nil || int64(len(raw)) != header.Size {
		return Report{}, ErrInvalid
	}
	expectedBytes := tarSpan(header.Size) + 1024
	counted.padAfter(header.Size)
	manifest, err := decodeManifest(raw)
	if err != nil {
		return Report{}, ErrInvalid
	}
	total, valid := validManifest(manifest, expectedController, expectedOperation)
	if !valid {
		return Report{}, ErrInvalid
	}
	for _, entry := range manifest.Files {
		expectedBytes += tarSpan(entry.Size)
		header, err = tr.Next()
		if err != nil || !regularHeader(header, entry.Name, entry.Size) {
			return Report{}, ErrInvalid
		}
		hash := sha256.New()
		var output io.WriteCloser
		var writer io.Writer = hash
		if stage != nil {
			output, err = stage(entry)
			if err != nil {
				return Report{}, ErrInvalid
			}
			writer = io.MultiWriter(hash, output)
		}
		n, err := io.Copy(writer, tr)
		if output != nil {
			if e := output.Close(); e != nil {
				return Report{}, ErrInvalid
			}
		}
		if err != nil || n != entry.Size || hex.EncodeToString(hash.Sum(nil)) != entry.SHA256 {
			return Report{}, ErrInvalid
		}
		counted.padAfter(entry.Size)
	}
	if _, err := tr.Next(); err != io.EOF {
		return Report{}, ErrInvalid
	}
	if counted.bytes != expectedBytes {
		return Report{}, ErrInvalid
	}
	// tar EOF alone is insufficient: authenticate age's final chunk and refuse
	// every trailing plaintext byte, including another archive or extra padding.
	var probe [1]byte
	if n, err := clear.Read(probe[:]); n != 0 || err != io.EOF {
		return Report{}, ErrInvalid
	}
	if authenticated != nil {
		authenticated(manifest)
	}
	return Report{Schema: 1, Protocol: Protocol, ControllerID: manifest.ControllerID, OperationID: manifest.OperationID,
		SourceCommit: manifest.SourceCommit, Entries: len(manifest.Files), DataBytes: total,
		Authenticated: true, ContentIntegrityVerified: true}, nil
}

func ownedInput(path string, maximum int64) (*os.File, os.FileInfo, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\r\n\x00") {
		return nil, nil, ErrInvalid
	}
	owner := uint32(os.Geteuid())
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, nil, ErrInvalid
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 && st.Uid != owner || info.Mode().Perm()&0022 != 0 && !(st.Uid == 0 && info.Mode()&os.ModeSticky != 0) {
			return nil, nil, ErrInvalid
		}
		if parent == "/" {
			break
		}
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, ErrInvalid
	}
	f := os.NewFile(uintptr(fd), "migration-input")
	info, err := f.Stat()
	if err == nil {
		st, ok := info.Sys().(*syscall.Stat_t)
		if ok && st.Uid == owner && st.Nlink == 1 && info.Mode().IsRegular() && info.Mode().Perm() == 0600 &&
			info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 && info.Size() > 0 && info.Size() <= maximum {
			return f, info, nil
		}
	}
	f.Close()
	return nil, nil, ErrInvalid
}

// InspectFiles is read-only and may run offline as the owner of both private
// inputs. It never opens a database, extracts archive paths or activates a host.
func InspectFiles(archive, keyFile, expectedController, expectedOperation string) (Report, error) {
	return inspectFiles(archive, keyFile, expectedController, expectedOperation, nil, nil)
}

func inspectFiles(archive, keyFile, expectedController, expectedOperation string, stage func(Entry) (io.WriteCloser, error), authenticated func(Manifest)) (Report, error) {
	if !controllerID.MatchString(expectedController) || !operationID.MatchString(expectedOperation) {
		return Report{}, ErrInvalid
	}
	k, beforeKey, err := ownedInput(keyFile, 160)
	if err != nil {
		return Report{}, ErrInvalid
	}
	defer k.Close()
	raw, err := io.ReadAll(io.LimitReader(k, 161))
	key := strings.TrimSuffix(string(raw), "\n")
	if err != nil || len(raw) != len(KeyPrefix)+65 || !strings.HasPrefix(key, KeyPrefix) || !shaPattern.MatchString(strings.TrimPrefix(key, KeyPrefix)) {
		return Report{}, ErrInvalid
	}
	f, before, err := ownedInput(archive, MaxCipherBytes)
	if err != nil {
		return Report{}, ErrInvalid
	}
	defer f.Close()
	result, err := inspect(io.LimitReader(f, before.Size()+1), key, expectedController, expectedOperation, stage, authenticated)
	if err != nil {
		return Report{}, ErrInvalid
	}
	for _, item := range []struct {
		file   *os.File
		before os.FileInfo
	}{{k, beforeKey}, {f, before}} {
		after, e := item.file.Stat()
		if e != nil || !os.SameFile(item.before, after) || item.before.Size() != after.Size() || !item.before.ModTime().Equal(after.ModTime()) || item.before.Mode() != after.Mode() {
			return Report{}, ErrInvalid
		}
	}
	return result, nil
}
