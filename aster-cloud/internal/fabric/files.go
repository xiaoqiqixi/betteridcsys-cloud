package fabric

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func securePath(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrInvalid
	}
	current := "/"
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		current = filepath.Join(current, part)
		st, e := os.Lstat(current)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return ErrUnavailable
		}
		s, ok := st.Sys().(*syscall.Stat_t)
		if !ok || st.Mode()&os.ModeSymlink != 0 || s.Uid != 0 && s.Uid != uint32(os.Geteuid()) || st.IsDir() && st.Mode().Perm()&0022 != 0 && !(s.Uid == 0 && st.Mode()&os.ModeSticky != 0 && current != path) {
			return ErrUnavailable
		}
	}
	return nil
}
func secureFile(path string, owner uint32) (*os.File, error) {
	if securePath(path) != nil {
		return nil, ErrUnavailable
	}
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, ErrUnavailable
	}
	s, e := f.Stat()
	if e != nil {
		f.Close()
		return nil, ErrUnavailable
	}
	st, ok := s.Sys().(*syscall.Stat_t)
	if !ok || !s.Mode().IsRegular() || st.Uid != owner || st.Nlink != 1 || s.Mode().Perm() != 0600 {
		f.Close()
		return nil, ErrUnavailable
	}
	return f, nil
}
func readPrivate(path string, owner uint32, max int64) ([]byte, error) {
	f, e := secureFile(path, owner)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	raw, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(raw)) > max {
		return nil, ErrUnavailable
	}
	return raw, nil
}
func LoadConfig(path string) (Config, error) {
	raw, e := readPrivate(path, 0, 65536)
	if e != nil {
		return Config{}, e
	}
	return DecodeConfig(raw)
}
func LoadTopology(path string) (Topology, error) {
	raw, e := readPrivate(path, uint32(os.Geteuid()), 1<<20)
	if e != nil {
		return Topology{}, e
	}
	return DecodeTopology(raw)
}

type record struct {
	Receipt  Receipt   `json:"receipt"`
	Topology Topology  `json:"topology"`
	Bindings []binding `json:"bindings"`
}
type journal struct {
	NATProfileIDs        []string           `json:"nat_profile_ids,omitempty"`
	OverlayProfileSHA256 string             `json:"overlay_profile_sha256,omitempty"`
	ArchiveHead          string             `json:"archive_head,omitempty"`
	Recovery             *recoveryRecord    `json:"recovery,omitempty"`
	Activations          []activationRecord `json:"activations,omitempty"`
	Schema               int                `json:"schema"`
	NodeID               string             `json:"node_id"`
	Bridge               string             `json:"bridge"`
	Records              []record           `json:"records"`
}
type ledger struct {
	cfg     Config
	lock    *os.File
	state   journal
	fault   func(string) error
	history []journal
}

func openLedger(c Config, write bool, fault func(string) error) (*ledger, error) {
	if !c.Validate() || securePath(c.StateDirectory) != nil {
		return nil, ErrUnavailable
	}
	if write {
		if e := os.Mkdir(c.StateDirectory, 0700); e != nil && !os.IsExist(e) {
			return nil, ErrUnavailable
		}
		// Persist the directory's parent entry before any durable intent may
		// authorize networking. Missing parent directories are not auto-created.
		parent, e := os.Open(filepath.Dir(c.StateDirectory))
		if e != nil {
			return nil, ErrUnavailable
		}
		e = parent.Sync()
		parent.Close()
		if e != nil {
			return nil, ErrUnavailable
		}
	}
	s, e := os.Lstat(c.StateDirectory)
	if e != nil || !s.IsDir() || s.Mode().Perm() != 0700 {
		return nil, ErrUnavailable
	}
	st, ok := s.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) {
		return nil, ErrUnavailable
	}
	lockPath := filepath.Join(c.StateDirectory, "fabric.lock")
	created := false
	flags := os.O_RDONLY
	if write {
		flags = os.O_RDWR | os.O_CREATE | os.O_EXCL
	}
	lf, e := os.OpenFile(lockPath, flags|syscall.O_NOFOLLOW, 0600)
	if write && os.IsExist(e) {
		lf, e = os.OpenFile(lockPath, os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	} else if write && e == nil {
		created = true
	}
	if e != nil {
		return nil, ErrUnavailable
	}
	check, e := secureFile(filepath.Join(c.StateDirectory, "fabric.lock"), uint32(os.Geteuid()))
	if e != nil {
		lf.Close()
		return nil, e
	}
	check.Close()
	flock := syscall.LOCK_SH
	if write {
		flock = syscall.LOCK_EX
	}
	if syscall.Flock(int(lf.Fd()), flock|syscall.LOCK_NB) != nil {
		lf.Close()
		return nil, ErrUnavailable
	}
	if created {
		if lf.Sync() != nil {
			lf.Close()
			return nil, ErrUnavailable
		}
		d, de := os.Open(c.StateDirectory)
		if de != nil {
			lf.Close()
			return nil, ErrUnavailable
		}
		de = d.Sync()
		d.Close()
		if de != nil {
			lf.Close()
			return nil, ErrUnavailable
		}
	}
	l := &ledger{cfg: c, lock: lf, fault: fault, state: journal{Schema: 1, NodeID: c.NodeID, Bridge: c.Bridge, Records: []record{}}}
	path := filepath.Join(c.StateDirectory, "journal.json")
	if _, e = os.Lstat(path); os.IsNotExist(e) {
		// The lock inode is also an initialization tombstone. If an earlier
		// attempt failed to save its first journal, do not silently start anew.
		if created {
			return l, nil
		}
		l.close()
		return nil, ErrUnavailable
	}
	raw, e := readPrivate(path, uint32(os.Geteuid()), 8<<20)
	if e != nil || decodeJournal(raw, &l.state) != nil || (l.state.Schema != 1 && l.state.Schema != 2 && l.state.Schema != 3) || l.state.NodeID != c.NodeID || l.state.Bridge != c.Bridge || l.state.Records == nil || len(l.state.Records) > 64 {
		l.close()
		return nil, ErrUnavailable
	}
	if l.validateState(l.state) != nil || l.loadArchives() != nil {
		l.close()
		return nil, ErrUnavailable
	}
	return l, nil
}

func validStage(s string) bool {
	switch s {
	case "recorded", "probe_unconfirmed", "intent_unconfirmed", "plan_storage_unconfirmed", "foreign_flows_rejected", "isolation_unconfirmed", "port_identity_unconfirmed", "port_identity_changed", "port_mapping_changed", "foreign_meters_rejected", "meters_unconfirmed", "meter_readback_unconfirmed", "flows_unconfirmed", "flow_readback_unconfirmed", "receipt_storage_unconfirmed", "verified":
		return true
	}
	return false
}
func validBindings(items []binding) bool {
	ports := map[int]bool{}
	ids := map[string]bool{}
	names := map[string]bool{}
	for _, b := range items {
		if !nameRE.MatchString(b.Name) || b.OFPort < 1 || b.OFPort > 32767 || ports[b.OFPort] || names[b.Name] || ids[b.InterfaceID] || b.InterfaceID != InterfaceID(b.InstanceID) || !idRE.MatchString(b.InstanceID) || !idRE.MatchString(b.OwnerRef) || !idRE.MatchString(b.VPCID) {
			return false
		}
		ports[b.OFPort] = true
		ids[b.InterfaceID] = true
		names[b.Name] = true
	}
	return true
}
func decodeJournal(raw []byte, j *journal) error {
	var header struct {
		Schema int `json:"schema"`
	}
	if json.Unmarshal(raw, &header) != nil {
		return ErrUnavailable
	}
	keys := []string{"schema", "node_id", "bridge", "records"}
	if header.Schema == 2 || header.Schema == 3 {
		keys = append(keys, "activations")
	}
	if header.Schema == 3 {
		keys = append(keys, "archive_head")
		var f map[string]json.RawMessage
		if json.Unmarshal(raw, &f) != nil {
			return ErrUnavailable
		}
		if _, ok := f["nat_profile_ids"]; ok {
			keys = append(keys, "nat_profile_ids")
		}
		if _, ok := f["overlay_profile_sha256"]; ok {
			keys = append(keys, "overlay_profile_sha256")
		}
		if _, ok := f["recovery"]; ok {
			keys = append(keys, "recovery")
		}
	}
	if object(raw, keys, j) != nil {
		return ErrUnavailable
	}
	var root map[string]json.RawMessage
	_ = json.Unmarshal(raw, &root)
	if header.Schema == 3 {
		if raw, ok := root["recovery"]; ok {
			if decodeRecovery(raw, Config{NodeID: j.NodeID}) != nil {
				return ErrUnavailable
			}
		}
	}
	if header.Schema == 2 || header.Schema == 3 {
		var items []json.RawMessage
		if json.Unmarshal(root["activations"], &items) != nil || len(items) > 64 {
			return ErrUnavailable
		}
		for _, raw := range items {
			if decodeActivationRecord(raw) != nil {
				return ErrUnavailable
			}
		}
	}
	var records []json.RawMessage
	if json.Unmarshal(root["records"], &records) != nil || len(records) > 64 {
		return ErrUnavailable
	}
	for _, r := range records {
		var rec record
		if object(r, []string{"receipt", "topology", "bindings"}, &rec) != nil {
			return ErrUnavailable
		}
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(r, &fields)
		var receipt Receipt
		if object(fields["receipt"], []string{"schema", "node_id", "revision", "digest", "state", "stage", "updated_at"}, &receipt) != nil {
			return ErrUnavailable
		}
		if _, err := DecodeTopology(fields["topology"]); err != nil {
			return ErrUnavailable
		}
		var bindings []json.RawMessage
		if json.Unmarshal(fields["bindings"], &bindings) != nil || len(bindings) > 128 {
			return ErrUnavailable
		}
		for _, b := range bindings {
			var item binding
			if object(b, []string{"name", "ofport", "interface_id", "instance_id", "owner_ref", "vpc_id"}, &item) != nil {
				return ErrUnavailable
			}
		}
	}
	return nil
}
func (l *ledger) close() {
	if l.lock != nil {
		_ = syscall.Flock(int(l.lock.Fd()), syscall.LOCK_UN)
		l.lock.Close()
		l.lock = nil
	}
}
func (l *ledger) atomic(name string, data []byte) error {
	if len(data) > 8<<20 {
		return ErrUnavailable
	}
	dst := filepath.Join(l.cfg.StateDirectory, name)
	if _, e := os.Lstat(dst); e == nil {
		f, e := secureFile(dst, uint32(os.Geteuid()))
		if e != nil {
			return e
		}
		f.Close()
	} else if !os.IsNotExist(e) {
		return ErrUnavailable
	}
	call := func(stage string) error {
		if l.fault != nil {
			return l.fault(name + ":" + stage)
		}
		return nil
	}
	if call("before_write") != nil {
		return ErrUnavailable
	}
	f, e := os.CreateTemp(l.cfg.StateDirectory, ".fabric-*")
	if e != nil {
		return ErrUnavailable
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = call("before_sync")
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return ErrUnavailable
	}
	if call("before_rename") != nil {
		return ErrUnavailable
	}
	if os.Rename(tmp, dst) != nil {
		return ErrUnavailable
	}
	if call("after_rename") != nil {
		return ErrUnavailable
	}
	d, e := os.Open(l.cfg.StateDirectory)
	if e != nil {
		return ErrUnavailable
	}
	e = d.Sync()
	d.Close()
	if e != nil || call("after_dir_sync") != nil {
		return ErrUnavailable
	}
	return nil
}
func (l *ledger) save() error {
	raw, e := json.Marshal(l.state)
	if e != nil {
		return ErrUnavailable
	}
	return l.atomic("journal.json", raw)
}
func interrupted(r Receipt) Receipt {
	if r.State == "intent" {
		r.State = "uncertain"
		r.Stage = "interrupted"
	}
	return r
}

func Status(c Config, revision int64) (Receipt, error) {
	l, e := openLedger(c, false, nil)
	if e != nil {
		return Receipt{}, e
	}
	defer l.close()
	if l.activationPending() {
		return Receipt{}, ErrUncertain
	}
	for n := len(l.state.Records) - 1; n >= 0; n-- {
		r := l.state.Records[n].Receipt
		if revision == 0 || revision == r.Revision {
			return interrupted(r), nil
		}
	}
	for _, j := range l.history {
		for _, r := range j.Records {
			if revision == r.Receipt.Revision {
				return interrupted(r.Receipt), nil
			}
		}
	}
	return Receipt{}, errors.New("FABRIC_RECEIPT_NOT_FOUND")
}

func (l *ledger) validateState(j journal) error {
	if len(j.NATProfileIDs) > 32 || len(j.NATProfileIDs) > 0 && (j.Schema != 3 || j.OverlayProfileSHA256 == "") {
		return ErrUnavailable
	}
	for i, id := range j.NATProfileIDs {
		if !nodeRE.MatchString(id) || i > 0 && id <= j.NATProfileIDs[i-1] {
			return ErrUnavailable
		}
	}
	if j.OverlayProfileSHA256 != "" && (j.Schema != 3 || !validSHA(j.OverlayProfileSHA256)) {
		return ErrUnavailable
	}
	previous := l.state
	l.state = j
	defer func() { l.state = previous }()
	if err := l.validateActivations(); err != nil {
		return ErrUnavailable
	}
	seen := map[int64]bool{}
	lastRevision := int64(0)
	for _, r := range l.state.Records {
		p, e := Compile(r.Topology)
		if e != nil || r.Receipt.Schema != 1 || r.Receipt.NodeID != l.cfg.NodeID || r.Topology.NodeID != l.cfg.NodeID || r.Receipt.Revision != r.Topology.Revision || r.Receipt.Digest != p.Digest || seen[r.Receipt.Revision] || r.Receipt.Revision <= lastRevision {
			return ErrUnavailable
		}
		seen[r.Receipt.Revision] = true
		lastRevision = r.Receipt.Revision
		at, te := time.Parse(time.RFC3339Nano, r.Receipt.UpdatedAt)
		if te != nil || !strings.HasSuffix(r.Receipt.UpdatedAt, "Z") || at.Year() < 1 || !validStage(r.Receipt.Stage) || r.Bindings == nil || len(r.Bindings) > 128 || !validBindings(r.Bindings) {
			return ErrUnavailable
		}
		switch r.Receipt.State {
		case "intent":
			if r.Receipt.Stage != "recorded" {
				return ErrUnavailable
			}
		case "applied":
			if r.Receipt.Stage != "verified" || !matchesTopology(r.Bindings, p) {
				return ErrUnavailable
			}
		case "uncertain":
		default:
			return ErrUnavailable
		}
	}
	if validateRecovery(j) != nil {
		return ErrUnavailable
	}
	return nil
}
