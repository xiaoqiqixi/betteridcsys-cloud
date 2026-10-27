package hypervisor

import (
	"aster/cloud/internal/fabric"
	"aster/cloud/internal/nodeproto"
	"aster/cloud/internal/overlayproto"
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"sort"
	"strings"
	"time"
)

// The operator explicitly approves a second network contract. Original VM and
// billing snapshots remain byte-for-byte unchanged; an overlay profile may only
// reference the same bridge and lock as its original fabric profile.
type overlayGate interface {
	PrepareOverlay(context.Context, fabric.OverlayConfig, overlayproto.Task, func(context.Context) error) (overlayproto.Receipt, error)
	ProgramOverlay(context.Context, fabric.OverlayConfig, overlayproto.Task) (overlayproto.Receipt, error)
	ReleaseOverlay(context.Context, fabric.OverlayConfig, overlayproto.Task, func(context.Context) error) (overlayproto.Receipt, error)
	LookupOverlay(context.Context, fabric.OverlayConfig, string, string) (overlayproto.Receipt, error)
}

func (m *Manager) approvedOverlay(profile string) (fabric.OverlayConfig, overlayGate, error) {
	p, ok := m.Config.OVSProfiles[profile]
	if !ok || p.OverlayConfig == "" {
		return fabric.OverlayConfig{}, nil, ErrUnsupported
	}
	load := m.loadOverlayConfig
	if load == nil {
		load = fabric.LoadOverlayConfig
	}
	cfg, err := load(p.OverlayConfig)
	if err != nil {
		return cfg, nil, err
	}
	baseLoad := m.loadOVSConfig
	if baseLoad == nil {
		baseLoad = fabric.LoadConfig
	}
	base, err := baseLoad(p.FabricConfig)
	if err != nil || cfg.Base != base || base.NodeID != m.Config.NodeID || base.Bridge == m.Config.Network.Bridge {
		return cfg, nil, ErrOwnership
	}
	if _, err = fabric.OverlayConfigSHA256(cfg); err != nil {
		return cfg, nil, err
	}
	if m.overlayFactory != nil {
		g, e := m.overlayFactory(base)
		return cfg, g, e
	}
	g, err := fabric.NewExecutor(base, fabric.OSRunner{})
	return cfg, g, err
}

func (m *Manager) overlayProfile(s overlayproto.Snapshot) (string, fabric.OverlayConfig, overlayGate, error) {
	for _, p := range s.Profiles {
		if p.NodeID != m.Config.NodeID {
			continue
		}
		c, g, e := m.approvedOverlay(p.ProfileID)
		if e != nil {
			return "", c, nil, e
		}
		sha, e := fabric.OverlayConfigSHA256(c)
		if e != nil || sha != p.ProfileSHA256 {
			return "", c, nil, ErrOwnership
		}
		return p.ProfileID, c, g, nil
	}
	return "", fabric.OverlayConfig{}, nil, ErrOwnership
}

// An epoch must describe the complete local inventory on the dedicated bridge,
// not an attacker-chosen subset. Disabled identities remain reserved and fenced.
// Every member is checked against the original immutable lease and node binding.
func (m *Manager) overlayInventory(profile string, s overlayproto.Snapshot) ([]Instance, map[string]bool, error) {
	return m.overlayInventoryMode(profile, s, false)
}

func (m *Manager) overlayInventoryMode(profile string, s overlayproto.Snapshot, recovery bool) ([]Instance, map[string]bool, error) {
	members := map[string]overlayproto.Member{}
	vpcs := map[string]overlayproto.VPC{}
	enabled := map[string]bool{}
	for _, v := range s.VPCs {
		vpcs[v.ID] = v
	}
	for _, member := range s.Members {
		if member.NodeID == m.Config.NodeID {
			members[member.InstanceID] = member
		}
	}
	var instances []Instance
	for _, i := range m.Ledger.Instances() {
		if i.Network.IsZero() || i.Network.ProfileID != profile || i.State == "deleted" {
			continue
		}
		n := i.Network
		member, ok := members[i.ID]
		v := vpcs[member.VPCID]
		if !ok || member.NetworkSHA256 != n.Digest() || member.LocalVPCID != n.VPCID || member.LeaseID != n.LeaseID || member.PoolID != n.PoolID || member.OwnerRef != i.OwnerRef || member.NodeID != n.NodeID || member.InterfaceID != n.InterfaceID || member.IPv4 != n.IPv4 || member.MAC != n.MAC || member.InboundMbps != n.InboundMbps || member.OutboundMbps != n.OutboundMbps || v.OwnerRef != n.OwnerRef || v.CIDR != n.CIDR || i.SourceFence != nil || i.TargetBinding != nil || !n.ValidFor(nodeproto.NodeTask{NodeID: m.Config.NodeID, OwnerRef: i.OwnerRef, InstanceID: i.ID, Resources: i.Resources}) {
			return nil, nil, ErrOwnership
		}
		if _, _, e := m.approvedOVS(n); e != nil {
			return nil, nil, e
		}
		// Overlay cannot resolve an unknown create/storage result by guessing power.
		if !recovery && (i.State == "uncertain" || i.State == "reserved" || m.Ledger.HasPendingInstance(i.ID, "")) {
			return nil, nil, errors.New("OVERLAY_INSTANCE_UNRESOLVED")
		}
		instances = append(instances, i)
		enabled[i.ID] = member.Enabled && i.State == "running"
		delete(members, i.ID)
	}
	for id, member := range members {
		if !member.Reserved {
			return nil, nil, ErrOwnership
		}
		if _, exists := m.Ledger.Instance(id); exists {
			return nil, nil, ErrOwnership
		}
		// No guest exists yet. This explicit reservation only authorizes a future
		// node/2 task with the exact frozen NetworkSHA256, never a callback now.
	}
	sort.Slice(instances, func(i, j int) bool { return instances[i].ID < instances[j].ID })
	return instances, enabled, nil
}

// fenceOVSInventory is called only AFTER the fabric has durably isolated the
// whole dedicated bridge. A failure does not imply isolation or permit resume.
func (m *Manager) fenceOVSInventory(ctx context.Context, instances []Instance, enabled map[string]bool) error {
	for _, i := range instances {
		if e := m.assertOwned(ctx, i); e != nil {
			return e
		}
		if e := m.ovsBootPolicy(ctx, i); e != nil {
			return e
		}
		state, e := m.state(ctx, i.Domain)
		if e != nil || state != "running" && state != "paused" && state != "shut off" || enabled[i.ID] && state == "shut off" {
			return ErrOwnership
		}
	}
	for _, i := range instances {
		state, e := m.state(ctx, i.Domain)
		if e != nil {
			return e
		}
		if state == "shut off" {
			continue
		}
		if state != "running" && state != "paused" {
			return ErrOwnership
		}
		if e = m.assertOwned(ctx, i); e != nil {
			return e
		}
		if _, e = m.virsh(ctx, "domif-setlink", i.Domain, i.MAC, "down"); e != nil {
			return e
		}
		if e = m.assertOVSLink(ctx, i, "down"); e != nil {
			return e
		}
		if state == "running" {
			if _, e = m.virsh(ctx, "suspend", i.Domain); e != nil {
				return e
			}
		}
		if state, e = m.state(ctx, i.Domain); e != nil || state != "paused" {
			return ErrOwnership
		}
	}
	return m.checkFencedInventory(ctx, instances, enabled)
}
func (m *Manager) checkFencedInventory(ctx context.Context, instances []Instance, enabled map[string]bool) error {
	for _, i := range instances {
		if e := m.assertOwned(ctx, i); e != nil {
			return e
		}
		if e := m.ovsBootPolicy(ctx, i); e != nil {
			return e
		}
		state, e := m.state(ctx, i.Domain)
		if e != nil {
			return e
		}
		if state == "shut off" && !enabled[i.ID] {
			continue
		}
		if state != "paused" {
			return ErrOwnership
		}
		if e = m.assertOVSLink(ctx, i, "down"); e != nil {
			return e
		}
	}
	return nil
}
func (m *Manager) releaseOVSInventory(ctx context.Context, instances []Instance, enabled map[string]bool) error {
	if e := m.checkFencedInventory(ctx, instances, enabled); e != nil {
		return e
	}
	for _, i := range instances {
		if !enabled[i.ID] {
			continue
		}
		if e := m.assertOwned(ctx, i); e != nil {
			return e
		}
		if _, e := m.virsh(ctx, "domif-setlink", i.Domain, i.MAC, "up"); e != nil {
			return e
		}
		if e := m.assertOVSLink(ctx, i, "up"); e != nil {
			return e
		}
		if _, e := m.virsh(ctx, "resume", i.Domain); e != nil {
			return e
		}
		if state, e := m.state(ctx, i.Domain); e != nil || state != "running" {
			return ErrOwnership
		}
		if e := m.assertOwned(ctx, i); e != nil {
			return e
		}
	}
	return nil
}
func (m *Manager) ApplyOverlay(ctx context.Context, t overlayproto.Task) (overlayproto.Receipt, error) {
	_, sha, e := t.BytesAndDigest()
	if e != nil || t.NodeID != m.Config.NodeID {
		return overlayproto.Receipt{}, overlayproto.ErrInput
	}
	m.admission.Lock()
	defer m.admission.Unlock()
	if m.active || m.stopping || m.Config.Maintenance {
		return overlayproto.Receipt{}, errors.New("NODE_BUSY_OR_MAINTENANCE")
	}
	profile, c, g, e := m.overlayProfile(t.Snapshot)
	if e != nil {
		return overlayproto.Receipt{}, e
	}
	// Preserve the exact node-side task before fabric can acknowledge a phase.
	// A fabric receipt alone cannot prove the node recovery journal committed.
	if e = m.saveOverlayNodeTask(t); e != nil {
		return overlayproto.Receipt{}, e
	}
	// Exact receipts are historical outcomes, not a cached live network permit.
	if r, _ := g.LookupOverlay(ctx, c, t.OperationID, sha); r.Matches(t, sha) {
		return m.visibleOverlayReceipt(t, r), nil
	}
	var instances []Instance
	var enabled map[string]bool
	validate := func(ctx context.Context) error {
		var err error
		instances, enabled, err = m.overlayInventory(profile, t.Snapshot)
		return err
	}
	var r overlayproto.Receipt
	if t.Recovery != nil {
		r, instances, e = m.applyOverlayRecovery(ctx, profile, c, g, t)
	} else {
		switch t.Phase {
		case "prepare":
			r, e = g.PrepareOverlay(ctx, c, t, func(ctx context.Context) error {
				if e := validate(ctx); e != nil {
					return e
				}
				return m.fenceOVSInventory(ctx, instances, enabled)
			})
		case "program":
			if e = validate(ctx); e == nil {
				e = m.checkFencedInventory(ctx, instances, enabled)
			}
			if e == nil {
				r, e = g.ProgramOverlay(ctx, c, t)
			}
		case "release":
			r, e = g.ReleaseOverlay(ctx, c, t, func(ctx context.Context) error {
				if e := validate(ctx); e != nil {
					return e
				}
				return m.releaseOVSInventory(ctx, instances, enabled)
			})
		default:
			e = overlayproto.ErrInput
		}
	}
	if e != nil {
		if len(instances) == 0 {
			for _, i := range m.Ledger.Instances() {
				if !i.Network.IsZero() && i.Network.ProfileID == profile && i.State != "deleted" {
					instances = append(instances, i)
				}
			}
		}
		for _, i := range instances {
			m.fenceOVSGuest(i)
		}
	}
	return r, e
}
func (m *Manager) LookupOverlay(ctx context.Context, id, sha string) (overlayproto.Receipt, error) {
	if !nodeproto.ValidID(id) || !overlayproto.ValidSHA(sha) {
		return overlayproto.Receipt{}, overlayproto.ErrInput
	}
	m.admission.Lock()
	defer m.admission.Unlock()
	profiles := make([]string, 0, len(m.Config.OVSProfiles))
	for id := range m.Config.OVSProfiles {
		profiles = append(profiles, id)
	}
	sort.Strings(profiles)
	for _, profile := range profiles {
		c, g, e := m.approvedOverlay(profile)
		if e != nil {
			continue
		}
		r, _ := g.LookupOverlay(ctx, c, id, sha)
		if r.Valid() && r.OperationID == id && r.RequestSHA256 == sha && r.NodeID == m.Config.NodeID {
			t, e := m.readOverlayNodeTask(id)
			if e != nil || !r.Matches(t, sha) {
				return uncertainOverlayReceipt(r, "NODE_OVERLAY_TASK_UNCONFIRMED"), nil
			}
			return m.visibleOverlayReceipt(t, r), nil
		}
	}
	return overlayproto.Receipt{}, ErrNotFound
}
func (m *Manager) serveOverlay(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == "/v1/overlay/head" {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			respond(w, 405, errorBody("METHOD_NOT_ALLOWED"))
			return true
		}
		q := r.URL.Query()
		profile := q.Get("profile_id")
		if len(q) != 1 || len(q["profile_id"]) != 1 || !nodeproto.ValidNodeID(profile) {
			respond(w, 400, errorBody("INVALID_QUERY"))
			return true
		}
		m.admission.Lock()
		c, _, e := m.approvedOverlay(profile)
		var h overlayproto.Head
		if e == nil {
			h, e = fabric.ReadOverlayHead(c)
		}
		m.admission.Unlock()
		if e != nil {
			respond(w, 409, errorBody("OVERLAY_HEAD_UNCONFIRMED"))
		} else {
			respond(w, 200, h)
		}
		return true
	}
	const path = "/v1/overlay/tasks"
	if r.URL.Path != path && !strings.HasPrefix(r.URL.Path, path+"/") {
		return false
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		respond(w, 400, errorBody("INVALID_QUERY"))
		return true
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	if r.URL.Path == path && r.Method == http.MethodPost {
		media, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if e != nil || media != "application/json" || r.Header.Get("Content-Encoding") != "" {
			respond(w, 415, errorBody("JSON_REQUIRED"))
			return true
		}
		raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, overlayproto.MaxBytes))
		t, de := overlayproto.DecodeTask(raw)
		if e != nil || de != nil || t.NodeID != m.Config.NodeID || overlayproto.Digest(raw) != r.Header.Get("X-Request-SHA256") {
			respond(w, 400, errorBody("INVALID_OVERLAY_TASK"))
			return true
		}
		result, e := m.ApplyOverlay(ctx, t)
		if result.Matches(t, overlayproto.Digest(raw)) {
			respond(w, 200, result)
		} else if e != nil {
			respond(w, 409, errorBody("OVERLAY_OUTCOME_UNCONFIRMED"))
		} else {
			respond(w, 503, errorBody("OVERLAY_OUTCOME_UNCONFIRMED"))
		}
		return true
	}
	if strings.HasPrefix(r.URL.Path, path+"/") && r.Method == http.MethodGet {
		id := strings.TrimPrefix(r.URL.Path, path+"/")
		result, e := m.LookupOverlay(ctx, id, r.Header.Get("X-Request-SHA256"))
		if e != nil {
			respond(w, 404, errorBody("OVERLAY_RECEIPT_UNCONFIRMED"))
		} else {
			respond(w, 200, result)
		}
		return true
	}
	w.Header().Set("Allow", "GET, POST")
	respond(w, 405, errorBody("METHOD_NOT_ALLOWED"))
	return true
}

type overlayLifecycleGate interface {
	OverlayActivate(context.Context, fabric.OverlayConfig, fabric.ActivationIntent, string, func(context.Context) error, func(context.Context) error) (fabric.LiveVerification, error)
	OverlayDeactivate(context.Context, fabric.OverlayConfig, fabric.ActivationIntent, string, func(context.Context) error) (fabric.LiveVerification, error)
	OverlayCheck(context.Context, fabric.OverlayConfig, fabric.ActivationIntent, string) (fabric.LiveVerification, error)
}
type overlayLifecycleAdapter struct {
	cfg        fabric.OverlayConfig
	gate       overlayLifecycleGate
	bindingSHA string
}

func (g overlayLifecycleAdapter) Activate(ctx context.Context, in fabric.ActivationIntent, bootstrap, release func(context.Context) error) (fabric.LiveVerification, error) {
	return g.gate.OverlayActivate(ctx, g.cfg, in, g.bindingSHA, bootstrap, release)
}
func (g overlayLifecycleAdapter) Deactivate(ctx context.Context, in fabric.ActivationIntent, stop func(context.Context) error) (fabric.LiveVerification, error) {
	return g.gate.OverlayDeactivate(ctx, g.cfg, in, g.bindingSHA, stop)
}
func (g overlayLifecycleAdapter) Check(ctx context.Context, in fabric.ActivationIntent) (fabric.LiveVerification, error) {
	return g.gate.OverlayCheck(ctx, g.cfg, in, g.bindingSHA)
}

// The controller stages a reserved member and completes all-node release before
// dispatching its original node/2 create. Reject an early call before reserving
// VM files or changing its local state to uncertain.
func (m *Manager) checkOverlayAdmission(t nodeproto.NodeTask) error {
	if t.Network.IsZero() || m.Config.OVSProfiles[t.Network.ProfileID].OverlayConfig == "" {
		return nil
	}
	c, _, e := m.approvedOverlay(t.Network.ProfileID)
	if e != nil {
		return e
	}
	read := m.readOverlaySnapshot
	if read == nil {
		read = fabric.ReadOverlaySnapshot
	}
	snapshot, state, e := read(c)
	if e != nil || state != "applied" {
		return ErrOwnership
	}
	for _, member := range snapshot.Members {
		if member.NodeID != m.Config.NodeID || member.InstanceID != t.InstanceID {
			continue
		}
		if member.NetworkSHA256 != t.Network.Digest() || member.LocalVPCID != t.Network.VPCID || member.LeaseID != t.Network.LeaseID || member.PoolID != t.Network.PoolID || member.OwnerRef != t.OwnerRef {
			return ErrOwnership
		}
		if (t.Action == "create" || t.Action == "start") && !member.Enabled {
			return ErrOwnership
		}
		return nil
	}
	return ErrOwnership
}
