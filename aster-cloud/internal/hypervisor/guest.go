package hypervisor

import (
	"aster/billing/controllerapi"
	"aster/cloud/internal/nodeproto"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type GuestConfig struct {
	Enabled        bool              `json:"enabled"`
	Families       map[string]string `json:"families,omitempty"`
	RescueImages   []string          `json:"rescue_images,omitempty"`
	RescueWritable bool              `json:"rescue_writable,omitempty"`
}

func (g GuestConfig) validate(images map[string]Image) error {
	for id, family := range g.Families {
		if _, ok := images[id]; !ok || family != "linux" && family != "windows" {
			return ErrUnsupported
		}
	}
	seen := map[string]bool{}
	for _, id := range g.RescueImages {
		if _, ok := images[id]; !ok || seen[id] || g.Families[id] != "linux" {
			return ErrUnsupported
		}
		seen[id] = true
	}
	return nil
}

func (c Config) guestImageApprovals() map[string]nodeproto.GuestImageApproval {
	if !c.Guest.Enabled {
		return nil
	}
	approved := map[string]nodeproto.GuestImageApproval{}
	for id, family := range c.Guest.Families {
		image, ok := c.Images[id]
		if !ok || family != "linux" && family != "windows" {
			continue
		}
		rescue := false
		for _, rescueID := range c.Guest.RescueImages {
			rescue = rescue || rescueID == id
		}
		approved[id] = nodeproto.GuestImageApproval{SHA256: image.SHA256, Family: family, Rescue: rescue}
	}
	return approved
}

type RescueState struct {
	OperationID string `json:"operation_id"`
	ImageID     string `json:"image_id"`
	ImageSHA256 string `json:"image_sha256"`
	Writable    bool   `json:"writable"`
}
type GuestChange struct {
	OperationID       string                  `json:"operation_id"`
	Action            string                  `json:"action"`
	Phase             string                  `json:"phase"`
	PreviousResources controllerapi.Resources `json:"previous_resources"`
	PreviousSeed      bool                    `json:"previous_seed"`
	WasRunning        bool                    `json:"was_running"`
}

func validateGuestInstance(i Instance, schema int) error {
	if (i.Suspended || i.Rescue != nil || i.GuestChange != nil) && schema < 7 {
		return errors.New("guest lifecycle needs journal schema 7")
	}
	if i.Rescue != nil && (!nodeproto.ValidID(i.Rescue.OperationID) || !safeName.MatchString(i.Rescue.ImageID) || !hashString(i.Rescue.ImageSHA256)) {
		return ErrOwnership
	}
	if g := i.GuestChange; g != nil && (!nodeproto.ValidID(g.OperationID) || !nodeproto.GuestAction(g.Action) || g.Phase == "") {
		return ErrOwnership
	}
	return nil
}
func (m *Manager) guestAdmission(t nodeproto.NodeTask, i Instance) string {
	if i.Suspended && (t.Action == "start" || t.Action == "reboot" || t.Action == "reinstall" || t.Action == "reset_password" || t.Action == "rescue_enter" || t.Action == "rescue_exit") {
		return "INSTANCE_SUSPENDED"
	}
	if !nodeproto.GuestAction(t.Action) {
		return ""
	}
	if !m.Config.Guest.Enabled {
		return "GUEST_LIFECYCLE_DISABLED"
	}
	// OVS suspension uses its existing fenced stop/start path. Disk redefinition
	// awaits an OVS-bound lifecycle contract and is never silently flattened.
	if !i.Network.IsZero() && t.Action != "suspend" && t.Action != "unsuspend" {
		return "UNSUPPORTED_NETWORK"
	}
	if i.Rescue != nil && t.Action != "rescue_exit" && t.Action != "suspend" && t.Action != "unsuspend" {
		return "RESCUE_ACTIVE"
	}
	if i.GuestChange != nil {
		return "GUEST_RECOVERY_REQUIRED"
	}
	if t.Guest.PasswordRequired && t.Guest.Params.Password == "" {
		return "SECRET_UNAVAILABLE"
	}
	if t.Action == "reset_password" && m.Config.Guest.Families[i.Resources.ImageID] != "linux" {
		return "UNSUPPORTED_GUEST"
	}
	if t.Action == "reinstall" || t.Action == "rescue_enter" {
		p := t.Guest.Params
		image, ok := m.Config.Images[p.ImageID]
		if !ok || image.SHA256 != t.Guest.ImageSHA256 {
			return "IMAGE_NOT_APPROVED"
		}
		if m.Config.Guest.Families[p.ImageID] != "linux" {
			return "UNSUPPORTED_GUEST"
		}
		if t.Action == "rescue_enter" {
			approved := false
			for _, id := range m.Config.Guest.RescueImages {
				approved = approved || id == p.ImageID
			}
			if !approved {
				return "RESCUE_IMAGE_NOT_APPROVED"
			}
		}
	}
	if t.Action == "rescue_exit" && i.Rescue == nil {
		return "RESCUE_NOT_ACTIVE"
	}
	if t.Action == "resize" {
		p := t.Guest.Params
		proposed := i.Resources
		if p.SetBandwidth {
			proposed.BandwidthMbps = p.BandwidthMbps
			proposed.InboundBandwidthMbps = p.InboundBandwidthMbps
		}
		if !m.Config.allowsBandwidth(proposed) {
			return "UNSUPPORTED_BANDWIDTH"
		}
		if p.DiskGB < i.Resources.SystemDiskGiB {
			return "DISK_SHRINK_FORBIDDEN"
		}
		cpu, mem, disk := p.CPUCores, p.MemoryMB, p.DiskGB
		for _, other := range m.Ledger.Instances() {
			if other.ID != i.ID && other.State != "deleted" && !other.PublicRetired {
				cpu += other.Resources.CPUCores
				mem += other.Resources.MemoryMiB
				disk += other.Resources.SystemDiskGiB
			}
		}
		if cpu > m.Config.CPUAllocationLimit || mem > m.Config.MemoryAllocationLimitMiB || disk > m.Config.DiskAllocationLimitGiB {
			return "ALLOCATION_LIMIT"
		}
	}
	return ""
}
func (m *Manager) guestCheckpoint(t nodeproto.NodeTask, i Instance, phase string) error {
	if i.GuestChange != nil {
		i.GuestChange.Phase = phase
	}
	i.State = "uncertain"
	_, e := m.Ledger.Finish(t.OperationID, "accepted", "GUEST_"+phase, &i)
	return e
}
func (m *Manager) guestStop(ctx context.Context, t nodeproto.NodeTask, i Instance) error {
	state, e := m.state(ctx, i.Domain)
	if e != nil {
		return e
	}
	if state == "shut off" {
		return restoreRescueDiskOwner(i)
	}
	if !nodeproto.ValidObservedState(state) {
		return ErrOwnership
	}
	if !i.Network.IsZero() {
		raw, sha, _ := t.BytesAndDigest()
		_ = raw
		return m.stopOVS(ctx, i, t, sha, "destroy")
	}
	if _, e = m.virsh(ctx, "destroy", i.Domain); e != nil {
		return e
	}
	_, e = m.observePower(ctx, i.Domain, "shut off", 10*time.Second)
	if e == nil {
		e = restoreRescueDiskOwner(i)
	}
	return e
}
func (m *Manager) guestStart(ctx context.Context, t nodeproto.NodeTask, i Instance) error {
	if i.Suspended {
		return ErrOwnership
	}
	if e := m.assertOwned(ctx, i); e != nil {
		return e
	}
	if !i.Network.IsZero() {
		_, sha, _ := t.BytesAndDigest()
		return m.startOVS(ctx, i, t, sha)
	}
	if i.IPv4 != "" {
		if e := m.verifyNetwork(ctx); e != nil {
			return e
		}
	}
	if _, e := m.virsh(ctx, "start", i.Domain); e != nil {
		return e
	}
	_, e := m.observePower(ctx, i.Domain, "running", 10*time.Second)
	return e
}
func (m *Manager) redefineGuest(ctx context.Context, i Instance) error {
	raw, e := m.domainXML(i)
	if e != nil {
		return e
	}
	path := filepath.Join(i.Directory, "domain.xml")
	// Atomic root-owned definition publication; never overwrite a link.
	if e = NoSymlinkPath(path); e != nil {
		return e
	}
	temp := path + ".guest"
	if e = writeExclusive(temp, raw); e != nil {
		return e
	}
	defer os.Remove(temp)
	if e = os.Rename(temp, path); e != nil {
		return e
	}
	if _, e = m.virsh(ctx, "define", path); e != nil {
		return e
	}
	return m.assertOwned(ctx, i)
}
func (m *Manager) executeGuest(ctx context.Context, t nodeproto.NodeTask, i Instance, state string) (nodeproto.NodeResult, error) {
	original := cloneInstance(i)
	finish := func(status, code string, next Instance) (nodeproto.NodeResult, error) {
		r, e := m.Ledger.Finish(t.OperationID, status, code, &next)
		m.logOutcome(t, r, code, e == nil)
		return r, e
	}
	reject := func(code string) (nodeproto.NodeResult, error) { return finish("rejected", code, original) }
	if state != "running" && state != "shut off" && t.Action != "suspend" {
		return reject("DOMAIN_STATE_REJECTED")
	}
	if t.Action == "resize" && state != "shut off" {
		return reject("RESIZE_REQUIRES_STOPPED")
	}
	if code := m.guestAdmission(t, i); code != "" {
		return reject(code)
	}
	if t.Action == "resize" {
		info, e := m.qcowInfo(ctx, i.Disk, m.Config.Images[i.Resources.ImageID].Path)
		if e != nil || info.VirtualSize > uint64(i.Resources.SystemDiskGiB)<<30 || info.Backing != "" && info.Backing != m.Config.Images[i.Resources.ImageID].Path {
			return reject("DISK_VERIFICATION_FAILED")
		}
	}
	if t.Action == "reinstall" || t.Action == "rescue_enter" {
		if e := m.verifyGuestImage(ctx, t.Guest.Params.ImageID, t.Guest.ImageSHA256, i.Resources.SystemDiskGiB); e != nil {
			return reject("IMAGE_VERIFICATION_FAILED")
		}
	}
	i.GuestChange = &GuestChange{OperationID: t.OperationID, Action: t.Action, Phase: "INTENT", PreviousResources: i.Resources, PreviousSeed: i.Seed != "", WasRunning: state == "running"}
	uncertain := func(code string) (nodeproto.NodeResult, error) {
		i.State = "uncertain"
		return finish("uncertain", code, i)
	}
	// The persisted flag precedes destroy, blocking all starts even after a crash.
	if t.Action == "suspend" {
		i.Suspended = true
	}
	if e := m.guestCheckpoint(t, i, "INTENT"); e != nil {
		return uncertain("GUEST_INTENT_UNCONFIRMED")
	}
	var e error
	switch t.Action {
	case "suspend":
		e = m.guestStop(ctx, t, i)
		i.State = "shut off"
	case "unsuspend":
		i.Suspended = false
		if e = m.guestCheckpoint(t, i, "UNSUSPEND"); e == nil && t.Guest.Params.StartAfter && state != "running" {
			e = m.guestStart(ctx, t, i)
			i.State = "running"
		} else {
			i.State = state
		}
	case "resize":
		p := t.Guest.Params
		if p.DiskGB > i.Resources.SystemDiskGiB {
			_, e = m.Runner.Run(ctx, QemuImg, "resize", "-f", "qcow2", i.Disk, fmt.Sprintf("%dG", p.DiskGB))
			if e == nil {
				var info qcowInformation
				info, e = m.qcowInfo(ctx, i.Disk, m.Config.Images[i.Resources.ImageID].Path)
				if e == nil && (info.VirtualSize != uint64(p.DiskGB)<<30 || info.Backing != "" && info.Backing != m.Config.Images[i.Resources.ImageID].Path) {
					e = ErrOwnership
				}
			}
		}
		if e == nil {
			i.Resources.CPUCores = p.CPUCores
			i.Resources.MemoryMiB = p.MemoryMB
			i.Resources.SystemDiskGiB = p.DiskGB
			if p.SetBandwidth {
				i.Resources.BandwidthMbps = p.BandwidthMbps
				i.Resources.InboundBandwidthMbps = p.InboundBandwidthMbps
			}
			e = m.guestCheckpoint(t, i, "RESIZED")
		}
		if e == nil {
			e = m.redefineGuest(ctx, i)
		}
		i.State = "shut off"
	case "reset_password":
		if e = m.guestStop(ctx, t, i); e == nil {
			e = m.resetGuestPassword(ctx, i, t.Guest.Params.Password)
		}
		if e == nil {
			e = m.guestStart(ctx, t, i)
		}
		i.State = "running"
	case "reinstall":
		i, e = m.reinstall(ctx, t, i)
		if e != nil {
			if restored, ok := m.rollbackReinstall(ctx, t, i); ok {
				return finish("rejected", "REINSTALL_ROLLED_BACK", restored)
			}
		}
	case "rescue_enter":
		i, e = m.enterRescue(ctx, t, i)
	case "rescue_exit":
		i, e = m.exitRescue(ctx, t, i)
	}
	if e != nil {
		return uncertain("GUEST_OUTCOME_UNCERTAIN")
	}
	i.GuestChange = nil
	return finish("succeeded", "", i)
}
