package hypervisor

import (
	"aster/billing/controllerapi"
	"aster/cloud/internal/nodeproto"
	"context"
	"encoding/xml"
	"strconv"
	"time"
)

func effectiveBandwidth(i Instance) controllerapi.Resources {
	r := i.Resources
	n := i.TrafficControl.ThrottleMbps
	if n > 0 {
		if r.InboundBandwidthMbps == 0 || r.InboundBandwidthMbps > n {
			r.InboundBandwidthMbps = n
		}
		if r.BandwidthMbps == 0 || r.BandwidthMbps > n {
			r.BandwidthMbps = n
		}
	}
	return r
}
func (m *Manager) trafficAdmission(t nodeproto.NodeTask, i Instance) string {
	if i.TrafficControl.Suspended && (t.Action == "start" || t.Action == "reboot" || t.Action == "reinstall" || t.Action == "reset_password" || t.Action == "rescue_enter" || t.Action == "rescue_exit" || t.Action == "unsuspend" && t.Guest.Params.StartAfter) {
		return "TRAFFIC_SUSPENDED"
	}
	if t.Action != nodeproto.TrafficControlAction {
		return ""
	}
	if t.TrafficControl.ExpiresAt != "" {
		end, _ := time.Parse(time.RFC3339Nano, t.TrafficControl.ExpiresAt)
		if !time.Now().UTC().Before(end) {
			return "TRAFFIC_POLICY_EXPIRED"
		}
	}
	if !m.Config.AllowTrafficAccounting {
		return "TRAFFIC_ACCOUNTING_DISABLED"
	}
	if t.TrafficControl.ThrottleMbps > 0 && (!i.Network.IsZero() || !m.Config.AllowBandwidthLimits || i.MAC == "") {
		return "TRAFFIC_THROTTLE_UNSUPPORTED"
	}
	if i.Rescue != nil || i.GuestChange != nil {
		return "GUEST_RECOVERY_REQUIRED"
	}
	return ""
}
func (m *Manager) executeTrafficControl(ctx context.Context, t nodeproto.NodeTask, i Instance) (nodeproto.NodeResult, error) {
	finish := func(status, code string) (nodeproto.NodeResult, error) {
		r, e := m.Ledger.Finish(t.OperationID, status, code, &i)
		m.logOutcome(t, r, code, e == nil)
		return r, e
	}
	if e := m.assertOwned(ctx, i); e != nil {
		i.State = "uncertain"
		return finish("uncertain", "OWNERSHIP_UNCONFIRMED")
	}
	state, e := m.state(ctx, i.Domain)
	if e != nil {
		i.State = "uncertain"
		return finish("uncertain", "STATE_UNCONFIRMED")
	}
	before := i
	i.TrafficControl = t.TrafficControl
	i.State = "uncertain"
	if _, e = m.Ledger.Finish(t.OperationID, "accepted", "TRAFFIC_POLICY_INTENT", &i); e != nil {
		return nodeproto.NodeResult{}, e
	}
	if i.TrafficControl.Suspended {
		e = m.guestStop(ctx, t, before)
		if e == nil {
			state = "shut off"
		}
	}
	if e == nil && i.Network.IsZero() && effectiveBandwidth(before) != effectiveBandwidth(i) {
		r := effectiveBandwidth(i)
		args := []string{"domiftune", i.Domain, i.MAC, "--inbound", strconv.FormatUint(bandwidthKiB(r.InboundBandwidthMbps), 10), "--outbound", strconv.FormatUint(bandwidthKiB(r.BandwidthMbps), 10), "--config"}
		if state != "shut off" {
			args = append(args, "--live")
		}
		_, e = m.virsh(ctx, args...)
		if e == nil {
			e = m.assertOwned(ctx, i)
		}
		if e == nil {
			var raw []byte
			raw, e = m.virsh(ctx, "dumpxml", i.Domain, "--inactive")
			var domain domainXML
			if e == nil && (xml.Unmarshal(raw, &domain) != nil || len(domain.Devices.Interfaces) != 1 || !bandwidthMatches(domain.Devices.Interfaces[0].Bandwidth, bandwidthFor(effectiveBandwidth(i)))) {
				e = ErrOwnership
			}
		}
	}
	if e != nil {
		return finish("uncertain", "TRAFFIC_POLICY_UNCONFIRMED")
	}
	i.State = state
	return finish("succeeded", "TRAFFIC_POLICY_APPLIED")
}
