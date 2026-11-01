package control

import (
	"aster/cloud/internal/identity"
	"aster/cloud/internal/nodeproto"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (c Console) instanceTraffic(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/console/v1/"), "/")
	if len(parts) != 3 || parts[0] != "instances" || parts[2] != "traffic" || !nodeproto.ValidID(parts[1]) {
		failure(w, 404, "NOT_FOUND")
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		failure(w, 400, "INVALID_QUERY")
		return
	}
	if r.Method == http.MethodPost {
		user, ok := identity.Actor(r.Context())
		if !ok || !user.Can("instances.manage") {
			failure(w, 403, "FORBIDDEN")
			return
		}
		var input consoleTrafficPolicy
		if !readConsoleJSON(w, r, &input) {
			return
		}
		p, e := input.policy()
		if e != nil {
			consoleError(w, e)
			return
		}
		if e := c.Store.SetTrafficPolicy(r.Context(), c.Config, user.ID, parts[1], p, time.Now().UTC()); e != nil {
			consoleError(w, e)
			return
		}
	} else if r.Method != http.MethodGet {
		failure(w, 405, "METHOD_NOT_ALLOWED")
		return
	}
	view, e := c.Store.TrafficView(r.Context(), parts[1], time.Now().UTC())
	if e != nil {
		consoleError(w, e)
		return
	}
	output(w, 200, consoleTraffic(view))
}

type consoleTrafficPolicy struct {
	ResetDay      int     `json:"reset_day"`
	Direction     string  `json:"direction"`
	LimitBytes    *string `json:"limit_bytes"`
	OveragePolicy string  `json:"overage_policy"`
}

func (p consoleTrafficPolicy) policy() (TrafficPolicy, error) {
	out := TrafficPolicy{ResetDay: p.ResetDay, Direction: p.Direction, OveragePolicy: p.OveragePolicy}
	if p.LimitBytes != nil {
		n, e := strconv.ParseUint(*p.LimitBytes, 10, 64)
		if e != nil || strconv.FormatUint(n, 10) != *p.LimitBytes {
			return out, ErrInput
		}
		out.LimitBytes = &n
	}
	if !out.Valid() {
		return out, ErrInput
	}
	return out, nil
}
func consoleTraffic(v TrafficView) any {
	p := consoleTrafficPolicy{ResetDay: v.Policy.ResetDay, Direction: v.Policy.Direction, OveragePolicy: v.Policy.OveragePolicy}
	if v.Policy.LimitBytes != nil {
		value := strconv.FormatUint(*v.Policy.LimitBytes, 10)
		p.LimitBytes = &value
	}
	return struct {
		TrafficView
		Policy consoleTrafficPolicy `json:"policy"`
	}{v, p}
}
