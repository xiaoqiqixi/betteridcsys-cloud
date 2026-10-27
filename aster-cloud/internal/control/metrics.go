package control

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"net/http"
	"time"
)

// MetricsReader deliberately has no mutation method. A monitoring refresh must
// never become an operation dispatch, reconciliation or billable traffic write.
type MetricsReader interface {
	Metrics(context.Context, string) (nodeproto.InstanceMetrics, error)
}

func (c *NodeClient) Metrics(ctx context.Context, instance string) (nodeproto.InstanceMetrics, error) {
	if !nodeproto.ValidID(instance) {
		return nodeproto.InstanceMetrics{}, ErrInput
	}
	raw, status, err := c.callStatus(ctx, http.MethodGet, "/v1/instances/"+instance+"/metrics", nil, "")
	if err != nil {
		return nodeproto.InstanceMetrics{}, err
	}
	var failure struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if status == http.StatusConflict && strict(raw, &failure) && failure.Error.Code == "LIVE_INSTANCE_METRICS_UNCONFIRMED" {
		return nodeproto.InstanceMetrics{}, ErrState
	}
	if status != http.StatusOK {
		return nodeproto.InstanceMetrics{}, ErrUnavailable
	}
	v, err := nodeproto.DecodeInstanceMetrics(raw)
	if err != nil || v.NodeID != c.profile.ID || v.InstanceID != instance || !metricsFresh(v.ObservedAt, time.Now().UTC()) {
		return nodeproto.InstanceMetrics{}, ErrUnavailable
	}
	return v, nil
}

func metricsFresh(value string, now time.Time) bool {
	at, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && !at.After(now.Add(5*time.Second)) && now.Sub(at) <= time.Minute
}

func metricsBound(v nodeproto.InstanceMetrics, instance Instance) bool {
	return v.Validate() && v.InstanceID == instance.ID && v.NodeID == instance.NodeID &&
		v.OwnerRef == instance.OwnerRef && v.Hostname == instance.Hostname &&
		v.VCPUs == instance.Resources.CPUCores && metricsFresh(v.ObservedAt, time.Now().UTC())
}

func (c Console) instanceMetrics(w http.ResponseWriter, r *http.Request, id string) {
	ctx := r.Context()
	instance, err := c.Store.Instance(ctx, id)
	if err != nil {
		consoleError(w, err)
		return
	}
	if instance.State == "deleted" {
		consoleError(w, ErrNotFound)
		return
	}
	profile, ok := c.Config.Node(instance.NodeID)
	if !ok {
		consoleError(w, ErrState)
		return
	}
	var reader MetricsReader
	if c.MetricsRPC != nil {
		reader, err = c.MetricsRPC(ctx, profile)
	} else {
		reader, err = NewNodeClient(ctx, profile)
	}
	if err != nil || reader == nil {
		consoleError(w, ErrUnavailable)
		return
	}
	metrics, err := reader.Metrics(ctx, instance.ID)
	if err != nil {
		consoleError(w, err)
		return
	}
	if !metricsBound(metrics, instance) {
		consoleError(w, ErrUnavailable)
		return
	}
	// A cold migration/ownership change may finish while the remote GET is in
	// flight. Do not return a freshly sampled *old* node under the current ID.
	latest, err := c.Store.Instance(ctx, id)
	if err != nil || latest.State == "deleted" || latest.NodeID != instance.NodeID || latest.OwnerRef != instance.OwnerRef ||
		latest.Hostname != instance.Hostname || latest.Resources != instance.Resources {
		consoleError(w, ErrState)
		return
	}
	output(w, http.StatusOK, map[string]any{"metrics": metrics})
}
