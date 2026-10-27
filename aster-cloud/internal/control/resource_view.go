package control

import (
	"aster/billing/controllerapi"
	"aster/cloud/internal/nodeproto"
	"context"
	"net/http"
	"strings"
	"time"
)

// ResourceView is a new read-only resource observation contract, deliberately
// separate from the immutable six-field financial provisioning result.
type ResourceView struct {
	Protocol   string                  `json:"protocol"`
	ResourceID string                  `json:"resource_id"`
	OwnerRef   string                  `json:"owner_ref"`
	Hostname   string                  `json:"hostname"`
	State      string                  `json:"state"`
	NodeID     string                  `json:"node_id"`
	Resources  controllerapi.Resources `json:"resources"`
	UpdatedAt  time.Time               `json:"updated_at"`
}

func (a App) resourceView(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		failure(w, 405, "METHOD_NOT_ALLOWED")
		return
	}
	instance := strings.TrimPrefix(r.URL.Path, "/v1/resources/")
	owner := r.Header.Values("X-Aster-Owner-Ref")
	if !nodeproto.ValidID(instance) || len(owner) != 1 || !nodeproto.ValidID(owner[0]) {
		failure(w, 404, "NOT_FOUND")
		return
	}
	store, ok := a.Store.(interface {
		Instance(context.Context, string) (Instance, error)
	})
	if !ok {
		failure(w, 503, "STORAGE_UNAVAILABLE")
		return
	}
	v, e := store.Instance(r.Context(), instance)
	if e != nil || v.OwnerRef != owner[0] {
		failure(w, 404, "NOT_FOUND")
		return
	}
	output(w, 200, ResourceView{Protocol: "aster.resource/1", ResourceID: v.ID, OwnerRef: v.OwnerRef, Hostname: v.Hostname, State: v.State, NodeID: v.NodeID, Resources: v.Resources, UpdatedAt: v.UpdatedAt})
}
