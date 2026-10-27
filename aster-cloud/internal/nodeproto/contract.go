// Package nodeproto defines the authenticated control-to-KVM-node wire contract.
package nodeproto

import (
	"aster/billing/controllerapi"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
)

const Protocol = "aster.node/1"

var ErrInvalid = errors.New("invalid node task")
var hexID = regexp.MustCompile(`^[0-9a-f]{32}$`)
var nodeID = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
var hostname = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var digest = regexp.MustCompile(`^[0-9a-f]{64}$`)

type NodeTask struct {
	DirectPublic DirectPublicBinding     `json:"direct_public,omitzero"`
	Network      NetworkBinding          `json:"network,omitzero"`
	Protocol     string                  `json:"protocol"`
	OperationID  string                  `json:"operation_id"`
	NodeID       string                  `json:"node_id"`
	Action       string                  `json:"action"`
	InstanceID   string                  `json:"instance_id"`
	OwnerRef     string                  `json:"owner_ref"`
	Hostname     string                  `json:"hostname"`
	Resources    controllerapi.Resources `json:"resources"`
	// Delete additionally requires the operator-configured allow_delete and this exact ID.
	ConfirmInstanceID string `json:"confirm_instance_id,omitempty"`
}

type NodeResult struct {
	Protocol      string `json:"protocol"`
	OperationID   string `json:"operation_id"`
	RequestSHA256 string `json:"request_sha256"`
	Status        string `json:"status"` // accepted, succeeded, rejected, uncertain
	InstanceID    string `json:"instance_id"`
}

func ValidID(value string) bool     { return hexID.MatchString(value) }
func ValidNodeID(value string) bool { return nodeID.MatchString(value) }
func (t NodeTask) Valid() bool {
	if (t.Protocol != Protocol && t.Protocol != NetworkProtocol && t.Protocol != DirectPublicProtocol) || !ValidID(t.OperationID) || !ValidNodeID(t.NodeID) || !ValidID(t.InstanceID) || !ValidID(t.OwnerRef) || !hostname.MatchString(t.Hostname) {
		return false
	}
	if t.Protocol != DirectPublicProtocol && !t.DirectPublic.IsZero() || t.Protocol == DirectPublicProtocol && (!t.Network.IsZero() || !t.DirectPublic.ValidFor(t)) || t.Protocol == Protocol && !t.Network.IsZero() || t.Protocol == NetworkProtocol && !t.Network.ValidFor(t) {
		return false
	}
	switch t.Action {
	case "create", "start", "shutdown", "reboot", "force_off":
		return t.ConfirmInstanceID == ""
	case "public_adopt", "public_detach":
		return t.Protocol == DirectPublicProtocol && t.ConfirmInstanceID == t.InstanceID
	case "delete":
		return t.ConfirmInstanceID == t.InstanceID
	default:
		return false
	}
}
func Digest(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func (t NodeTask) BytesAndDigest() ([]byte, string, error) {
	if !t.Valid() {
		return nil, "", ErrInvalid
	}
	raw, err := json.Marshal(t)
	if err != nil {
		return nil, "", ErrInvalid
	}
	return raw, Digest(raw), nil
}
func (r NodeResult) Matches(t NodeTask, requestSHA string) bool {
	if !t.Valid() || r.Protocol != t.Protocol || r.OperationID != t.OperationID || r.InstanceID != t.InstanceID || !digest.MatchString(requestSHA) || r.RequestSHA256 != requestSHA {
		return false
	}
	switch r.Status {
	case "accepted", "succeeded", "rejected", "uncertain":
		return true
	}
	return false
}

// DecodeTask rejects unknown, duplicate and wrong-case fields, including nested resources.
func DecodeTask(raw []byte) (NodeTask, error) {
	var task NodeTask
	if len(raw) == 0 || len(raw) > 65536 || !uniqueFields(raw) {
		return task, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&task) != nil || decoder.Decode(new(any)) != io.EOF || !task.Valid() {
		return NodeTask{}, ErrInvalid
	}
	// encoding/json's case-insensitive fallback is not a wire-contract feature.
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return NodeTask{}, ErrInvalid
	}
	allowed := map[string]bool{"protocol": true, "operation_id": true, "node_id": true, "action": true, "instance_id": true, "owner_ref": true, "hostname": true, "resources": true, "confirm_instance_id": true}
	if task.Protocol == NetworkProtocol {
		allowed["network"] = true
		n, err := decodeNetworkBinding(fields["network"])
		if err != nil || n != task.Network {
			return NodeTask{}, ErrInvalid
		}
	}
	if task.Protocol == DirectPublicProtocol {
		allowed["direct_public"] = true
		b, err := decodeDirectPublic(fields["direct_public"])
		if err != nil || b != task.DirectPublic {
			return NodeTask{}, ErrInvalid
		}
	}
	for key, value := range fields {
		if !allowed[key] || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return NodeTask{}, ErrInvalid
		}
	}
	if len(fields) < 8 {
		return NodeTask{}, ErrInvalid
	}
	var resources map[string]json.RawMessage
	if json.Unmarshal(fields["resources"], &resources) != nil {
		return NodeTask{}, ErrInvalid
	}
	kind := reflectResources()
	for key, value := range resources {
		if !kind[key] || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return NodeTask{}, ErrInvalid
		}
	}
	if len(resources) != len(kind) {
		return NodeTask{}, ErrInvalid
	}
	return task, nil
}
func reflectResources() map[string]bool {
	return map[string]bool{"datacenter_id": true, "compute_node_id": true, "node_group_id": true, "image_id": true, "cpu_cores": true, "memory_mib": true, "system_disk_gib": true, "system_storage_id": true, "data_disk_gib": true, "data_storage_id": true, "network_type": true, "bandwidth_mbps": true, "inbound_bandwidth_mbps": true, "transfer_gib": true, "traffic_direction": true, "ipv4_count": true, "ipv6_count": true}
}
func uniqueFields(raw []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		d, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch d {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return ErrInvalid
				}
				seen[name] = true
				if err = walk(); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
		default:
			return ErrInvalid
		}
		_, err = decoder.Token()
		return err
	}
	return walk() == nil && decoder.Decode(new(any)) == io.EOF
}
