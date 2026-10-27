package billingconnector

import (
	"aster/billing/controllerapi"
	"bytes"
	"encoding/json"
	"io"
	"unicode/utf8"
)

// uniqueJSON rejects duplicate decoded keys (including escaped aliases), deep
// input, trailing values and invalid UTF-8 before typed decoding loses evidence.
func uniqueJSON(raw []byte) bool {
	if len(raw) == 0 || len(raw) > MaximumInput || !utf8.Valid(raw) {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) bool
	walk = func(depth int) bool {
		if depth > 8 {
			return false
		}
		token, err := d.Token()
		if err != nil {
			return false
		}
		switch token {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				name, ok := key.(string)
				if err != nil || !ok || seen[name] || !walk(depth+1) {
					return false
				}
				seen[name] = true
			}
			end, err := d.Token()
			return err == nil && end == json.Delim('}')
		case json.Delim('['):
			for d.More() {
				if !walk(depth + 1) {
					return false
				}
			}
			end, err := d.Token()
			return err == nil && end == json.Delim(']')
		}
		_, delimiter := token.(json.Delim)
		return !delimiter
	}
	if !walk(0) {
		return false
	}
	var trailing any
	return d.Decode(&trailing) == io.EOF
}

func object(raw []byte, required []string, nullable string) (map[string]json.RawMessage, bool) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil || len(fields) != len(required) {
		return nil, false
	}
	for _, key := range required {
		value, ok := fields[key]
		if !ok || key != nullable && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, false
		}
	}
	return fields, true
}

var productKeys = []string{"mode", "controller_id", "remote_product_id", "resources"}
var resourceKeys = []string{"datacenter_id", "compute_node_id", "node_group_id", "image_id", "cpu_cores", "memory_mib", "system_disk_gib", "system_storage_id", "data_disk_gib", "data_storage_id", "network_type", "bandwidth_mbps", "inbound_bandwidth_mbps", "transfer_gib", "traffic_direction", "ipv4_count", "ipv6_count"}
var requestKeys = []string{"protocol", "operation_id", "order_id", "owner_ref", "hostname", "configuration_revision", "configuration_sha256", "product"}

func productShape(raw []byte) bool {
	fields, ok := object(raw, productKeys, "resources")
	if !ok {
		return false
	}
	if !bytes.Equal(bytes.TrimSpace(fields["resources"]), []byte("null")) {
		_, ok = object(fields["resources"], resourceKeys, "")
	}
	return ok
}

func DecodeProduct(raw []byte) (controllerapi.ProductSpec, error) {
	var product controllerapi.ProductSpec
	if !uniqueJSON(raw) || !productShape(raw) || json.Unmarshal(raw, &product) != nil || !product.Valid() {
		return controllerapi.ProductSpec{}, controllerapi.ErrConfiguration
	}
	return product, nil
}

func DecodeRequest(raw []byte) (controllerapi.Request, error) {
	var request controllerapi.Request
	if !uniqueJSON(raw) {
		return request, controllerapi.ErrConfiguration
	}
	fields, ok := object(raw, requestKeys, "")
	if !ok || !productShape(fields["product"]) || json.Unmarshal(raw, &request) != nil || !request.Valid() {
		return controllerapi.Request{}, controllerapi.ErrConfiguration
	}
	return request, nil
}

func ReadInput(reader io.Reader) ([]byte, error) {
	if reader == nil {
		return nil, controllerapi.ErrConfiguration
	}
	raw, err := io.ReadAll(io.LimitReader(reader, MaximumInput+1))
	if err != nil || len(raw) == 0 || len(raw) > MaximumInput {
		return nil, controllerapi.ErrConfiguration
	}
	return raw, nil
}
