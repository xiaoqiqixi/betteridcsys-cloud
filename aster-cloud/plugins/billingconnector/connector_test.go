package billingconnector

import (
	"aster/billing/controllerapi"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

func fixtureRequest(t *testing.T) controllerapi.Request {
	t.Helper()
	product := controllerapi.ProductSpec{Mode: "preset", ControllerID: "primary", RemoteProductID: "small"}
	digest, err := product.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return controllerapi.Request{Protocol: controllerapi.Protocol, OperationID: strings.Repeat("a", 32), OrderID: strings.Repeat("b", 32), OwnerRef: strings.Repeat("c", 32), Hostname: "test-vm", ConfigurationRevision: 3, ConfigurationSHA256: digest, Product: product}
}

func fixtureResult(t *testing.T, request controllerapi.Request) controllerapi.Result {
	t.Helper()
	_, digest, err := request.BytesAndDigest()
	if err != nil {
		t.Fatal(err)
	}
	return controllerapi.Result{Protocol: controllerapi.Protocol, OperationID: request.OperationID, OrderID: request.OrderID, RequestSHA256: digest, Status: "accepted"}
}

func TestOfflineManifestAndProductValidation(t *testing.T) {
	manifest := Describe()
	if manifest.Protocol != controllerapi.Protocol || manifest.RuntimePlugin || manifest.MoneyOperations || manifest.AutomaticRetries || manifest.Kind != "external-resource-adapter" || !reflect.DeepEqual(manifest.Commands, []string{"manifest", "validate-product", "send", "lookup"}) {
		t.Fatal("manifest misrepresents this explicit resource adapter")
	}
	for _, product := range []controllerapi.ProductSpec{
		{Mode: "disabled"}, fixtureRequest(t).Product,
		{Mode: "custom", ControllerID: "primary", Resources: &controllerapi.Resources{ComputeNodeID: "node-a", ImageID: "ubuntu-22", CPUCores: 2, MemoryMiB: 4096, SystemDiskGiB: 40, NetworkType: "normal", TrafficDirection: "all", IPv4Count: 1}},
	} {
		raw, _ := json.Marshal(product)
		got, err := DecodeProduct(raw)
		if err != nil || !reflect.DeepEqual(got, product) {
			t.Fatal("published product contract changed", err)
		}
		validation, err := ValidateProduct(raw)
		digest, _ := product.Digest()
		if err != nil || validation.Status != "valid" || validation.Mode != product.Mode || validation.ConfigurationSHA256 != digest {
			t.Fatal("offline validation changed snapshot digest", err)
		}
	}
}

func TestStrictPreparedRequestAndProductParsing(t *testing.T) {
	request := fixtureRequest(t)
	raw, digest, _ := request.BytesAndDigest()
	got, err := DecodeRequest(raw)
	gotRaw, gotDigest, _ := got.BytesAndDigest()
	if err != nil || !reflect.DeepEqual(got, request) || !bytes.Equal(gotRaw, raw) || digest != gotDigest {
		t.Fatal("prepared request/order/operation/digest changed", err)
	}
	for name, body := range map[string]string{
		"duplicate":                   strings.Replace(string(raw), `"operation_id":`, `"operation_id":"`+request.OperationID+`","operation_id":`, 1),
		"escaped_duplicate":           strings.Replace(string(raw), `"operation_id":`, `"\u006fperation_id":"`+request.OperationID+`","operation_id":`, 1),
		"case_alias":                  strings.Replace(string(raw), `"operation_id":`, `"Operation_ID":`, 1),
		"unknown_url":                 strings.TrimSuffix(string(raw), "}") + `,"url":"https://wrong.invalid"}`,
		"root_path":                   strings.Replace(string(raw), `"product":`, `"root_path":"/private","product":`, 1),
		"command":                     strings.Replace(string(raw), `"product":`, `"command":"touch /private","product":`, 1),
		"null_hostname":               strings.Replace(string(raw), `"hostname":"test-vm"`, `"hostname":null`, 1),
		"null_optional_product_field": strings.Replace(string(raw), `"remote_product_id":"small"`, `"remote_product_id":null`, 1),
		"nested_duplicate":            strings.Replace(string(raw), `"mode":"preset"`, `"mode":"preset","mode":"preset"`, 1),
		"missing_null_resources":      strings.Replace(string(raw), `,"resources":null`, "", 1),
		"configuration_hash":          strings.Replace(string(raw), request.ConfigurationSHA256, strings.Repeat("0", 64), 1),
		"revision_float":              strings.Replace(string(raw), `"configuration_revision":3`, `"configuration_revision":3.0`, 1),
		"array":                       "[" + string(raw) + "]", "null": "null", "trailing": string(raw) + "{}", "invalid_utf8": string(raw) + string([]byte{0xff}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeRequest([]byte(body)); !errors.Is(err, controllerapi.ErrConfiguration) {
				t.Fatal("ambiguous or destination-bearing request accepted", err)
			}
		})
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	for key := range fields {
		t.Run("missing_"+key, func(t *testing.T) {
			copy := map[string]json.RawMessage{}
			for k, value := range fields {
				if k != key {
					copy[k] = value
				}
			}
			body, _ := json.Marshal(copy)
			if _, err := DecodeRequest(body); err == nil {
				t.Fatal("missing request field accepted")
			}
		})
	}
}

func TestResourceShapeCannotSmuggleSettingsOrOmitOptionalEmptyFields(t *testing.T) {
	product := controllerapi.ProductSpec{Mode: "custom", ControllerID: "primary", Resources: &controllerapi.Resources{ComputeNodeID: "node-a", ImageID: "ubuntu-22", CPUCores: 2, MemoryMiB: 4096, SystemDiskGiB: 40, NetworkType: "normal", TrafficDirection: "all", IPv4Count: 1}}
	raw, _ := json.Marshal(product)
	for name, body := range map[string]string{
		"unknown":          strings.Replace(string(raw), `"resources":{`, `"resources":{"endpoint":"https://bad.invalid",`, 1),
		"null_optional":    strings.Replace(string(raw), `"data_storage_id":""`, `"data_storage_id":null`, 1),
		"missing_optional": strings.Replace(string(raw), `,"data_storage_id":""`, "", 1),
		"counter_float":    strings.Replace(string(raw), `"cpu_cores":2`, `"cpu_cores":2.0`, 1),
		"duplicate":        strings.Replace(string(raw), `"cpu_cores":2`, `"cpu_cores":2,"cpu_cores":2`, 1),
		"unknown_mode":     strings.Replace(string(raw), `"mode":"custom"`, `"mode":"execute"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeProduct([]byte(body)); err == nil {
				t.Fatal("unsafe/missing resource setting accepted")
			}
		})
	}
}

func TestBoundedInput(t *testing.T) {
	for _, raw := range [][]byte{nil, []byte(""), bytes.Repeat([]byte("x"), MaximumInput+1)} {
		if _, err := ReadInput(bytes.NewReader(raw)); err == nil {
			t.Fatal("unbounded/empty input accepted")
		}
	}
	if _, err := ReadInput(nil); err == nil {
		t.Fatal("nil input accepted")
	}
	if raw, err := ReadInput(bytes.NewReader(bytes.Repeat([]byte("x"), MaximumInput))); err != nil || len(raw) != MaximumInput {
		t.Fatal("exact byte limit changed")
	}
	if _, err := ReadInput(errorReader{}); err == nil {
		t.Fatal("input error ignored")
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

type fakeTransport struct {
	sends, lookups int
	request        controllerapi.Request
	result         controllerapi.Result
	err            error
}

func (f *fakeTransport) Send(_ context.Context, r controllerapi.Request) (controllerapi.Result, error) {
	f.sends++
	f.request = r
	return f.result, f.err
}
func (f *fakeTransport) Lookup(_ context.Context, r controllerapi.Request) (controllerapi.Result, error) {
	f.lookups++
	f.request = r
	return f.result, f.err
}

func TestConnectorPreservesOriginalIntentAndNeverRetriesOrConvertsUnknown(t *testing.T) {
	request := fixtureRequest(t)
	transport := &fakeTransport{result: fixtureResult(t, request)}
	connector := &Connector{controllerID: "primary", client: transport}
	for _, lookup := range []bool{false, true} {
		result, err := connector.call(t.Context(), request, lookup)
		if err != nil || !result.Matches(request) || !reflect.DeepEqual(transport.request, request) {
			t.Fatal("original intent changed", err)
		}
	}
	if transport.sends != 1 || transport.lookups != 1 {
		t.Fatal("implicit replay")
	}
	for _, status := range []string{"accepted", "succeeded", "rejected"} {
		transport.result = fixtureResult(t, request)
		transport.result.Status = status
		if status == "succeeded" {
			transport.result.ResourceID = "vm-a"
		}
		got, err := connector.Send(t.Context(), request)
		if err != nil || got.Status != status {
			t.Fatal("valid original status changed", err)
		}
	}
	transport.err = controllerapi.ErrUncertain
	got, err := connector.Send(t.Context(), request)
	if !errors.Is(err, controllerapi.ErrUncertain) || got != (controllerapi.Result{}) {
		t.Fatal("unknown result became confirmation")
	}
	if transport.sends != 5 || transport.lookups != 1 {
		t.Fatal("unknown automatically replayed or looked up")
	}
	transport.err = nil
	transport.result.OrderID = strings.Repeat("d", 32)
	if got, err = connector.Lookup(t.Context(), request); !errors.Is(err, controllerapi.ErrUncertain) || got != (controllerapi.Result{}) {
		t.Fatal("wrong binding accepted")
	}
	request.Product.ControllerID = "other"
	before := transport.sends
	if _, err = connector.Send(t.Context(), request); !errors.Is(err, controllerapi.ErrConfiguration) || transport.sends != before {
		t.Fatal("wrong controller reached transport")
	}
	if _, err = (*Connector)(nil).Send(t.Context(), request); !errors.Is(err, controllerapi.ErrUnavailable) {
		t.Fatal("nil connector accepted")
	}
}
