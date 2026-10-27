package main

import (
	"aster/billing/controllerapi"
	"aster/cloud/plugins/billingconnector"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

type unreadable struct{}

func (unreadable) Read([]byte) (int, error) { panic("stdin must not be read") }

func requestFixture(t *testing.T) controllerapi.Request {
	t.Helper()
	product := controllerapi.ProductSpec{Mode: "preset", ControllerID: "primary", RemoteProductID: "small"}
	digest, _ := product.Digest()
	return controllerapi.Request{Protocol: controllerapi.Protocol, OperationID: strings.Repeat("a", 32), OrderID: strings.Repeat("b", 32), OwnerRef: strings.Repeat("c", 32), Hostname: "vm-a", ConfigurationRevision: 1, ConfigurationSHA256: digest, Product: product}
}

type fakeClient struct {
	sends, lookups int
	request        controllerapi.Request
	result         controllerapi.Result
	err            error
}

func (f *fakeClient) Send(_ context.Context, request controllerapi.Request) (controllerapi.Result, error) {
	f.sends++
	f.request = request
	return f.result, f.err
}
func (f *fakeClient) Lookup(_ context.Context, request controllerapi.Request) (controllerapi.Result, error) {
	f.lookups++
	f.request = request
	return f.result, f.err
}

func TestDefaultHelpAndManifestNeverReadInputOrOpenTransport(t *testing.T) {
	deps := dependencies{euid: func() int { panic("offline command queried root") }, open: func(context.Context, string, string) (operationClient, error) {
		panic("offline command contacted controller")
	}}
	for _, args := range [][]string{nil, {"help"}, {"-h"}, {"--help"}, {"manifest"}, {"send", "--help"}, {"lookup", "--help"}} {
		var stdout, stderr bytes.Buffer
		if exit := run(args, unreadable{}, &stdout, &stderr, deps); exit != 0 || stdout.Len() == 0 || stderr.Len() != 0 {
			t.Fatal("offline startup/help failed", exit)
		}
		if len(args) > 0 && args[0] == "manifest" {
			var manifest billingconnector.Manifest
			if json.Unmarshal(stdout.Bytes(), &manifest) != nil || manifest.RuntimePlugin || manifest.MoneyOperations || manifest.Protocol != controllerapi.Protocol {
				t.Fatal("misleading manifest")
			}
		}
	}
}

func TestValidateProductIsOfflineAndKeepsOriginalDigest(t *testing.T) {
	request := requestFixture(t)
	raw, _ := json.Marshal(request.Product)
	var stdout, stderr bytes.Buffer
	exit := run([]string{"validate-product"}, bytes.NewReader(raw), &stdout, &stderr, dependencies{euid: func() int { panic("offline validation queried root") }, open: func(context.Context, string, string) (operationClient, error) {
		panic("offline validation contacted controller")
	}})
	var validation billingconnector.ProductValidation
	if exit != 0 || stderr.Len() != 0 || json.Unmarshal(stdout.Bytes(), &validation) != nil || validation.ConfigurationSHA256 != request.ConfigurationSHA256 {
		t.Fatal("offline validation failed", exit)
	}
}

func TestNetworkCommandsRequireRootBeforeReadingOrOpening(t *testing.T) {
	for _, command := range []string{"send", "lookup"} {
		var stdout, stderr bytes.Buffer
		exit := run([]string{command}, unreadable{}, &stdout, &stderr, dependencies{euid: func() int { return 501 }, open: func(context.Context, string, string) (operationClient, error) { panic("nonroot reached transport") }})
		if exit != 5 || stdout.Len() != 0 || stderr.String() != "ROOT_REQUIRED\n" {
			t.Fatal("nonroot dispatch not blocked", exit)
		}
	}
}

func TestExplicitSendAndLookupPreserveRequestAndExactSixFieldResult(t *testing.T) {
	request := requestFixture(t)
	raw, digest, _ := request.BytesAndDigest()
	for _, command := range []string{"send", "lookup"} {
		client := &fakeClient{result: controllerapi.Result{Protocol: controllerapi.Protocol, OperationID: request.OperationID, OrderID: request.OrderID, RequestSHA256: digest, Status: "accepted"}}
		opens := 0
		deps := dependencies{euid: func() int { return 0 }, open: func(_ context.Context, path, controller string) (operationClient, error) {
			opens++
			if path != billingconnector.DefaultPolicyPath || controller != request.Product.ControllerID {
				t.Fatal("request selected arbitrary destination")
			}
			return client, nil
		}}
		var stdout, stderr bytes.Buffer
		if exit := run([]string{command}, bytes.NewReader(raw), &stdout, &stderr, deps); exit != 0 || stderr.Len() != 0 || opens != 1 || !reflect.DeepEqual(client.request, request) {
			t.Fatal("explicit original request failed", exit)
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(stdout.Bytes(), &fields) != nil || len(fields) != 6 || string(fields["status"]) != `"accepted"` {
			t.Fatal("result contract changed or accepted called VM success", stdout.String())
		}
		if command == "send" && (client.sends != 1 || client.lookups != 0) || command == "lookup" && (client.sends != 0 || client.lookups != 1) {
			t.Fatal("automatic redispatch/reconciliation")
		}
	}
}

func TestErrorsNeverEchoSecretsOrTurnPartialResultIntoSuccess(t *testing.T) {
	request := requestFixture(t)
	raw, digest, _ := request.BytesAndDigest()
	for _, mode := range []string{"unknown", "wrong_binding", "open_failure", "output_failure", "invalid_request", "invalid_flags"} {
		t.Run(mode, func(t *testing.T) {
			client := &fakeClient{result: controllerapi.Result{Protocol: controllerapi.Protocol, OperationID: request.OperationID, OrderID: request.OrderID, RequestSHA256: digest, Status: "accepted"}}
			if mode == "unknown" {
				client.err = errors.New("PRIVATE_TOKEN /private/policy secret-body")
			}
			if mode == "wrong_binding" {
				client.result.OrderID = strings.Repeat("f", 32)
			}
			deps := dependencies{euid: func() int { return 0 }, open: func(context.Context, string, string) (operationClient, error) {
				if mode == "open_failure" {
					return nil, errors.New("PRIVATE_TOKEN /private/policy secret-body")
				}
				return client, nil
			}}
			args := []string{"send"}
			body := raw
			if mode == "invalid_request" {
				body = []byte(`{"token":"PRIVATE_TOKEN"}`)
			}
			if mode == "invalid_flags" {
				args = append(args, "--token", "PRIVATE_TOKEN")
			}
			var stdout, stderr bytes.Buffer
			var writer io.Writer = &stdout
			if mode == "output_failure" {
				writer = errorWriter{}
			}
			exit := run(args, bytes.NewReader(body), writer, &stderr, deps)
			if exit == 0 || stdout.Len() != 0 || stderr.Len() == 0 || strings.Contains(stderr.String(), "PRIVATE") || strings.Contains(stderr.String(), "secret-body") || strings.Contains(stderr.String(), "/private") {
				t.Fatal("error leaked sensitive details or succeeded", exit, stderr.String())
			}
			if client.sends > 1 || client.lookups != 0 {
				t.Fatal("unknown replayed")
			}
			if (mode == "invalid_request" || mode == "invalid_flags" || mode == "open_failure") && client.sends != 0 {
				t.Fatal("invalid input dispatched")
			}
		})
	}
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
