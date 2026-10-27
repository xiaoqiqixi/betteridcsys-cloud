// aster-billing-plugin is an explicit host resource adapter. It never starts a
// daemon, claims a financial job, records a payment, or dispatches on startup.
package main

import (
	"aster/billing/controllerapi"
	"aster/cloud/plugins/billingconnector"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"
)

type operationClient interface {
	Send(context.Context, controllerapi.Request) (controllerapi.Result, error)
	Lookup(context.Context, controllerapi.Request) (controllerapi.Result, error)
}

type dependencies struct {
	euid func() int
	open func(context.Context, string, string) (operationClient, error)
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, dependencies{
		euid: os.Geteuid,
		open: func(ctx context.Context, path, controller string) (operationClient, error) {
			return billingconnector.Open(ctx, path, controller)
		},
	}))
}

const help = `Aster financial resource connector (aster.controller/1)

Usage:
  aster-billing-plugin help
  aster-billing-plugin manifest
  aster-billing-plugin validate-product < product.json
  aster-billing-plugin send [--policy /etc/aster-billing-plugin/policy.json] < prepared-request.json
  aster-billing-plugin lookup [--policy /etc/aster-billing-plugin/policy.json] < same-prepared-request.json

No command, help, manifest and validate-product never contact a controller.
send and lookup require root. Credentials are read only from protected policy files.
Supply the immutable original request with the same operation/order/digests.
An accepted result is not a running VM. An unknown result requires lookup, not a new operation.
This is not a payment channel or a loadable payment/plugin-manager extension.
`

func run(args []string, stdin io.Reader, stdout, stderr io.Writer, deps dependencies) int {
	fail := func(code string, exit int) int {
		// Closed vocabulary only: never echo argv, tokens, paths, peer errors or
		// request bytes, including when flag parsing itself failed.
		_, _ = fmt.Fprintln(stderr, code)
		return exit
	}
	if len(args) == 0 || len(args) == 1 && (args[0] == "help" || args[0] == "-h" || args[0] == "--help") {
		if _, err := io.WriteString(stdout, help); err != nil {
			return fail("OUTPUT_UNAVAILABLE", 2)
		}
		return 0
	}
	command := args[0]
	if command != "manifest" && command != "validate-product" && command != "send" && command != "lookup" {
		return fail("INVALID_COMMAND", 2)
	}
	flags := flag.NewFlagSet("aster-billing-plugin", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	policy := billingconnector.DefaultPolicyPath
	if command == "send" || command == "lookup" {
		flags.StringVar(&policy, "policy", policy, "root-protected host controller policy")
	}
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			if _, err = io.WriteString(stdout, help); err == nil {
				return 0
			}
			return fail("OUTPUT_UNAVAILABLE", 2)
		}
		return fail("INVALID_ARGUMENTS", 2)
	}
	if flags.NArg() != 0 {
		return fail("INVALID_ARGUMENTS", 2)
	}
	if command == "manifest" {
		if json.NewEncoder(stdout).Encode(billingconnector.Describe()) != nil {
			return fail("OUTPUT_UNAVAILABLE", 2)
		}
		return 0
	}
	if command != "validate-product" && (deps.euid == nil || deps.euid() != 0) {
		return fail("ROOT_REQUIRED", 5)
	}
	raw, err := billingconnector.ReadInput(stdin)
	if err != nil {
		return fail("INVALID_INPUT", 2)
	}
	if command == "validate-product" {
		validation, err := billingconnector.ValidateProduct(raw)
		if err != nil {
			return fail("INVALID_PRODUCT", 2)
		}
		if json.NewEncoder(stdout).Encode(validation) != nil {
			return fail("OUTPUT_UNAVAILABLE", 2)
		}
		return 0
	}
	request, err := billingconnector.DecodeRequest(raw)
	if err != nil {
		return fail("INVALID_REQUEST", 2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if deps.open == nil {
		return fail("CONTROLLER_UNAVAILABLE", 4)
	}
	client, err := deps.open(ctx, policy, request.Product.ControllerID)
	if err != nil || client == nil {
		return fail("CONTROLLER_UNAVAILABLE", 4)
	}
	var result controllerapi.Result
	if command == "lookup" {
		result, err = client.Lookup(ctx, request)
	} else {
		result, err = client.Send(ctx, request)
	}
	if err != nil || !result.Matches(request) {
		if errors.Is(err, controllerapi.ErrConfiguration) {
			return fail("INVALID_REQUEST", 2)
		}
		// A remote failure after explicit send can be an applied mutation with a
		// lost ACK. No partial DTO, success marker or automatic resend is emitted.
		return fail("OUTCOME_UNCERTAIN_USE_LOOKUP", 3)
	}
	if json.NewEncoder(stdout).Encode(result) != nil {
		return fail("OUTCOME_UNCERTAIN_USE_LOOKUP", 3)
	}
	return 0
}
