// Package billingconnector adapts Aster's published financial provisioning
// contract to its existing root-protected HTTPS controller transport. It is
// neither a payment plugin nor a replacement for billing's durable job ledger.
package billingconnector

import (
	"aster/billing/controllerapi"
	"context"
)

const DefaultPolicyPath = "/etc/aster-billing-plugin/policy.json"
const MaximumInput = 64 << 10

type Manifest struct {
	Schema           int      `json:"schema"`
	ID               string   `json:"id"`
	Kind             string   `json:"kind"`
	Protocol         string   `json:"protocol"`
	RuntimePlugin    bool     `json:"runtime_plugin"`
	Execution        string   `json:"execution"`
	Commands         []string `json:"commands"`
	ProductModes     []string `json:"product_modes"`
	MoneyOperations  bool     `json:"money_operations"`
	AutomaticRetries bool     `json:"automatic_retries"`
}

func Describe() Manifest {
	return Manifest{Schema: 1, ID: "aster-cloud-billing-connector", Kind: "external-resource-adapter",
		Protocol: controllerapi.Protocol, RuntimePlugin: false, Execution: "explicit-root-cli",
		Commands:     []string{"manifest", "validate-product", "send", "lookup"},
		ProductModes: []string{"disabled", "preset", "custom"}, MoneyOperations: false, AutomaticRetries: false}
}

type ProductValidation struct {
	Protocol            string `json:"protocol"`
	Status              string `json:"status"`
	Mode                string `json:"mode"`
	ConfigurationSHA256 string `json:"configuration_sha256"`
}

// ValidateProduct checks the published bridge contract offline. It does not
// claim a preset exists or that the selected node can execute its resources.
func ValidateProduct(raw []byte) (ProductValidation, error) {
	product, err := DecodeProduct(raw)
	if err != nil {
		return ProductValidation{}, err
	}
	digest, err := product.Digest()
	if err != nil {
		return ProductValidation{}, controllerapi.ErrConfiguration
	}
	return ProductValidation{Protocol: controllerapi.Protocol, Status: "valid", Mode: product.Mode, ConfigurationSHA256: digest}, nil
}

type transport interface {
	Send(context.Context, controllerapi.Request) (controllerapi.Result, error)
	Lookup(context.Context, controllerapi.Request) (controllerapi.Result, error)
}

type Connector struct {
	controllerID string
	client       transport
}

// Open reads only host policy and credentials through the original financial
// transport. The caller must select ControllerID from the immutable request.
func Open(ctx context.Context, policyPath, controllerID string) (*Connector, error) {
	client, err := controllerapi.New(ctx, policyPath, controllerID)
	if err != nil {
		return nil, err
	}
	return &Connector{controllerID: controllerID, client: client}, nil
}

func (c *Connector) Send(ctx context.Context, request controllerapi.Request) (controllerapi.Result, error) {
	return c.call(ctx, request, false)
}

func (c *Connector) Lookup(ctx context.Context, request controllerapi.Request) (controllerapi.Result, error) {
	return c.call(ctx, request, true)
}

func (c *Connector) call(ctx context.Context, request controllerapi.Request, lookup bool) (controllerapi.Result, error) {
	if c == nil || c.client == nil {
		return controllerapi.Result{}, controllerapi.ErrUnavailable
	}
	if !request.Valid() || request.Product.ControllerID != c.controllerID {
		return controllerapi.Result{}, controllerapi.ErrConfiguration
	}
	var result controllerapi.Result
	var err error
	if lookup {
		result, err = c.client.Lookup(ctx, request)
	} else {
		result, err = c.client.Send(ctx, request)
	}
	// A nonempty result accompanying an error is not partial confirmation. Never
	// print/return it as success, and never generate a replacement operation ID.
	if err != nil {
		return controllerapi.Result{}, err
	}
	if !result.Matches(request) {
		return controllerapi.Result{}, controllerapi.ErrUncertain
	}
	return result, nil
}
