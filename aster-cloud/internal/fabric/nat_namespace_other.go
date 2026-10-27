//go:build !linux

package fabric

import "context"

func (OSRunner) RunNamespace(context.Context, NATProfile, string, ...string) ([]byte, error) {
	return nil, ErrUnavailable
}
