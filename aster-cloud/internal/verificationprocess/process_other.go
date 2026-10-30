//go:build !linux

package verificationprocess

import (
	"context"
	"os"
)

func serve(context.Context, *os.File, Config) error { return ErrRefused }
func Child() error                                  { return ErrRefused }
