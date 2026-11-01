//go:build !linux

package main

import "aster/cloud/internal/controllerbackup"

func verificationCoordinator() error { return controllerbackup.ErrInvalid }
