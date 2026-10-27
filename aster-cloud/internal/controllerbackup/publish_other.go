//go:build !linux

package controllerbackup

func publishNew(string, string) error { return ErrInvalid }
