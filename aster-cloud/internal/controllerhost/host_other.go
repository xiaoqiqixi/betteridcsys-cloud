//go:build !linux

package controllerhost

import "os"

type Host struct{}

func Open(string, string) (*Host, error)                  { return nil, ErrUnavailable }
func (*Host) Close()                                      {}
func (*Host) Admit() error                                { return ErrUnavailable }
func (*Host) Check() error                                { return ErrUnavailable }
func (*Host) Status() (Status, error)                     { return Status{}, ErrUnavailable }
func (*Host) Fence(string) (Status, error)                { return Status{}, ErrUnavailable }
func (*Host) Cancel(string) (Status, error)               { return Status{}, ErrUnavailable }
func (*Host) WithSealedSource(string, func() error) error { return ErrUnavailable }

func (*Host) PrepareTarget(string, string) (Status, error) { return Status{}, ErrUnavailable }

func (*Host) TargetStatus(string, string) (Status, error) { return Status{}, ErrUnavailable }

func (*Host) WithSealedTarget(string, string, func() error) error { return ErrUnavailable }

func (*Host) PrepareVerificationRuntime(string, string, func() error) (*os.File, error) {
	return nil, ErrUnavailable
}
