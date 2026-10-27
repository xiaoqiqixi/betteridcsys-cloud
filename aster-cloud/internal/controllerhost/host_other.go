//go:build !linux

package controllerhost

type Host struct{}

func Open(string, string) (*Host, error)                  { return nil, ErrUnavailable }
func (*Host) Close()                                      {}
func (*Host) Admit() error                                { return ErrUnavailable }
func (*Host) Check() error                                { return ErrUnavailable }
func (*Host) Status() (Status, error)                     { return Status{}, ErrUnavailable }
func (*Host) Fence(string) (Status, error)                { return Status{}, ErrUnavailable }
func (*Host) Cancel(string) (Status, error)               { return Status{}, ErrUnavailable }
func (*Host) WithSealedSource(string, func() error) error { return ErrUnavailable }
