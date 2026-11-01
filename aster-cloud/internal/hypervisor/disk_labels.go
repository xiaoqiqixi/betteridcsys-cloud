package hypervisor

import (
	"encoding/binary"
	"errors"
)

// Only the exact approved base may be a backing source. Flat restores/imports
// must keep an empty backingStore instead of accidentally attaching the base.
// This bounded header read does not ask QEMU to probe an untrusted chain.
func (m *Manager) domainBacking(i Instance) (string, error) {
	image, ok := m.Config.Images[i.Resources.ImageID]
	if !ok {
		return "", ErrUnsupported
	}
	if err := validateQcowHeader(i.Disk, image.Path); err != nil {
		return "", err
	}
	f, err := openApproved(i.Disk, true)
	if err != nil {
		return "", err
	}
	defer f.Close()
	var header [20]byte
	if _, err = f.ReadAt(header[:], 0); err != nil {
		return "", err
	}
	if binary.BigEndian.Uint64(header[8:16]) == 0 {
		return "", nil
	}
	n := binary.BigEndian.Uint32(header[16:20])
	offset := binary.BigEndian.Uint64(header[8:16])
	if n < 1 || n > 1023 || offset > 1<<30 {
		return "", errors.New("backing header changed")
	}
	raw := make([]byte, n)
	if _, err = f.ReadAt(raw, int64(offset)); err != nil || string(raw) != image.Path {
		return "", ErrOwnership
	}
	return image.Path, nil
}
