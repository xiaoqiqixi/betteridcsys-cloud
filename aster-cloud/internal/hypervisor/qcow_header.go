package hypervisor

import (
	"encoding/binary"
	"errors"
	"io"
)

// Validate the QEMU-documented header BEFORE invoking qemu-img on transferred
// bytes. This closes implicit backing/data-file protocol access during parsing,
// not merely a JSON check after the tool already opened external references.
// Deliberately restrict v2/v3 to clean, unencrypted, standard qcow2 profiles.
func validateQcowHeader(path, allowedBacking string) error {
	f, e := openApproved(path, true)
	if e != nil {
		return e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return e
	}
	header := make([]byte, 104)
	if _, e = io.ReadFull(f, header); e != nil {
		return errors.New("truncated qcow2 header")
	}
	be := binary.BigEndian
	if string(header[:4]) != "QFI\xfb" {
		return errors.New("qcow2 magic rejected")
	}
	version := be.Uint32(header[4:8])
	if version != 2 && version != 3 {
		return errors.New("qcow2 version unsupported")
	}
	clusterBits := be.Uint32(header[20:24])
	if clusterBits < 9 || clusterBits > 21 || be.Uint64(header[24:32]) == 0 || be.Uint32(header[32:36]) != 0 || be.Uint32(header[60:64]) != 0 {
		return errors.New("qcow2 unsupported geometry/encryption/internal snapshots")
	}
	length := uint32(72)
	if version == 3 {
		length = be.Uint32(header[100:104])
		if length < 104 || length%8 != 0 || be.Uint64(header[72:80]) != 0 || be.Uint64(header[88:96]) != 0 {
			return errors.New("qcow2 incompatible/external/dirty/bitmap features rejected")
		}
	}
	clusterSize := uint64(1) << clusterBits
	if uint64(length) > clusterSize || int64(length) > st.Size() {
		return errors.New("qcow2 header bounds rejected")
	}
	backingOffset, backingBytes := be.Uint64(header[8:16]), be.Uint32(header[16:20])
	if backingOffset != 0 {
		if allowedBacking == "" || backingBytes < 1 || backingBytes > 1023 || backingOffset > uint64(st.Size()) || uint64(backingBytes) > uint64(st.Size())-backingOffset {
			return errors.New("qcow2 backing reference rejected")
		}
		raw := make([]byte, backingBytes)
		if _, e = f.ReadAt(raw, int64(backingOffset)); e != nil || string(raw) != allowedBacking {
			return errors.New("qcow2 backing approval mismatch")
		}
	} else if backingBytes != 0 {
		return errors.New("inconsistent qcow2 backing header")
	}
	// Reject external-data/encryption/bitmap extensions even if malformed feature
	// flags try to conceal them. Other optional metadata never becomes a path.
	limit := clusterSize
	if uint64(st.Size()) < limit {
		limit = uint64(st.Size())
	}
	if backingOffset != 0 && backingOffset < limit {
		limit = backingOffset
	}
	for offset := uint64(length); offset+8 <= limit; {
		var h [8]byte
		if _, e = f.ReadAt(h[:], int64(offset)); e != nil {
			return e
		}
		kind, n := be.Uint32(h[:4]), be.Uint32(h[4:])
		if kind == 0 {
			break
		}
		if kind == 0x44415441 || kind == 0x0537be77 || kind == 0x23852875 {
			return errors.New("external qcow2 metadata extension rejected")
		}
		padded := (uint64(n) + 7) &^ uint64(7)
		if padded > limit-offset-8 {
			return errors.New("qcow2 extension bounds rejected")
		}
		offset += 8 + padded
	}
	return nil
}
