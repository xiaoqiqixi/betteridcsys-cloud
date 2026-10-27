package fabric

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"
)

func nativeNATChecksum(packet []byte) uint16 {
	var sum uint32
	for len(packet) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(packet))
		packet = packet[2:]
	}
	if len(packet) == 1 {
		sum += uint32(packet[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// Go 1.27.3 src/net/iprawsock_posix.go IPConn.readFrom strips the IPv4 header
// for ReadFromIP. This receives only the ICMP message, never a raw IPv4 frame.
// Exact length/checksum/identity/data checks reject unknown packets rather than
// treating any successful raw-socket read as proof of working NAT.
func nativeNATEchoReply(echo []byte) error {
	if len(echo) != 16 || echo[0] != 0 || echo[1] != 0 {
		return fmt.Errorf("not this probe's complete ICMP echo reply")
	}
	if nativeNATChecksum(echo) != 0 {
		return fmt.Errorf("invalid ICMP echo checksum")
	}
	if binary.BigEndian.Uint16(echo[4:6]) != 0x4a53 || binary.BigEndian.Uint16(echo[6:8]) != 1 || !bytes.Equal(echo[8:], []byte("nat-echo")) {
		return fmt.Errorf("ICMP echo identity/sequence/payload differs")
	}
	return nil
}

func TestNativeNATEchoReplyStrictPayload(t *testing.T) {
	// Actual Ubuntu22 packet captured by the 2026-10-24 native gate: 20 IPv4 bytes,
	// then the exact 16-byte ICMP echo reply. ReadFromIP supplies only the latter.
	actualFrame, err := hex.DecodeString("45000024de2a00003f018190090909090a0b00020000054a4a5300016e61742d6563686f")
	if err != nil {
		t.Fatal(err)
	}
	actual := actualFrame[20:]
	if err := nativeNATEchoReply(actual); err != nil {
		t.Fatal("real ICMP payload rejected", err)
	}
	if err := nativeNATEchoReply(actualFrame); err == nil {
		t.Fatal("raw IPv4 frame confused with ICMP payload")
	}
	fixChecksum := func(payload []byte) {
		payload[2], payload[3] = 0, 0
		binary.BigEndian.PutUint16(payload[2:4], nativeNATChecksum(payload))
	}
	for name, mutate := range map[string]func([]byte) []byte{
		"wrong_type":        func(p []byte) []byte { p[0] = 8; fixChecksum(p); return p },
		"wrong_code":        func(p []byte) []byte { p[1] = 1; fixChecksum(p); return p },
		"wrong_id":          func(p []byte) []byte { p[4]++; fixChecksum(p); return p },
		"wrong_sequence":    func(p []byte) []byte { p[7]++; fixChecksum(p); return p },
		"wrong_payload":     func(p []byte) []byte { p[15] ^= 1; fixChecksum(p); return p },
		"wrong_checksum":    func(p []byte) []byte { p[2] ^= 1; return p },
		"truncated_header":  func(p []byte) []byte { return p[:7] },
		"truncated_payload": func(p []byte) []byte { p = p[:15]; fixChecksum(p); return p },
		"extra_payload":     func(p []byte) []byte { p = append(p, 'x'); fixChecksum(p); return p },
	} {
		t.Run(name, func(t *testing.T) {
			payload := mutate(append([]byte{}, actual...))
			if err := nativeNATEchoReply(payload); err == nil {
				t.Fatalf("invalid/unknown ICMP payload accepted: %x", payload)
			}
		})
	}
	for _, payload := range [][]byte{nil, {}, {0}, actual[:8]} {
		if err := nativeNATEchoReply(payload); err == nil {
			t.Fatal("empty/truncated ICMP payload accepted")
		}
	}
}
