package identity

import (
	"testing"
	"time"
)

func TestLoginPrefixCanonicalization(t *testing.T) {
	for input, want := range map[string]string{
		"192.0.2.1:1234": "192.0.2.1", "192.0.2.2": "192.0.2.2",
		"[::ffff:192.0.2.1]:443":                  "192.0.2.1",
		"[2001:db8:1234:5678::1]:443":             "2001:db8:1234:5678::/64",
		"2001:0db8:1234:5678:ffff:ffff:ffff:ffff": "2001:db8:1234:5678::/64",
		"[2001:db8:1234:5679::1]:443":             "2001:db8:1234:5679::/64",
		"forwarded.example.invalid":               "", "": "",
	} {
		if got := loginIP(input); got != want {
			t.Errorf("prefix %q = %q, want %q", input, got, want)
		}
	}
}

func TestEmailBackoffIsExponentialAndCapped(t *testing.T) {
	for failures, want := range map[int]time.Duration{
		0: 0, 1: 100 * time.Millisecond, 2: 200 * time.Millisecond,
		3: 400 * time.Millisecond, 4: 800 * time.Millisecond,
		5: 1600 * time.Millisecond, 6: 2 * time.Second, 1000: 2 * time.Second,
	} {
		if got := loginBackoff(failures); got != want {
			t.Errorf("backoff(%d) = %s, want %s", failures, got, want)
		}
	}
}
