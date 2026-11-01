package identity

import (
	"context"
	"database/sql"
	"errors"
	"testing"
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

func TestLoginReservationHonorsCancellation(t *testing.T) {
	db, err := sql.Open("mysql", "unused:unused@unix(/nonexistent)/aster_cloud_test")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s, err := New(db, Config{Origin: "https://console.example.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.reserveLogin(ctx, "192.0.2.11:1234"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled login reservation reached the database", err)
	}
}
