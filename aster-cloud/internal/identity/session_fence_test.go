package identity

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestIdentityWritesRequireBoundSessionBeforeDatabaseUse(t *testing.T) {
	actor := strings.Repeat("a", 32)
	proof := managerSessionProof{hash: tokenHash(strings.Repeat("c", 64)), userID: actor}
	for name, ctx := range map[string]context.Context{
		"missing":       context.Background(),
		"wrong_type":    context.WithValue(context.Background(), managerSessionKey{}, "untrusted"),
		"different_id":  context.WithValue(context.Background(), managerSessionKey{}, managerSessionProof{hash: proof.hash, userID: strings.Repeat("b", 32)}),
		"empty_hash":    context.WithValue(context.Background(), managerSessionKey{}, managerSessionProof{userID: actor}),
		"empty_subject": context.WithValue(context.Background(), managerSessionKey{}, managerSessionProof{hash: proof.hash}),
	} {
		t.Run(name, func(t *testing.T) {
			// A nil DB makes any attempt to bypass the precondition fail loudly.
			s := &Service{}
			if _, err := s.createUser(ctx, actor, CreateUser{Email: "new@example.invalid", Name: "New", Password: testPassword, Role: "viewer"}); !errors.Is(err, ErrAuthentication) {
				t.Fatal("unbound create did not fail closed", err)
			}
			name := "Updated"
			if _, err := s.updateUser(ctx, actor, strings.Repeat("d", 32), UpdateUser{Name: &name}); !errors.Is(err, ErrAuthentication) {
				t.Fatal("unbound update did not fail closed", err)
			}
		})
	}
	if got, err := managerSession(context.WithValue(context.Background(), managerSessionKey{}, proof), actor); err != nil || got != proof {
		t.Fatal("typed matching request proof was not preserved", err)
	}
}
