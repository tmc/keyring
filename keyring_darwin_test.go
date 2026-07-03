//go:build darwin

package keyring

import (
	"errors"
	"strings"
	"testing"
)

// TestOSXSetDataTooBig verifies that an oversized secret is rejected before it
// reaches security(1), rather than being silently truncated.
func TestOSXSetDataTooBig(t *testing.T) {
	p := osxProvider{}
	big := strings.Repeat("x", maxSecurityInput)
	if err := p.Set("keyring-test-toobig", "user", big); !errors.Is(err, ErrSetDataTooBig) {
		t.Fatalf("Set() error = %v, want ErrSetDataTooBig", err)
	}
}

// TestOSXBinarySecretRoundTrip verifies that secrets containing bytes that
// would break the textual security(1) interface — quotes, newlines, NUL — are
// preserved by the base64 encoding.
func TestOSXBinarySecretRoundTrip(t *testing.T) {
	p := osxProvider{}
	const service = "keyring-test-binary"
	cases := []struct {
		user   string
		secret string
	}{
		{"quote", "he said 'hi'"},
		{"newline", "line1\nline2"},
		{"nul", "a\x00b"},
		{"backslash", `a\b\c`},
		{"mixed", "\"'\n\t\\ end"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.user, func(t *testing.T) {
			t.Cleanup(func() { _ = p.Delete(service, tc.user) })
			if err := p.Set(service, tc.user, tc.secret); err != nil {
				t.Fatalf("Set() error: %v", err)
			}
			got, err := p.Get(service, tc.user)
			if err != nil {
				t.Fatalf("Get() error: %v", err)
			}
			if got != tc.secret {
				t.Fatalf("Get() = %q, want %q", got, tc.secret)
			}
		})
	}
}
