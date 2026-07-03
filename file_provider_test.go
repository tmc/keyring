package keyring

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func testFileProvider(t *testing.T, passphrase string) (*FileProvider, string) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "store.enc")
	return NewFileProvider(FileOptions{
		Path:       path,
		Passphrase: passphrase,
	}), path
}

func TestFileProviderRoundTrip(t *testing.T) {
	p, _ := testFileProvider(t, "test-pass")

	if err := p.Set("service", "user", "secret"); err != nil {
		t.Fatalf("Set() error: %v", err)
	}
	got, err := p.Get("service", "user")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if got != "secret" {
		t.Fatalf("Get() = %q, want %q", got, "secret")
	}
}

func TestFileProviderMissing(t *testing.T) {
	p, _ := testFileProvider(t, "test-pass")

	if _, err := p.Get("missing", "user"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get() error = %v, want ErrNotFound", err)
	}
	if err := p.Delete("missing", "user"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete() error = %v, want ErrNotFound", err)
	}
}

func TestFileProviderDelete(t *testing.T) {
	p, _ := testFileProvider(t, "test-pass")

	if err := p.Set("service", "user", "secret"); err != nil {
		t.Fatalf("Set() error: %v", err)
	}
	if err := p.Delete("service", "user"); err != nil {
		t.Fatalf("Delete() error: %v", err)
	}
	if _, err := p.Get("service", "user"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get() after Delete() error = %v, want ErrNotFound", err)
	}
}

func TestFileProviderOverwrite(t *testing.T) {
	p, _ := testFileProvider(t, "test-pass")

	if err := p.Set("service", "user", "first"); err != nil {
		t.Fatalf("first Set() error: %v", err)
	}
	if err := p.Set("service", "user", "second"); err != nil {
		t.Fatalf("second Set() error: %v", err)
	}
	got, err := p.Get("service", "user")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if got != "second" {
		t.Fatalf("Get() = %q, want %q", got, "second")
	}
}

func TestFileProviderMultipleEntries(t *testing.T) {
	p, _ := testFileProvider(t, "test-pass")

	if err := p.Set("svcA", "userA", "secretA"); err != nil {
		t.Fatalf("Set A error: %v", err)
	}
	if err := p.Set("svcB", "userB", "secretB"); err != nil {
		t.Fatalf("Set B error: %v", err)
	}
	gotA, err := p.Get("svcA", "userA")
	if err != nil {
		t.Fatalf("Get A error: %v", err)
	}
	gotB, err := p.Get("svcB", "userB")
	if err != nil {
		t.Fatalf("Get B error: %v", err)
	}
	if gotA != "secretA" || gotB != "secretB" {
		t.Fatalf("Get() = (%q, %q), want (secretA, secretB)", gotA, gotB)
	}
}

func TestFileProviderNULInKeys(t *testing.T) {
	p, _ := testFileProvider(t, "test-pass")

	if err := p.Set("a", "b\x00c", "first"); err != nil {
		t.Fatalf("Set first error: %v", err)
	}
	if err := p.Set("a\x00b", "c", "second"); err != nil {
		t.Fatalf("Set second error: %v", err)
	}
	got, err := p.Get("a", "b\x00c")
	if err != nil {
		t.Fatalf("Get first error: %v", err)
	}
	if got != "first" {
		t.Fatalf("Get first = %q, want first", got)
	}
	got, err = p.Get("a\x00b", "c")
	if err != nil {
		t.Fatalf("Get second error: %v", err)
	}
	if got != "second" {
		t.Fatalf("Get second = %q, want second", got)
	}
	if err := p.Delete("a", "b\x00c"); err != nil {
		t.Fatalf("Delete first error: %v", err)
	}
	if _, err := p.Get("a", "b\x00c"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get first after Delete error = %v, want ErrNotFound", err)
	}
	got, err = p.Get("a\x00b", "c")
	if err != nil {
		t.Fatalf("Get second after Delete first error: %v", err)
	}
	if got != "second" {
		t.Fatalf("Get second after Delete first = %q, want second", got)
	}
}

func TestFileProviderEncryptsStore(t *testing.T) {
	p, path := testFileProvider(t, "test-pass")
	password := []byte("plain secret")

	if err := p.Set("service", "user", string(password)); err != nil {
		t.Fatalf("Set() error: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error: %v", err)
	}
	if bytes.Contains(raw, password) {
		t.Fatalf("store file contains plaintext password")
	}
}

func TestFileProviderWrongPassphrase(t *testing.T) {
	p, path := testFileProvider(t, "pass1")
	if err := p.Set("service", "user", "secret"); err != nil {
		t.Fatalf("Set() error: %v", err)
	}

	wrong := NewFileProvider(FileOptions{Path: path, Passphrase: "pass2"})
	_, err := wrong.Get("service", "user")
	if err == nil {
		t.Fatalf("Get() error = nil, want decrypt error")
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatalf("Get() error = %v, want non-ErrNotFound decrypt error", err)
	}
}

func TestFileProviderDecryptsWithStoredParams(t *testing.T) {
	p, path := testFileProvider(t, "test-pass")
	if err := p.Set("service", "user", "secret"); err != nil {
		t.Fatalf("Set() error: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error: %v", err)
	}
	var envelope fileEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}
	if envelope.Time != argon2Time {
		t.Fatalf("envelope time = %d, want %d", envelope.Time, argon2Time)
	}
	if envelope.Memory != argon2Memory {
		t.Fatalf("envelope memory = %d, want %d", envelope.Memory, argon2Memory)
	}
	if envelope.Threads != argon2Threads {
		t.Fatalf("envelope threads = %d, want %d", envelope.Threads, argon2Threads)
	}
	if envelope.KeyLen != argon2KeyLen {
		t.Fatalf("envelope keylen = %d, want %d", envelope.KeyLen, argon2KeyLen)
	}

	got, err := p.Get("service", "user")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if got != "secret" {
		t.Fatalf("Get() = %q, want secret", got)
	}
}

func TestFileProviderEnvPassphrase(t *testing.T) {
	t.Setenv("KEYRING_PASSPHRASE", "envpass")
	p := NewFileProvider(FileOptions{Path: filepath.Join(t.TempDir(), "store.enc")})

	if err := p.Set("service", "user", "secret"); err != nil {
		t.Fatalf("Set() error: %v", err)
	}
	got, err := p.Get("service", "user")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if got != "secret" {
		t.Fatalf("Get() = %q, want %q", got, "secret")
	}
}

func TestFileProviderRequiresPassphrase(t *testing.T) {
	t.Setenv("KEYRING_PASSPHRASE", "")
	p := NewFileProvider(FileOptions{Path: filepath.Join(t.TempDir(), "store.enc")})

	if _, err := p.Get("service", "user"); !errors.Is(err, errFileProviderPassphrase) {
		t.Fatalf("Get() error = %v, want passphrase error", err)
	}
	if err := p.Set("service", "user", "secret"); !errors.Is(err, errFileProviderPassphrase) {
		t.Fatalf("Set() error = %v, want passphrase error", err)
	}
	if err := p.Delete("service", "user"); !errors.Is(err, errFileProviderPassphrase) {
		t.Fatalf("Delete() error = %v, want passphrase error", err)
	}
}

func TestFileProviderRegisterAndSelect(t *testing.T) {
	saveProviders(t)

	p, _ := testFileProvider(t, "test-pass")
	RegisterProvider("file", 1, p)

	if err := Set("service", "user", "secret"); err != nil {
		t.Fatalf("Set() error: %v", err)
	}
	got, err := Get("service", "user")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if got != "secret" {
		t.Fatalf("Get() = %q, want %q", got, "secret")
	}
}
