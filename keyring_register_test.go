package keyring

import (
	"errors"
	"testing"
)

type fakeProvider struct {
	name string
	data map[string]string
}

func newFakeProvider(name string) *fakeProvider {
	return &fakeProvider{
		name: name,
		data: make(map[string]string),
	}
}

func (p *fakeProvider) Get(service, username string) (string, error) {
	password, ok := p.data[service+"/"+username]
	if !ok {
		return "", ErrNotFound
	}
	return p.name + ":" + password, nil
}

func (p *fakeProvider) Set(service, username, password string) error {
	p.data[service+"/"+username] = password
	return nil
}

func (p *fakeProvider) Delete(service, username string) error {
	key := service + "/" + username
	if _, ok := p.data[key]; !ok {
		return ErrNotFound
	}
	delete(p.data, key)
	return nil
}

func saveProviders(t *testing.T) {
	t.Helper()

	providersMu.Lock()
	oldProviders := append([]providerRegistration(nil), providers...)
	providers = nil
	providersMu.Unlock()

	t.Cleanup(func() {
		providersMu.Lock()
		providers = oldProviders
		providersMu.Unlock()
	})
}

func TestRegisterProviderSelectsHighestPriority(t *testing.T) {
	saveProviders(t)

	low := newFakeProvider("low")
	high := newFakeProvider("high")
	RegisterProvider("low", 1, low)
	RegisterProvider("high", 10, high)

	if err := Set("service", "user", "password"); err != nil {
		t.Fatalf("Set() error: %v", err)
	}
	got, err := Get("service", "user")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if got != "high:password" {
		t.Fatalf("Get() = %q, want %q", got, "high:password")
	}
	if _, err := low.Get("service", "user"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("low provider Get() error = %v, want ErrNotFound", err)
	}
}

func TestRegisterProviderReplacesByName(t *testing.T) {
	saveProviders(t)

	oldProvider := newFakeProvider("old")
	newProvider := newFakeProvider("new")
	RegisterProvider("memory", 1, oldProvider)
	RegisterProvider("memory", 1, newProvider)

	if err := Set("service", "user", "password"); err != nil {
		t.Fatalf("Set() error: %v", err)
	}
	got, err := Get("service", "user")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if got != "new:password" {
		t.Fatalf("Get() = %q, want %q", got, "new:password")
	}
	if _, err := oldProvider.Get("service", "user"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old provider Get() error = %v, want ErrNotFound", err)
	}
}

func TestSetupProviderEmptyRegistry(t *testing.T) {
	saveProviders(t)

	_, err := setupProvider()
	if !errors.Is(err, ErrNoDefault) {
		t.Fatalf("setupProvider() error = %v, want ErrNoDefault", err)
	}
}
