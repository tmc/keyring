// Package keyring provides a cross-platform interface to keychains for
// password management

// TODO(tmc): Implement dummy local file storage
// TODO(tmc): Write SecretService Provider
// TODO(tmc): Write KWallet Provider?
// TODO(tmc): Write gnome-keyring Provider?
package keyring

import "errors"

var (
	providers       map[string]Provider
	defaultProvider Provider
	ErrNoDefault    = errors.New("No default provider found")
)

// Provider provides a simple interface to keychain sevice
type Provider interface {
	Get(Service, Username string) (string, error)
	Set(Service, Username, Password string) error
}

// Get gets the password for a paricular Service and Username using the
// default keyring provider.
func Get(Service, Username string) (string, error) {
	if defaultProvider == nil {
		return "", ErrNoDefault
	}
	return defaultProvider.Get(Service, Username)
}

// Set sets the password for a particular Service and Username using the
// default keyring provider.
func Set(Service, Username, Password string) error {
	if defaultProvider == nil {
		return ErrNoDefault
	}
	return defaultProvider.Set(Service, Username, Password)
}

// Fetch a map of registered Providers. Keys are provider short names
func Providers() map[string]Provider {
	p := make(map[string]Provider)
	for k, v := range providers {
		p[k] = v
	}
	return p
}

// RegisterProvider registers a Provider with a short name
func RegisterProvider(Name string, Provider Provider, makeDefault bool) {
	providers[Name] = Provider
	if makeDefault {
		defaultProvider = Provider
	}
}

func init() {
	providers = make(map[string]Provider)
}
