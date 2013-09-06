// Package keyring provides a cross-platform interface to keychains for
// password management
//
// Example:
// 	pw, err := keyring.Get("libFoo", "john.doe")
//
// TODO: Write SecretService Provider
//
// TODO: Write KWallet Provider?
//
// TODO: Implement encrypted local file storage Provider ?
package keyring

import "errors"

var (
	// ErrNoDefault means that no default keyring provider has been found
	ErrNoDefault    = errors.New("No default provider found")
	providers       = map[string]Provider{}
	defaultProvider Provider
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

// Providers provides a map of registered Providers keyed on short names
func Providers() map[string]Provider {
	p := make(map[string]Provider)
	for k, v := range providers {
		p[k] = v
	}
	return p
}

// RegisterProvider registers a Provider with a short name (for use by Provider)
// libraries
func registerProvider(Name string, Provider Provider, makeDefault bool) {
	providers[Name] = Provider
	if makeDefault {
		defaultProvider = Provider
	}
}
