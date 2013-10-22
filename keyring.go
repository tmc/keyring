// Package keyring provides a cross-platform interface to keychains for
// password management
//
// Example:
// 	pw, err := keyring.Get("libFoo", "john.doe")
//
// TODO: Write Windows provider
package keyring

import "errors"

var (
	// ErrNotFound means the requested password was not found
	ErrNotFound = errors.New("Password not found")
	// ErrNoDefault means that no default keyring provider has been found
	ErrNoDefault = errors.New("No keyring provider found (check your build flags)")

	defaultProvider provider
)

// provider provides a simple interface to keychain sevice
type provider interface {
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
