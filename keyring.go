package keyring

import (
	"errors"
	"sync"
)

var (
	// ErrNotFound means the requested password was not found
	ErrNotFound = errors.New("keyring: password not found")
	// ErrNoDefault means that no default keyring provider has been found
	ErrNoDefault = errors.New("keyring: no suitable keyring provider found (check your build flags)")
	// ErrSetDataTooBig means the secret exceeds a limit imposed by the
	// underlying platform provider.
	ErrSetDataTooBig = errors.New("keyring: secret too large for provider")

	providersMu sync.Mutex
	providers   []providerRegistration
)

// Provider provides a simple interface to keychain service.
type Provider interface {
	Get(service, username string) (string, error)
	Set(service, username, password string) error
	Delete(service, username string) error
}

type providerRegistration struct {
	name     string
	priority int
	provider Provider
}

// RegisterProvider registers a named keyring Provider with a selection
// priority. When no provider has been chosen explicitly, the registered
// provider with the highest priority is used. Higher values win.
func RegisterProvider(name string, priority int, p Provider) {
	providersMu.Lock()
	defer providersMu.Unlock()

	for i := range providers {
		if providers[i].name == name {
			providers[i].priority = priority
			providers[i].provider = p
			return
		}
	}
	providers = append(providers, providerRegistration{
		name:     name,
		priority: priority,
		provider: p,
	})
}

func setupProvider() (Provider, error) {
	providersMu.Lock()
	defer providersMu.Unlock()

	if len(providers) == 0 {
		return nil, ErrNoDefault
	}

	best := providers[0]
	for _, r := range providers[1:] {
		if r.priority > best.priority {
			best = r
		}
	}
	if best.provider == nil {
		return nil, ErrNoDefault
	}
	return best.provider, nil
}

type lazyProvider struct {
	once sync.Once
	init func() (Provider, error)
	p    Provider
	err  error
}

func (p *lazyProvider) resolve() (Provider, error) {
	p.once.Do(func() {
		p.p, p.err = p.init()
	})
	return p.p, p.err
}

func (p *lazyProvider) Get(service, username string) (string, error) {
	provider, err := p.resolve()
	if err != nil {
		return "", err
	}
	return provider.Get(service, username)
}

func (p *lazyProvider) Set(service, username, password string) error {
	provider, err := p.resolve()
	if err != nil {
		return err
	}
	return provider.Set(service, username, password)
}

func (p *lazyProvider) Delete(service, username string) error {
	provider, err := p.resolve()
	if err != nil {
		return err
	}
	return provider.Delete(service, username)
}

// Get gets the password for a particular service and username using the
// default keyring provider.
func Get(service, username string) (string, error) {
	p, err := setupProvider()
	if err != nil {
		return "", err
	}

	return p.Get(service, username)
}

// Set sets the password for a particular service and username using the
// default keyring provider.
func Set(service, username, password string) error {
	p, err := setupProvider()
	if err != nil {
		return err
	}

	return p.Set(service, username, password)
}

// Delete removes the password for a particular service and username using the
// default keyring provider. It returns ErrNotFound when no matching password
// exists.
func Delete(service, username string) error {
	p, err := setupProvider()
	if err != nil {
		return err
	}

	return p.Delete(service, username)
}
