// +build windows

package keyring

import (
	"github.com/danieljoos/wincred"
)

type winProvider struct {
}

func (p *winProvider) Get(Service, Username string) (string, error) {
	cred1, err := wincred.GetGenericCredential(Service)
	if err == nil && cred1.UserName == Username {
		return string(cred1.CredentialBlob), nil

	}
	cred2, err := wincred.GetDomainPassword(Service)
	if err == nil && cred2.UserName == Username {
		return string(cred2.CredentialBlob), nil

	}
	return "", ErrNotFound
}

func (p *winProvider) Set(Service, Username, Password string) error {
	cred := wincred.NewGenericCredential(Service)
	cred.UserName = Username
	cred.CredentialBlob = []byte(Password)
	return cred.Write()
}

func initializeProvider() (provider, error) {
	return &winProvider{}, nil
}
