/*
Package keyring provides a cross-platform interface to system keychains.

Currently implemented:

  - OSX
  - SecretService
  - gnome-keychain (via "gnome_keyring" build flag)
  - Windows Credential Manager

The default SecretService provider is pure Go; gnome_keyring is an advanced cgo
opt-in for environments that require libsecret.

# Usage

Example usage:

	err := keyring.Set("libraryFoo", "jack", "sacrifice")
	if err != nil {
		log.Fatal(err)
	}
	password, err := keyring.Get("libraryFoo", "jack")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(password)
	err = keyring.Delete("libraryFoo", "jack")
	if err != nil {
		log.Fatal(err)
	}
*/
package keyring
