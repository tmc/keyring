package keyring_test

import "github.com/tmc/keyring"

func ExampleNewFileProvider() {
	provider := keyring.NewFileProvider(keyring.FileOptions{})
	keyring.RegisterProvider("file", 1, provider)
}
