# keyring provides cross-platform keychain access

https://pkg.go.dev/github.com/tmc/keyring

Keyring provides a common interface to keyring/keychain tools.

License: ISC

Currently implemented:
- OSX
- SecretService
- gnome-keychain (via "gnome_keyring" build flag)
- Windows

Contributions welcome!

Usage example:

```go
  err := keyring.Set("libraryFoo", "jack", "sacrifice")
  password, err := keyring.Get("libraryFoo", "jack")
  fmt.Println(password) //Output: sacrifice
  err = keyring.Delete("libraryFoo", "jack")
```

## Linux

Linux requirements:

### SecretService provider

- dbus

### gnome-keychain provider

- gnome-keychain headers
- Ubuntu/Debian: `libsecret-dev`
- Fedora: `libsecret-devel`
- Archlinux: `libsecret`

Tests on Linux:
```sh
 $ go test github.com/tmc/keyring
 $ # for gnome-keyring provider
 $ go test -tags gnome_keyring github.com/tmc/keyring
```

## Security considerations

- macOS: passwords are passed to `/usr/bin/security` with the `-w`
  command-line argument. They may be briefly visible in the process argument
  list to other processes on the same machine. A future implementation should
  call Keychain Services directly.
- Linux SecretService: sessions are opened with `"plain"` negotiation, so
  secrets traverse the user's D-Bus session bus unencrypted. A local process
  able to snoop that bus could read them. A future implementation should use
  `dh-ietf-1024-sha256` session encryption.
- File provider: security depends on passphrase strength.
  `KEYRING_PASSPHRASE` can leak to child processes and process listings; prefer
  `FileOptions.Passphrase` when using `NewFileProvider`.
