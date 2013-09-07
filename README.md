keyring provides cross-platform keychain access
-----------------------------------------------
http://godoc.org/github.com/tmc/keyring

Keyring provides a common interface to keyring/keychain tools.

License: ISC

Currently implemented:
- OSX
- gnome-keychain

Contributions welcome!


Example:

```go
  err := keyring.Set("libraryFoo", "jack", "sacrifice")
  password, err := keyring.Get("libraryFoo", "jack")
  fmt.Println(password)
  Output: sacrifice
```

Example (generic):
```sh
 $ go build github.com/tmc/keyring/example
 $ ./example
```


Linux
=====

Linux requirements:

gnome-keychain headers:
  `libgnome-keyring-dev` on ubuntu, `libgnome-keyring` on archlinux

Tests on Linux:
```sh
 $ go test -tags gnome_keyring
```


Example (Linux, use gnome_keyring flag):
```sh
 $ go build -tags gnome_keyring github.com/tmc/keyring/example
 $ ./example
```

