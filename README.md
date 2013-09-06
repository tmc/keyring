keyring provides cross-platform keychain access
-----------------------------------------------
http://godoc.org/github.com/tmc/keyring

Currently implemented:
- OSX
- gnome-keychain (needs testing/love)

Contributions welcome!

Example:

```go
  password, err := keyring.Get("libraryFoo", "jack")
  err := keyring.Set("libraryFoo", "jack", "s4craf1ce")
```
License: ISC
