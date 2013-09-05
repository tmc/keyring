keyring provides cross-platform keychain access
-----------------------------------------------

Currently implemented:
- (none)

Example:

```go
  password, err := keyring.Get("libraryFoo", "jack")
  err := keyring.Set("libraryFoo", "jack", "s4craf1ce")
```
License: ISC
