keyring provides cross-platform keychain access
-----------------------------------------------
http://godoc.org/github.com/tmc/keyring

Currently implemented:
- OSX
- gnome-keychain

Contributions welcome!

Linux requirements:
- gnome-keychain headers:
  `libgnome-keyring-dev` on ubuntu, `libgnome-keyring` on archlinux

Example:

```go
  err := keyring.Set("libraryFoo", "jack", "sacrifice")
  password, err := keyring.Get("libraryFoo", "jack")
  fmt.Println(password)
  Output: sacrifice
```
License: ISC
