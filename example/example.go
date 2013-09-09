// Shows example use of the keyring package
//
// May need to be built with a platform-specific build flag to specify a
// provider.
//
// For Example, on Linux, to use the gnome-keyring provider:
// 	$ go build +gnome_keyring github.com/tmc/keyring/example
// 	$ ./example
//
package main

import (
	"os"
	"fmt"
	"code.google.com/p/gopass"
	"github.com/tmc/keyring"
)

func main() {
	if pw, err := keyring.Get("keyring_example", "jack"); err == nil {
		fmt.Println("current stored password:", pw)
	} else if err == keyring.ErrNotFound {
		fmt.Println("no password stored yet")
	} else {
		fmt.Println("got unexpected error:", err)
		os.Exit(1)
	}
	pw, err := gopass.GetPass("enter new password: ")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	keyring.Set("keyring_example", "jack", pw)
	if pw, err := keyring.Get("keyring_example", "jack"); err == nil {
		fmt.Println("stored", pw)
	} else {
		fmt.Println("error:", err)
	}
}
