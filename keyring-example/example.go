// Shows example use of the keyring package
//
// May need to be built with a platform-specific build flag to specify a
// provider. See keyring documentation for details.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/tmc/keyring"
	"golang.org/x/term"
)

func main() {
	if pw, err := keyring.Get("keyring_example", "jack"); err == nil {
		fmt.Println("current stored password:", pw)
	} else if errors.Is(err, keyring.ErrNotFound) {
		fmt.Println("no password stored yet")
	} else {
		fmt.Println("got unexpected error:", err)
		os.Exit(1)
	}

	fmt.Printf("enter new password: ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("setting keyring_example/jack to..", pw)
	err = keyring.Set("keyring_example", "jack", string(pw))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("fetching keyring_example/jack..")
	if pw, err := keyring.Get("keyring_example", "jack"); err == nil {
		fmt.Println("got", pw)
	} else {
		fmt.Println("error:", err)
	}
	if err := keyring.Delete("keyring_example", "jack"); err != nil {
		fmt.Println("delete error:", err)
	}
}
