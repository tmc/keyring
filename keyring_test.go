package keyring

import (
	"fmt"
	"testing"
)

func TestBasicSetGet(t *testing.T) {
	var (
		pw  string
		err error
	)
	pw, err = Get("keyring-test", "jack")
	if err != nil {
		fmt.Println("Get() error:", err)
	}
	err = Set("keyring-test", "jack", "test")
	if err != nil {
		fmt.Println("Set() error:", err)
	}
	pw, err = Get("keyring-test", "jack")
	if err != nil {
		fmt.Println("Get() error:", err)
	}
	if pw != "test" {
		fmt.Errorf("expected 'test', got '%s'", pw)
	}
}
