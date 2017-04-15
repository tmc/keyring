package keyring

import (
	"fmt"
	"testing"
)

func AssertPasswordSticks(t *testing.T, user, password string) {
	var (
		pw  string
		err error
	)
	pw, err = Get("keyring-test", user)
	if err != nil {
		// ok on initial invokation
		fmt.Println("Get() error:", err)
	}
	err = Set("keyring-test", user, password)
	if err != nil {
		t.Error("Set() error:", err)
	}
	pw, err = Get("keyring-test", user)
	if err != nil {
		t.Errorf("Get() error for %s: %s", user, err)
	}

	if pw != password {
		fmt.Errorf("expected 'test', got '%s'", pw)
		t.Fail()
	}
}

func TestBasicSetGet(t *testing.T) {
	AssertPasswordSticks(t, "jack", "pass")
	AssertPasswordSticks(t, "alice", "cr4zyp!s\\%")
}
