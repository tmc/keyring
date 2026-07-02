package keyring

import (
	"errors"
	"testing"
)

func assertPasswordSticks(t *testing.T, service, user, password string) {
	t.Helper()
	var (
		pw  string
		err error
	)
	t.Cleanup(func() {
		_ = Delete(service, user)
	})
	pw, err = Get(service, user)
	if err != nil {
		// ok on initial invocation
		t.Logf("(expected) Initial Get() error for %s: %s", user, err)
	}
	err = Set(service, user, password)
	if err != nil {
		t.Errorf("Set() error for %s: %s", user, err)
	}
	pw, err = Get(service, user)
	if err != nil {
		t.Errorf("Get() error for %s: %s", user, err)
	}

	if pw != password {
		t.Errorf("expected '%s' for %s, got '%s'", password, user, pw)
	}
}

func TestBasicSetGet(t *testing.T) {
	service := "keyring-test"
	cases := []struct {
		user     string
		password string
	}{
		{"jack", "foo"},
		{"jill", "bar"},
		{"alice", "cr4zyp!s\\%"},
		{"punctuator", "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"},
		{"pierre", "bérets"},
		{"unibomba", "I❤Unicode"},
	}
	for _, testCase := range cases {
		assertPasswordSticks(t, service, testCase.user, testCase.password)
	}
}

func TestDelete(t *testing.T) {
	service := "keyring-test-delete"
	user := "deleteuser"
	password := "deletepass"
	t.Cleanup(func() {
		_ = Delete(service, user)
	})

	err := Set(service, user, password)
	if err != nil {
		t.Fatalf("Set() error: %s", err)
	}

	pw, err := Get(service, user)
	if err != nil {
		t.Fatalf("Get() error after Set(): %s", err)
	}
	if pw != password {
		t.Errorf("expected '%s', got '%s'", password, pw)
	}

	err = Delete(service, user)
	if err != nil {
		t.Fatalf("Delete() error: %s", err)
	}

	_, err = Get(service, user)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound after Delete(), got: %v", err)
	}
}

func TestDeleteNonExistent(t *testing.T) {
	service := "keyring-test-delete-nonexistent"
	user := "nonexistentuser"

	err := Delete(service, user)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound for non-existent password, got: %v", err)
	}
}
