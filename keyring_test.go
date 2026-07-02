package keyring

import (
	"testing"
)

func assertPasswordSticks(t *testing.T, user, password string) {
	var (
		pw  string
		err error
	)
	pw, err = Get("keyring-test", user)
	if err != nil {
		// ok on initial invokation
		t.Logf("(expected) Initial Get() error for %s: %s", user, err)
	}
	err = Set("keyring-test", user, password)
	if err != nil {
		t.Errorf("Set() error for %s: %s", user, err)
	}
	pw, err = Get("keyring-test", user)
	if err != nil {
		t.Errorf("Get() error for %s: %s", user, err)
	}

	if pw != password {
		t.Errorf("expected '%s' for %s, got '%s'", password, user, pw)
	}
}

func TestBasicSetGet(t *testing.T) {
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
		assertPasswordSticks(t, testCase.user, testCase.password)
	}
}

func TestDelete(t *testing.T) {
	service := "keyring-test-delete"
	user := "deleteuser"
	password := "deletepass"

	// Set a password
	err := Set(service, user, password)
	if err != nil {
		t.Fatalf("Set() error: %s", err)
	}

	// Verify it was set
	pw, err := Get(service, user)
	if err != nil {
		t.Fatalf("Get() error after Set(): %s", err)
	}
	if pw != password {
		t.Errorf("expected '%s', got '%s'", password, pw)
	}

	// Delete the password
	err = Delete(service, user)
	if err != nil {
		t.Fatalf("Delete() error: %s", err)
	}

	// Verify it was deleted
	_, err = Get(service, user)
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound after Delete(), got: %v", err)
	}
}

func TestDeleteNonExistent(t *testing.T) {
	service := "keyring-test-delete-nonexistent"
	user := "nonexistentuser"

	// Try to delete a non-existent password
	err := Delete(service, user)
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound for non-existent password, got: %v", err)
	}
}
