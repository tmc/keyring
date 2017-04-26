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
	}
	for _, testCase := range cases {
		assertPasswordSticks(t, testCase.user, testCase.password)
	}
}
