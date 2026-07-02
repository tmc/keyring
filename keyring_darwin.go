package keyring

import (
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
)

type osxProvider struct {
}

func init() {
	RegisterProvider("osx", 10, osxProvider{})
}

var pwRe = regexp.MustCompile(`password:\s+(?:0x[A-Fa-f0-9]+\s+)?"(.+)"`)

var escapeCodeRegexp = regexp.MustCompile(`\\([0-3][0-7]{2})`)

func unescapeOne(code []byte) []byte {
	i, _ := strconv.ParseUint(string(code[1:]), 8, 8)
	return []byte{byte(i)}
}

func unescape(raw string) string {
	if !escapeCodeRegexp.MatchString(raw) {
		return raw
	} else {
		return string(escapeCodeRegexp.ReplaceAllFunc([]byte(raw), unescapeOne))
	}
}

func (p osxProvider) Get(Service, Username string) (string, error) {
	args := []string{"find-generic-password",
		"-s", Service,
		"-a", Username,
		"-g"}
	c := exec.Command("/usr/bin/security", args...)
	o, err := c.CombinedOutput()
	if err != nil {
		if exitCode(err) == 44 {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("/usr/bin/security: %w", err)
	}
	matches := pwRe.FindStringSubmatch(string(o))
	if len(matches) != 2 {
		return "", ErrNotFound
	}
	return unescape(matches[1]), nil
}

func (p osxProvider) Set(Service, Username, Password string) error {
	args := []string{"add-generic-password",
		"-s", Service,
		"-a", Username,
		"-w", Password,
		"-U"}
	c := exec.Command("/usr/bin/security", args...)
	o, err := c.CombinedOutput()
	if err != nil {
		return fmt.Errorf("/usr/bin/security: %w: %s", err, o)
	}
	return nil
}

func (p osxProvider) Delete(service, username string) error {
	args := []string{"delete-generic-password",
		"-s", service,
		"-a", username}
	c := exec.Command("/usr/bin/security", args...)
	err := c.Run()
	if err != nil {
		if exitCode(err) == 44 {
			return ErrNotFound
		}
		return fmt.Errorf("/usr/bin/security: %w", err)
	}
	return nil
}

func exitCode(err error) int {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}
