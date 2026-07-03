package keyring

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

type osxProvider struct {
}

func init() {
	RegisterProvider("osx", 10, osxProvider{})
}

// encodingPrefix marks a value that was base64-encoded before being handed to
// security(1). Encoding lets secrets containing newlines, quotes, or arbitrary
// bytes survive the round trip through the command's textual interface. Values
// written by older versions of this package (or by other tools) lack the prefix
// and are returned verbatim.
const encodingPrefix = "keyring-base64:"

// maxSecurityInput bounds the command written to security(1)'s stdin. The tool
// reads a bounded line, and an over-long secret is better reported than sent
// and silently truncated.
const maxSecurityInput = 4096

var pwRe = regexp.MustCompile(`password:\s+(?:0x[A-Fa-f0-9]+\s+)?"(.+)"`)

var escapeCodeRegexp = regexp.MustCompile(`\\([0-3][0-7]{2})`)

func unescapeOne(code []byte) []byte {
	i, _ := strconv.ParseUint(string(code[1:]), 8, 8)
	return []byte{byte(i)}
}

func unescape(raw string) string {
	if !escapeCodeRegexp.MatchString(raw) {
		return raw
	}
	return string(escapeCodeRegexp.ReplaceAllFunc([]byte(raw), unescapeOne))
}

// shellQuote wraps s in single quotes for security(1)'s input parser, which
// tokenizes its stdin with shell-like quoting. An embedded single quote is
// closed, backslash-escaped, then reopened.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func (p osxProvider) Get(service, username string) (string, error) {
	args := []string{"find-generic-password",
		"-s", service,
		"-a", username,
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
	value := unescape(matches[1])
	if strings.HasPrefix(value, encodingPrefix) {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, encodingPrefix))
		if err != nil {
			return "", fmt.Errorf("/usr/bin/security: decode secret: %w", err)
		}
		return string(decoded), nil
	}
	return value, nil
}

func (p osxProvider) Set(service, username, password string) error {
	// Write the command to security(1)'s stdin rather than passing the
	// secret as a -w argument, which would expose it in the process argument
	// list. The password is base64-encoded so any byte value survives the
	// textual interface.
	encoded := encodingPrefix + base64.StdEncoding.EncodeToString([]byte(password))
	command := fmt.Sprintf("add-generic-password -U -s %s -a %s -w %s\n",
		shellQuote(service), shellQuote(username), shellQuote(encoded))
	if len(command) > maxSecurityInput {
		return ErrSetDataTooBig
	}

	c := exec.Command("/usr/bin/security", "-i")
	stdin, err := c.StdinPipe()
	if err != nil {
		return err
	}
	if err := c.Start(); err != nil {
		return err
	}
	if _, err := stdin.Write([]byte(command)); err != nil {
		stdin.Close()
		_ = c.Wait()
		return err
	}
	if err := stdin.Close(); err != nil {
		_ = c.Wait()
		return err
	}
	if err := c.Wait(); err != nil {
		return fmt.Errorf("/usr/bin/security: %w", err)
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
