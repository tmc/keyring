package keyring

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	fileProviderVersion = 1
	fileProviderKDF     = "argon2id"

	argon2Time    = 1
	argon2Memory  = 64 * 1024
	argon2Threads = 4
	argon2KeyLen  = 32

	maxArgon2Time    = 16
	maxArgon2Memory  = 1 << 20
	maxArgon2Threads = 16
)

var errFileProviderPassphrase = errors.New("keyring: file provider requires a passphrase (set KEYRING_PASSPHRASE or FileOptions.Passphrase)")

var (
	_ Provider   = (*FileProvider)(nil)
	_ Lister     = (*FileProvider)(nil)
	_ DeleterAll = (*FileProvider)(nil)
)

// FileProvider is a platform-neutral keyring Provider that stores secrets
// in an encrypted file. It is not registered automatically; construct one
// with NewFileProvider and register it with RegisterProvider to enable it.
//
// A FileProvider is safe for concurrent use through a single instance.
// Concurrent writers to the same file through separate FileProvider instances
// or separate processes are not coordinated; the last writer wins. Writes use
// a temporary file and rename, so readers see either the old file or the new
// file; file contents are fsynced before rename. Each Get, Set, and Delete
// derives the key with memory-hard Argon2id and operations on one instance are
// serialized by a mutex, so FileProvider is intended for low-frequency fallback
// use, not high-throughput lookups.
type FileProvider struct {
	path       string
	passphrase string
	mu         sync.Mutex
}

// FileOptions configures a FileProvider.
type FileOptions struct {
	// Path is the store file location. Empty means
	// <UserConfigDir>/keyring/store.enc.
	Path string
	// Passphrase is the encryption passphrase. Empty means read
	// KEYRING_PASSPHRASE at operation time.
	Passphrase string
}

type fileEnvelope struct {
	Version    int    `json:"version"`
	KDF        string `json:"kdf"`
	Time       uint32 `json:"time"`
	Memory     uint32 `json:"memory"`
	Threads    uint8  `json:"threads"`
	KeyLen     uint32 `json:"keylen"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// NewFileProvider returns a platform-neutral keyring Provider backed by an
// encrypted file.
func NewFileProvider(opts FileOptions) *FileProvider {
	return &FileProvider{
		path:       opts.Path,
		passphrase: opts.Passphrase,
	}
}

func (p *FileProvider) Get(service, username string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	passphrase, err := p.resolvePassphrase()
	if err != nil {
		return "", err
	}
	store, _, err := p.readStore(passphrase)
	if err != nil {
		return "", err
	}
	users, ok := store[service]
	if !ok {
		return "", ErrNotFound
	}
	password, ok := users[username]
	if !ok {
		return "", ErrNotFound
	}
	return password, nil
}

func (p *FileProvider) Set(service, username, password string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	passphrase, err := p.resolvePassphrase()
	if err != nil {
		return err
	}
	store, salt, err := p.readStore(passphrase)
	if err != nil {
		return err
	}
	if store[service] == nil {
		store[service] = make(map[string]string)
	}
	store[service][username] = password
	return p.writeStore(passphrase, salt, store)
}

func (p *FileProvider) Delete(service, username string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	passphrase, err := p.resolvePassphrase()
	if err != nil {
		return err
	}
	store, salt, err := p.readStore(passphrase)
	if err != nil {
		return err
	}
	users, ok := store[service]
	if !ok {
		return ErrNotFound
	}
	if _, ok := users[username]; !ok {
		return ErrNotFound
	}
	delete(users, username)
	if len(users) == 0 {
		delete(store, service)
	}
	return p.writeStore(passphrase, salt, store)
}

// ListUsers returns the usernames stored under service, in unspecified order.
// It returns an empty slice when the service has no entries. FileProvider
// implements the package Lister interface.
func (p *FileProvider) ListUsers(service string) ([]string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	passphrase, err := p.resolvePassphrase()
	if err != nil {
		return nil, err
	}
	store, _, err := p.readStore(passphrase)
	if err != nil {
		return nil, err
	}
	users := make([]string, 0, len(store[service]))
	for username := range store[service] {
		users = append(users, username)
	}
	return users, nil
}

// DeleteAll removes every entry stored under service. It returns ErrNotFound
// when the service has no entries. FileProvider implements the package
// DeleterAll interface.
func (p *FileProvider) DeleteAll(service string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	passphrase, err := p.resolvePassphrase()
	if err != nil {
		return err
	}
	store, salt, err := p.readStore(passphrase)
	if err != nil {
		return err
	}
	if _, ok := store[service]; !ok {
		return ErrNotFound
	}
	delete(store, service)
	return p.writeStore(passphrase, salt, store)
}

func (p *FileProvider) resolvePassphrase() (string, error) {
	if p.passphrase != "" {
		return p.passphrase, nil
	}
	if passphrase := os.Getenv("KEYRING_PASSPHRASE"); passphrase != "" {
		return passphrase, nil
	}
	return "", errFileProviderPassphrase
}

func (p *FileProvider) storePath() (string, error) {
	if p.path != "" {
		return p.path, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "keyring", "store.enc"), nil
}

func (p *FileProvider) readStore(passphrase string) (map[string]map[string]string, []byte, error) {
	path, err := p.storePath()
	if err != nil {
		return nil, nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return make(map[string]map[string]string), nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var envelope fileEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, nil, err
	}
	plain, salt, err := decryptFileStore(passphrase, envelope)
	if err != nil {
		return nil, nil, fmt.Errorf("keyring: decrypt store: %w", err)
	}
	var store map[string]map[string]string
	if err := json.Unmarshal(plain, &store); err != nil {
		return nil, nil, err
	}
	if store == nil {
		store = make(map[string]map[string]string)
	}
	return store, salt, nil
}

func (p *FileProvider) writeStore(passphrase string, salt []byte, store map[string]map[string]string) error {
	path, err := p.storePath()
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	plain, err := json.Marshal(store)
	if err != nil {
		return err
	}
	envelope, err := encryptFileStore(passphrase, salt, plain)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(envelope, "", "\t")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".store-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func encryptFileStore(passphrase string, salt, plain []byte) (fileEnvelope, error) {
	var err error
	if salt == nil {
		salt, err = randomBytes(16)
		if err != nil {
			return fileEnvelope{}, err
		}
	}
	if len(salt) != 16 {
		return fileEnvelope{}, fmt.Errorf("invalid salt size")
	}
	nonce, err := randomBytes(chacha20poly1305.NonceSizeX)
	if err != nil {
		return fileEnvelope{}, err
	}
	key := argon2.IDKey([]byte(passphrase), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fileEnvelope{}, err
	}
	ciphertext := aead.Seal(nil, nonce, plain, nil)
	return fileEnvelope{
		Version:    fileProviderVersion,
		KDF:        fileProviderKDF,
		Time:       argon2Time,
		Memory:     argon2Memory,
		Threads:    argon2Threads,
		KeyLen:     argon2KeyLen,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}, nil
}

func decryptFileStore(passphrase string, envelope fileEnvelope) ([]byte, []byte, error) {
	if envelope.Version != fileProviderVersion {
		return nil, nil, fmt.Errorf("unsupported version %d", envelope.Version)
	}
	if envelope.KDF != fileProviderKDF {
		return nil, nil, fmt.Errorf("unsupported kdf %q", envelope.KDF)
	}
	if err := validateArgon2Params(envelope); err != nil {
		return nil, nil, err
	}
	salt, err := base64.StdEncoding.DecodeString(envelope.Salt)
	if err != nil {
		return nil, nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(envelope.Nonce)
	if err != nil {
		return nil, nil, err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return nil, nil, err
	}
	if len(salt) != 16 {
		return nil, nil, fmt.Errorf("invalid salt size")
	}
	if len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, nil, fmt.Errorf("invalid nonce size")
	}
	key := argon2.IDKey([]byte(passphrase), salt, envelope.Time, envelope.Memory, envelope.Threads, envelope.KeyLen)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, err
	}
	plain, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, nil, err
	}
	return plain, salt, nil
}

func validateArgon2Params(envelope fileEnvelope) error {
	if envelope.Time == 0 || envelope.Time > maxArgon2Time {
		return fmt.Errorf("invalid argon2 time %d", envelope.Time)
	}
	if envelope.Memory == 0 || envelope.Memory > maxArgon2Memory {
		return fmt.Errorf("invalid argon2 memory %d", envelope.Memory)
	}
	if envelope.Threads == 0 || envelope.Threads > maxArgon2Threads {
		return fmt.Errorf("invalid argon2 threads %d", envelope.Threads)
	}
	if envelope.KeyLen != argon2KeyLen {
		return fmt.Errorf("invalid argon2 key length %d", envelope.KeyLen)
	}
	return nil
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}
