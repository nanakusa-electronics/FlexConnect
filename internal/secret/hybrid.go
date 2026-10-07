package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

const blobMarker = "encrypted-blob:v1"
const blobKeyRef = "flexconnect/encrypted-blob-key/v1"

// HybridStore keeps short secrets in the configured Store. Larger credentials
// are encrypted in private files with a key protected by that same Store.
// This avoids platform keyring item-size limits without persisting plaintext.
type HybridStore struct {
	base Store
	dir  string
	mu   sync.Mutex
}

func NewHybridStore(base Store, dir string) *HybridStore { return &HybridStore{base: base, dir: dir} }

func (s *HybridStore) path(ref string) string {
	hash := sha256.Sum256([]byte(ref))
	return filepath.Join(s.dir, hex.EncodeToString(hash[:])+".blob")
}

func (s *HybridStore) key() ([]byte, error) {
	encoded, err := s.base.Get(blobKeyRef)
	if errors.Is(err, ErrNotFound) {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		if err := s.base.Put(blobKeyRef, base64.StdEncoding.EncodeToString(key)); err != nil {
			return nil, err
		}
		return key, nil
	}
	if err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(key) != 32 {
		return nil, errors.New("invalid encrypted secret key")
	}
	return key, nil
}

func (s *HybridStore) Get(ref string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, err := s.base.Get(ref)
	if err != nil || value != blobMarker {
		return value, err
	}
	key, err := s.key()
	if err != nil {
		return "", err
	}
	path := s.path(ref)
	if err := secureDir(s.dir); err != nil {
		return "", err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() < 12 || info.Size() > 2<<20 {
		return "", errors.New("invalid encrypted credential file")
	}
	if err := secureFile(path); err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(data) < aead.NonceSize() {
		return "", errors.New("encrypted credential is truncated")
	}
	plain, err := aead.Open(nil, data[:aead.NonceSize()], data[aead.NonceSize():], []byte(ref))
	if err != nil {
		return "", errors.New("cannot decrypt credential")
	}
	return string(plain), nil
}

func (s *HybridStore) Put(ref, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	previous, err := s.base.Get(ref)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if len(value) <= 1024 && previous != blobMarker {
		return s.base.Put(ref, value)
	}
	if len(value) > 1<<20 {
		return errors.New("credential exceeds maximum size")
	}
	key, err := s.key()
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	data := append(nonce, aead.Seal(nil, nonce, []byte(value), []byte(ref))...)
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	if err := secureDir(s.dir); err != nil {
		return err
	}
	f, err := os.CreateTemp(s.dir, ".credential-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := replaceAtomic(tmp, s.path(ref)); err != nil {
		return err
	}
	if err := secureFile(s.path(ref)); err != nil {
		return err
	}
	if err := syncDir(s.dir); err != nil {
		return err
	}
	if err := s.base.Put(ref, blobMarker); err != nil {
		return fmt.Errorf("commit encrypted credential reference: %w", err)
	}
	return nil
}

func (s *HybridStore) Delete(ref string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, err := s.base.Get(ref)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := s.base.Delete(ref); err != nil {
		return err
	}
	if value == blobMarker {
		if err := os.Remove(s.path(ref)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := syncDir(s.dir); err != nil {
			return err
		}
	}
	return nil
}

var _ Store = (*HybridStore)(nil)
