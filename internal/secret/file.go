package secret

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// FileStore persists daemon-owned plaintext secrets. The file and its parent
// directory are restricted; Linux daemons use this backend by default.
type FileStore struct {
	path string
	mu   sync.Mutex
}

func NewFileStore(path string) *FileStore {
	return &FileStore{path: path}
}

func (s *FileStore) Get(ref string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.loadLocked()
	if err != nil {
		return "", err
	}
	v, ok := data[ref]
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrNotFound, ref)
	}
	return v, nil
}

func (s *FileStore) Put(ref, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.loadLocked()
	if err != nil {
		return err
	}
	data[ref] = value
	return s.saveLocked(data)
}

func (s *FileStore) Delete(ref string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.loadLocked()
	if err != nil {
		return err
	}
	if _, ok := data[ref]; !ok {
		return nil
	}
	delete(data, ref)
	return s.saveLocked(data)
}

func (s *FileStore) loadLocked() (map[string]string, error) {
	_, err := os.Stat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	if err := secureDir(filepath.Dir(s.path)); err != nil {
		return nil, fmt.Errorf("secure secret directory: %w", err)
	}
	if err := secureFile(s.path); err != nil {
		return nil, fmt.Errorf("secure secret file: %w", err)
	}
	b, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return map[string]string{}, nil
	}
	var data map[string]string
	if err := json.Unmarshal(b, &data); err != nil {
		return nil, fmt.Errorf("load secret file %s: %w", s.path, err)
	}
	if data == nil {
		return map[string]string{}, nil
	}
	return data, nil
}

func (s *FileStore) saveLocked(data map[string]string) error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := secureDir(dir); err != nil {
		return fmt.Errorf("secure secret directory: %w", err)
	}
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	// CreateTemp uses O_EXCL, so a pre-placed symlink at a fixed tmp name
	// cannot redirect the write; fsync guards against losing secrets on crash.
	f, err := os.CreateTemp(dir, filepath.Base(s.path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op after a successful rename
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(b); err != nil {
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
	if err := replaceAtomic(tmp, s.path); err != nil {
		return err
	}
	if err := secureFile(s.path); err != nil {
		return fmt.Errorf("secure secret file: %w", err)
	}
	// Flush the directory entry so the rename itself survives a crash.
	return syncDir(dir)
}
