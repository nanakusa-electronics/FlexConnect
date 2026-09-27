package atrust

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sync"

	"flexconnect/internal/secret"
)

// gatewayPinStore persists gateway public-key pins beside the profile secret.
// Probes for the same profile share one store, so first-use pins cannot race.
type gatewayPinStore struct {
	mu      sync.Mutex
	secrets secret.Store
	ref     string
}

func (s *gatewayPinStore) key(addr string) string {
	h := sha256.Sum256([]byte(addr))
	return s.ref + "/gateway/" + hex.EncodeToString(h[:])
}

func (s *gatewayPinStore) LoadPin(ctx context.Context, addr string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v, err := s.secrets.Get(s.key(addr))
	if errors.Is(err, secret.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	pin, err := base64.StdEncoding.DecodeString(v)
	if err != nil || len(pin) != sha256.Size {
		return nil, errors.New("invalid gateway pin")
	}
	return pin, nil
}

func (s *gatewayPinStore) SavePin(ctx context.Context, addr string, pin []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(pin) != sha256.Size {
		return errors.New("invalid gateway pin")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := s.key(addr)
	if existing, err := s.secrets.Get(key); err == nil {
		decoded, err := base64.StdEncoding.DecodeString(existing)
		if err != nil || len(decoded) != sha256.Size || !equalPin(decoded, pin) {
			return errors.New("gateway public key changed")
		}
		return nil
	} else if !errors.Is(err, secret.ErrNotFound) {
		return err
	}
	return s.secrets.Put(key, base64.StdEncoding.EncodeToString(pin))
}

func equalPin(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
