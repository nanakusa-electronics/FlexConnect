package atrust

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sync"

	"flexconnect/internal/secret"
	geektrust "github.com/ShanghaitechGeekPie/geektrust/client"
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

func (s *gatewayPinStore) CheckOrEnroll(ctx context.Context, identity geektrust.GatewayIdentity, pin [sha256.Size]byte) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := s.key(identity.Address)
	v, err := s.secrets.Get(key)
	if errors.Is(err, secret.ErrNotFound) {
		err = s.secrets.Put(key, base64.StdEncoding.EncodeToString(pin[:]))
		return err == nil, err
	}
	if err != nil {
		return false, err
	}
	stored, err := base64.StdEncoding.DecodeString(v)
	if err != nil || len(stored) != sha256.Size {
		return false, errors.New("invalid gateway pin")
	}
	return subtle.ConstantTimeCompare(stored, pin[:]) == 1, nil
}
