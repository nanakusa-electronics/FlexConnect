package secret

import (
	"os"
	"strings"
	"testing"
)

func TestHybridStoreEncryptsLargeCredentialAndPersistsUpdate(t *testing.T) {
	base := NewMemoryStore()
	dir := t.TempDir()
	store := NewHybridStore(base, dir)
	ref := "profile/test"
	initial := strings.Repeat("private-keystore-data", 200)
	if err := store.Put(ref, initial); err != nil {
		t.Fatal(err)
	}
	if raw, err := base.Get(ref); err != nil || raw != blobMarker {
		t.Fatalf("base contains %q: %v", raw, err)
	}
	onDisk, err := os.ReadFile(store.path(ref))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(onDisk), "private-keystore-data") {
		t.Fatal("credential stored in plaintext")
	}
	updated := initial + "-counter-1"
	if err := store.Put(ref, updated); err != nil {
		t.Fatal(err)
	}
	reopened := NewHybridStore(base, dir)
	if got, err := reopened.Get(ref); err != nil || got != updated {
		t.Fatalf("reloaded credential mismatch: %v", err)
	}
	if err := reopened.Delete(ref); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(store.path(ref)); !os.IsNotExist(err) {
		t.Fatalf("encrypted payload remains: %v", err)
	}
}
