//go:build !linux

package main

import (
	"testing"

	"flexconnect/internal/secret"
	"github.com/zalando/go-keyring"
)

func TestDefaultSecretsUseKeyring(t *testing.T) {
	keyring.MockInit()
	defer keyring.MockInit()
	opts, err := parseDaemonOptions(nil, mapEnv{}.lookup)
	if err != nil {
		t.Fatal(err)
	}
	if opts.secretStore != "keyring" {
		t.Fatalf("default store = %q", opts.secretStore)
	}
	store, err := newSecretStore(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.(*secret.KeyringStore); !ok {
		t.Fatalf("store = %T", store)
	}
}
