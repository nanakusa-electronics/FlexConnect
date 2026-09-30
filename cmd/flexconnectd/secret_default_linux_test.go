//go:build linux

package main

import (
	"errors"
	"path/filepath"
	"testing"

	"flexconnect/internal/secret"
	"github.com/zalando/go-keyring"
)

func TestLinuxDefaultSecretsSurviveRestartWithoutKeyring(t *testing.T) {
	keyring.MockInitWithError(errors.New("no desktop session"))
	defer keyring.MockInit()
	opts, err := parseDaemonOptions(nil, mapEnv{}.lookup)
	if err != nil {
		t.Fatal(err)
	}
	if opts.secretStore != "file" {
		t.Fatalf("default store = %q", opts.secretStore)
	}
	state := filepath.Join(t.TempDir(), "daemon", "state.json")
	for _, kind := range []string{opts.secretStore, ""} {
		store, err := newSecretStore(state, kind)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := store.(*secret.FileStore); !ok {
			t.Fatalf("store = %T", store)
		}
		if err := store.Put("profile-secret", "test-password"); err != nil {
			t.Fatal(err)
		}
	}
	restarted, err := newSecretStore(state, "")
	if err != nil {
		t.Fatal(err)
	}
	got, err := restarted.Get("profile-secret")
	if err != nil || got != "test-password" {
		t.Fatalf("secret did not survive restart: %v", err)
	}
	if err := restarted.Delete("profile-secret"); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Get("profile-secret"); !errors.Is(err, secret.ErrNotFound) {
		t.Fatalf("deleted secret: %v", err)
	}
}
