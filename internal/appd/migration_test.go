package appd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"flexconnect/internal/router"
	"flexconnect/internal/secret"
	storefile "flexconnect/internal/store/file"
	"flexconnect/internal/types"
)

func TestSchema2MigrationPreservesProfilesAndCredentials(t *testing.T) {
	for _, mode := range []string{"user", "machine"} {
		t.Run(mode, func(t *testing.T) {
			profile := testProfile("p1", true)
			profile.Provider, profile.AuthMethod = "", ""
			profile.OwnerID = "test-owner"
			profile.Scope = types.ProfileScopeUser
			profile.CustomInclude = []string{"10.0.0.0/8"}
			profile.DNSOverrides = []string{"10.0.0.53"}
			data := storefile.Data{SchemaVersion: 2, Profiles: []types.Profile{profile}, CurrentProfileID: profile.ID, ControlMode: mode, SelectedProfiles: map[string]string{profile.OwnerID: profile.ID}}
			if mode == "machine" {
				profile.Scope, profile.OwnerID = types.ProfileScopeMachine, "system"
				data.Profiles[0] = profile
				data.MachineProfileID = profile.ID
				data.SelectedProfiles = map[string]string{}
			}
			store := storefile.New(filepath.Join(t.TempDir(), "state.json"))
			if err := store.Save(data); err != nil {
				t.Fatal(err)
			}
			secrets := secret.NewMemoryStore()
			if err := secrets.Put(profile.SecretRef, "existing-password"); err != nil {
				t.Fatal(err)
			}
			start := func() {
				service, err := New(store, secrets, newFakeBackend(), router.DefaultPlanner{})
				if err != nil {
					t.Fatal(err)
				}
				if err := service.Close(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			start()
			loaded, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			profile.Provider, profile.AuthMethod = types.ProviderAnyConnect, types.AuthPassword
			data.SchemaVersion, data.Profiles[0] = storefile.CurrentSchemaVersion, profile
			if !reflect.DeepEqual(loaded, data) {
				t.Fatal("migration changed existing profile or control metadata")
			}
			password, err := secrets.Get(profile.SecretRef)
			if err != nil || password != "existing-password" {
				t.Fatal("existing password reference was lost")
			}
			start()
			again, err := store.Load()
			if err != nil || !reflect.DeepEqual(loaded, again) {
				t.Fatal("restart changed migrated state")
			}
		})
	}
}

func TestSchema2MigrationRecoversPendingProfile(t *testing.T) {
	profile := testProfile("p1", false)
	profile.Provider, profile.AuthMethod = "", ""
	store := &memoryStore{data: storefile.Data{SchemaVersion: 2, ControlMode: "user", Intent: &storefile.Intent{Version: 1, Kind: "upsert", ProfileID: profile.ID, NewProfile: &profile, NewSecretRef: profile.SecretRef}}}
	secrets := secret.NewMemoryStore()
	if err := secrets.Put(profile.SecretRef, "password"); err != nil {
		t.Fatal(err)
	}
	service, err := New(store, secrets, newFakeBackend(), router.DefaultPlanner{})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close(context.Background())
	data, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if data.SchemaVersion != 3 || data.Intent != nil || len(data.Profiles) != 1 || data.Profiles[0].Provider != types.ProviderAnyConnect || data.Profiles[0].AuthMethod != types.AuthPassword {
		t.Fatal("pending legacy transaction was not migrated and recovered")
	}
}

func TestSchema2MigrationRejectsInvalidStateWithoutWriting(t *testing.T) {
	for _, schema := range []int{2, 1, 4} {
		path := filepath.Join(t.TempDir(), "state.json")
		store := storefile.New(path)
		if err := store.Save(storefile.Data{SchemaVersion: schema, ControlMode: "invalid"}); err != nil {
			t.Fatal(err)
		}
		// Compare bytes to ensure rejected input is not rewritten.
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := New(store, secret.NewMemoryStore(), newFakeBackend(), router.DefaultPlanner{}); err == nil {
			t.Fatal("invalid state accepted")
		}
		after, err := os.ReadFile(path)
		if err != nil || string(before) != string(after) {
			t.Fatal("rejected state changed")
		}
	}
}

type migrationSaveFailure struct{ memoryStore }

func (s *migrationSaveFailure) Save(storefile.Data) error { return errors.New("save failed") }

func TestSchema2MigrationSaveFailurePreventsStartup(t *testing.T) {
	store := &migrationSaveFailure{memoryStore{data: storefile.Data{SchemaVersion: 2, ControlMode: "user"}}}
	_, err := New(store, secret.NewMemoryStore(), newFakeBackend(), router.DefaultPlanner{})
	if err == nil || !strings.Contains(err.Error(), "persist schema 2 to 3 migration") {
		t.Fatalf("error = %v", err)
	}
}
