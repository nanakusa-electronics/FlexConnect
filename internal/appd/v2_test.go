package appd

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"flexconnect/internal/router"
	"flexconnect/internal/secret"
	storefile "flexconnect/internal/store/file"
	"flexconnect/internal/types"
	"flexconnect/internal/vpn"
)

func TestActorProfileIsolation(t *testing.T) {
	alice := testProfile("alice-profile", false)
	alice.Scope = types.ProfileScopeUser
	alice.OwnerID = "alice"
	bob := testProfile("bob-profile", false)
	bob.Scope = types.ProfileScopeUser
	bob.OwnerID = "bob"
	machine := testProfile("machine-profile", false)
	machine.Scope = types.ProfileScopeMachine
	machine.OwnerID = "system"
	service := newTestService(t, newFakeBackend(), alice, bob, machine)
	profiles, err := service.ListProfilesFor(Actor{ID: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 1 || profiles[0].ID != alice.ID {
		t.Fatalf("profiles = %+v", profiles)
	}
	if profiles[0].OwnerID != "" || profiles[0].SecretRef != "" {
		t.Fatalf("internal fields leaked: %+v", profiles[0])
	}
	if _, err := service.UpdateProfileFor(Actor{ID: "alice"}, bob.ID, types.ProfileUpdateRequest{}); errorCode(err) != "profile_not_found" {
		t.Fatalf("cross-owner update error = %v", err)
	}
}

func TestMachineModeLocksUsersUntilAdminExit(t *testing.T) {
	profile := testProfile("machine", false)
	profile.Scope = types.ProfileScopeMachine
	profile.OwnerID = "system"
	service := newTestService(t, newFakeBackend(), profile)
	admin := Actor{ID: "administrator", Admin: true}
	if err := service.SetControlMode(context.Background(), admin, types.ControlModeRequest{Mode: "machine", ProfileID: profile.ID}); err != nil {
		t.Fatal(err)
	}
	if err := service.DisconnectFor(context.Background(), Actor{ID: "alice"}); errorCode(err) != "machine_mode_locked" {
		t.Fatalf("ordinary disconnect error = %v", err)
	}
	status, err := service.StatusFor(Actor{ID: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if status.ControlMode != "machine" || status.ConnectedProfileID != "" || status.Session != nil {
		t.Fatalf("ordinary status = %+v", status)
	}
	if err := service.SetControlMode(context.Background(), admin, types.ControlModeRequest{Mode: "user"}); err != nil {
		t.Fatal(err)
	}
	if got := service.Status().ControlMode; got != "user" {
		t.Fatalf("control mode = %q", got)
	}
}

func TestMachineProfileCreationDoesNotCorruptPerUserSelection(t *testing.T) {
	store := &memoryStore{}
	service, err := New(store, secret.NewMemoryStore(), newFakeBackend(), router.DefaultPlanner{})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close(context.Background())
	_, err = service.CreateProfileFor(SystemActor(), types.ProfileCreateRequest{
		Provider: types.ProviderAnyConnect, AuthMethod: types.AuthPassword,
		Name: "unattended", ServerURL: "https://vpn.example.test", Username: "machine",
		Password: "secret", Scope: types.ProfileScopeMachine, MTU: 1406,
	})
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	selected := cloneStringMap(store.data.SelectedProfiles)
	stored := store.data
	store.mu.Unlock()
	if len(selected) != 0 {
		t.Fatalf("machine profile entered per-user selection: %+v", selected)
	}
	secrets := secret.NewMemoryStore()
	if err := secrets.Put(stored.Profiles[0].SecretRef, "secret"); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(&memoryStore{data: stored}, secrets, newFakeBackend(), router.DefaultPlanner{})
	if err != nil {
		t.Fatalf("strict restart rejected machine profile state: %v", err)
	}
	defer restarted.Close(context.Background())
}

func TestElevatedAdministratorCannotMutateAnotherUsersProfile(t *testing.T) {
	service := newTestService(t, newFakeBackend(), testProfile("alice-profile", false))
	profile := service.ListProfiles()[0]
	profile.Scope = types.ProfileScopeUser
	profile.OwnerID = "alice"
	service.mu.Lock()
	service.profiles[0] = profile
	service.mu.Unlock()
	name := "changed"
	_, err := service.UpdateProfileFor(Actor{ID: "administrator", Admin: true}, profile.ID, types.ProfileUpdateRequest{Name: &name})
	if err == nil {
		t.Fatal("administrator modified another user's profile")
	}
}

func TestInvalidIdleWriteDoesNotClaimDaemonOwnership(t *testing.T) {
	service := newTestService(t, newFakeBackend(), testProfile("existing", false))
	defer service.Close(context.Background())
	name := "changed"
	if _, err := service.UpdateProfileFor(Actor{ID: "alice"}, "missing", types.ProfileUpdateRequest{Name: &name}); err == nil {
		t.Fatal("missing profile update succeeded")
	}
	service.mu.Lock()
	owner := service.activeOwnerID
	service.mu.Unlock()
	if owner != "" {
		t.Fatalf("invalid write claimed daemon owner %q", owner)
	}
}

func TestTerminalUserDisconnectReleasesDaemonOwnership(t *testing.T) {
	profile := testProfile("alice-profile", false)
	profile.Scope = types.ProfileScopeUser
	profile.OwnerID = "alice"
	backend := newFakeBackend()
	service := newTestService(t, backend, profile)
	defer service.Close(context.Background())
	actor := Actor{ID: "alice"}
	if err := service.ConnectFor(context.Background(), actor, profile.ID); err != nil {
		t.Fatal(err)
	}
	service.mu.Lock()
	connectionID := service.activeConnectionID
	service.mu.Unlock()
	backend.emit(vpn.Event{Type: "disconnected", ConnectionID: connectionID, ProfileID: profile.ID, Close: &vpn.DisconnectInfo{Code: "authentication_failed", Error: "session rejected"}})
	waitUntil(t, time.Second, func() bool {
		service.mu.Lock()
		defer service.mu.Unlock()
		return service.activeOwnerID == ""
	})
}

func TestWatchReplayAndEpochResync(t *testing.T) {
	profile := testProfile("p1", false)
	service := newTestService(t, newFakeBackend(), profile)
	service.mu.Lock()
	service.emitLocked(types.Notify{Event: "profile", Profile: &profile})
	epoch, revision := service.epoch, service.revision
	service.emitLocked(types.Notify{Event: "status", Status: ptrStatus(service.status)})
	service.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	replay := service.WatchSince(ctx, SystemActor(), epoch, revision)
	select {
	case event := <-replay:
		if event.Event != "status" || event.Revision <= revision {
			t.Fatalf("replay event = %+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("watch replay timed out")
	}
	resync := service.WatchSince(ctx, SystemActor(), "stale-epoch", 999)
	select {
	case event := <-resync:
		if event.Event != "snapshot" || event.Epoch != epoch {
			t.Fatalf("resync event = %+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("watch resync timed out")
	}
}

func TestRandomFailureStopsDaemonProfileAndConnectionCreation(t *testing.T) {
	randomErr := errors.New("random source unavailable")
	originalID, originalProfile := newID, newProfile
	defer func() { newID, newProfile = originalID, originalProfile }()
	newID = func() (string, error) { return "", randomErr }
	if _, err := New(&memoryStore{}, secret.NewMemoryStore(), newFakeBackend(), router.DefaultPlanner{}); !errors.Is(err, randomErr) {
		t.Fatalf("New error = %v", err)
	}
	newID = originalID
	service := newTestService(t, newFakeBackend(), testProfile("p1", false))
	newProfile = func(string) (types.Profile, error) { return types.Profile{}, randomErr }
	if _, err := service.CreateProfileFor(SystemActor(), types.ProfileCreateRequest{Provider: types.ProviderAnyConnect, AuthMethod: types.AuthPassword, Name: "new", Password: "test-password"}); !errors.Is(err, randomErr) {
		t.Fatalf("CreateProfileFor error = %v", err)
	}
	newProfile = originalProfile
	newID = func() (string, error) { return "", randomErr }
	if err := service.Connect(context.Background(), "p1"); !errors.Is(err, randomErr) {
		t.Fatalf("Connect error = %v", err)
	}
}

func TestWatchResyncsWhenRevisionFellOutOfRing(t *testing.T) {
	service := newTestService(t, newFakeBackend(), testProfile("p1", false))
	service.mu.Lock()
	for i := 0; i < 1030; i++ {
		service.emitLocked(types.Notify{Event: "health", Message: "tick"})
	}
	epoch := service.epoch
	service.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watch := service.WatchSince(ctx, SystemActor(), epoch, 1)
	select {
	case event := <-watch:
		if event.Event != "snapshot" {
			t.Fatalf("event = %+v, want snapshot", event)
		}
	case <-time.After(time.Second):
		t.Fatal("watch resync timed out")
	}
}

func TestActiveProfileUpdatePersistsBeforeAsyncReconnect(t *testing.T) {
	profile := testProfile("p1", false)
	service := newTestService(t, newFakeBackend(), profile)
	if err := service.Connect(context.Background(), profile.ID); err != nil {
		t.Fatal(err)
	}
	name := "updated"
	op, err := service.UpdateActiveProfileFor(SystemActor(), profile.ID, types.ProfileUpdateRequest{Name: &name})
	if err != nil {
		t.Fatal(err)
	}
	if op.State != types.OperationRunning {
		t.Fatalf("operation = %+v", op)
	}
	profiles, err := service.ListProfilesFor(SystemActor())
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 1 || profiles[0].Name != name {
		t.Fatalf("profiles = %+v", profiles)
	}
}

func TestTerminalOperationIsDeletedAfterWatchPublication(t *testing.T) {
	service := newTestService(t, newFakeBackend(), testProfile("p1", false))
	op, err := service.StartOperation(SystemActor(), "test", "p1", func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	waitUntil(t, time.Second, func() bool {
		_, err := service.OperationFor(SystemActor(), op.ID)
		return errorCode(err) == "operation_not_found"
	})
	service.mu.Lock()
	defer service.mu.Unlock()
	found := false
	for _, event := range service.eventRing {
		if event.Operation != nil && event.Operation.ID == op.ID && event.Operation.State == types.OperationSucceeded {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("terminal operation was not retained in the watch ring")
	}
}

func TestStatusExposesOnlyActorsRunningOperation(t *testing.T) {
	service := newTestService(t, newFakeBackend(), testProfile("p1", false))
	defer service.Close(context.Background())
	release := make(chan struct{})
	op, err := service.StartOperation(Actor{ID: "alice"}, "test", "", func(context.Context) error {
		<-release
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	alice, err := service.StatusFor(Actor{ID: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if alice.Operation == nil || alice.Operation.ID != op.ID {
		t.Fatalf("owner status operation = %+v", alice.Operation)
	}
	bob, err := service.StatusFor(Actor{ID: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	if bob.Operation != nil {
		t.Fatalf("other actor saw operation %+v", bob.Operation)
	}
	close(release)
	waitUntil(t, time.Second, func() bool {
		status, _ := service.StatusFor(Actor{ID: "alice"})
		return status.Operation == nil
	})
}

func TestStartupRecoversCommittedProfileIntent(t *testing.T) {
	old := testProfile("p1", false)
	updated := old
	updated.Name = "updated"
	updated.SecretRef = "profile/p1/new"
	store := &memoryStore{data: storefile.Data{SchemaVersion: storefile.CurrentSchemaVersion, Profiles: []types.Profile{old}, CurrentProfileID: old.ID, ControlMode: "user", SelectedProfiles: map[string]string{}, Intent: &storefile.Intent{Version: 1, Kind: "upsert", ProfileID: old.ID, NewProfile: &updated, OldSecretRef: old.SecretRef, NewSecretRef: updated.SecretRef}}}
	secrets := secret.NewMemoryStore()
	if err := secrets.Put(old.SecretRef, "old"); err != nil {
		t.Fatal(err)
	}
	if err := secrets.Put(updated.SecretRef, "new"); err != nil {
		t.Fatal(err)
	}
	service, err := New(store, secrets, newFakeBackend(), router.DefaultPlanner{})
	if err != nil {
		t.Fatal(err)
	}
	if got := service.ListProfiles(); len(got) != 1 || got[0].Name != "updated" {
		t.Fatalf("profiles = %+v", got)
	}
	if _, err := secrets.Get(old.SecretRef); err == nil {
		t.Fatal("old secret survived recovery")
	}
	store.mu.Lock()
	intent := store.data.Intent
	store.mu.Unlock()
	if intent != nil {
		t.Fatalf("intent not cleared: %+v", intent)
	}
}

func TestStartupRejectsLegacyProfileWithoutOwner(t *testing.T) {
	profile := testProfile("legacy", false)
	profile.OwnerID = ""
	store := &memoryStore{data: storefile.Data{SchemaVersion: storefile.CurrentSchemaVersion, Profiles: []types.Profile{profile}, CurrentProfileID: profile.ID, ControlMode: "user", SelectedProfiles: map[string]string{}}}
	secrets := secret.NewMemoryStore()
	_ = secrets.Put(profile.SecretRef, "password")
	if _, err := New(store, secrets, newFakeBackend(), router.DefaultPlanner{}); err == nil || !strings.Contains(err.Error(), "profile owner is required") {
		t.Fatalf("startup error = %v", err)
	}
}

type lateBackend struct {
	started chan struct{}
	release chan struct{}
	events  chan vpn.Event
	once    sync.Once
}

func newLateBackend() *lateBackend {
	return &lateBackend{started: make(chan struct{}), release: make(chan struct{}), events: make(chan vpn.Event)}
}
func (b *lateBackend) Connect(context.Context, vpn.ConnectRequest) (*types.SessionInfo, error) {
	b.once.Do(func() { close(b.started) })
	<-b.release
	return &types.SessionInfo{ConnectionID: "late"}, nil
}
func (*lateBackend) Disconnect(context.Context) error { return nil }
func (*lateBackend) Close(context.Context) error      { return nil }
func (*lateBackend) SessionInfo() *types.SessionInfo  { return nil }
func (*lateBackend) Traffic() *types.TrafficStats     { return nil }
func (*lateBackend) ReadServerConfig() map[string]any { return nil }
func (b *lateBackend) Events() <-chan vpn.Event       { return b.events }
func (*lateBackend) TunnelDialer(context.Context) (vpn.TunnelDialer, error) {
	return nil, errors.New("not connected")
}

func TestCanceledConnectingAttemptRejectsLateSuccess(t *testing.T) {
	profile := testProfile("p1", false)
	backend := newLateBackend()
	store := &memoryStore{data: storefile.Data{SchemaVersion: storefile.CurrentSchemaVersion, Profiles: []types.Profile{profile}, CurrentProfileID: profile.ID, ControlMode: "user", SelectedProfiles: map[string]string{}}}
	secrets := secret.NewMemoryStore()
	if err := secrets.Put(profile.SecretRef, "password"); err != nil {
		t.Fatal(err)
	}
	service, err := New(store, secrets, backend, router.DefaultPlanner{})
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- service.Connect(context.Background(), profile.ID) }()
	select {
	case <-backend.started:
	case <-time.After(time.Second):
		t.Fatal("connect did not start")
	}
	if err := service.Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	close(backend.release)
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("late connect error = %v", err)
	}
	status := service.Status()
	if status.State != types.StateDisconnected || status.ConnectedProfileID != "" {
		t.Fatalf("status = %+v", status)
	}
}
