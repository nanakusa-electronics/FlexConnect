package appd

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"flexconnect/internal/types"
	"flexconnect/internal/vpn"
)

func closeLifecycleService(t *testing.T, service *Service) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := service.Close(ctx); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
}

func TestSuspendPausesRetriesWithoutConsumingBudget(t *testing.T) {
	restoreReconnectPolicy(t, 20*time.Millisecond, 20*time.Millisecond, 3)
	profile := testProfile("p1", true)
	backend := newFakeBackend()
	service := newTestService(t, backend, profile)
	closeLifecycleService(t, service)
	if err := service.Connect(context.Background(), profile.ID); err != nil {
		t.Fatal(err)
	}
	service.SetSuspended(true)
	backend.emit(vpn.Event{Type: "disconnected", Close: &vpn.DisconnectInfo{Code: "tls_read_timeout"}})
	waitUntil(t, time.Second, func() bool { return service.Status().State == types.StateDisconnected })
	time.Sleep(50 * time.Millisecond)
	if got := backend.connectCount(); got != 1 {
		t.Fatalf("connects during suspend = %d, want 1", got)
	}
	service.SetSuspended(false)
	waitUntil(t, time.Second, func() bool { return service.Status().State == types.StateConnected && backend.connectCount() == 2 })
}

func TestOfflineRecoveryRestartsExhaustedCycle(t *testing.T) {
	restoreReconnectPolicy(t, time.Millisecond, time.Millisecond, 3)
	profile := testProfile("p1", true)
	failure := vpn.WrapConnectError("network", true, errors.New("temporary loss"))
	backend := newFakeBackend(nil, failure, failure, failure, nil)
	service := newTestService(t, backend, profile)
	closeLifecycleService(t, service)
	if err := service.Connect(context.Background(), profile.ID); err != nil {
		t.Fatal(err)
	}
	backend.emit(vpn.Event{Type: "disconnected", Close: &vpn.DisconnectInfo{Code: "tls_read_timeout"}})
	waitUntil(t, time.Second, func() bool { return service.Status().State == types.StateError && backend.connectCount() == 4 })
	backend.emit(vpn.Event{Type: "network_change", ProfileID: profile.ID, Network: &vpn.NetworkChange{Error: "no physical route", RebindRequired: true}})
	waitUntil(t, time.Second, func() bool {
		service.mu.Lock()
		defer service.mu.Unlock()
		return service.networkOffline
	})
	service.SetSuspended(false)
	if got := backend.connectCount(); got != 4 {
		t.Fatalf("unlock while offline consumed a retry: %d", got)
	}
	backend.emit(vpn.Event{Type: "network_change", ProfileID: profile.ID, Network: &vpn.NetworkChange{RebindRequired: true, Reasons: []string{"network_recovered"}}})
	waitUntil(t, time.Second, func() bool { return service.Status().State == types.StateConnected && backend.connectCount() == 5 })
}

func TestNetworkReplacementUsesSameThreeAttemptBudget(t *testing.T) {
	restoreReconnectPolicy(t, time.Millisecond, time.Millisecond, 3)
	profile := testProfile("p1", true)
	failure := vpn.WrapConnectError("network", true, errors.New("temporary loss"))
	backend := newFakeBackend(nil, failure, failure, failure, nil)
	service := newTestService(t, backend, profile)
	closeLifecycleService(t, service)
	if err := service.Connect(context.Background(), profile.ID); err != nil {
		t.Fatal(err)
	}
	backend.emit(vpn.Event{Type: "network_change", ProfileID: profile.ID, Network: &vpn.NetworkChange{RebindRequired: true}})
	waitUntil(t, time.Second, func() bool {
		history := service.Diagnostics().ConnectionHistory
		return len(history) > 0 && history[len(history)-1].Kind == "reconnect_exhausted"
	})
	if got := backend.connectCount(); got != 4 {
		t.Fatalf("network replacement made %d connections, want initial plus 3", got)
	}
}

func TestNetworkReplacementWithoutAutoReconnectAttemptsOnce(t *testing.T) {
	restoreReconnectPolicy(t, time.Millisecond, time.Millisecond, 3)
	profile := testProfile("p1", false)
	backend := newFakeBackend(nil, vpn.WrapConnectError("network", true, errors.New("temporary loss")))
	service := newTestService(t, backend, profile)
	closeLifecycleService(t, service)
	if err := service.Connect(context.Background(), profile.ID); err != nil {
		t.Fatal(err)
	}
	backend.emit(vpn.Event{Type: "network_change", ProfileID: profile.ID, Network: &vpn.NetworkChange{RebindRequired: true}})
	waitUntil(t, time.Second, func() bool { return service.Status().State == types.StateError })
	service.SetSuspended(false)
	if got := backend.connectCount(); got != 2 {
		t.Fatalf("replacement without auto-reconnect made %d connections, want 2", got)
	}
}

func TestManualDisconnectDuringOfflineWaitClearsIntent(t *testing.T) {
	profile := testProfile("p1", true)
	backend := newFakeBackend()
	service := newTestService(t, backend, profile)
	closeLifecycleService(t, service)
	if err := service.Connect(context.Background(), profile.ID); err != nil {
		t.Fatal(err)
	}
	service.SetSuspended(true)
	if err := service.Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	service.SetSuspended(false)
	backend.emit(vpn.Event{Type: "network_change", ProfileID: profile.ID, Network: &vpn.NetworkChange{RebindRequired: true}})
	time.Sleep(20 * time.Millisecond)
	if got := backend.connectCount(); got != 1 {
		t.Fatalf("manual disconnect was undone: %d connections", got)
	}
}

type cancelReconnectBackend struct {
	*fakeBackend
	started  chan struct{}
	canceled chan struct{}
	once     sync.Once
}

func (b *cancelReconnectBackend) Connect(ctx context.Context, req vpn.ConnectRequest) (*types.SessionInfo, error) {
	if b.connectCount() == 1 {
		b.mu.Lock()
		b.connects++
		b.mu.Unlock()
		b.once.Do(func() { close(b.started) })
		<-ctx.Done()
		close(b.canceled)
		return nil, ctx.Err()
	}
	return b.fakeBackend.Connect(ctx, req)
}

func TestSuspendCancelsInFlightReconnectAndWakeReplacesIt(t *testing.T) {
	restoreReconnectPolicy(t, time.Millisecond, time.Millisecond, 3)
	profile := testProfile("p1", true)
	backend := &cancelReconnectBackend{fakeBackend: newFakeBackend(), started: make(chan struct{}), canceled: make(chan struct{})}
	service := newTestService(t, backend, profile)
	closeLifecycleService(t, service)
	if err := service.Connect(context.Background(), profile.ID); err != nil {
		t.Fatal(err)
	}
	backend.emit(vpn.Event{Type: "disconnected", Close: &vpn.DisconnectInfo{Code: "tls_read_timeout"}})
	select {
	case <-backend.started:
	case <-time.After(time.Second):
		t.Fatal("reconnect did not start")
	}
	if !service.Diagnostics().Reconnect.Active {
		t.Fatal("running reconnect is missing from diagnostics")
	}
	service.SetSuspended(true)
	select {
	case <-backend.canceled:
	case <-time.After(time.Second):
		t.Fatal("suspend did not cancel reconnect")
	}
	service.SetSuspended(false)
	waitUntil(t, time.Second, func() bool { return backend.connectCount() == 3 && service.Status().State == types.StateConnected })
}

func TestManualOperationCancelsReconnectBeforeWaitingForCommandLock(t *testing.T) {
	restoreReconnectPolicy(t, time.Millisecond, time.Millisecond, 3)
	profile := testProfile("p1", true)
	backend := &cancelReconnectBackend{fakeBackend: newFakeBackend(), started: make(chan struct{}), canceled: make(chan struct{})}
	service := newTestService(t, backend, profile)
	closeLifecycleService(t, service)
	if err := service.Connect(context.Background(), profile.ID); err != nil {
		t.Fatal(err)
	}
	backend.emit(vpn.Event{Type: "disconnected", Close: &vpn.DisconnectInfo{Code: "tls_read_timeout"}})
	select {
	case <-backend.started:
	case <-time.After(time.Second):
		t.Fatal("reconnect did not start")
	}
	op, err := service.StartOperation(SystemActor(), "disconnect", "", service.Disconnect)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-backend.canceled:
	case <-time.After(time.Second):
		t.Fatal("manual operation waited for the reconnect timeout")
	}
	waitUntil(t, time.Second, func() bool {
		service.mu.Lock()
		defer service.mu.Unlock()
		for _, event := range service.eventRing {
			if event.Operation != nil && event.Operation.ID == op.ID && event.Operation.State == types.OperationSucceeded {
				return true
			}
		}
		return false
	})
	service.SetSuspended(false)
	if got := backend.connectCount(); got != 2 {
		t.Fatalf("manual disconnect retained retry intent: %d", got)
	}
}

func TestStaleNetworkAndDisconnectEventsCannotReplaceNewConnection(t *testing.T) {
	profile := testProfile("p1", true)
	backend := newFakeBackend()
	service := newTestService(t, backend, profile)
	closeLifecycleService(t, service)
	if err := service.Connect(context.Background(), profile.ID); err != nil {
		t.Fatal(err)
	}
	backend.emit(vpn.Event{Type: "network_change", ConnectionID: "old-connection", ProfileID: profile.ID, Network: &vpn.NetworkChange{RebindRequired: true}})
	backend.emit(vpn.Event{Type: "disconnected", ConnectionID: "old-connection", Close: &vpn.DisconnectInfo{Code: "tls_read_timeout"}})
	time.Sleep(20 * time.Millisecond)
	if service.Status().State != types.StateConnected || backend.connectCount() != 1 {
		t.Fatal("stale event changed the active connection")
	}
}

func TestExplicitConnectAfterOfflineDisconnectRestoresReconnect(t *testing.T) {
	restoreReconnectPolicy(t, time.Millisecond, time.Millisecond, 3)
	profile := testProfile("p1", true)
	backend := newFakeBackend()
	service := newTestService(t, backend, profile)
	closeLifecycleService(t, service)
	if err := service.Connect(context.Background(), profile.ID); err != nil {
		t.Fatal(err)
	}
	backend.emit(vpn.Event{Type: "network_change", Network: &vpn.NetworkChange{Error: "no route", RebindRequired: true}})
	waitUntil(t, time.Second, func() bool {
		service.mu.Lock()
		defer service.mu.Unlock()
		return service.networkOffline
	})
	if err := service.Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A successful explicit connection proves the underlay is available, even
	// if the old observer's recovery notification never arrives.
	if err := service.Connect(context.Background(), profile.ID); err != nil {
		t.Fatal(err)
	}
	backend.emit(vpn.Event{Type: "disconnected", Close: &vpn.DisconnectInfo{Code: "tls_read_timeout"}})
	waitUntil(t, time.Second, func() bool { return service.Status().State == types.StateConnected && backend.connectCount() == 3 })
}

func TestManualDisconnectAfterExhaustionReleasesOwner(t *testing.T) {
	restoreReconnectPolicy(t, time.Millisecond, time.Millisecond, 1)
	profile := testProfile("p1", true)
	profile.Scope, profile.OwnerID = types.ProfileScopeUser, "alice"
	backend := newFakeBackend(nil, vpn.WrapConnectError("network", true, errors.New("temporary loss")))
	service := newTestService(t, backend, profile)
	closeLifecycleService(t, service)
	actor := Actor{ID: "alice"}
	if err := service.ConnectFor(context.Background(), actor, profile.ID); err != nil {
		t.Fatal(err)
	}
	backend.emit(vpn.Event{Type: "disconnected", Close: &vpn.DisconnectInfo{Code: "tls_read_timeout"}})
	waitUntil(t, time.Second, func() bool { return service.Status().State == types.StateError && backend.connectCount() == 2 })
	if err := service.authorize(Actor{ID: "bob"}, true); err == nil {
		t.Fatal("another user took ownership while reconnect intent was retained")
	}
	if err := service.DisconnectFor(context.Background(), actor); err != nil {
		t.Fatal(err)
	}
	if err := service.authorize(Actor{ID: "bob"}, true); err != nil {
		t.Fatalf("manual disconnect did not release owner: %v", err)
	}
}
