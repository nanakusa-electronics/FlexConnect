package systray

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"flexconnect/client/local"
	"flexconnect/internal/types"
)

// fakeFailingClient returns a distinct error from Status/Profiles/Traffic so
// that consolidation tests can distinguish "three alerts" (old behavior) from
// "one alert" (new behavior) even though reportError would otherwise dedup by
// message.
type fakeFailingClient struct{}

type unattendedClient struct {
	fakeFailingClient
	id  string
	req types.ProfileUpdateRequest
}

func (c *unattendedClient) UpdateProfile(_ context.Context, id string, req types.ProfileUpdateRequest) (types.ProfileMutationResult, error) {
	c.id, c.req = id, req
	return types.ProfileMutationResult{}, nil
}

func TestUnattendedModeToggleUpdatesSelectedProfile(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		client := &unattendedClient{}
		menu := &Menu{Client: client, notifier: &recordingNotifier{}, status: &types.Status{SelectedProfileID: "selected"}}
		menu.init()
		menu.handleUnattendedModeToggle(enabled)
		if client.id != "selected" || client.req.UnattendedMode == nil || *client.req.UnattendedMode != enabled {
			t.Fatalf("update = %q %+v", client.id, client.req)
		}
	}
}

func (fakeFailingClient) Status(context.Context) (*types.Status, error) {
	return nil, errors.New("status unavailable")
}
func (fakeFailingClient) Profiles(context.Context) ([]types.Profile, error) {
	return nil, errors.New("profiles unavailable")
}
func (fakeFailingClient) Traffic(context.Context) (*types.TrafficSnapshot, error) {
	return nil, errors.New("traffic unavailable")
}
func (fakeFailingClient) UpdateCheck(context.Context) (*types.UpdateInfo, error) {
	return nil, errors.New("update check unavailable")
}
func (fakeFailingClient) Disconnect(context.Context) error { return nil }
func (fakeFailingClient) SwitchProfile(context.Context, string) error {
	return nil
}
func (fakeFailingClient) Connect(context.Context, string) error { return nil }
func (fakeFailingClient) ConnectCurrent(context.Context) error  { return nil }
func (fakeFailingClient) UpdateProfile(context.Context, string, types.ProfileUpdateRequest) (types.ProfileMutationResult, error) {
	return types.ProfileMutationResult{}, nil
}
func (fakeFailingClient) DiagnosticsText(context.Context) (string, error) { return "", nil }
func (fakeFailingClient) Watch(context.Context) (*local.Watcher, error)   { return nil, nil }

// assert jitterFraction is overridable and deterministic at midpoint.
func TestRetryDelayCapsAndGrows(t *testing.T) {
	prev := jitterFraction
	jitterFraction = func() float64 { return 0.5 } // midpoint => zero offset
	defer func() { jitterFraction = prev }()

	d0 := retryDelay(0)
	if d0 != backoffBase {
		t.Fatalf("attempt 0 = %v, want %v", d0, backoffBase)
	}
	last := d0
	for a := 1; a < 8; a++ {
		d := retryDelay(a)
		if d < backoffBase {
			t.Fatalf("attempt %d = %v below base %v", a, d, backoffBase)
		}
		if d > backoffMax {
			t.Fatalf("attempt %d = %v above cap %v", a, d, backoffMax)
		}
		if d < last {
			t.Fatalf("attempt %d = %v < previous %v (non-monotonic)", a, d, last)
		}
		last = d
	}
	if got := retryDelay(100); got != backoffMax {
		t.Fatalf("attempt 100 = %v, want cap %v", got, backoffMax)
	}
}

func TestRetryDelayNeverBelowBase(t *testing.T) {
	prev := jitterFraction
	jitterFraction = func() float64 { return 0 } // max negative offset
	defer func() { jitterFraction = prev }()
	for a := 0; a < 6; a++ {
		if d := retryDelay(a); d < backoffBase {
			t.Fatalf("attempt %d = %v below base %v", a, d, backoffBase)
		}
	}
}

func TestRefreshConsolidatesErrorsToOneAlert(t *testing.T) {
	recorder := &recordingNotifier{}
	menu := &Menu{Client: fakeFailingClient{}, notifier: recorder}
	menu.init()
	menu.refresh(context.Background())
	if len(recorder.alerts) != 1 {
		t.Fatalf("alerts = %d, want 1 (one consolidated alert per refresh)", len(recorder.alerts))
	}
}

func TestErrorSeenSweepsExpiredAfterRecovery(t *testing.T) {
	prevTime := timeNow
	t0 := time.Now()
	timeNow = func() time.Time { return t0 }
	defer func() { timeNow = prevTime }()

	recorder := &recordingNotifier{}
	menu := &Menu{notifier: recorder}
	menu.init()
	menu.reportError("op", errors.New("err1"))
	menu.mu.Lock()
	n1 := len(menu.errorSeen)
	menu.mu.Unlock()
	if n1 != 1 {
		t.Fatalf("errorSeen = %d, want 1", n1)
	}

	// Advance past the dedup TTL and report a different error: the stale
	// err1 entry should be swept, leaving only the new entry.
	timeNow = func() time.Time { return t0.Add(31 * time.Second) }
	menu.reportError("op", errors.New("err2"))
	menu.mu.Lock()
	n2 := len(menu.errorSeen)
	menu.mu.Unlock()
	if n2 != 1 {
		t.Fatalf("errorSeen after sweep = %d, want 1 (stale entry should be gone)", n2)
	}
}

func TestNotifiedMapBoundedGrowth(t *testing.T) {
	menu := &Menu{rebuildCh: make(chan struct{}, 1), notifier: &recordingNotifier{}}
	menu.init()
	for i := 0; i < 200; i++ {
		id := fmt.Sprintf("reconnect-%d", i)
		event := types.ConnectionEvent{ID: id, ConnectionID: id, Kind: "reconnect_scheduled", Attempt: 1}
		menu.handleNotify(types.Notify{Connection: &event}, func() {})
	}
	menu.mu.Lock()
	n := len(menu.notified)
	menu.mu.Unlock()
	if n > notifiedMax {
		t.Fatalf("notified map grew to %d, want <= %d", n, notifiedMax)
	}
}

func TestOpCtxDerivedFromRunCtx(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	menu := &Menu{Client: fakeFailingClient{}}
	menu.init()
	menu.mu.Lock()
	menu.runCtx = ctx
	menu.mu.Unlock()

	opCtx, opCancel := menu.opCtx()
	defer opCancel()
	if err := opCtx.Err(); err != nil {
		t.Fatalf("opCtx already done before runCtx cancel: %v", err)
	}
	cancel()
	select {
	case <-opCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("opCtx not cancelled after runCtx was cancelled")
	}
}

func TestRebuildDebouncesBurst(t *testing.T) {
	renders := make(chan menuModel, 4)
	menu := &Menu{
		Client: fakeFailingClient{},
		render: func(_ context.Context, model menuModel) { renders <- model },
	}
	menu.init()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go menu.rebuildLoop(ctx)

	// Fire a burst of rebuild requests.
	menu.requestRebuild()
	menu.requestRebuild()
	menu.requestRebuild()

	select {
	case <-renders:
	case <-time.After(time.Second):
		t.Fatal("expected at least one rebuild")
	}
	// After the debounce window, no extra renders should arrive from the burst.
	select {
	case extra := <-renders:
		t.Fatalf("expected single coalesced render, got extra: %+v", extra)
	case <-time.After(150 * time.Millisecond):
	}
}
