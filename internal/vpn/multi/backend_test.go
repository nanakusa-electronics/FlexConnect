package multi

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"flexconnect/internal/types"
	"flexconnect/internal/vpn"
)

type testBackend struct {
	connectErr error
	closeErr   error
	closed     int
	events     chan vpn.Event
}

func (b *testBackend) Connect(_ context.Context, req vpn.ConnectRequest) (*types.SessionInfo, error) {
	if b.connectErr != nil {
		return nil, b.connectErr
	}
	return &types.SessionInfo{ConnectionID: req.ConnectionID}, nil
}
func (b *testBackend) Disconnect(context.Context) error { b.closed++; return b.closeErr }
func (b *testBackend) Close(ctx context.Context) error  { return b.Disconnect(ctx) }
func (b *testBackend) SessionInfo() *types.SessionInfo  { return nil }
func (b *testBackend) Traffic() *types.TrafficStats     { return nil }
func (b *testBackend) ReadServerConfig() map[string]any { return nil }
func (b *testBackend) Events() <-chan vpn.Event         { return b.events }
func (b *testBackend) TunnelDialer(context.Context) (vpn.TunnelDialer, error) {
	return nil, net.ErrClosed
}

func TestFailedConnectionRetainsFailedCleanup(t *testing.T) {
	bad := &testBackend{connectErr: errors.New("connect failed"), closeErr: errors.New("route cleanup failed"), events: make(chan vpn.Event)}
	created := 0
	selector := New(map[types.Provider]Factory{types.ProviderATrust: func() vpn.Backend { created++; return bad }})
	request := vpn.ConnectRequest{Profile: types.Profile{Provider: types.ProviderATrust}}
	if _, err := selector.Connect(context.Background(), request); err == nil {
		t.Fatal("failed connection accepted")
	}
	if selector.current() != bad {
		t.Fatal("failed cleanup was forgotten")
	}
	if _, err := selector.Connect(context.Background(), request); err == nil {
		t.Fatal("new attempt bypassed cleanup")
	}
	if created != 1 {
		t.Fatal("factory ran before old cleanup")
	}
	bad.closeErr = nil
	if err := selector.Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestSwitchStopsOnCleanupFailure(t *testing.T) {
	old := &testBackend{events: make(chan vpn.Event, 1)}
	next := &testBackend{events: make(chan vpn.Event, 1)}
	created := 0
	selector := New(map[types.Provider]Factory{
		types.ProviderAnyConnect: func() vpn.Backend { return old },
		types.ProviderATrust:     func() vpn.Backend { created++; return next },
	})
	ctx := context.Background()
	if _, err := selector.Connect(ctx, vpn.ConnectRequest{Profile: types.Profile{Provider: types.ProviderAnyConnect}, ConnectionID: "old"}); err != nil {
		t.Fatal(err)
	}
	old.closeErr = errors.New("route cleanup failed")
	if _, err := selector.Connect(ctx, vpn.ConnectRequest{Profile: types.Profile{Provider: types.ProviderATrust}, ConnectionID: "next"}); err == nil {
		t.Fatal("switch succeeded after cleanup failure")
	}
	if created != 0 || selector.current() != old {
		t.Fatal("new provider started after cleanup failure")
	}
	old.closeErr = nil
	if _, err := selector.Connect(ctx, vpn.ConnectRequest{Profile: types.Profile{Provider: types.ProviderATrust}, ConnectionID: "next"}); err != nil {
		t.Fatal(err)
	}
	old.events <- vpn.Event{Type: "disconnected", ConnectionID: "old"}
	next.events <- vpn.Event{Type: "health", ConnectionID: "next"}
	select {
	case event := <-selector.Events():
		if event.ConnectionID != "next" {
			t.Fatalf("stale event forwarded: %+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("current event not forwarded")
	}
	if err := selector.Disconnect(ctx); err != nil {
		t.Fatal(err)
	}
}
