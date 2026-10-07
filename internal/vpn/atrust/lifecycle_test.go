package atrust

import (
	"context"
	"errors"
	"flexconnect/internal/osnet"
	"flexconnect/internal/secret"
	"flexconnect/internal/vpn"
	"sync/atomic"
	"testing"
	"time"
)

type testMonitor struct {
	changes chan osnet.UnderlayChange
	closed  atomic.Bool
}

func (m *testMonitor) Snapshot(context.Context) (osnet.UnderlaySnapshot, error) {
	return osnet.UnderlaySnapshot{}, nil
}
func (m *testMonitor) Changes(context.Context) <-chan osnet.UnderlayChange { return m.changes }
func (m *testMonitor) Close() error                                        { m.closed.Store(true); return nil }

type testManager struct {
	err     error
	stopped *bool
}

func (*testManager) Up(context.Context) error                                    { return nil }
func (*testManager) Set(context.Context, *osnet.Config) error                    { return nil }
func (*testManager) SetDynamicRoutes(context.Context, osnet.DynamicRoutes) error { return nil }
func (m *testManager) Close(context.Context) error {
	if !*m.stopped {
		return errors.New("traffic still active during cleanup")
	}
	return m.err
}

func TestDisconnectKeepsMonitorAndRetriesNetworkCleanup(t *testing.T) {
	b := New(secret.NewMemoryStore())
	monitor := &testMonitor{changes: make(chan osnet.UnderlayChange, 2)}
	stopped := false
	manager := &testManager{err: errors.New("route removal failed"), stopped: &stopped}
	ctx, cancel := context.WithCancel(context.Background())
	b.monitor, b.monitorCancel, b.manager, b.cancel = monitor, cancel, manager, func() { stopped = true }
	done := make(chan struct{})
	go func() { b.watchNetwork(ctx, monitor, vpn.ConnectRequest{ConnectionID: "connection"}); close(done) }()
	defer b.Close(context.Background())
	if err := b.Disconnect(context.Background()); err == nil {
		t.Fatal("cleanup failure lost")
	}
	if monitor.closed.Load() || b.manager != manager || !stopped {
		t.Fatal("ownership or observer lost before cleanup")
	}
	manager.err = nil
	if err := b.Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, reason := range []string{"network_lost", "network_recovered"} {
		monitor.changes <- osnet.UnderlayChange{Reasons: []string{reason}}
		select {
		case event := <-b.Events():
			if event.Network.Reasons[0] != reason {
				t.Fatal("wrong event")
			}
		case <-time.After(time.Second):
			t.Fatal("observer stopped after first change or disconnect")
		}
	}
	if err := b.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !monitor.closed.Load() {
		t.Fatal("observer not closed")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("observer goroutine leaked")
	}
}
