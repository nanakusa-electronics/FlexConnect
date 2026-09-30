package osnet

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type fakeSnapshotSource struct {
	mu      sync.Mutex
	current UnderlaySnapshot
	err     error
}

func (f *fakeSnapshotSource) Snapshot(context.Context, string) (UnderlaySnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.current, f.err
}

func (f *fakeSnapshotSource) Set(snapshot UnderlaySnapshot, err error) {
	f.mu.Lock()
	f.current = snapshot
	f.err = err
	f.mu.Unlock()
}

func TestUnderlayMonitorDebouncesChangesAndAdvancesGeneration(t *testing.T) {
	source := &fakeSnapshotSource{current: UnderlaySnapshot{
		InterfaceName: "Ethernet", InterfaceIndex: 7,
		LocalIPv4: netip.MustParseAddr("192.0.2.10"), Gateway: netip.MustParseAddr("192.0.2.1"),
		GatewayInterface: 7, RouteMetric: 25,
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	monitor, err := NewMonitor(ctx, MonitorOptions{
		Interval: 10 * time.Millisecond, Debounce: time.Millisecond,
		Snapshot: source.Snapshot,
		Notifier: func(func()) (io.Closer, error) { return nil, errors.New("test polling") },
	})
	if err != nil {
		t.Fatalf("NewMonitor: %v", err)
	}
	defer monitor.Close()
	changes := monitor.Changes(ctx)
	source.Set(UnderlaySnapshot{
		InterfaceName: "Wi-Fi", InterfaceIndex: 8,
		LocalIPv4: netip.MustParseAddr("198.51.100.10"), Gateway: netip.MustParseAddr("198.51.100.1"),
		GatewayInterface: 8, RouteMetric: 10,
	}, nil)
	select {
	case change := <-changes:
		if change.Err != nil {
			t.Fatalf("unexpected monitor error: %v", change.Err)
		}
		if change.After.Generation != 2 {
			t.Fatalf("generation = %d, want 2", change.After.Generation)
		}
		if !change.RebindRequired {
			t.Fatal("underlay change did not require rebind")
		}
		if len(change.Reasons) == 0 || change.Reasons[0] != "interface_changed" {
			t.Fatalf("reasons = %v", change.Reasons)
		}
	case <-time.After(time.Second):
		t.Fatal("underlay monitor did not emit change")
	}
}

func TestUnderlayMonitorReportsSnapshotErrorOnceUntilRecovery(t *testing.T) {
	source := &fakeSnapshotSource{current: UnderlaySnapshot{InterfaceName: "Ethernet"}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	monitor, err := NewMonitor(ctx, MonitorOptions{
		Interval: 10 * time.Millisecond, Debounce: time.Millisecond,
		Snapshot: source.Snapshot,
		Notifier: func(func()) (io.Closer, error) { return nil, errors.New("test polling") },
	})
	if err != nil {
		t.Fatalf("NewMonitor: %v", err)
	}
	defer monitor.Close()
	changes := monitor.Changes(ctx)
	source.Set(UnderlaySnapshot{}, errors.New("route table unavailable"))
	select {
	case change := <-changes:
		if change.Err == nil || !change.RebindRequired || len(change.Reasons) != 1 || change.Reasons[0] != "snapshot_error" {
			t.Fatalf("change = %+v", change)
		}
	case <-time.After(time.Second):
		t.Fatal("underlay monitor did not report snapshot error")
	}
	select {
	case change := <-changes:
		if change.Err != nil {
			t.Fatalf("snapshot error repeated: %+v", change)
		}
	case <-time.After(35 * time.Millisecond):
	}
	// Recovery to exactly the previous interface/address still wakes a paused
	// lifecycle; a value comparison alone would lose this transition.
	source.Set(UnderlaySnapshot{InterfaceName: "Ethernet"}, nil)
	select {
	case change := <-changes:
		if change.Err != nil || !change.RebindRequired || change.After.Generation != 2 {
			t.Fatalf("recovery change = %+v", change)
		}
		found := false
		for _, reason := range change.Reasons {
			found = found || reason == "network_recovered"
		}
		if !found {
			t.Fatalf("recovery reasons = %v", change.Reasons)
		}
	case <-time.After(time.Second):
		t.Fatal("same-path recovery was not reported")
	}
}
