package osnet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"time"
)

// UnderlaySnapshot describes the physical path used to reach the VPN
// endpoint. It intentionally excludes the FlexConnect TUN interface.
type UnderlaySnapshot struct {
	InterfaceName    string
	InterfaceIndex   int
	LocalIPv4        netip.Addr
	Gateway          netip.Addr
	GatewayInterface int
	RouteMetric      int
	Generation       uint64
}

// UnderlayChange is emitted after the physical path changes or a snapshot
// operation fails. Err is kept internal to the daemon; callers expose only a
// sanitized reason through the diagnostics API.
type UnderlayChange struct {
	Before         UnderlaySnapshot
	After          UnderlaySnapshot
	Reasons        []string
	RebindRequired bool
	Err            error
}

type Monitor interface {
	Snapshot(context.Context) (UnderlaySnapshot, error)
	Changes(context.Context) <-chan UnderlayChange
	Close() error
}

type MonitorOptions struct {
	ExcludeInterface string
	Interval         time.Duration
	Debounce         time.Duration
	Snapshot         func(context.Context, string) (UnderlaySnapshot, error)
	Notifier         func(func()) (io.Closer, error)
}

type underlayMonitor struct {
	ctx         context.Context
	cancel      context.CancelFunc
	changes     chan UnderlayChange
	trigger     chan struct{}
	notifier    io.Closer
	snapshot    func(context.Context) (UnderlaySnapshot, error)
	interval    time.Duration
	debounce    time.Duration
	notifierErr error
	mu          sync.RWMutex
	current     UnderlaySnapshot
	closed      bool
	once        sync.Once
}

func NewMonitor(ctx context.Context, opts MonitorOptions) (Monitor, error) {
	if ctx == nil {
		return nil, errors.New("nil underlay monitor context")
	}
	if opts.Interval <= 0 {
		opts.Interval = time.Second
	}
	if opts.Debounce <= 0 {
		opts.Debounce = 300 * time.Millisecond
	}
	if opts.Snapshot == nil {
		opts.Snapshot = GetUnderlaySnapshot
	}
	if opts.Notifier == nil {
		opts.Notifier = newUnderlayNotifier
	}

	initial, err := opts.Snapshot(ctx, opts.ExcludeInterface)
	if err != nil {
		return nil, fmt.Errorf("read initial underlay snapshot: %w", err)
	}
	initial.Generation = 1
	monitorCtx, cancel := context.WithCancel(ctx)
	m := &underlayMonitor{
		ctx:      monitorCtx,
		cancel:   cancel,
		changes:  make(chan UnderlayChange, 16),
		trigger:  make(chan struct{}, 1),
		current:  initial,
		interval: opts.Interval,
		debounce: opts.Debounce,
		snapshot: func(ctx context.Context) (UnderlaySnapshot, error) {
			return opts.Snapshot(ctx, opts.ExcludeInterface)
		},
	}
	if notifier, notifyErr := opts.Notifier(func() {
		select {
		case m.trigger <- struct{}{}:
		default:
		}
	}); notifyErr == nil {
		m.notifier = notifier
	} else {
		m.notifierErr = notifyErr
	}
	go m.run()
	return m, nil
}

func (m *underlayMonitor) NotifierError() error {
	if m == nil {
		return errors.New("nil underlay monitor")
	}
	return m.notifierErr
}

func (m *underlayMonitor) Snapshot(ctx context.Context) (UnderlaySnapshot, error) {
	if m == nil {
		return UnderlaySnapshot{}, errors.New("nil underlay monitor")
	}
	if ctx == nil {
		return UnderlaySnapshot{}, errors.New("nil underlay snapshot context")
	}
	return m.snapshot(ctx)
}

func (m *underlayMonitor) Changes(ctx context.Context) <-chan UnderlayChange {
	if ctx == nil {
		return m.changes
	}
	out := make(chan UnderlayChange, 16)
	go func() {
		defer close(out)
		for {
			select {
			case change, ok := <-m.changes:
				if !ok {
					return
				}
				select {
				case out <- change:
				case <-ctx.Done():
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

func (m *underlayMonitor) Close() error {
	if m == nil {
		return nil
	}
	m.once.Do(func() {
		m.cancel()
		if m.notifier != nil {
			_ = m.notifier.Close()
		}
	})
	return nil
}

func (m *underlayMonitor) run() {
	defer close(m.changes)
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	lastSnapshotError := false
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
		case <-m.trigger:
		}

		next, err := m.snapshot(m.ctx)
		if err != nil {
			if !lastSnapshotError {
				lastSnapshotError = true
				m.emit(UnderlayChange{
					Before:         m.currentSnapshot(),
					Reasons:        []string{"snapshot_error"},
					RebindRequired: true,
					Err:            err,
				})
			}
			continue
		}
		recovered := lastSnapshotError
		if !recovered && sameUnderlay(m.currentSnapshot(), next) {
			continue
		}

		if m.debounce > 0 {
			timer := time.NewTimer(m.debounce)
			select {
			case <-timer.C:
			case <-m.ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				return
			}
			latest, latestErr := m.snapshot(m.ctx)
			if latestErr != nil {
				lastSnapshotError = true
				m.emit(UnderlayChange{
					Before:         m.currentSnapshot(),
					Reasons:        []string{"snapshot_error_after_change"},
					RebindRequired: true,
					Err:            latestErr,
				})
				continue
			}
			next = latest
		}

		lastSnapshotError = false
		before := m.currentSnapshot()
		next.Generation = before.Generation + 1
		change := UnderlayChange{
			Before:         before,
			After:          next,
			Reasons:        underlayReasons(before, next),
			RebindRequired: underlayRequiresRebind(before, next),
		}
		if recovered {
			change.Reasons = append(change.Reasons, "network_recovered")
			change.RebindRequired = true
		}
		m.mu.Lock()
		m.current = next
		m.mu.Unlock()
		m.emit(change)
	}
}

func (m *underlayMonitor) currentSnapshot() UnderlaySnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current
}

func (m *underlayMonitor) emit(change UnderlayChange) {
	select {
	case m.changes <- change:
	case <-m.ctx.Done():
	}
}

func sameUnderlay(a, b UnderlaySnapshot) bool {
	return a.InterfaceName == b.InterfaceName &&
		a.InterfaceIndex == b.InterfaceIndex &&
		a.LocalIPv4 == b.LocalIPv4 &&
		a.Gateway == b.Gateway &&
		a.GatewayInterface == b.GatewayInterface &&
		a.RouteMetric == b.RouteMetric
}

func underlayRequiresRebind(a, b UnderlaySnapshot) bool {
	return a.InterfaceName != b.InterfaceName ||
		a.InterfaceIndex != b.InterfaceIndex ||
		a.LocalIPv4 != b.LocalIPv4 ||
		a.Gateway != b.Gateway ||
		a.GatewayInterface != b.GatewayInterface ||
		a.RouteMetric != b.RouteMetric
}

func underlayReasons(a, b UnderlaySnapshot) []string {
	reasons := make([]string, 0, 5)
	if a.InterfaceName != b.InterfaceName || a.InterfaceIndex != b.InterfaceIndex {
		reasons = append(reasons, "interface_changed")
	}
	if a.LocalIPv4 != b.LocalIPv4 {
		reasons = append(reasons, "local_address_changed")
	}
	if a.Gateway != b.Gateway || a.GatewayInterface != b.GatewayInterface {
		reasons = append(reasons, "gateway_changed")
	}
	if a.RouteMetric != b.RouteMetric {
		reasons = append(reasons, "route_metric_changed")
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "underlay_changed")
	}
	return reasons
}
