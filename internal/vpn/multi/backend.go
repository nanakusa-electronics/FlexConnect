package multi

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"flexconnect/internal/types"
	"flexconnect/internal/vpn"
)

// Factory creates a fresh backend for every connection attempt.
type Factory func() vpn.Backend

// Backend serializes provider ownership while forwarding only events from the
// current attempt. The daemon remains responsible for whole-VPN retries.
type Backend struct {
	mu         sync.Mutex
	factories  map[types.Provider]Factory
	active     vpn.Backend
	stop       chan struct{}
	generation uint64
	events     chan vpn.Event
}

func New(factories map[types.Provider]Factory) *Backend {
	copy := make(map[types.Provider]Factory, len(factories))
	for name, factory := range factories {
		copy[name] = factory
	}
	return &Backend{factories: copy, events: make(chan vpn.Event, 32)}
}

func (b *Backend) Connect(ctx context.Context, req vpn.ConnectRequest) (*types.SessionInfo, error) {
	b.mu.Lock()
	factory := b.factories[req.Profile.Provider]
	if factory == nil {
		b.mu.Unlock()
		return nil, fmt.Errorf("unknown VPN provider %q", req.Profile.Provider)
	}
	old := b.active
	oldStop := b.stop
	b.mu.Unlock()
	if old != nil {
		if err := old.Close(ctx); err != nil {
			return nil, fmt.Errorf("cleanup previous provider: %w", err)
		}
	}
	next := factory()
	if next == nil {
		return nil, errors.New("VPN provider factory returned no backend")
	}
	b.mu.Lock()
	if b.active != old {
		b.mu.Unlock()
		_ = next.Close(ctx)
		return nil, context.Canceled
	}
	if oldStop != nil {
		close(oldStop)
	}
	b.generation++
	gen := b.generation
	stop := make(chan struct{})
	b.active, b.stop = next, stop
	b.mu.Unlock()
	go b.forward(next.Events(), gen, stop)
	info, err := next.Connect(ctx, req)
	if err != nil {
		// Retain the provider and underlay events while the daemon owns retry.
		cleanupErr := next.Disconnect(ctx)
		return nil, errors.Join(err, cleanupErr)
	}
	return info, nil
}

func (b *Backend) forward(source <-chan vpn.Event, generation uint64, stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		case event, ok := <-source:
			if !ok {
				return
			}
			b.mu.Lock()
			current := b.generation == generation
			b.mu.Unlock()
			if !current {
				continue
			}
			select {
			case <-stop:
				return
			case b.events <- event:
			}
		}
	}
}

// Disconnect stops traffic but preserves the observer used to recover from
// suspended or lost physical networks. The daemon filters events by intent.
func (b *Backend) Disconnect(ctx context.Context) error {
	if active := b.current(); active != nil {
		return active.Disconnect(ctx)
	}
	return nil
}

func (b *Backend) Close(ctx context.Context) error {
	active := b.current()
	if active == nil {
		return nil
	}
	if err := active.Close(ctx); err != nil {
		return err
	}
	b.mu.Lock()
	if b.active == active {
		b.active = nil
		if b.stop != nil {
			close(b.stop)
			b.stop = nil
		}
		b.generation++
	}
	b.mu.Unlock()
	return nil
}
func (b *Backend) Events() <-chan vpn.Event { return b.events }
func (b *Backend) current() vpn.Backend     { b.mu.Lock(); defer b.mu.Unlock(); return b.active }
func (b *Backend) SessionInfo() *types.SessionInfo {
	if active := b.current(); active != nil {
		return active.SessionInfo()
	}
	return nil
}
func (b *Backend) Traffic() *types.TrafficStats {
	if active := b.current(); active != nil {
		return active.Traffic()
	}
	return nil
}
func (b *Backend) ReadServerConfig() map[string]any {
	if active := b.current(); active != nil {
		return active.ReadServerConfig()
	}
	return map[string]any{}
}
func (b *Backend) RuntimeDiagnostics() *types.RuntimeDiagnostics {
	if active := b.current(); active != nil {
		if provider, ok := active.(interface {
			RuntimeDiagnostics() *types.RuntimeDiagnostics
		}); ok {
			return provider.RuntimeDiagnostics()
		}
	}
	return nil
}
func (b *Backend) TunnelDialer(ctx context.Context) (vpn.TunnelDialer, error) {
	if active := b.current(); active != nil {
		return active.TunnelDialer(ctx)
	}
	return nil, errors.New("VPN is not connected")
}
