package anyconnect

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	acAuth "flexconnect/internal/anyconnect/auth"
	acBase "flexconnect/internal/anyconnect/base"
	acRPC "flexconnect/internal/anyconnect/rpc"
	acSession "flexconnect/internal/anyconnect/session"
	acTunnel "flexconnect/internal/anyconnect/tunnel"
	"flexconnect/internal/osnet"
	"flexconnect/internal/types"
	"flexconnect/internal/vpn"
)

type Backend struct {
	mu            sync.Mutex
	events        chan vpn.Event
	monitorMu     sync.Mutex
	monitor       osnet.Monitor
	monitorCancel context.CancelFunc
	monitorID     string
	newMonitor    func(ctx context.Context, opts osnet.MonitorOptions) (osnet.Monitor, error)
	active        *acRPC.Connection
	connecting    *acRPC.Connection
}

func New() *Backend {
	acBase.Setup()
	acBase.Info("vpn backend initialized")
	return &Backend{events: make(chan vpn.Event, 32), newMonitor: osnet.NewMonitor}
}

func (b *Backend) Connect(ctx context.Context, request vpn.ConnectRequest) (*types.SessionInfo, error) {
	profile, password := request.Profile, request.Password
	b.mu.Lock()
	if b.connecting != nil {
		b.mu.Unlock()
		return nil, fmt.Errorf("VPN connection attempt already in progress")
	}
	stale := b.active
	b.active = nil
	acBase.Info("vpn connect start", "host", profile.ServerURL, "username", profile.Username)
	connection := acRPC.NewConnection(buildAuthProfile(profile, password))
	b.connecting = connection
	b.mu.Unlock()

	if stale != nil {
		acBase.Warn("tearing down lingering connection before new connect")
		if err := disconnectConnection(stale); err != nil {
			b.clearConnecting(connection)
			return nil, fmt.Errorf("disconnect lingering VPN connection: %w", err)
		}
	}

	done := make(chan error, 1)
	go func() {
		done <- connection.Connect(ctx)
	}()

	select {
	case <-ctx.Done():
		acBase.Warn("vpn connect canceled", "error", ctx.Err().Error())
		_ = disconnectConnection(connection)
		select {
		case err := <-done:
			if err != nil {
				acBase.Warn("vpn connect cleanup completed", "error", err.Error())
			} else {
				acBase.Info("vpn connect cleanup completed")
			}
		case <-time.After(30 * time.Second):
			acBase.Warn("vpn connect cleanup timed out")
		}
		b.clearConnecting(connection)
		return nil, ctx.Err()
	case err := <-done:
		if err != nil {
			_ = disconnectConnection(connection)
			b.clearConnecting(connection)
			acBase.Warn("vpn connect failed", "error", err.Error())
			return nil, err
		}
		cSess := connection.Session.CSess
		if cSess == nil {
			b.clearConnecting(connection)
			return nil, fmt.Errorf("vpn connect completed without a connection session")
		}
		b.mu.Lock()
		if b.connecting != connection {
			b.mu.Unlock()
			_ = disconnectConnection(connection)
			return nil, context.Canceled
		}
		cSess.ConnectionID = request.ConnectionID
		b.mu.Unlock()
		session := b.sessionInfo(cSess)
		acBase.Info("vpn connect success", "server", session.ServerAddress, "tun", session.TUNName)
		if err := b.startUnderlayMonitor(cSess, cSess.ConnectionID, request); err != nil {
			acBase.Error("underlay monitor start failed:", err)
			_ = disconnectConnection(connection)
			b.clearConnecting(connection)
			return nil, fmt.Errorf("start underlay monitor: %w", err)
		}
		b.mu.Lock()
		if b.connecting != connection {
			b.mu.Unlock()
			b.stopMonitorFor(cSess.ConnectionID)
			_ = disconnectConnection(connection)
			return nil, context.Canceled
		}
		b.connecting = nil
		b.active = connection
		b.mu.Unlock()
		b.events <- vpn.Event{Type: "connected", ConnectionID: cSess.ConnectionID, AttemptID: request.AttemptID, ProfileID: profile.ID, OwnerID: request.OwnerID, Session: session}
		go b.monitorNetworkHealth(cSess, cSess.ConnectionID, request)
		go b.monitorClose(cSess, cSess.ConnectionID, request)
		return session, nil
	}
}

func (b *Backend) monitorNetworkHealth(cSess *acSession.ConnSession, connectionID string, request vpn.ConnectRequest) {
	for {
		select {
		case <-cSess.CloseChan:
			return
		case err := <-cSess.NetworkErrors:
			b.events <- vpn.Event{Type: "health", ConnectionID: connectionID, AttemptID: request.AttemptID, ProfileID: request.Profile.ID, OwnerID: request.OwnerID, Component: "route", Err: err}
		}
	}
}

func (b *Backend) clearConnecting(connection *acRPC.Connection) {
	b.mu.Lock()
	if b.connecting == connection {
		b.connecting = nil
	}
	b.mu.Unlock()
}

func disconnectConnection(connection *acRPC.Connection) error {
	if connection == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return connection.Disconnect(ctx)
}

func (b *Backend) monitorClose(cSess *acSession.ConnSession, connectionID string, request vpn.ConnectRequest) {
	if cSess == nil || cSess.CloseChan == nil {
		acBase.Warn("monitor close skipped: close channel missing")
		return
	}
	acBase.Info("vpn monitor close started")
	<-cSess.CloseChan
	// The physical-network observer belongs to the backend lifetime, so it
	// can report recovery even after the transport has ended.
	acBase.Info("vpn monitor close done")
	info := cSess.CloseInfo()
	faults := make([]vpn.TransportFault, 0, len(info.TransportFaults))
	for _, fault := range info.TransportFaults {
		faults = append(faults, vpn.TransportFault{Code: fault.Code, Transport: fault.Transport, Error: fault.Error, Time: fault.Time})
	}
	b.events <- vpn.Event{
		Type: "disconnected", ConnectionID: connectionID, AttemptID: request.AttemptID, ProfileID: request.Profile.ID, OwnerID: request.OwnerID,
		Close: &vpn.DisconnectInfo{Code: info.Code, Transport: info.Transport, Error: info.Error, Time: info.Time, TransportFaults: faults},
	}
}

func (b *Backend) Disconnect(ctx context.Context) error {
	b.mu.Lock()
	acBase.Info("vpn disconnect called")
	connection := b.active
	connecting := b.connecting
	b.active = nil
	b.connecting = nil
	b.mu.Unlock()
	var firstErr error
	if connecting != nil && connecting != connection {
		if err := connecting.Disconnect(ctx); err != nil {
			firstErr = err
		}
	}
	if connection != nil {
		if err := connection.Disconnect(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (b *Backend) Close(ctx context.Context) error {
	b.stopUnderlayMonitor()
	return b.Disconnect(ctx)
}

func (b *Backend) SessionInfo() *types.SessionInfo {
	c := b.activeSession()
	if c == nil {
		return nil
	}
	return b.sessionInfo(c)
}

func (b *Backend) sessionInfo(c *acSession.ConnSession) *types.SessionInfo {
	if c == nil {
		return nil
	}
	info := &types.SessionInfo{
		ConnectionID:  c.ConnectionID,
		ServerAddress: c.ServerAddress,
		LocalAddress:  c.LocalSocketAddress,
		RemoteAddress: c.RemoteSocketAddress,
		Hostname:      c.Hostname,
		TUNName:       c.TunName,
		VPNAddress:    c.VPNAddress,
		VPNMask:       c.VPNMask,
		DNS:           append([]string(nil), c.DNS...),
		MTU:           c.MTU,
		SplitInclude:  append([]string(nil), c.SplitInclude...),
		SplitExclude:  append([]string(nil), c.SplitExclude...),
		TLSCipher:     c.TLSCipherSuite,
		DTLSCipher:    c.DTLSCipherSuite,
	}
	if c.Underlay.LocalIPv4.IsValid() {
		info.Underlay = &types.UnderlayInfo{
			InterfaceName: c.Underlay.InterfaceName, InterfaceIndex: c.Underlay.InterfaceIndex,
			LocalIPv4: c.Underlay.LocalIPv4.String(), Gateway: c.Underlay.Gateway.String(),
			GatewayInterface: c.Underlay.GatewayInterface, RouteMetric: c.Underlay.RouteMetric,
			Generation: c.Underlay.Generation,
		}
	}
	return info
}

func (b *Backend) Traffic() *types.TrafficStats {
	c := b.activeSession()
	if c == nil || c.Stat == nil {
		return nil
	}
	return &types.TrafficStats{
		BytesSent:     c.Stat.BytesSent.Load(),
		BytesReceived: c.Stat.BytesReceived.Load(),
	}
}

func (b *Backend) ReadServerConfig() map[string]any {
	c := b.activeSession()
	if c == nil {
		return map[string]any{}
	}
	return map[string]any{
		"dns":           append([]string(nil), c.DNS...),
		"split_include": append([]string(nil), c.SplitInclude...),
		"split_exclude": append([]string(nil), c.SplitExclude...),
		"dynamic_split": c.DynamicSplitTunneling,
		"underlay":      b.sessionInfo(c).Underlay,
		"runtime":       b.runtimeDiagnostics(c),
	}
}

func (b *Backend) RuntimeDiagnostics() *types.RuntimeDiagnostics {
	c := b.activeSession()
	if c == nil {
		return nil
	}
	return b.runtimeDiagnostics(c)
}

func (b *Backend) runtimeDiagnostics(c *acSession.ConnSession) *types.RuntimeDiagnostics {
	if c == nil {
		return nil
	}
	stats := c.RuntimeStats()
	runtime := &types.TunnelRuntime{
		State: c.LifecycleState.Load(), TLSState: c.TLSState.Load(), DTLSState: c.DTLSState.Load(),
		TUNReads: stats.TUNReads, TUNWrites: stats.TUNWrites,
		TUNReadErrors: stats.TUNReadErrors, TUNWriteErrors: stats.TUNWriteErrors,
		DPDSent: stats.DPDSent, DPDResponses: stats.DPDResponses, QueueDrops: stats.QueueDrops,
	}
	var underlay *types.UnderlayInfo
	if info := b.sessionInfo(c); info != nil {
		underlay = info.Underlay
	}
	return &types.RuntimeDiagnostics{Underlay: underlay, Tunnel: runtime}
}

func (b *Backend) startUnderlayMonitor(cSess *acSession.ConnSession, connectionID string, request vpn.ConnectRequest) error {
	b.monitorMu.Lock()
	defer b.monitorMu.Unlock()
	if b.monitor != nil {
		// Refresh the TUN exclusion and connection identity on replacement.
		b.stopUnderlayMonitorLocked()
	}
	ctx, cancel := context.WithCancel(context.Background())
	monitor, err := b.newMonitor(ctx, osnet.MonitorOptions{ExcludeInterface: cSess.TunName})
	if err != nil {
		cancel()
		return err
	}
	if status, ok := monitor.(interface{ NotifierError() error }); ok {
		if notifierErr := status.NotifierError(); notifierErr != nil {
			acBase.Warn("underlay notifications unavailable; polling fallback active:", notifierErr)
		}
	}
	b.monitor = monitor
	b.monitorCancel = cancel
	b.monitorID = connectionID
	go b.watchUnderlay(ctx, monitor, connectionID, request)
	return nil
}

func (b *Backend) watchUnderlay(ctx context.Context, monitor osnet.Monitor, connectionID string, request vpn.ConnectRequest) {
	changes := monitor.Changes(ctx)
	for {
		var change osnet.UnderlayChange
		select {
		case <-ctx.Done():
			return
		case next, ok := <-changes:
			if !ok {
				return
			}
			change = next
		}
		event := vpn.Event{Type: "network_change", ConnectionID: connectionID, ProfileID: request.Profile.ID, OwnerID: request.OwnerID, Network: convertNetworkChange(change)}
		select {
		case b.events <- event:
		case <-ctx.Done():
			return
		}
	}
}

func (b *Backend) stopUnderlayMonitor() {
	b.monitorMu.Lock()
	defer b.monitorMu.Unlock()
	b.stopUnderlayMonitorLocked()
}

// stopMonitorFor releases the monitor only when it still belongs to the given
// connection, so a delayed teardown of an old session cannot stop the monitor
// of its replacement.
func (b *Backend) stopMonitorFor(connectionID string) {
	b.monitorMu.Lock()
	defer b.monitorMu.Unlock()
	if connectionID != "" && b.monitorID != connectionID {
		return
	}
	b.stopUnderlayMonitorLocked()
}

func (b *Backend) stopUnderlayMonitorLocked() {
	if b.monitorCancel != nil {
		b.monitorCancel()
	}
	if b.monitor != nil {
		_ = b.monitor.Close()
	}
	b.monitor = nil
	b.monitorCancel = nil
	b.monitorID = ""
}

func convertNetworkChange(change osnet.UnderlayChange) *vpn.NetworkChange {
	return &vpn.NetworkChange{
		Before: convertNetworkSnapshot(change.Before), After: convertNetworkSnapshot(change.After),
		Reasons: append([]string(nil), change.Reasons...), RebindRequired: change.RebindRequired,
		Error: diagnosticNetworkError(change.Err),
	}
}

func convertNetworkSnapshot(snapshot osnet.UnderlaySnapshot) vpn.NetworkSnapshot {
	return vpn.NetworkSnapshot{
		InterfaceName: snapshot.InterfaceName, InterfaceIndex: snapshot.InterfaceIndex,
		LocalIPv4: snapshot.LocalIPv4.String(), Gateway: snapshot.Gateway.String(),
		GatewayInterface: snapshot.GatewayInterface, RouteMetric: snapshot.RouteMetric,
		Generation: snapshot.Generation,
	}
}

func diagnosticNetworkError(err error) string {
	if err == nil {
		return ""
	}
	message := err.Error()
	if len(message) > 512 {
		message = message[:512]
	}
	return message
}

func (b *Backend) Events() <-chan vpn.Event {
	return b.events
}

func (b *Backend) TunnelDialer(ctx context.Context) (vpn.TunnelDialer, error) {
	return acTunnel.SessionTunnelDialer(ctx, b.activeSession())
}

func (b *Backend) activeSession() *acSession.ConnSession {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.active == nil || b.active.Session == nil {
		return nil
	}
	return b.active.Session.CSess
}

func buildAuthProfile(profile types.Profile, password string) acAuth.Profile {
	host := profile.ServerURL
	if parsed, err := url.Parse(profile.ServerURL); err == nil && parsed.Host != "" {
		host = parsed.Host
	}
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")

	acBase.Cfg.AgentName = "AnyConnect"
	return acAuth.Profile{
		Host: host, GroupAccess: groupAccessURL(profile.ServerURL), Username: profile.Username,
		Password: password, Group: profile.Group, SecretKey: "", Scheme: "https://",
		AcceptServerRoutes: profile.AcceptServerRoutes, ApplyDNS: types.BoolValue(profile.ApplyDNS, true),
		CustomInclude: append([]string(nil), profile.CustomInclude...),
		CustomExclude: append([]string(nil), profile.CustomExclude...),
		DNSOverrides:  append([]string(nil), profile.DNSOverrides...), MTU: profile.MTU,
	}
}

func groupAccessURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		host := strings.TrimPrefix(rawURL, "https://")
		host = strings.TrimPrefix(host, "http://")
		return "https://" + strings.TrimRight(host, "/")
	}
	parsed.Scheme = "https"
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return strings.TrimRight(parsed.String(), "/")
}
