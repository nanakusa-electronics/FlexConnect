package atrust

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"net"
	"net/netip"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"time"

	"flexconnect/internal/osnet"
	"flexconnect/internal/router"
	"flexconnect/internal/secret"
	"flexconnect/internal/tunflow"
	"flexconnect/internal/types"
	"flexconnect/internal/vpn"
	geektrust "github.com/nanakusa-electronics/geektrust/client"
	wgtun "github.com/tailscale/wireguard-go/tun"
)

// Backend owns a single aTrust protocol session. System networking belongs to
// the daemon; the SDK provides only authorized transport and name resolution.
type Backend struct {
	mu            sync.Mutex
	secrets       secret.Store
	client        *geektrust.Client
	info          *types.SessionInfo
	manager       osnet.Manager
	flows         *tunflow.Stack
	cancel        context.CancelFunc
	monitor       osnet.Monitor
	monitorCancel context.CancelFunc
	protocol      geektrust.Info
	events        chan vpn.Event
}

func New(secrets secret.Store) *Backend {
	return &Backend{secrets: secrets, events: make(chan vpn.Event, 16)}
}

type blobStore struct {
	secrets secret.Store
	ref     string
}

func (s blobStore) Load(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	encoded, err := s.secrets.Get(s.ref)
	if errors.Is(err, secret.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(encoded)
}

func (s blobStore) Save(ctx context.Context, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.secrets.Put(s.ref, base64.StdEncoding.EncodeToString(data))
}

func (b *Backend) deviceID(ref string) (string, error) {
	key := ref + "/device"
	id, err := b.secrets.Get(key)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, secret.ErrNotFound) {
		return "", err
	}
	id, err = geektrust.NewDeviceID()
	if err != nil {
		return "", err
	}
	if err := b.secrets.Put(key, id); err != nil {
		return "", err
	}
	return id, nil
}

func (b *Backend) Connect(ctx context.Context, req vpn.ConnectRequest) (*types.SessionInfo, error) {
	if req.Profile.Provider != types.ProviderATrust {
		return nil, errors.New("aTrust backend requires aTrust profile")
	}
	if err := b.Disconnect(ctx); err != nil {
		return nil, fmt.Errorf("release previous aTrust session: %w", err)
	}
	if req.Profile.SecretRef == "" {
		return nil, errors.New("aTrust profile has no imported credential")
	}
	id, err := b.deviceID("profile/" + req.Profile.ID)
	if err != nil {
		return nil, fmt.Errorf("load aTrust device identity: %w", err)
	}
	c, err := geektrust.New(geektrust.Options{
		ControllerURL:         req.Profile.ServerURL,
		DeviceID:              id,
		LoginDomain:           req.Profile.LoginDomain,
		DisableSystemResolver: true,
		GatewayTrustStore:     &gatewayPinStore{secrets: b.secrets, ref: "profile/" + req.Profile.ID},
		Authenticator:         &geektrust.PasskeyAuthenticator{Store: blobStore{b.secrets, req.Profile.SecretRef}},
		SessionStore:          blobStore{b.secrets, req.Profile.SecretRef + "/session"},
	})
	if err != nil {
		return nil, err
	}
	result, err := c.Connect(ctx)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	transport, err := c.OpenTransport(ctx)
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("establish aTrust gateway: %w", err)
	}
	info := &types.SessionInfo{ConnectionID: req.ConnectionID, ServerAddress: req.Profile.ServerURL, Hostname: req.Profile.ServerURL, DNS: result.DNS, MTU: req.Profile.MTU}
	info.RemoteAddress = transport.Gateway
	for _, resource := range result.Resources {
		for _, prefix := range resourcePrefixes(resource.Address) {
			info.SplitInclude = append(info.SplitInclude, prefix.String())
		}
	}
	manager, flows, tunName, cancel, err := b.startTUN(ctx, req, c, result, info)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	info.TUNName = tunName
	info.VPNAddress = fakeLocal.String()
	info.VPNMask = "255.255.255.255"
	monitorCtx, cancelMonitor := context.WithCancel(context.Background())
	monitor, err := osnet.NewMonitor(monitorCtx, osnet.MonitorOptions{ExcludeInterface: tunName})
	if err != nil {
		cancelMonitor()
		cancel()
		cleanupErr := closeNetworkManager(manager)
		_ = flows.Close()
		_ = c.Close()
		return nil, errors.Join(fmt.Errorf("start aTrust network monitor: %w", err), cleanupErr)
	}
	b.mu.Lock()
	if err := ctx.Err(); err != nil {
		b.mu.Unlock()
		cancelMonitor()
		_ = monitor.Close()
		cancel()
		cleanupErr := closeNetworkManager(manager)
		_ = flows.Close()
		_ = c.Close()
		return nil, errors.Join(err, cleanupErr)
	}
	b.client, b.info, b.manager, b.flows, b.cancel, b.monitor, b.monitorCancel, b.protocol = c, info, manager, flows, cancel, monitor, cancelMonitor, result
	b.mu.Unlock()
	go b.watchFlows(flows, req)
	go b.watchNetwork(monitorCtx, monitor, req)
	return info, nil
}

func resourcePrefixes(raw string) []netip.Prefix {
	if addr, err := netip.ParseAddr(raw); err == nil && addr.Is4() {
		return []netip.Prefix{netip.PrefixFrom(addr, 32)}
	}
	if prefix, err := netip.ParsePrefix(raw); err == nil && prefix.Addr().Is4() {
		return []netip.Prefix{prefix.Masked()}
	}
	loRaw, hiRaw, ok := strings.Cut(raw, "-")
	if !ok {
		return nil
	}
	lo, errLo := netip.ParseAddr(loRaw)
	hi, errHi := netip.ParseAddr(hiRaw)
	if errLo != nil || errHi != nil || !lo.Is4() || !hi.Is4() {
		return nil
	}
	start, end := uint64(binary.BigEndian.Uint32(lo.AsSlice())), uint64(binary.BigEndian.Uint32(hi.AsSlice()))
	if start > end {
		return nil
	}
	out := make([]netip.Prefix, 0, 32)
	for start <= end {
		zeros := bits.TrailingZeros32(uint32(start))
		if start == 0 {
			zeros = 32
		}
		remaining := end - start + 1
		maxBlock := bits.Len64(remaining) - 1
		if zeros > maxBlock {
			zeros = maxBlock
		}
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(start))
		out = append(out, netip.PrefixFrom(netip.AddrFrom4(b), 32-zeros))
		start += uint64(1) << zeros
	}
	return out
}

func (b *Backend) Disconnect(ctx context.Context) error {
	b.mu.Lock()
	manager := b.manager
	monitor, cancelMonitor := b.monitor, b.monitorCancel
	b.mu.Unlock()
	if cancelMonitor != nil {
		cancelMonitor()
	}
	if monitor != nil {
		_ = monitor.Close()
	}
	if manager != nil {
		if err := manager.Close(ctx); err != nil {
			return fmt.Errorf("restore aTrust routes and DNS: %w", err)
		}
	}
	b.mu.Lock()
	c := b.client
	flows, cancel := b.flows, b.cancel
	b.client, b.info, b.manager, b.flows, b.cancel, b.monitor, b.monitorCancel, b.protocol = nil, nil, nil, nil, nil, nil, nil, geektrust.Info{}
	b.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if flows != nil {
		_ = flows.Close()
	}
	if c != nil {
		return c.Close()
	}
	return nil
}

func (b *Backend) watchFlows(flows *tunflow.Stack, req vpn.ConnectRequest) {
	select {
	case err := <-flows.Errors():
		if err != nil {
			select {
			case b.events <- vpn.Event{Type: "disconnected", ConnectionID: req.ConnectionID, AttemptID: req.AttemptID, ProfileID: req.Profile.ID, OwnerID: req.OwnerID, Err: vpn.WrapConnectError("tun", true, err)}:
			case <-flows.Done():
			}
		}
	case <-flows.Done():
	}
}

func (b *Backend) watchNetwork(ctx context.Context, monitor osnet.Monitor, req vpn.ConnectRequest) {
	for change := range monitor.Changes(ctx) {
		event := vpn.Event{Type: "network_change", ConnectionID: req.ConnectionID, AttemptID: req.AttemptID, ProfileID: req.Profile.ID, OwnerID: req.OwnerID,
			Network: &vpn.NetworkChange{Before: snapshot(change.Before), After: snapshot(change.After), Reasons: change.Reasons, RebindRequired: change.RebindRequired}}
		if change.Err != nil {
			event.Network.Error = change.Err.Error()
		}
		select {
		case b.events <- event:
		case <-ctx.Done():
		}
		return
	}
}

func snapshot(s osnet.UnderlaySnapshot) vpn.NetworkSnapshot {
	return vpn.NetworkSnapshot{InterfaceName: s.InterfaceName, InterfaceIndex: s.InterfaceIndex, LocalIPv4: s.LocalIPv4.String(), Gateway: s.Gateway.String(), GatewayInterface: s.GatewayInterface, RouteMetric: s.RouteMetric, Generation: s.Generation}
}

func (b *Backend) startTUN(ctx context.Context, req vpn.ConnectRequest, c *geektrust.Client, result geektrust.Info, info *types.SessionInfo) (osnet.Manager, *tunflow.Stack, string, context.CancelFunc, error) {
	underlay, err := osnet.GetUnderlaySnapshot(ctx, "")
	if err != nil {
		return nil, nil, "", nil, fmt.Errorf("resolve aTrust physical network: %w", err)
	}
	protected, controller, err := protectedRoutes(ctx, req.Profile.ServerURL, req.Profile.SecretRef, b.secrets, result.Gateways)
	if err != nil {
		return nil, nil, "", nil, err
	}
	name := "flexconnect"
	if runtime.GOOS == "windows" {
		name = "FlexConnect"
	} else if runtime.GOOS == "darwin" {
		name = "utun"
	}
	dev, err := wgtun.CreateTUN(name, req.Profile.MTU)
	if err != nil {
		return nil, nil, "", nil, fmt.Errorf("create aTrust TUN: %w", err)
	}
	manager, err := osnet.NewManager(dev, name)
	if err != nil {
		dev.Close()
		return nil, nil, "", nil, err
	}
	cleanup := func(err error) (osnet.Manager, *tunflow.Stack, string, context.CancelFunc, error) {
		cleanupErr := closeNetworkManager(manager)
		_ = dev.Close()
		return nil, nil, "", nil, errors.Join(err, cleanupErr)
	}
	ready, cancelReady := context.WithTimeout(ctx, 30*time.Second)
	defer cancelReady()
	for {
		if err = manager.Up(ready); err == nil {
			break
		}
		select {
		case <-ready.Done():
			return cleanup(fmt.Errorf("bring up aTrust TUN: %w", err))
		case <-time.After(250 * time.Millisecond):
		}
	}
	tunName, _ := dev.Name()
	if tunName == "" {
		tunName = name
	}
	include, exclude := routePrefixes(req.Profile, info.SplitInclude, protected)
	dns := []netip.Addr{}
	if types.BoolValue(req.Profile.ApplyDNS, true) {
		include = append(include, netip.PrefixFrom(fakeDNS, 32), netip.MustParsePrefix("198.18.0.0/15"))
		dns = append(dns, fakeDNS)
		info.DNS = []string{fakeDNS.String()}
	}
	cfg := &osnet.Config{InterfaceName: tunName, VPNAddress: netip.PrefixFrom(fakeLocal, 32), MTU: req.Profile.MTU, Underlay: underlay, ServerAddress: controller, Gateway: underlay.Gateway, GatewayInterfaceIndex: underlay.GatewayInterface, IncludeRoutes: include, ExcludeRoutes: exclude, DNSServers: dns}
	if err := manager.Set(ctx, cfg); err != nil {
		return cleanup(fmt.Errorf("configure aTrust routes and DNS: %w", err))
	}
	lifetime, cancel := context.WithCancel(context.Background())
	mapper := newDNSMapper(result, c)
	flows, err := tunflow.New(lifetime, dev, flowDialer{ctx: lifetime, client: c, dns: mapper}, c, req.Profile.MTU)
	if err != nil {
		cancel()
		return cleanup(fmt.Errorf("start aTrust packet forwarding: %w", err))
	}
	return manager, flows, tunName, cancel, nil
}

func closeNetworkManager(manager osnet.Manager) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := manager.Close(ctx); err != nil {
		return fmt.Errorf("restore aTrust routes and DNS: %w", err)
	}
	return nil
}

func routePrefixes(profile types.Profile, server []string, protected []netip.Prefix) ([]netip.Prefix, []netip.Prefix) {
	if !profile.AcceptServerRoutes {
		server = nil
	}
	merged := router.MergeRouteLists(server, nil, profile.CustomInclude, profile.CustomExclude)
	include, _ := osnet.ParsePrefixes(merged.Include)
	exclude, _ := osnet.ParsePrefixes(merged.Exclude)
	exclude = append(exclude, protected...)
	return include, exclude
}

func protectedRoutes(ctx context.Context, controllerURL, credentialRef string, secrets secret.Store, gateways []string) ([]netip.Prefix, netip.Addr, error) {
	urls := append([]string{controllerURL}, gateways...)
	if encoded, err := secrets.Get(credentialRef); err == nil {
		if blob, err := base64.StdEncoding.DecodeString(encoded); err == nil {
			if meta, err := geektrust.InspectPasskey(blob); err == nil {
				urls = append(urls, meta.Origin)
			}
		}
	}
	// GeekTrust's direct DNS stages must also stay on the physical network.
	urls = append(urls, "223.5.5.5", "119.29.29.29")
	seen := map[netip.Addr]bool{}
	protected := make([]netip.Prefix, 0, len(urls))
	var controller netip.Addr
	for index, raw := range urls {
		host := raw
		if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
			host = u.Hostname()
		} else if split, _, err := net.SplitHostPort(raw); err == nil {
			host = split
		} else {
			host = strings.Trim(raw, "[]")
		}
		var addrs []netip.Addr
		if parsed, err := netip.ParseAddr(host); err == nil {
			addrs = []netip.Addr{parsed}
		} else {
			var err error
			addrs, err = net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
			if err != nil {
				return nil, netip.Addr{}, fmt.Errorf("resolve aTrust control endpoint: %w", err)
			}
		}
		for _, addr := range addrs {
			addr = addr.Unmap()
			if !addr.Is4() || seen[addr] {
				continue
			}
			if index == 0 && !controller.IsValid() {
				controller = addr
			}
			seen[addr] = true
			protected = append(protected, netip.PrefixFrom(addr, 32))
		}
	}
	if !controller.IsValid() {
		return nil, netip.Addr{}, errors.New("aTrust controller has no IPv4 route")
	}
	return protected, controller, nil
}

func (b *Backend) Close(ctx context.Context) error { return b.Disconnect(ctx) }
func (b *Backend) Events() <-chan vpn.Event        { return b.events }

func (b *Backend) SessionInfo() *types.SessionInfo {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.info == nil {
		return nil
	}
	copy := *b.info
	return &copy
}

func (b *Backend) Traffic() *types.TrafficStats {
	b.mu.Lock()
	flows := b.flows
	b.mu.Unlock()
	if flows == nil {
		return nil
	}
	sent, received := flows.Traffic()
	return &types.TrafficStats{BytesSent: sent, BytesReceived: received}
}
func (b *Backend) ReadServerConfig() map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()
	return map[string]any{"provider": "atrust", "gateways": append([]string(nil), b.protocol.Gateways...), "dns": append([]string(nil), b.protocol.DNS...), "resource_count": len(b.protocol.Resources), "capabilities": b.protocol.Capabilities}
}
func (b *Backend) RuntimeDiagnostics() *types.RuntimeDiagnostics {
	b.mu.Lock()
	flows := b.flows
	b.mu.Unlock()
	if flows == nil {
		return nil
	}
	return &types.RuntimeDiagnostics{Tunnel: &types.TunnelRuntime{State: "connected"}}
}

func (b *Backend) TunnelDialer(context.Context) (vpn.TunnelDialer, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.client == nil {
		return nil, errors.New("aTrust session is not connected")
	}
	return b.client, nil
}
