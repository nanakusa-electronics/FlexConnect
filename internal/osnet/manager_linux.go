//go:build linux

package osnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/godbus/dbus/v5"
	wgtun "github.com/tailscale/wireguard-go/tun"
	"github.com/vishvananda/netlink"
)

type platformManager struct {
	mu              sync.Mutex
	name            string
	link            netlink.Link
	localLink       netlink.Link
	gateway         net.IP
	serverRoutes    map[netip.Prefix]bool
	includeRoutes   map[netip.Prefix]bool
	excludeRoutes   map[netip.Prefix]bool
	dynamicInclude  map[netip.Prefix]bool
	dynamicExclude  map[netip.Prefix]bool
	dnsBackend      string
	nmDevice        dbus.ObjectPath
	nmOriginal      map[string]map[string]dbus.Variant
	vpnAddress      *netlink.Addr
	vpnAddressOwned bool
}

func newPlatformManager(_ wgtun.Device, name string) (Manager, error) {
	return &platformManager{
		name:           name,
		serverRoutes:   map[netip.Prefix]bool{},
		includeRoutes:  map[netip.Prefix]bool{},
		excludeRoutes:  map[netip.Prefix]bool{},
		dynamicInclude: map[netip.Prefix]bool{},
		dynamicExclude: map[netip.Prefix]bool{},
	}, nil
}

func (m *platformManager) Up(context.Context) error {
	link, err := netlink.LinkByName(m.name)
	if err != nil {
		return err
	}
	m.link = link
	if err := netlink.LinkSetUp(link); err != nil {
		return err
	}
	_ = netlink.LinkSetMulticastOff(link)
	return nil
}

func (m *platformManager) Set(ctx context.Context, cfg *Config) error {
	if cfg == nil || !cfg.VPNAddress.IsValid() {
		return m.Close(ctx)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.link == nil {
		if err := m.Up(ctx); err != nil {
			return err
		}
	}
	if cfg.MTU > 0 {
		if err := netlink.LinkSetMTU(m.link, cfg.MTU); err != nil {
			return err
		}
	}
	addr, err := netlink.ParseAddr(cfg.VPNAddress.String())
	if err != nil {
		return err
	}
	if err := m.setVPNAddress(addr); err != nil {
		return err
	}

	m.localLink = nil
	if cfg.GatewayInterfaceIndex != 0 {
		m.localLink, err = netlink.LinkByIndex(cfg.GatewayInterfaceIndex)
		if err != nil {
			return fmt.Errorf("resolve physical gateway interface %d: %w", cfg.GatewayInterfaceIndex, err)
		}
	}
	if cfg.Gateway.IsValid() {
		m.gateway = net.ParseIP(cfg.Gateway.String())
	}
	if cfg.ServerAddress.IsValid() && (m.localLink == nil || m.gateway == nil || m.localLink.Attrs().Index == m.link.Attrs().Index) {
		return fmt.Errorf("missing physical underlay for VPN server route")
	}

	var server []netip.Prefix
	if cfg.ServerAddress.IsValid() {
		server = append(server, netip.PrefixFrom(cfg.ServerAddress, cfg.ServerAddress.BitLen()))
	}
	if err := m.syncRoutes(&m.serverRoutes, server, m.localLink, m.gateway, 5); err != nil {
		return err
	}
	if err := m.syncRoutes(&m.includeRoutes, cfg.IncludeRoutes, m.link, nil, 6); err != nil {
		return err
	}
	if err := m.syncRoutes(&m.excludeRoutes, withoutPrefixes(cfg.ExcludeRoutes, server), m.localLink, m.gateway, 5); err != nil {
		return err
	}
	if err := m.setDNS(ctx, cfg.DNSServers); err != nil {
		return err
	}
	return nil
}

func (m *platformManager) SetDynamicRoutes(_ context.Context, routes DynamicRoutes) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.syncRoutes(&m.dynamicInclude, addrsToHostPrefixes(routes.Include), m.link, nil, 6); err != nil {
		return err
	}
	return m.syncRoutes(&m.dynamicExclude, addrsToHostPrefixes(routes.Exclude), m.localLink, m.gateway, 5)
}

func (m *platformManager) Close(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var firstErr error
	groups := []struct {
		routes   *map[netip.Prefix]bool
		link     netlink.Link
		gateway  net.IP
		priority int
	}{
		{&m.serverRoutes, m.localLink, m.gateway, 5},
		{&m.includeRoutes, m.link, nil, 6},
		{&m.excludeRoutes, m.localLink, m.gateway, 5},
		{&m.dynamicInclude, m.link, nil, 6},
		{&m.dynamicExclude, m.localLink, m.gateway, 5},
	}
	for _, group := range groups {
		for prefix := range *group.routes {
			if err := routeDel(prefix, group.link, group.gateway, group.priority); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		*group.routes = map[netip.Prefix]bool{}
	}
	if err := m.restoreDNS(ctx); err != nil && firstErr == nil {
		firstErr = err
	}
	if m.vpnAddressOwned && m.vpnAddress != nil {
		if err := deleteExactAddress(m.link, m.vpnAddress); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	m.vpnAddress = nil
	m.vpnAddressOwned = false
	return firstErr
}

func (m *platformManager) syncRoutes(old *map[netip.Prefix]bool, next []netip.Prefix, link netlink.Link, gw net.IP, priority int) error {
	if link == nil {
		return nil
	}
	add, del, state := DiffPrefixes(*old, next)
	owned := make(map[netip.Prefix]bool, len(*old))
	for prefix := range *old {
		owned[prefix] = true
	}
	for _, prefix := range add {
		dst, err := netlink.ParseIPNet(prefix.String())
		if err != nil {
			return err
		}
		route := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst, Gw: gw, Priority: priority}
		if err := netlink.RouteAdd(route); err != nil {
			*old = owned
			return err
		}
		owned[prefix] = true
	}
	for _, prefix := range del {
		if err := routeDel(prefix, link, gw, priority); err != nil {
			*old = owned
			return err
		}
		delete(owned, prefix)
	}
	*old = state
	return nil
}

func (m *platformManager) setVPNAddress(addr *netlink.Addr) error {
	if m.vpnAddressOwned && m.vpnAddress != nil && m.vpnAddress.Equal(*addr) {
		return nil
	}
	if m.vpnAddressOwned && m.vpnAddress != nil {
		if err := deleteExactAddress(m.link, m.vpnAddress); err != nil {
			return err
		}
		m.vpnAddressOwned = false
	}
	addresses, err := netlink.AddrList(m.link, netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	for i := range addresses {
		if addresses[i].Equal(*addr) {
			m.vpnAddress = addr
			return nil
		}
	}
	if err := netlink.AddrAdd(m.link, addr); err != nil {
		return fmt.Errorf("add VPN address %s: %w", addr, err)
	}
	m.vpnAddress = addr
	m.vpnAddressOwned = true
	return nil
}

func deleteExactAddress(link netlink.Link, owned *netlink.Addr) error {
	if link == nil || owned == nil {
		return nil
	}
	addresses, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	for i := range addresses {
		if addresses[i].Equal(*owned) {
			return netlink.AddrDel(link, &addresses[i])
		}
	}
	return nil
}

func routeDel(prefix netip.Prefix, link netlink.Link, gateway net.IP, priority int) error {
	if link == nil {
		return fmt.Errorf("missing link for route cleanup %s", prefix)
	}
	dst, err := netlink.ParseIPNet(prefix.String())
	if err != nil {
		return err
	}
	filter := &netlink.Route{Dst: dst, LinkIndex: link.Attrs().Index}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, filter, netlink.RT_FILTER_DST|netlink.RT_FILTER_OIF)
	if err != nil {
		return err
	}
	for _, route := range routes {
		if priority > 0 && route.Priority != priority {
			continue
		}
		if gateway == nil {
			if route.Gw != nil && !route.Gw.IsUnspecified() {
				continue
			}
		} else if route.Gw == nil || !route.Gw.Equal(gateway) {
			continue
		}
		if err := netlink.RouteDel(&route); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func GetLocalInterface(context.Context) (LocalInterface, error) {
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Dst: nil}, netlink.RT_FILTER_DST)
	if err != nil {
		return LocalInterface{}, err
	}
	route, err := selectLocalDefaultIPv4Route(routes)
	if err != nil {
		return LocalInterface{}, err
	}
	link, err := netlink.LinkByIndex(route.LinkIndex)
	if err != nil {
		return LocalInterface{}, err
	}
	return LocalInterface{
		Name:           link.Attrs().Name,
		IP4:            routeSourceIPv4(route, link),
		MAC:            link.Attrs().HardwareAddr.String(),
		Gateway:        route.Gw.String(),
		InterfaceIndex: route.LinkIndex,
	}, nil
}

func (m *platformManager) setDNS(ctx context.Context, servers []netip.Addr) error {
	if len(servers) == 0 {
		return m.restoreDNS(ctx)
	}
	attempts := []dnsBackendAttempt{
		{name: "systemd-resolved", set: func() error { return m.setResolvedDNS(servers) }},
		{name: "network-manager", set: func() error { return m.setNetworkManagerDNS(servers) }},
	}
	if path, err := exec.LookPath("resolvconf"); err == nil {
		attempts = append(attempts, dnsBackendAttempt{name: "resolvconf", set: func() error {
			var b strings.Builder
			for _, server := range servers {
				fmt.Fprintf(&b, "nameserver %s\n", server)
			}
			cmd := exec.CommandContext(ctx, path, "-a", "flexconnect."+m.name)
			cmd.Stdin = strings.NewReader(b.String())
			out, err := cmd.CombinedOutput()
			if err != nil {
				return fmt.Errorf("resolvconf add failed: %w: %s", err, strings.TrimSpace(string(out)))
			}
			return nil
		}})
	}
	backend, err := chooseDNSBackend(attempts)
	if err != nil {
		return fmt.Errorf("no supported Linux DNS owner succeeded: %w", err)
	}
	m.dnsBackend = backend
	return nil
}

func (m *platformManager) restoreDNS(ctx context.Context) error {
	switch m.dnsBackend {
	case "":
		return nil
	case "systemd-resolved":
		conn, err := dbus.SystemBus()
		if err != nil {
			return err
		}
		defer conn.Close()
		if m.link == nil {
			return errors.New("missing link for DNS cleanup")
		}
		err = conn.Object("org.freedesktop.resolve1", dbus.ObjectPath("/org/freedesktop/resolve1")).Call("org.freedesktop.resolve1.Manager.RevertLink", 0, int32(m.link.Attrs().Index)).Err
		if err == nil {
			m.dnsBackend = ""
		}
		return err
	case "resolvconf":
		path, err := exec.LookPath("resolvconf")
		if err != nil {
			return err
		}
		out, err := exec.CommandContext(ctx, path, "-d", "flexconnect."+m.name).CombinedOutput()
		if err != nil {
			return fmt.Errorf("resolvconf delete failed: %w: %s", err, strings.TrimSpace(string(out)))
		}
		m.dnsBackend = ""
		return nil
	case "network-manager":
		if !m.nmDevice.IsValid() || m.nmOriginal == nil {
			return errors.New("missing NetworkManager DNS ownership state")
		}
		conn, err := dbus.SystemBus()
		if err != nil {
			return err
		}
		defer conn.Close()
		err = conn.Object("org.freedesktop.NetworkManager", m.nmDevice).
			Call("org.freedesktop.NetworkManager.Device.Reapply", 0, m.nmOriginal, uint64(0), uint32(0)).Err
		if err == nil {
			m.dnsBackend = ""
			m.nmDevice = ""
			m.nmOriginal = nil
		}
		return err
	default:
		return fmt.Errorf("unknown DNS backend %q", m.dnsBackend)
	}
}

type resolvedDNSAddress struct {
	Family  int32
	Address []byte
}
type resolvedDomain struct {
	Name        string
	RoutingOnly bool
}

func (m *platformManager) setResolvedDNS(servers []netip.Addr) error {
	if m.link == nil {
		return errors.New("missing link for DNS")
	}
	conn, err := dbus.SystemBus()
	if err != nil {
		return err
	}
	defer conn.Close()
	obj := conn.Object("org.freedesktop.resolve1", dbus.ObjectPath("/org/freedesktop/resolve1"))
	addresses := make([]resolvedDNSAddress, 0, len(servers))
	for _, server := range servers {
		addresses = append(addresses, resolvedDNSAddress{Family: 2, Address: append([]byte(nil), server.AsSlice()...)})
	}
	if err := obj.Call("org.freedesktop.resolve1.Manager.SetLinkDNS", 0, int32(m.link.Attrs().Index), addresses).Err; err != nil {
		return err
	}
	if err := obj.Call("org.freedesktop.resolve1.Manager.SetLinkDomains", 0, int32(m.link.Attrs().Index), []resolvedDomain{{Name: ".", RoutingOnly: true}}).Err; err != nil {
		_ = obj.Call("org.freedesktop.resolve1.Manager.RevertLink", 0, int32(m.link.Attrs().Index)).Err
		return err
	}
	return nil
}

func (m *platformManager) setNetworkManagerDNS(servers []netip.Addr) error {
	conn, err := dbus.SystemBus()
	if err != nil {
		return err
	}
	defer conn.Close()
	nm := conn.Object("org.freedesktop.NetworkManager", dbus.ObjectPath("/org/freedesktop/NetworkManager"))
	var device dbus.ObjectPath
	if err := nm.Call("org.freedesktop.NetworkManager.GetDeviceByIpIface", 0, m.name).Store(&device); err != nil {
		return err
	}
	if !device.IsValid() {
		return errors.New("NetworkManager returned an invalid device path")
	}
	obj := conn.Object("org.freedesktop.NetworkManager", device)
	var settings map[string]map[string]dbus.Variant
	var version uint64
	if err := obj.Call("org.freedesktop.NetworkManager.Device.GetAppliedConnection", 0, uint32(0)).Store(&settings, &version); err != nil {
		return err
	}
	original := cloneNMSettings(settings)
	ipv4 := settings["ipv4"]
	if ipv4 == nil {
		ipv4 = make(map[string]dbus.Variant)
		settings["ipv4"] = ipv4
	}
	dnsData := make([]map[string]dbus.Variant, 0, len(servers))
	for _, server := range servers {
		if !server.Unmap().Is4() {
			return fmt.Errorf("NetworkManager DNS only supports IPv4 addresses: %s", server)
		}
		dnsData = append(dnsData, map[string]dbus.Variant{"address": dbus.MakeVariant(server.Unmap().String())})
	}
	ipv4["dns-data"] = dbus.MakeVariant(dnsData)
	ipv4["ignore-auto-dns"] = dbus.MakeVariant(true)
	if err := obj.Call("org.freedesktop.NetworkManager.Device.Reapply", 0, settings, version, uint32(0)).Err; err != nil {
		return err
	}
	m.nmDevice = device
	m.nmOriginal = original
	return nil
}

func cloneNMSettings(in map[string]map[string]dbus.Variant) map[string]map[string]dbus.Variant {
	out := make(map[string]map[string]dbus.Variant, len(in))
	for section, values := range in {
		copyValues := make(map[string]dbus.Variant, len(values))
		for key, value := range values {
			copyValues[key] = value
		}
		out[section] = copyValues
	}
	return out
}

func routeSourceIPv4(route netlink.Route, link netlink.Link) string {
	if route.Src != nil && route.Src.To4() != nil {
		return route.Src.String()
	}
	addrs, _ := netlink.AddrList(link, netlink.FAMILY_V4)
	for _, addr := range addrs {
		if addr.IP != nil && addr.IP.To4() != nil {
			return addr.IP.String()
		}
	}
	return ""
}

func addrsToHostPrefixes(addrs []netip.Addr) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(addrs))
	for _, addr := range addrs {
		addr = addr.Unmap()
		out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return out
}
