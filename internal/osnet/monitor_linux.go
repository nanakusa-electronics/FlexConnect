//go:build linux

package osnet

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
)

func GetUnderlaySnapshot(ctx context.Context, excludeInterface string) (UnderlaySnapshot, error) {
	if ctx == nil {
		return UnderlaySnapshot{}, errors.New("nil underlay context")
	}
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return UnderlaySnapshot{}, err
	}
	var best *netlink.Route
	for i := range routes {
		route := &routes[i]
		if !isDefaultIPv4Route(*route) {
			continue
		}
		link, linkErr := netlink.LinkByIndex(route.LinkIndex)
		if linkErr != nil || link.Attrs().Name == excludeInterface {
			continue
		}
		if best == nil || route.Priority < best.Priority {
			copy := *route
			best = &copy
		}
	}
	if best == nil {
		return UnderlaySnapshot{}, errors.New("no physical default IPv4 route")
	}
	link, err := netlink.LinkByIndex(best.LinkIndex)
	if err != nil {
		return UnderlaySnapshot{}, err
	}
	local := netip.Addr{}
	if best.Src != nil && best.Src.To4() != nil {
		local = netip.MustParseAddr(best.Src.String()).Unmap()
	}
	if !local.IsValid() {
		addrs, addrErr := netlink.AddrList(link, netlink.FAMILY_V4)
		if addrErr != nil {
			return UnderlaySnapshot{}, addrErr
		}
		for _, addr := range addrs {
			if addr.IP != nil && addr.IP.To4() != nil {
				local = netip.MustParseAddr(addr.IP.String()).Unmap()
				break
			}
		}
	}
	if !local.IsValid() {
		return UnderlaySnapshot{}, errors.New("physical default interface has no IPv4 address")
	}
	var gateway netip.Addr
	if best.Gw != nil && best.Gw.To4() != nil {
		gateway = netip.MustParseAddr(best.Gw.String()).Unmap()
	}
	return UnderlaySnapshot{
		InterfaceName:    link.Attrs().Name,
		InterfaceIndex:   best.LinkIndex,
		LocalIPv4:        local,
		Gateway:          gateway,
		GatewayInterface: best.LinkIndex,
		RouteMetric:      best.Priority,
	}, nil
}

func newUnderlayNotifier(trigger func()) (io.Closer, error) {
	return newLinuxUnderlayNotifier(trigger)
}

var _ = net.IPv4len
