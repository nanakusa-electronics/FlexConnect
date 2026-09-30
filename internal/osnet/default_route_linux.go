//go:build linux

package osnet

import (
	"errors"

	"github.com/vishvananda/netlink"
)

// netlink represents a default destination as either nil or 0.0.0.0/0.
func isDefaultIPv4Route(route netlink.Route) bool {
	if route.Dst == nil {
		return true
	}
	ones, bits := route.Dst.Mask.Size()
	return route.Dst.IP.To4() != nil && route.Dst.IP.IsUnspecified() && ones == 0 && bits == 32
}

func selectLocalDefaultIPv4Route(routes []netlink.Route) (netlink.Route, error) {
	var best *netlink.Route
	for i := range routes {
		route := &routes[i]
		if !isDefaultIPv4Route(*route) || route.Gw == nil {
			continue
		}
		if best == nil || route.Priority < best.Priority {
			best = route
		}
	}
	if best == nil {
		return netlink.Route{}, errors.New("no default IPv4 route")
	}
	return *best, nil
}
