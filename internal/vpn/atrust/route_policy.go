package atrust

import (
	"errors"
	"flexconnect/internal/osnet"
	"flexconnect/internal/router"
	"flexconnect/internal/types"
	"net/netip"
)

var errRouteExcluded = errors.New("destination is excluded by profile routing")

type routePolicy struct {
	acceptServer     bool
	include, exclude []netip.Prefix
}

func newRoutePolicy(profile types.Profile, server []string) *routePolicy {
	if !profile.AcceptServerRoutes {
		server = nil
	}
	routes := router.MergeRouteLists(server, nil, profile.CustomInclude, profile.CustomExclude)
	include, _ := osnet.ParsePrefixes(routes.Include)
	exclude, _ := osnet.ParsePrefixes(routes.Exclude)
	return &routePolicy{acceptServer: profile.AcceptServerRoutes, include: include, exclude: exclude}
}

func (p *routePolicy) check(ip netip.Addr) error {
	allowed, bits := p.acceptServer, -1
	for _, prefix := range p.include {
		if prefix.Contains(ip) && prefix.Bits() > bits {
			allowed, bits = true, prefix.Bits()
		}
	}
	for _, prefix := range p.exclude {
		if prefix.Contains(ip) && prefix.Bits() >= bits {
			allowed, bits = false, prefix.Bits()
		}
	}
	if !allowed {
		return errRouteExcluded
	}
	return nil
}
