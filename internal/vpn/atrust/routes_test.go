package atrust

import (
	"net/netip"
	"slices"
	"testing"

	"flexconnect/internal/types"
)

func TestRoutePrefixesPreserveSystemBroadcastRoute(t *testing.T) {
	broadcast := netip.MustParsePrefix("255.255.255.255/32")
	controller := netip.MustParsePrefix("203.0.113.1/32")
	for resource, expected := range map[string][]netip.Prefix{
		"255.255.255.255":                 nil,
		"255.255.255.255/32":              nil,
		"255.255.255.255-255.255.255.255": nil,
		"255.255.255.253-255.255.255.255": {netip.MustParsePrefix("255.255.255.253/32"), netip.MustParsePrefix("255.255.255.254/31")},
		"0.0.0.0-255.255.255.255":         {netip.MustParsePrefix("0.0.0.0/0")},
	} {
		t.Run(resource, func(t *testing.T) {
			var server []string
			for _, prefix := range resourcePrefixes(resource) {
				server = append(server, prefix.String())
			}
			profile := types.Profile{AcceptServerRoutes: true, CustomExclude: []string{broadcast.String()}}
			include, exclude := routePrefixes(profile, server, []netip.Prefix{controller})
			if !slices.Equal(include, expected) {
				t.Fatalf("include = %v, want %v", include, expected)
			}
			if !slices.Equal(exclude, []netip.Prefix{controller}) {
				t.Fatalf("exclude = %v, want protected controller only", exclude)
			}
		})
	}
}

func TestRoutePrefixesFilterCustomBroadcastAndPreserveBroadRoutes(t *testing.T) {
	profile := types.Profile{
		AcceptServerRoutes: false,
		CustomInclude:      []string{"255.255.255.255/32", "0.0.0.0/0", "255.255.255.254/31", "10.0.0.0/8"},
		CustomExclude:      []string{"192.168.0.0/16"},
	}
	include, exclude := routePrefixes(profile, []string{"172.16.0.0/12"}, nil)
	want := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("255.255.255.254/31"), netip.MustParsePrefix("10.0.0.0/8")}
	if !slices.Equal(include, want) {
		t.Fatalf("include = %v, want %v", include, want)
	}
	if !slices.Equal(exclude, []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}) {
		t.Fatalf("exclude = %v", exclude)
	}
}
