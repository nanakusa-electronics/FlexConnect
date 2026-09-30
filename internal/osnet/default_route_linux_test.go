//go:build linux

package osnet

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestSelectLocalDefaultIPv4Route(t *testing.T) {
	_, default4, _ := net.ParseCIDR("0.0.0.0/0")
	_, specific4, _ := net.ParseCIDR("192.0.2.0/24")
	_, default6, _ := net.ParseCIDR("::/0")
	gateway := net.ParseIP("192.0.2.1")
	tests := []struct {
		name      string
		routes    []netlink.Route
		wantIndex int
	}{
		{"netlink explicit default", []netlink.Route{{Dst: default4, Gw: gateway, LinkIndex: 2}}, 2},
		{"legacy nil destination", []netlink.Route{{Gw: gateway, LinkIndex: 3}}, 3},
		{"lowest default metric", []netlink.Route{
			{Dst: specific4, Gw: gateway, LinkIndex: 1},
			{Dst: default4, Gw: gateway, LinkIndex: 2, Priority: 600},
			{Dst: default4, Gw: gateway, LinkIndex: 3, Priority: 100},
		}, 3},
		{"nondefault only", []netlink.Route{{Dst: specific4, Gw: gateway, LinkIndex: 1}}, 0},
		{"IPv6 is not IPv4", []netlink.Route{{Dst: default6, Gw: gateway, LinkIndex: 1}}, 0},
		{"empty table", nil, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := selectLocalDefaultIPv4Route(tt.routes)
			if tt.wantIndex == 0 {
				if err == nil {
					t.Fatal("expected missing default route error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.LinkIndex != tt.wantIndex {
				t.Fatalf("selected interface %d, want %d", got.LinkIndex, tt.wantIndex)
			}
		})
	}
}
