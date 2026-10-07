//go:build windows

package atrust

import wgtun "github.com/tailscale/wireguard-go/tun"

func init() { wgtun.WintunTunnelType = "FlexConnect" }
