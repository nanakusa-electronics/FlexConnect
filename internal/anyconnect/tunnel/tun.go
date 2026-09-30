package vpn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"time"

	"flexconnect/internal/anyconnect/base"
	"flexconnect/internal/anyconnect/proto"
	"flexconnect/internal/anyconnect/session"
	"flexconnect/internal/anyconnect/utils"
	"flexconnect/internal/osnet"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	wgtun "github.com/tailscale/wireguard-go/tun"
)

// Reserve room for Linux virtio-net headers (10 bytes) and Darwin headers (4 bytes).
const tunPacketOffset = 16

var getLocalInterface = osnet.GetLocalInterface

func setupTun(cSess *session.ConnSession) (wgtun.Device, error) {
	if runtime.GOOS == "windows" {
		cSess.TunName = "FlexConnect"
		setPlatformTunnelType()
	} else if runtime.GOOS == "darwin" {
		cSess.TunName = "utun"
	} else {
		cSess.TunName = "flexconnect"
	}
	dev, err := wgtun.CreateTUN(cSess.TunName, cSess.MTU)
	if err != nil {
		base.Error("failed to creates a new tun interface")
		return nil, err
	}
	base.Info("tun interface created", "name", cSess.TunName, "mtu", cSess.MTU)
	if runtime.GOOS == "darwin" {
		cSess.TunName, _ = dev.Name()
	}

	base.Info("tun configured", "iface", cSess.TunName)

	manager, err := osnet.NewManager(dev, cSess.TunName)
	if err != nil {
		_ = dev.Close()
		return nil, err
	}
	if err = waitManagerUp(context.Background(), manager, 30*time.Second); err != nil {
		_ = manager.Close(context.Background())
		_ = dev.Close()
		return nil, err
	}
	if name, err := dev.Name(); err == nil && name != "" {
		cSess.TunName = name
	}
	cSess.NetworkManager = manager
	return dev, nil
}

// startTun begins packet I/O only after the operating-system address and
// routes have been installed. This mirrors the Tailscale TUN lifecycle: the
// device can exist while it is being configured, but no packet worker owns it
// until the configuration is known to be usable.
func startTun(dev wgtun.Device, cSess *session.ConnSession) (*TunnelController, error) {
	base.Info("start tun packet workers", "iface", cSess.TunName)
	controller, err := newTunnelController(dev, cSess.NetworkManager, cSess)
	if err != nil {
		return nil, err
	}
	if err := controller.Start(); err != nil {
		return nil, err
	}
	return controller, nil
}

// watchTunEvents turns a native-device failure into a session failure. The
// wireguard-go Device contract exposes Events for exactly this lifecycle
// boundary; ignoring it leaves the CSTP workers alive after the interface is
// down and makes the next failure look like a remote disconnect.
func watchTunEvents(dev wgtun.Device, cSess *session.ConnSession) {
	for {
		select {
		case <-cSess.CloseChan:
			return
		case event, ok := <-dev.Events():
			if !ok {
				select {
				case <-cSess.CloseChan:
					return
				default:
				}
				cSess.RecordClose("tun_events_closed", "tun", io.EOF)
				cSess.Close()
				return
			}
			base.Debug("tun event", "event", event)
			if event&wgtun.EventDown != 0 {
				err := fmt.Errorf("TUN interface reported down")
				cSess.RecordClose("tun_down", "tun", err)
				cSess.Close()
				return
			}
		}
	}
}

func waitManagerUp(ctx context.Context, manager osnet.Manager, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	var lastErr error
	for {
		if err := manager.Up(ctx); err == nil {
			return nil
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			if lastErr != nil {
				return lastErr
			}
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// Step 3
// 网络栈将应用数据包转给 tun 后，该函数从 tun 读取数据包，放入 cSess.PayloadOutTLS 或 cSess.PayloadOutDTLS
// 之后由 payloadOutTLSToServer 或 payloadOutDTLSToServer 调整格式，发送给服务端
func tunToPayloadOut(dev wgtun.Device, cSess *session.ConnSession) {
	defer base.Info("tun to payloadOut exit")
	batchSize := dev.BatchSize()
	if batchSize < 1 {
		batchSize = 1
	}
	bufs := make([][]byte, batchSize)
	sizes := make([]int, batchSize)
	for i := range bufs {
		bufs[i] = make([]byte, payloadBufferSize(cSess.MTU))
	}
	for {
		select {
		case <-cSess.CloseChan:
			return
		default:
		}
		clear(sizes)
		count, err := dev.Read(bufs, sizes, tunPacketOffset)
		if err != nil {
			select {
			case <-cSess.CloseChan:
				return
			default:
			}
			cSess.Stat.TUNReadErrors.Inc()
			cSess.RecordClose("tun_read_error", "tun", err)
			cSess.Close()
			return
		}
		if count < 0 || count > batchSize {
			err = fmt.Errorf("TUN read returned count=%d", count)
		} else {
			for i := 0; i < count; i++ {
				if sizes[i] <= 0 || sizes[i] > len(bufs[i])-tunPacketOffset {
					err = fmt.Errorf("TUN read returned count=%d size=%d", count, sizes[i])
					break
				}
			}
		}
		if err != nil {
			cSess.Stat.TUNReadErrors.Inc()
			cSess.RecordClose("tun_read_invalid", "tun", err)
			cSess.Close()
			return
		}
		for i := 0; i < count; i++ {
			pl := getPayloadBuffer(cSess.MTU)
			copy(pl.Data, bufs[i][tunPacketOffset:tunPacketOffset+sizes[i]])
			pl.Data = pl.Data[:sizes[i]]
			if !sendPayloadToServer(cSess, pl) {
				putPayloadBuffer(pl)
				return
			}
			cSess.Stat.TUNReads.Inc()
		}
	}
}

// Step 22
// 读取 tlsChannel、dtlsChannel 放入 cSess.PayloadIn 的数据包（由服务端返回，已调整格式），写入 tun，网络栈交给应用
func payloadInToTun(dev wgtun.Device, cSess *session.ConnSession) {
	// tun 设备写错误或者cSess.CloseChan
	defer func() {
		base.Info("payloadIn to tun exit")
		closeUserTunnel(cSess)
		// 可能由写错误触发，和 tunToPayloadOut 一起，只要有一处确保退出 cSess 即可，否则 tls 不会退出
		// 如果由外部触发，cSess.Close() 因为使用 sync.Once，所以没影响
		cSess.Close()
	}()

	var (
		err error
		pl  *proto.Payload
	)

	received := 0
	for {
		select {
		case payload, ok := <-cSess.PayloadIn:
			if !ok {
				return
			}
			pl = payload
		case <-cSess.CloseChan:
			return
		}
		if pl == nil {
			err := fmt.Errorf("nil payload received from CSTP worker")
			cSess.RecordClose("payload_in_invalid", "tun", err)
			base.Error("payloadIn to tun invalid payload:", err)
			return
		}

		if routeUserInbound(cSess, pl.Data) {
			putPayloadBuffer(pl)
			continue
		}

		// 只有当使用域名分流且返回数据包为 DNS 时才进一步分析，少建几个协程
		if cSess.DynamicSplitTunneling {
			_, srcPort, _, _ := utils.ResolvePacket(pl.Data)
			if srcPort == 53 {
				data := append([]byte(nil), pl.Data...)
				select {
				case cSess.DynamicRoutePackets <- data:
				case <-cSess.CloseChan:
					putPayloadBuffer(pl)
					return
				}
			}
		}
		// base.Debug("payloadInToTun")
		// if base.Cfg.LogLevel == "Debug" {
		//     src, srcPort, dst, dstPort := utils.ResolvePacket(pl.Data)
		//     if src == "8.8.8.8" {
		//         base.Debug("target from", src, srcPort, "response to client", dst, dstPort)
		//     }
		// }

		expand := make([]byte, tunPacketOffset+len(pl.Data))
		copy(expand[tunPacketOffset:], pl.Data)
		// Match Tailscale native TUN injection: Write counts differ across OS
		// implementations, so the device error determines write success.
		_, err = dev.Write([][]byte{expand}, tunPacketOffset)

		if received < 3 {
			base.Debug("payloadIn to tun", "size", len(pl.Data))
		}
		received++
		if err != nil {
			cSess.Stat.TUNWriteErrors.Inc()
		} else {
			cSess.Stat.TUNWrites.Inc()
		}
		// 释放由 serverToPayloadIn 申请的内存 before handling either success
		// or failure; the failure path otherwise leaks a pooled buffer.
		putPayloadBuffer(pl)
		if err != nil {
			cSess.RecordClose("tun_write_error", "tun", err)
			base.Error("payloadIn to tun error:", err)
			return
		}
	}
}

const (
	minimumDynamicRouteTTL = 30 * time.Second
	maximumDynamicRouteTTL = time.Hour
	maximumDynamicRoutes   = 4096
)

type dynamicRouteLease struct {
	Addresses []string
	ExpiresAt time.Time
}

func dynamicRouteWorker(cSess *session.ConnSession, stop <-chan struct{}) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-cSess.CloseChan:
			return
		case data := <-cSess.DynamicRoutePackets:
			if dynamicSplitRoutes(data, cSess) {
				reconcileDynamicRoutes(cSess)
			}
		case now := <-ticker.C:
			if expireDynamicRoutes(cSess, now) {
				reconcileDynamicRoutes(cSess)
			}
		}
	}
}

func dynamicSplitRoutes(data []byte, cSess *session.ConnSession) bool {
	packet := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Default)
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return false
	}
	dns, ok := dnsLayer.(*layers.DNS)
	if !ok || !dns.QR || len(dns.Questions) != 1 {
		return false
	}
	question := dns.Questions[0]
	if question.Type != layers.DNSTypeA || question.Class != layers.DNSClassIN {
		return false
	}
	query, ok := normalizeDNSName(question.Name)
	if !ok {
		cSess.RecordTransportFault("dynamic_route_dns_invalid", "network", errors.New("invalid DNS question name"))
		return false
	}
	include := utils.InArrayGeneric(cSess.DynamicSplitIncludeDomains, query)
	exclude := !include && utils.InArrayGeneric(cSess.DynamicSplitExcludeDomains, query)
	if !include && !exclude {
		return false
	}
	addresses := make([]string, 0, len(dns.Answers))
	allowedNames := map[string]bool{query: true}
	for _, answer := range dns.Answers {
		if answer.Class != layers.DNSClassIN {
			continue
		}
		name, valid := normalizeDNSName(answer.Name)
		if !valid || !allowedNames[name] || answer.Type != layers.DNSTypeCNAME {
			continue
		}
		target, valid := normalizeDNSName(answer.CNAME)
		if valid {
			allowedNames[target] = true
		}
	}
	ttl := maximumDynamicRouteTTL
	for _, answer := range dns.Answers {
		if answer.Class != layers.DNSClassIN || answer.Type != layers.DNSTypeA || answer.IP == nil {
			continue
		}
		name, valid := normalizeDNSName(answer.Name)
		if !valid || !allowedNames[name] {
			continue
		}
		addr, ok := netip.AddrFromSlice(answer.IP)
		if !ok || !addr.Unmap().Is4() {
			continue
		}
		addresses = append(addresses, addr.Unmap().String())
		answerTTL := time.Duration(answer.TTL) * time.Second
		if answerTTL < ttl {
			ttl = answerTTL
		}
	}
	if len(addresses) == 0 {
		return false
	}
	if ttl < minimumDynamicRouteTTL {
		ttl = minimumDynamicRouteTTL
	}
	if ttl > maximumDynamicRouteTTL {
		ttl = maximumDynamicRouteTTL
	}
	if prospectiveDynamicRouteCount(cSess, query, addresses) > maximumDynamicRoutes {
		err := fmt.Errorf("dynamic route limit %d exceeded", maximumDynamicRoutes)
		cSess.RecordTransportFault("dynamic_route_limit", "network", err)
		recordNetworkHealth(cSess, err)
		return false
	}
	lease := dynamicRouteLease{Addresses: addresses, ExpiresAt: time.Now().Add(ttl)}
	target := &cSess.DynamicSplitIncludeResolved
	if exclude {
		target = &cSess.DynamicSplitExcludeResolved
	}
	target.Store(query, lease)
	return true
}

func normalizeDNSName(raw []byte) (string, bool) {
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(string(raw))), ".")
	if name == "" || len(name) > 253 {
		return "", false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_' {
				return "", false
			}
		}
	}
	return name, true
}

func prospectiveDynamicRouteCount(cSess *session.ConnSession, query string, addresses []string) int {
	unique := map[string]bool{}
	for _, table := range []*sync.Map{&cSess.DynamicSplitIncludeResolved, &cSess.DynamicSplitExcludeResolved} {
		table.Range(func(key, value any) bool {
			if keyString, _ := key.(string); keyString == query {
				return true
			}
			for _, addr := range parseDynamicAddrs(value) {
				unique[addr.String()] = true
			}
			return true
		})
	}
	for _, addr := range addresses {
		unique[addr] = true
	}
	return len(unique)
}

func reconcileDynamicRoutes(cSess *session.ConnSession) {
	if cSess.NetworkManager == nil {
		return
	}
	if err := cSess.NetworkManager.SetDynamicRoutes(context.Background(), collectDynamicRoutes(cSess)); err != nil {
		cSess.RecordTransportFault("dynamic_route_reconcile", "network", err)
		base.Error("dynamic route reconciliation failed:", err)
		recordNetworkHealth(cSess, err)
		return
	}
	recordNetworkHealth(cSess, nil)
}

func recordNetworkHealth(cSess *session.ConnSession, err error) {
	if cSess == nil || cSess.NetworkErrors == nil {
		return
	}
	for {
		select {
		case cSess.NetworkErrors <- err:
			return
		default:
		}
		select {
		case <-cSess.NetworkErrors:
		default:
		}
	}
}

func expireDynamicRoutes(cSess *session.ConnSession, now time.Time) bool {
	changed := false
	for _, table := range []*sync.Map{&cSess.DynamicSplitIncludeResolved, &cSess.DynamicSplitExcludeResolved} {
		table.Range(func(key, value any) bool {
			lease, ok := value.(dynamicRouteLease)
			if ok && !lease.ExpiresAt.After(now) {
				table.Delete(key)
				changed = true
			}
			return true
		})
	}
	return changed
}

func dynamicRouteAddressCount(cSess *session.ConnSession) int {
	routes := collectDynamicRoutes(cSess)
	return len(routes.Include) + len(routes.Exclude)
}

func buildOSNetConfig(cSess *session.ConnSession) (*osnet.Config, error) {
	vpnPrefix, err := osnet.PrefixFromIPMask(cSess.VPNAddress, cSess.VPNMask)
	if err != nil {
		return nil, err
	}
	serverAddress, err := parseServerAddress(cSess.ServerAddress)
	if err != nil {
		return nil, err
	}
	include, err := osnet.ParsePrefixes(cSess.SplitInclude)
	if err != nil {
		return nil, err
	}
	exclude, err := osnet.ParsePrefixes(cSess.SplitExclude)
	if err != nil {
		return nil, err
	}
	if cSess.UseDefaultRouteWhenEmpty && len(include) == 0 {
		include = append(include, netip.PrefixFrom(netip.IPv4Unspecified(), 0))
	}
	if serverAddress.IsValid() {
		exclude = appendUniquePrefix(exclude, netip.PrefixFrom(serverAddress, serverAddress.BitLen()))
		base.Debug("protect vpn server route", "serverAddress", serverAddress.String())
	}
	dns, err := osnet.ParseAddrs(cSess.DNS)
	if err != nil {
		return nil, err
	}
	cfg := &osnet.Config{
		InterfaceName: cSess.TunName,
		VPNAddress:    vpnPrefix,
		MTU:           cSess.MTU,
		IncludeRoutes: append([]netip.Prefix(nil), include...),
		ExcludeRoutes: append([]netip.Prefix(nil), exclude...),
		DNSServers:    dns,
	}
	if cSess.Underlay.LocalIPv4.IsValid() {
		cfg.Underlay = cSess.Underlay
		cfg.GatewayInterfaceIndex = cSess.Underlay.GatewayInterface
		cfg.Gateway = cSess.Underlay.Gateway
	} else {
		info, err := getLocalInterface(context.Background())
		if err != nil {
			return nil, fmt.Errorf("resolve physical underlay: %w", err)
		}
		cfg.GatewayInterfaceIndex = info.InterfaceIndex
		if info.Gateway != "" {
			if addr, err := netip.ParseAddr(info.Gateway); err == nil {
				cfg.Gateway = addr.Unmap()
			}
		}
	}
	cfg.ServerAddress = serverAddress
	return cfg, nil
}

func parseServerAddress(raw string) (netip.Addr, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return netip.Addr{}, nil
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid VPN server address %q: %w", raw, err)
	}
	return addr.Unmap(), nil
}

func appendUniquePrefix(prefixes []netip.Prefix, prefix netip.Prefix) []netip.Prefix {
	prefix = prefix.Masked()
	for _, existing := range prefixes {
		if existing.Masked() == prefix {
			return prefixes
		}
	}
	return append(prefixes, prefix)
}

func collectDynamicRoutes(cSess *session.ConnSession) osnet.DynamicRoutes {
	var routes osnet.DynamicRoutes
	cSess.DynamicSplitIncludeResolved.Range(func(_, value any) bool {
		routes.Include = append(routes.Include, parseDynamicAddrs(value)...)
		return true
	})
	cSess.DynamicSplitExcludeResolved.Range(func(_, value any) bool {
		routes.Exclude = append(routes.Exclude, parseDynamicAddrs(value)...)
		return true
	})
	return routes
}

func parseDynamicAddrs(value any) []netip.Addr {
	var raw []string
	switch value := value.(type) {
	case []string:
		raw = value
	case dynamicRouteLease:
		raw = value.Addresses
	default:
		return nil
	}
	addrs, _ := osnet.ParseAddrs(raw)
	return addrs
}
