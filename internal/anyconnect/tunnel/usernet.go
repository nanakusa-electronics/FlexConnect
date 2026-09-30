package vpn

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"flexconnect/internal/anyconnect/base"
	"flexconnect/internal/anyconnect/proto"
	"flexconnect/internal/anyconnect/session"
	corevpn "flexconnect/internal/vpn"

	"github.com/tailscale/wireguard-go/tun"
	"github.com/tailscale/wireguard-go/tun/netstack"
)

const userFlowTTL = 5 * time.Minute

var userTunnels sync.Map

type userTunnel struct {
	dev    tun.Device
	net    *netstack.Net
	cSess  *session.ConnSession
	router *userFlowRouter
	mu     sync.RWMutex
	once   sync.Once
	cancel context.CancelFunc
}

func SessionTunnelDialer(ctx context.Context, cSess *session.ConnSession) (corevpn.TunnelDialer, error) {
	if cSess == nil {
		return nil, errors.New("no active VPN session")
	}
	if ctx != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	select {
	case <-cSess.CloseChan:
		return nil, errors.New("VPN session is closed")
	default:
	}
	if existing, ok := userTunnels.Load(cSess); ok {
		return existing.(*userTunnel), nil
	}
	tunnel, err := newUserTunnel(cSess)
	if err != nil {
		return nil, err
	}
	if ctx != nil && ctx.Err() != nil {
		tunnel.Close()
		return nil, ctx.Err()
	}
	actual, loaded := userTunnels.LoadOrStore(cSess, tunnel)
	if loaded {
		tunnel.Close()
		tunnel = actual.(*userTunnel)
	}
	select {
	case <-cSess.CloseChan:
		tunnel.Close()
		return nil, errors.New("VPN session is closed")
	default:
	}
	return tunnel, nil
}

func newUserTunnel(cSess *session.ConnSession) (*userTunnel, error) {
	local, err := netip.ParseAddr(cSess.VPNAddress)
	if err != nil || !local.Is4() {
		return nil, fmt.Errorf("invalid IPv4 VPN address %q", cSess.VPNAddress)
	}
	dns, err := parseIPv4Addrs(cSess.DNS)
	if err != nil {
		return nil, err
	}
	mtu := cSess.MTU
	if mtu <= 0 {
		mtu = 1399
	}
	dev, tnet, err := netstack.CreateNetTUN([]netip.Addr{local}, dns, mtu)
	if err != nil {
		return nil, err
	}
	watchCtx, cancel := context.WithCancel(context.Background())
	tunnel := &userTunnel{
		cancel: cancel,
		dev:    dev,
		net:    tnet,
		cSess:  cSess,
		router: newUserFlowRouter(),
	}
	go func() {
		select {
		case <-cSess.CloseChan:
			tunnel.Close()
		case <-watchCtx.Done():
		}
	}()
	go tunnel.userTunToPayloadOut()
	base.Info("user-space VPN tunnel dialer started", "vpnAddress", cSess.VPNAddress, "dns", len(dns))
	return tunnel, nil
}

func parseIPv4Addrs(raw []string) ([]netip.Addr, error) {
	out := make([]netip.Addr, 0, len(raw))
	for _, value := range raw {
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return nil, fmt.Errorf("invalid VPN DNS address %q: %w", value, err)
		}
		addr = addr.Unmap()
		if addr.Is4() {
			out = append(out, addr)
		}
	}
	return out, nil
}

func (t *userTunnel) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if t == nil {
		return nil, errors.New("VPN tunnel dialer is closed")
	}
	t.mu.RLock()
	tnet := t.net
	t.mu.RUnlock()
	if tnet == nil {
		return nil, errors.New("VPN tunnel dialer is closed")
	}
	return tnet.DialContext(ctx, network, address)
}

func (t *userTunnel) LookupContextHost(ctx context.Context, host string) ([]string, error) {
	if t == nil {
		return nil, errors.New("VPN tunnel resolver is closed")
	}
	t.mu.RLock()
	tnet := t.net
	t.mu.RUnlock()
	if tnet == nil {
		return nil, errors.New("VPN tunnel resolver is closed")
	}
	return tnet.LookupContextHost(ctx, host)
}

func (t *userTunnel) Close() error {
	if t == nil {
		return nil
	}
	var err error
	t.once.Do(func() {
		userTunnels.CompareAndDelete(t.cSess, t)
		if t.cancel != nil {
			t.cancel()
		}
		t.mu.Lock()
		dev := t.dev
		t.dev = nil
		t.net = nil
		t.mu.Unlock()
		if dev != nil {
			err = dev.Close()
		}
		base.Info("user-space VPN tunnel dialer stopped")
	})
	return err
}

func (t *userTunnel) userTunToPayloadOut() {
	defer t.Close()
	for {
		t.mu.RLock()
		dev := t.dev
		t.mu.RUnlock()
		if dev == nil {
			return
		}
		pl := getPayloadBuffer(t.cSess.MTU)
		bufs := [][]byte{pl.Data}
		sizes := []int{0}
		readCount, err := dev.Read(bufs, sizes, 0)
		if err != nil {
			putPayloadBuffer(pl)
			return
		}
		if readCount != 1 {
			putPayloadBuffer(pl)
			base.Warn("user-space VPN tunnel returned invalid read count", "count", readCount)
			return
		}
		n := sizes[0]
		if n <= 0 || n > len(bufs[0]) {
			putPayloadBuffer(pl)
			if n < 0 || n > len(bufs[0]) {
				base.Warn("user-space VPN tunnel returned invalid packet size", "size", n)
				return
			}
			continue
		}
		pl.Data = pl.Data[:n]
		t.router.recordOutbound(pl.Data)
		if !sendPayloadToServer(t.cSess, pl) {
			putPayloadBuffer(pl)
			return
		}
	}
}

func sendPayloadToServer(cSess *session.ConnSession, pl *proto.Payload) bool {
	if cSess == nil {
		return false
	}
	if cSess.DtlsConnected.Load() {
		select {
		case cSess.PayloadOutDTLS <- pl:
			return true
		case <-cSess.DSess.CloseChan:
			// DTLS is an optimization. If it disappears while a packet is
			// being queued, retry on the reliable CSTP channel instead of
			// terminating the user-space tunnel.
		case <-cSess.CloseChan:
			return false
		}
	}
	select {
	case cSess.PayloadOutTLS <- pl:
		return true
	case <-cSess.CloseChan:
		return false
	}
}

func routeUserInbound(cSess *session.ConnSession, packet []byte) bool {
	if cSess == nil {
		return false
	}
	value, ok := userTunnels.Load(cSess)
	if !ok {
		return false
	}
	tunnel := value.(*userTunnel)
	if !tunnel.router.matchesInbound(packet) {
		return false
	}
	tunnel.mu.RLock()
	dev := tunnel.dev
	tunnel.mu.RUnlock()
	if dev == nil {
		return false
	}
	if _, err := dev.Write([][]byte{packet}, 0); err != nil {
		base.Warn("user-space VPN tunnel write failed:", err)
		_ = tunnel.Close()
		return false
	}
	return true
}

func closeUserTunnel(cSess *session.ConnSession) {
	if cSess == nil {
		return
	}
	if value, ok := userTunnels.Load(cSess); ok {
		_ = value.(*userTunnel).Close()
	}
}

type userFlowRouter struct {
	mu    sync.Mutex
	flows map[flowKey]time.Time
	now   func() time.Time
}

type flowKey struct {
	proto   byte
	src     [4]byte
	dst     [4]byte
	srcPort uint16
	dstPort uint16
}

func newUserFlowRouter() *userFlowRouter {
	return &userFlowRouter{
		flows: make(map[flowKey]time.Time),
		now:   time.Now,
	}
}

func (r *userFlowRouter) recordOutbound(packet []byte) bool {
	key, ok := packetFlowKey(packet)
	if !ok {
		return false
	}
	reverse := flowKey{
		proto:   key.proto,
		src:     key.dst,
		dst:     key.src,
		srcPort: key.dstPort,
		dstPort: key.srcPort,
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneLocked()
	r.flows[reverse] = r.now().Add(userFlowTTL)
	return true
}

func (r *userFlowRouter) matchesInbound(packet []byte) bool {
	key, ok := packetFlowKey(packet)
	if !ok {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneLocked()
	_, ok = r.flows[key]
	return ok
}

func (r *userFlowRouter) pruneLocked() {
	now := r.now()
	for key, expires := range r.flows {
		if now.After(expires) {
			delete(r.flows, key)
		}
	}
}

func packetFlowKey(packet []byte) (flowKey, bool) {
	if len(packet) < 24 || packet[0]>>4 != 4 {
		return flowKey{}, false
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl+4 {
		return flowKey{}, false
	}
	proto := packet[9]
	if proto != 6 && proto != 17 {
		return flowKey{}, false
	}
	var key flowKey
	key.proto = proto
	copy(key.src[:], packet[12:16])
	copy(key.dst[:], packet[16:20])
	key.srcPort = binary.BigEndian.Uint16(packet[ihl : ihl+2])
	key.dstPort = binary.BigEndian.Uint16(packet[ihl+2 : ihl+4])
	return key, true
}
