package atrust

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"flexconnect/internal/osnet"
	"flexconnect/internal/tunflow"
	wgtun "github.com/tailscale/wireguard-go/tun"
)

// Opt-in: creates a dedicated test adapter and routes only one documentation IP.
// Linux callers must use a fresh network namespace; CI runners are disposable.
func TestNativeATrustTUNFlows(t *testing.T) {
	if os.Getenv("FLEXCONNECT_ATRUST_TUN_TEST") != "1" {
		t.Skip("requires opt-in native TUN access")
	}
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("fcqa%x", suffix)
	if runtime.GOOS == "darwin" {
		name = "utun"
	}
	dev, err := wgtun.CreateTUN(name, 1399)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := osnet.NewManager(dev, name)
	if err != nil {
		dev.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var flows *tunflow.Stack
	defer func() {
		cancel()
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := manager.Close(cleanup); err != nil {
			t.Errorf("native route cleanup: %v", err)
		}
		if flows != nil {
			_ = flows.Close()
		} else {
			_ = dev.Close()
		}
	}()
	ready, stop := context.WithTimeout(ctx, 10*time.Second)
	defer stop()
	for {
		if err = manager.Up(ready); err == nil {
			break
		}
		select {
		case <-ready.Done():
			t.Fatal(err)
		case <-time.After(100 * time.Millisecond):
		}
	}
	localIP := netip.MustParseAddr("192.0.2.1")
	target := netip.MustParseAddr("192.0.2.2")
	if err := manager.Set(ready, &osnet.Config{VPNAddress: netip.PrefixFrom(localIP, 32), MTU: 1399, IncludeRoutes: []netip.Prefix{netip.PrefixFrom(target, 32)}}); err != nil {
		t.Fatal(err)
	}
	upstream := &echoTunnel{target: make(chan string, 4)}
	flows, err = tunflow.New(ctx, dev, upstream, nil, 1399)
	if err != nil {
		t.Fatal(err)
	}
	for _, network := range []string{"udp4", "tcp4"} {
		t.Run(network, func(t *testing.T) {
			dial := net.Dialer{Timeout: 3 * time.Second}
			if network == "udp4" {
				dial.LocalAddr = &net.UDPAddr{IP: net.IP(localIP.AsSlice())}
			} else {
				dial.LocalAddr = &net.TCPAddr{IP: net.IP(localIP.AsSlice())}
			}
			conn, err := dial.DialContext(ctx, network, net.JoinHostPort(target.String(), "4242"))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			payload := []byte("native aTrust TUN round trip")
			if _, err := conn.Write(payload); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, got); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatal("native TUN corrupted payload")
			}
			select {
			case address := <-upstream.target:
				if address != network[:3]+" 192.0.2.2:4242" {
					t.Fatalf("dial target=%s", address)
				}
			case <-time.After(time.Second):
				t.Fatal("native flow bypassed the configured transport")
			}
		})
	}
}
