package tunflow

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/tailscale/wireguard-go/tun"
)

type testTUN struct {
	in     chan []byte
	out    chan []byte
	done   chan struct{}
	events chan tun.Event
	once   sync.Once
}

func newTestTUN() *testTUN {
	return &testTUN{in: make(chan []byte, 16), out: make(chan []byte, 16), done: make(chan struct{}), events: make(chan tun.Event)}
}

func (*testTUN) File() *os.File { return nil }
func (d *testTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case packet := <-d.in:
		sizes[0] = copy(bufs[0][offset:], packet)
		return 1, nil
	case <-d.done:
		return 0, net.ErrClosed
	}
}
func (d *testTUN) Write(bufs [][]byte, offset int) (int, error) {
	select {
	case d.out <- append([]byte(nil), bufs[0][offset:]...):
		return 1, nil
	case <-d.done:
		return 0, net.ErrClosed
	}
}
func (*testTUN) MTU() (int, error)          { return 1399, nil }
func (*testTUN) Name() (string, error)      { return "test-tun", nil }
func (*testTUN) BatchSize() int             { return 1 }
func (d *testTUN) Events() <-chan tun.Event { return d.events }
func (d *testTUN) Close() error {
	d.once.Do(func() { close(d.done); close(d.events) })
	return nil
}

type gatedUDPDialer struct {
	started chan struct{}
	release chan struct{}
	calls   atomic.Int32
	once    sync.Once
}

func (d *gatedUDPDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.calls.Add(1)
	d.once.Do(func() { close(d.started) })
	if network != "udp" || address != "10.0.0.2:4242" {
		return nil, errors.New("unexpected dial target")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-d.release:
	}
	local, remote := net.Pipe()
	go func() {
		defer remote.Close()
		data := make([]byte, 1500)
		for {
			n, err := remote.Read(data)
			if err != nil {
				return
			}
			if _, err := remote.Write(data[:n]); err != nil {
				return
			}
		}
	}()
	return local, nil
}

func udpPacket(t *testing.T, payload string) []byte {
	t.Helper()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, SrcIP: net.IP{10, 0, 0, 1}, DstIP: net.IP{10, 0, 0, 2}, Protocol: layers.IPProtocolUDP}
	udp := &layers.UDP{SrcPort: 44000, DstPort: 4242}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, udp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func closeTestStack(t *testing.T, s *Stack) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- s.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stack cleanup blocked on a UDP flow")
	}
}

func TestUDPDatagramsDuringDialShareEndpoint(t *testing.T) {
	dev := newTestTUN()
	dialer := &gatedUDPDialer{started: make(chan struct{}), release: make(chan struct{})}
	s, err := New(context.Background(), dev, dialer, nil, 1399)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestStack(t, s) })
	// Feed a burst while the upstream dial is still blocked. Endpoint creation
	// must already be complete so every datagram queues on the same flow.
	for _, payload := range []string{"one", "two", "three"} {
		s.handlePacket(udpPacket(t, payload))
	}
	select {
	case <-dialer.started:
	case <-time.After(time.Second):
		t.Fatal("UDP dial did not start")
	}
	close(dialer.release)
	for _, want := range []string{"one", "two", "three"} {
		select {
		case packet := <-dev.out:
			decoded := gopacket.NewPacket(packet, layers.LayerTypeIPv4, gopacket.Default)
			udp, ok := decoded.Layer(layers.LayerTypeUDP).(*layers.UDP)
			if !ok || string(udp.Payload) != want {
				t.Fatalf("UDP reply = %v, want %q", decoded, want)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("UDP datagram %q lost during dial", want)
		}
	}
	if got := dialer.calls.Load(); got != 1 {
		t.Fatalf("upstream dials = %d, want 1 for one UDP flow", got)
	}
}

func TestCloseCancelsPendingUDPDial(t *testing.T) {
	dev := newTestTUN()
	dialer := &gatedUDPDialer{started: make(chan struct{}), release: make(chan struct{})}
	s, err := New(context.Background(), dev, dialer, nil, 1399)
	if err != nil {
		t.Fatal(err)
	}
	s.handlePacket(udpPacket(t, "pending"))
	select {
	case <-dialer.started:
	case <-time.After(time.Second):
		t.Fatal("UDP dial did not start")
	}
	closeTestStack(t, s)
}
