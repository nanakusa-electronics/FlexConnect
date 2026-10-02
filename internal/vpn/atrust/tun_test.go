package atrust

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"flexconnect/internal/tunflow"
	geektrust "github.com/ShanghaitechGeekPie/geektrust/client"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/tailscale/wireguard-go/tun"
	"github.com/tailscale/wireguard-go/tun/netstack"
	"golang.org/x/net/dns/dnsmessage"
)

type fakeTUN struct {
	in     chan []byte
	out    chan []byte
	events chan tun.Event
	done   chan struct{}
	once   sync.Once
}

func newFakeTUN() *fakeTUN {
	return &fakeTUN{in: make(chan []byte, 1), out: make(chan []byte, 1), events: make(chan tun.Event), done: make(chan struct{})}
}
func (*fakeTUN) File() *os.File { return nil }
func (d *fakeTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case packet := <-d.in:
		sizes[0] = copy(bufs[0][offset:], packet)
		return 1, nil
	case <-d.done:
		return 0, net.ErrClosed
	}
}
func (d *fakeTUN) Write(bufs [][]byte, offset int) (int, error) {
	select {
	case d.out <- append([]byte(nil), bufs[0][offset:]...):
		return 1, nil
	case <-d.done:
		return 0, net.ErrClosed
	}
}
func (*fakeTUN) MTU() (int, error)          { return 1399, nil }
func (*fakeTUN) Name() (string, error)      { return "test-tun", nil }
func (d *fakeTUN) Events() <-chan tun.Event { return d.events }
func (d *fakeTUN) Close() error             { d.once.Do(func() { close(d.done); close(d.events) }); return nil }
func (*fakeTUN) BatchSize() int             { return 1 }

func TestDNSPacketThroughUserStackPreservesDomain(t *testing.T) {
	name := dnsmessage.MustNewName("service.example.test.")
	query, err := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 1234, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, SrcIP: net.ParseIP("198.19.255.253").To4(), DstIP: net.ParseIP("198.19.255.254").To4(), Protocol: layers.IPProtocolUDP}
	udp := &layers.UDP{SrcPort: 44000, DstPort: 53}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, udp, gopacket.Payload(query)); err != nil {
		t.Fatal(err)
	}
	dev := newFakeTUN()
	mapper := newDNSMapper(geektrust.Info{Resources: []geektrust.Resource{{Address: "service.example.test"}}}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	flow, err := tunflow.New(ctx, dev, flowDialer{ctx: ctx, dns: mapper}, nil, 1399)
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	dev.in <- buf.Bytes()
	select {
	case packet := <-dev.out:
		decoded := gopacket.NewPacket(packet, layers.LayerTypeIPv4, gopacket.Default)
		udpLayer := decoded.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			t.Fatalf("no UDP response: %v", decoded.ErrorLayer())
		}
		var response dnsmessage.Message
		if err := response.Unpack(udpLayer.(*layers.UDP).Payload); err != nil {
			t.Fatal(err)
		}
		if !response.Response || response.ID != 1234 || len(response.Answers) != 1 {
			t.Fatalf("unexpected DNS response: %+v", response)
		}
		fake := netip.AddrFrom4(response.Answers[0].Body.(*dnsmessage.AResource).A)
		got := mapper.reserveIP(fake)
		mapper.releaseIP(fake)
		if got != "service.example.test" {
			t.Fatalf("Fake-IP maps to %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no DNS response from TUN stack")
	}
}

type echoTunnel struct{ target chan string }

func (e *echoTunnel) DialContext(_ context.Context, network, address string) (net.Conn, error) {
	e.target <- network + " " + address
	a, b := net.Pipe()
	go func() {
		defer b.Close()
		buf := make([]byte, 1500)
		for {
			n, err := b.Read(buf)
			if err != nil {
				return
			}
			if _, err := b.Write(buf[:n]); err != nil {
				return
			}
		}
	}()
	return a, nil
}
func (*echoTunnel) LookupContextHost(context.Context, string) ([]string, error) { return nil, nil }

func TestUDPFlowRestoresDomainBeforeDial(t *testing.T) {
	upstream := &echoTunnel{target: make(chan string, 1)}
	mapper := newDNSMapper(geektrust.Info{Resources: []geektrust.Resource{{Address: "service.example.test"}}}, upstream)
	fakeIP, err := mapper.allocate("service.example.test")
	if err != nil {
		t.Fatal(err)
	}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, SrcIP: net.ParseIP("198.19.255.253").To4(), DstIP: net.IP(fakeIP.AsSlice()), Protocol: layers.IPProtocolUDP}
	udp := &layers.UDP{SrcPort: 44000, DstPort: 4242}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, udp, gopacket.Payload([]byte("hello"))); err != nil {
		t.Fatal(err)
	}
	dev := newFakeTUN()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	flow, err := tunflow.New(ctx, dev, flowDialer{ctx: ctx, client: upstream, dns: mapper}, nil, 1399)
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	dev.in <- buf.Bytes()
	select {
	case target := <-upstream.target:
		if target != "udp service.example.test:4242" {
			t.Fatalf("authorized dial target = %q", target)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("UDP flow did not dial")
	}
	select {
	case packet := <-dev.out:
		decoded := gopacket.NewPacket(packet, layers.LayerTypeIPv4, gopacket.Default)
		got := decoded.Layer(layers.LayerTypeUDP)
		if got == nil || string(got.(*layers.UDP).Payload) != "hello" {
			t.Fatalf("UDP echo = %v", decoded.ErrorLayer())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("UDP reply did not reach TUN")
	}
}

func TestTCPFlowThroughUserStack(t *testing.T) {
	upstream := &echoTunnel{target: make(chan string, 1)}
	mapper := newDNSMapper(geektrust.Info{Resources: []geektrust.Resource{{Address: "service.example.test"}}}, upstream)
	fakeIP, err := mapper.allocate("service.example.test")
	if err != nil {
		t.Fatal(err)
	}
	dev := newFakeTUN()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	flow, err := tunflow.New(ctx, dev, flowDialer{ctx: ctx, client: upstream, dns: mapper}, nil, 1399)
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	clientDev, clientNet, err := netstack.CreateNetTUN([]netip.Addr{fakeLocal}, nil, 1399)
	if err != nil {
		t.Fatal(err)
	}
	defer clientDev.Close()
	go func() {
		for {
			buf := make([]byte, 1600)
			sizes := []int{0}
			if n, err := clientDev.Read([][]byte{buf}, sizes, 0); err != nil || n != 1 {
				return
			}
			select {
			case dev.in <- append([]byte(nil), buf[:sizes[0]]...):
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		for {
			select {
			case packet := <-dev.out:
				if _, err := clientDev.Write([][]byte{packet}, 0); err != nil {
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	dialCtx, stop := context.WithTimeout(ctx, 3*time.Second)
	defer stop()
	conn, err := clientNet.DialContext(dialCtx, "tcp", net.JoinHostPort(fakeIP.String(), "4242"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello" {
		t.Fatalf("TCP echo = %q", buf)
	}
	select {
	case target := <-upstream.target:
		if target != "tcp service.example.test:4242" {
			t.Fatalf("authorized dial target = %q", target)
		}
	default:
		t.Fatal("TCP did not use authorized domain")
	}
}

func TestResourceRangeIsRoutedPrecisely(t *testing.T) {
	got := resourcePrefixes("10.0.0.8-10.0.0.15")
	if len(got) != 1 || got[0].String() != "10.0.0.8/29" {
		t.Fatalf("range routes = %v", got)
	}
	got = resourcePrefixes("0.0.0.0-255.255.255.255")
	if len(got) != 1 || got[0].String() != "0.0.0.0/0" {
		t.Fatalf("full range routes = %v", got)
	}
}

type batchTUN struct {
	*fakeTUN
	reads int
}

func (*batchTUN) BatchSize() int { return 2 }
func (d *batchTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if d.reads > 0 {
		<-d.done
		return 0, net.ErrClosed
	}
	d.reads++
	if len(bufs) < 2 || len(sizes) < 2 || offset < 10 {
		return 0, errors.New("native TUN batch or headroom missing")
	}
	for i := range 2 {
		packet := make([]byte, 28)
		packet[0] = 0x45
		packet[9] = 1
		packet[20] = 8
		packet[27] = byte(i)
		copy(bufs[i][offset:], packet)
		sizes[i] = len(packet)
	}
	return 2, nil
}
func (d *batchTUN) Write(bufs [][]byte, offset int) (int, error) {
	if offset < 10 {
		return 0, errors.New("native TUN write headroom missing")
	}
	_, err := d.fakeTUN.Write(bufs, offset)
	return len(bufs[0]), err // Linux may return byte count rather than packet count.
}

type echoPacket struct{}

func (echoPacket) ExchangePacket(_ context.Context, packet []byte) ([]byte, error) {
	packet[20] = 0
	return packet, nil
}

func TestATrustConsumesEveryNativeTUNSegment(t *testing.T) {
	dev := &batchTUN{fakeTUN: newFakeTUN()}
	flow, err := tunflow.New(context.Background(), dev, &echoTunnel{target: make(chan string, 1)}, echoPacket{}, 1399)
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	seen := make(map[byte]bool)
	for range 2 {
		select {
		case packet := <-dev.out:
			seen[packet[27]] = true
		case err := <-flow.Errors():
			t.Fatal(err)
		case <-time.After(time.Second):
			t.Fatal("TUN batch lost a packet")
		}
	}
	if !seen[0] || !seen[1] {
		t.Fatal("duplicate or missing segment")
	}
}

func TestEmptyUDPDatagramThroughUserStack(t *testing.T) {
	upstream := &echoTunnel{target: make(chan string, 1)}
	mapper := newDNSMapper(geektrust.Info{Resources: []geektrust.Resource{{Address: "service.example.test"}}}, upstream)
	fakeIP, err := mapper.allocate("service.example.test")
	if err != nil {
		t.Fatal(err)
	}
	dev := newFakeTUN()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	flow, err := tunflow.New(ctx, dev, flowDialer{ctx: ctx, client: upstream, dns: mapper}, nil, 1399)
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, SrcIP: net.ParseIP("198.19.255.253").To4(), DstIP: net.IP(fakeIP.AsSlice()), Protocol: layers.IPProtocolUDP}
	udp := &layers.UDP{SrcPort: 44001, DstPort: 4242}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, udp); err != nil {
		t.Fatal(err)
	}
	dev.in <- buf.Bytes()
	select {
	case packet := <-dev.out:
		decoded := gopacket.NewPacket(packet, layers.LayerTypeIPv4, gopacket.Default)
		received := decoded.Layer(layers.LayerTypeUDP)
		if received == nil || len(received.(*layers.UDP).Payload) != 0 {
			t.Fatal("empty datagram corrupted")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("empty datagram dropped")
	}
}
