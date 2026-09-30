//go:build linux

package vpn

import (
	"bytes"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"flexconnect/internal/anyconnect/proto"
	"flexconnect/internal/anyconnect/session"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	wgtun "github.com/tailscale/wireguard-go/tun"
	"github.com/vishvananda/netlink"
)

// Run only inside an isolated network namespace with CAP_NET_ADMIN.
func TestNativeLinuxTUNPacketIO(t *testing.T) {
	if os.Getenv("FLEXCONNECT_TUN_TEST") != "1" {
		t.Skip("requires opt-in isolated network namespace")
	}
	dev, err := wgtun.CreateTUN("fctest", 1399)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	name, err := dev.Name()
	if err != nil {
		t.Fatal(err)
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := netlink.ParseAddr("192.0.2.1/24")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("192.0.2.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := listener.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x5a}, 32)
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP("192.0.2.2"), DstIP: net.ParseIP("192.0.2.1")}
	udp := &layers.UDP{SrcPort: 40000, DstPort: layers.UDPPort(listener.LocalAddr().(*net.UDPAddr).Port)}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	wire := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(wire, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, udp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	cSess := (&session.Session{}).NewConnSession(&http.Header{})
	cSess.MTU = 1399
	defer cSess.Close()
	done := make(chan struct{})
	go func() { payloadInToTun(dev, cSess); close(done) }()
	cSess.PayloadIn <- &proto.Payload{Data: wire.Bytes()}
	buf := make([]byte, 100)
	n, _, err := listener.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatal("native TUN corrupted inbound UDP payload")
	}
	cSess.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("native writer did not stop")
	}
	if cSess.Stat.TUNWriteErrors.Load() != 0 || cSess.Stat.TUNWrites.Load() != 1 {
		t.Fatalf("native write treated as failure: %+v", cSess.CloseInfo())
	}
	// Exercise the real native read API, including the device's batch size.
	outgoing, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 40001})
	if err != nil {
		t.Fatal(err)
	}
	defer outgoing.Close()
	if _, err := outgoing.Write(payload); err != nil {
		t.Fatal(err)
	}
	bufs := make([][]byte, dev.BatchSize())
	sizes := make([]int, len(bufs))
	for i := range bufs {
		bufs[i] = make([]byte, payloadBufferSize(1399))
	}
	readDone := make(chan error, 1)
	go func() {
		for {
			count, err := dev.Read(bufs, sizes, tunPacketOffset)
			if err != nil {
				readDone <- err
				return
			}
			if count <= 0 || count > len(bufs) {
				readDone <- os.ErrInvalid
				return
			}
			for i := 0; i < count; i++ {
				if sizes[i] <= 0 || sizes[i] > len(bufs[i])-tunPacketOffset {
					readDone <- os.ErrInvalid
					return
				}
				packet := gopacket.NewPacket(bufs[i][tunPacketOffset:tunPacketOffset+sizes[i]], layers.LayerTypeIPv4, gopacket.Default)
				layer := packet.Layer(layers.LayerTypeUDP)
				// Link activation can queue IPv6 neighbor discovery first.
				if layer != nil && bytes.Equal(layer.(*layers.UDP).Payload, payload) {
					readDone <- nil
					return
				}
			}
		}
	}()
	select {
	case err := <-readDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		dev.Close()
		t.Fatal("native TUN read timed out")
	}
}
