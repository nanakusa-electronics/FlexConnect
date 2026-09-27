// Package tunflow converts IPv4 packets on a system TUN into authorized TCP
// and UDP connections. It does not choose routes or modify system networking.
package tunflow

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type Dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}
type PacketTransport interface {
	ExchangePacket(context.Context, []byte) ([]byte, error)
}

type Stack struct {
	dev      tun.Device
	link     *channel.Endpoint
	ip       *stack.Stack
	dialer   Dialer
	packets  PacketTransport
	ctx      context.Context
	cancel   context.CancelFunc
	once     sync.Once
	mu       sync.Mutex
	writeMu  sync.Mutex
	closing  bool
	loops    sync.WaitGroup
	flows    sync.WaitGroup
	errs     chan error
	sent     atomic.Uint64
	received atomic.Uint64
}

func New(parent context.Context, dev tun.Device, dialer Dialer, packets PacketTransport, mtu int) (*Stack, error) {
	if dev == nil || dialer == nil || mtu < 576 {
		return nil, errors.New("invalid TUN flow configuration")
	}
	ctx, cancel := context.WithCancel(parent)
	s := &Stack{dev: dev, dialer: dialer, packets: packets, ctx: ctx, cancel: cancel, errs: make(chan error, 2)}
	s.ip = stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol}})
	s.link = channel.New(1024, uint32(mtu), "")
	if err := s.ip.CreateNIC(1, s.link); err != nil {
		cancel()
		return nil, errors.New(err.String())
	}
	if err := s.ip.SetPromiscuousMode(1, true); err != nil {
		cancel()
		return nil, errors.New(err.String())
	}
	if err := s.ip.SetSpoofing(1, true); err != nil {
		cancel()
		return nil, errors.New(err.String())
	}
	s.ip.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	tcpForwarder := tcp.NewForwarder(s.ip, 0, 1024, s.acceptTCP)
	udpForwarder := udp.NewForwarder(s.ip, s.acceptUDP)
	s.ip.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
	s.ip.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)
	s.loops.Add(2)
	go s.readTUN(mtu)
	go s.writeTUN()
	return s, nil
}

func (s *Stack) Errors() <-chan error      { return s.errs }
func (s *Stack) Done() <-chan struct{}     { return s.ctx.Done() }
func (s *Stack) Traffic() (uint64, uint64) { return s.sent.Load(), s.received.Load() }

func target(id stack.TransportEndpointID) string {
	return net.JoinHostPort(net.IP(id.LocalAddress.AsSlice()).String(), strconv.Itoa(int(id.LocalPort)))
}

func (s *Stack) acceptTCP(req *tcp.ForwarderRequest) {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		req.Complete(true)
		return
	}
	s.flows.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.flows.Done()
		ctx, cancel := context.WithTimeout(s.ctx, 15*time.Second)
		defer cancel()
		remote, err := s.dialer.DialContext(ctx, "tcp", target(req.ID()))
		if err != nil {
			req.Complete(true)
			return
		}
		var wq waiter.Queue
		ep, terr := req.CreateEndpoint(&wq)
		if terr != nil {
			req.Complete(true)
			remote.Close()
			return
		}
		req.Complete(false)
		local := gonet.NewTCPConn(&wq, ep)
		s.relay(local, remote)
	}()
}

func (s *Stack) acceptUDP(req *udp.ForwarderRequest) {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return
	}
	s.flows.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.flows.Done()
		ctx, cancel := context.WithTimeout(s.ctx, 15*time.Second)
		remote, err := s.dialer.DialContext(ctx, "udp", target(req.ID()))
		cancel()
		if err != nil {
			return
		}
		var wq waiter.Queue
		ep, terr := req.CreateEndpoint(&wq)
		if terr != nil {
			remote.Close()
			return
		}
		local := gonet.NewUDPConn(s.ip, &wq, ep)
		s.relay(local, remote)
	}()
}

func (s *Stack) relay(local, remote net.Conn) {
	defer local.Close()
	defer remote.Close()
	stop := context.AfterFunc(s.ctx, func() { local.Close(); remote.Close() })
	defer stop()
	done := make(chan struct{}, 2)
	copyOne := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if half, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = half.CloseWrite()
		}
		done <- struct{}{}
	}
	go copyOne(remote, local)
	go copyOne(local, remote)
	<-done
	if err := remote.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		remote.Close()
	}
	if err := local.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		local.Close()
	}
	<-done
}

func (s *Stack) readTUN(mtu int) {
	defer s.loops.Done()
	offset := 0
	if runtime.GOOS == "darwin" {
		offset = 4
	}
	buf := make([]byte, mtu+offset+64)
	for {
		sizes := []int{0}
		n, err := s.dev.Read([][]byte{buf}, sizes, offset)
		if err != nil {
			s.report(err)
			return
		}
		if n != 1 || sizes[0] < header.IPv4MinimumSize || sizes[0] > len(buf)-offset {
			continue
		}
		packet := buf[offset : offset+sizes[0]]
		if packet[0]>>4 != 4 {
			continue
		}
		s.sent.Add(uint64(len(packet)))
		if packet[9] == 1 {
			if s.packets != nil && len(packet) >= int(packet[0]&15)*4+8 && packet[int(packet[0]&15)*4] == 8 {
				s.mu.Lock()
				if !s.closing {
					s.flows.Add(1)
					go s.exchangeICMP(append([]byte(nil), packet...), offset)
				}
				s.mu.Unlock()
			}
			continue
		}
		p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), packet...))})
		s.link.InjectInbound(ipv4.ProtocolNumber, p)
		p.DecRef()
	}
}

func (s *Stack) exchangeICMP(packet []byte, offset int) {
	defer s.flows.Done()
	ctx, cancel := context.WithTimeout(s.ctx, 8*time.Second)
	defer cancel()
	reply, err := s.packets.ExchangePacket(ctx, packet)
	if err != nil || len(reply) < header.IPv4MinimumSize || reply[0]>>4 != 4 {
		return
	}
	out := make([]byte, offset+len(reply))
	copy(out[offset:], reply)
	s.writeMu.Lock()
	_, err = s.dev.Write([][]byte{out}, offset)
	s.writeMu.Unlock()
	if err != nil {
		s.report(err)
	} else {
		s.received.Add(uint64(len(reply)))
	}
}

func (s *Stack) writeTUN() {
	defer s.loops.Done()
	offset := 0
	if runtime.GOOS == "darwin" {
		offset = 4
	}
	for {
		p := s.link.ReadContext(s.ctx)
		if p == nil {
			return
		}
		view := p.ToView()
		packet := append([]byte(nil), view.AsSlice()...)
		view.Release()
		p.DecRef()
		if len(packet) == 0 {
			continue
		}
		out := make([]byte, offset+len(packet))
		copy(out[offset:], packet)
		s.writeMu.Lock()
		_, err := s.dev.Write([][]byte{out}, offset)
		s.writeMu.Unlock()
		if err != nil {
			s.report(err)
			return
		}
		s.received.Add(uint64(len(packet)))
	}
}

func (s *Stack) report(err error) {
	if s.ctx.Err() == nil {
		select {
		case s.errs <- err:
		default:
		}
	}
}

func (s *Stack) Close() error {
	s.once.Do(func() {
		s.mu.Lock()
		s.closing = true
		s.mu.Unlock()
		s.cancel()
		_ = s.dev.Close()
		s.link.Close()
		s.ip.Close()
	})
	s.loops.Wait()
	s.flows.Wait()
	s.ip.Wait()
	return nil
}
