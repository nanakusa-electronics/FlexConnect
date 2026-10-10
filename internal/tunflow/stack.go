// Package tunflow converts IPv4 packets on a system TUN into authorized TCP
// and UDP connections. It does not choose routes or modify system networking.
package tunflow

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"flexconnect/internal/tunio"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv4"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/udp"
	"github.com/metacubex/gvisor/pkg/waiter"
	"github.com/tailscale/wireguard-go/tun"
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

func (s *Stack) acceptUDP(req *udp.ForwarderRequest) bool {
	defer req.Packet().DecRef()
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return true
	}
	// Register before dialing so subsequent datagrams find this endpoint
	// instead of starting another dial and competing for the same flow.
	var wq waiter.Queue
	ep, terr := req.CreateEndpoint(&wq)
	if terr != nil {
		s.mu.Unlock()
		return true
	}
	local := gonet.NewUDPConn(&wq, ep)
	s.flows.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.flows.Done()
		defer local.Close()
		ctx, cancel := context.WithTimeout(s.ctx, 15*time.Second)
		remote, err := s.dialer.DialContext(ctx, "udp", target(req.ID()))
		cancel()
		if err != nil {
			return
		}
		s.relayUDP(local, remote)
	}()
	return true
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

// Datagram relays perform one Write per Read, including an empty datagram.
// io.Copy is stream-oriented and drops successful zero-byte reads.
func (s *Stack) relayUDP(local, remote net.Conn) {
	defer local.Close()
	defer remote.Close()
	stop := context.AfterFunc(s.ctx, func() { local.Close(); remote.Close() })
	defer stop()
	done := make(chan struct{}, 2)
	copyDatagrams := func(dst, src net.Conn) {
		defer func() { done <- struct{}{} }()
		data := make([]byte, 65535)
		for {
			if err := src.SetReadDeadline(time.Now().Add(2 * time.Minute)); err != nil {
				return
			}
			n, err := src.Read(data)
			if err != nil {
				return
			}
			if err := dst.SetWriteDeadline(time.Now().Add(15 * time.Second)); err != nil {
				return
			}
			if written, err := dst.Write(data[:n]); err != nil || written != n {
				return
			}
		}
	}
	go copyDatagrams(remote, local)
	go copyDatagrams(local, remote)
	<-done
	local.Close()
	remote.Close()
	<-done
}

func (s *Stack) readTUN(mtu int) {
	defer s.loops.Done()
	reader := tunio.NewReader(s.dev, mtu+64)
	for {
		packets, err := reader.Read()
		if err != nil {
			s.report(err)
			return
		}
		for _, packet := range packets {
			s.handlePacket(packet)
		}
	}
}

func (s *Stack) handlePacket(packet []byte) {
	if s.ctx.Err() != nil {
		return
	}
	if len(packet) < header.IPv4MinimumSize {
		return
	}
	if packet[0]>>4 != 4 {
		return
	}
	s.sent.Add(uint64(len(packet)))
	if packet[9] == 1 {
		if s.packets != nil && len(packet) >= int(packet[0]&15)*4+8 && packet[int(packet[0]&15)*4] == 8 {
			s.mu.Lock()
			if !s.closing {
				s.flows.Add(1)
				go s.exchangeICMP(append([]byte(nil), packet...))
			}
			s.mu.Unlock()
		}
		return
	}
	p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), packet...))})
	s.link.InjectInbound(ipv4.ProtocolNumber, p)
	p.DecRef()
}

func (s *Stack) exchangeICMP(packet []byte) {
	defer s.flows.Done()
	ctx, cancel := context.WithTimeout(s.ctx, 8*time.Second)
	defer cancel()
	reply, err := s.packets.ExchangePacket(ctx, packet)
	if err != nil || len(reply) < header.IPv4MinimumSize || reply[0]>>4 != 4 {
		return
	}
	s.writeMu.Lock()
	err = tunio.Write(s.dev, reply)
	s.writeMu.Unlock()
	if err != nil {
		s.report(err)
	} else {
		s.received.Add(uint64(len(reply)))
	}
}

func (s *Stack) writeTUN() {
	defer s.loops.Done()
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
		s.writeMu.Lock()
		err := tunio.Write(s.dev, packet)
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
