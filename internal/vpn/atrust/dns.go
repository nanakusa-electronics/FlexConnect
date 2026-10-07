package atrust

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"flexconnect/internal/vpn"
	geektrust "github.com/ShanghaitechGeekPie/geektrust/client"
	"golang.org/x/net/dns/dnsmessage"
)

var fakeDNS = netip.MustParseAddr("198.19.255.254")
var fakeLocal = netip.MustParseAddr("198.19.255.253")

type dnsMapper struct {
	mu      sync.Mutex
	next    uint32
	byName  map[string]netip.Addr
	byIP    map[netip.Addr]string
	leases  map[netip.Addr]time.Time
	active  map[netip.Addr]int
	policy  *routePolicy
	domains []string
	dialer  vpn.TunnelDialer
}

func newDNSMapper(info geektrust.Info, dialer vpn.TunnelDialer) *dnsMapper {
	m := &dnsMapper{byName: make(map[string]netip.Addr), byIP: make(map[netip.Addr]string), leases: make(map[netip.Addr]time.Time), active: make(map[netip.Addr]int), dialer: dialer}
	for _, resource := range info.Resources {
		name := strings.ToLower(strings.TrimSuffix(resource.Address, "."))
		if strings.HasPrefix(name, "*.") || strings.Contains(name, ".") && !strings.Contains(name, "/") && len(resourcePrefixes(name)) == 0 {
			if _, err := netip.ParseAddr(name); err != nil {
				m.domains = append(m.domains, name)
			}
		}
	}
	return m
}

func (m *dnsMapper) authorizedDomain(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for _, rule := range m.domains {
		if rule == name || strings.HasPrefix(rule, "*.") && strings.HasSuffix(name, rule[1:]) && name != rule[2:] {
			return true
		}
	}
	return false
}

func (m *dnsMapper) allocate(name string) (netip.Addr, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if existing, ok := m.byName[name]; ok {
		m.leases[existing] = time.Now().Add(30 * time.Second)
		return existing, nil
	}
	// 198.18.0.0/15 is reserved for local Fake-IP. The last two addresses
	// are kept for the TUN address and DNS endpoint.
	if m.next >= 131066 {
		now := time.Now()
		for ip, expiry := range m.leases {
			if now.Before(expiry) || m.active[ip] != 0 {
				continue
			}
			delete(m.byName, m.byIP[ip])
			m.byName[name], m.byIP[ip], m.leases[ip] = ip, name, now.Add(30*time.Second)
			return ip, nil
		}
		return netip.Addr{}, errors.New("Fake-IP address pool exhausted")
	}
	m.next++
	v := m.next
	ip := netip.AddrFrom4([4]byte{198, byte(18 + v/65536), byte(v / 256), byte(v)})
	m.byName[name], m.byIP[ip] = ip, name
	m.leases[ip] = time.Now().Add(30 * time.Second)
	return ip, nil
}

func (m *dnsMapper) reserveIP(ip netip.Addr) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	name := m.byIP[ip]
	if name != "" {
		m.active[ip]++
	}
	return name
}

func (m *dnsMapper) releaseIP(ip netip.Addr) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active[ip] > 1 {
		m.active[ip]--
	} else {
		delete(m.active, ip)
	}
}

type flowDialer struct {
	ctx    context.Context
	client vpn.TunnelDialer
	dns    *dnsMapper
}

func (d flowDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return nil, err
	}
	if ip == fakeDNS && port == "53" {
		switch network {
		case "udp":
			return newDNSConn(d.ctx, d.dns), nil
		case "tcp":
			return newDNSTCPConn(d.ctx, d.dns), nil
		}
	}
	if name := d.dns.reserveIP(ip); name != "" {
		host = name
		conn, err := d.client.DialContext(ctx, network, net.JoinHostPort(host, port))
		if err != nil {
			d.dns.releaseIP(ip)
			return nil, err
		}
		return &leasedConn{Conn: conn, release: func() { d.dns.releaseIP(ip) }}, nil
	}
	if netip.MustParsePrefix("198.18.0.0/15").Contains(ip) {
		return nil, errors.New("unknown Fake-IP destination")
	}
	return d.client.DialContext(ctx, network, net.JoinHostPort(host, port))
}

type leasedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *leasedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

func (m *dnsMapper) answer(ctx context.Context, query []byte) ([]byte, error) {
	var request dnsmessage.Message
	if err := request.Unpack(query); err != nil {
		return nil, err
	}
	response := dnsmessage.Message{Header: dnsmessage.Header{ID: request.Header.ID, Response: true, RecursionDesired: request.RecursionDesired, RecursionAvailable: true}, Questions: request.Questions}
	if len(request.Questions) != 1 {
		response.RCode = dnsmessage.RCodeFormatError
		return response.Pack()
	}
	question := request.Questions[0]
	name := strings.TrimSuffix(question.Name.String(), ".")
	if question.Type != dnsmessage.TypeA || question.Class != dnsmessage.ClassINET {
		return response.Pack()
	}
	var ip netip.Addr
	useFake := m.authorizedDomain(name)
	// Decide using real addresses when local route choices may bypass the VPN.
	if !useFake || (m.policy != nil && (!m.policy.acceptServer || len(m.policy.exclude) > 0)) {
		addrs, err := m.dialer.LookupContextHost(ctx, name)
		if err != nil {
			response.RCode = dnsmessage.RCodeServerFailure
			return response.Pack()
		}
		for _, addr := range addrs {
			if parsed, err := netip.ParseAddr(addr); err == nil && parsed.Is4() {
				ip = parsed
				break
			}
		}
		if !ip.IsValid() {
			return response.Pack()
		}
		if useFake && m.policy.check(ip) != nil {
			useFake = false
		}
	}
	if useFake {
		var err error
		ip, err = m.allocate(name)
		if err != nil {
			response.RCode = dnsmessage.RCodeServerFailure
			return response.Pack()
		}
	}
	response.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.AResource{A: ip.As4()}}}
	return response.Pack()
}

type dnsConn struct {
	ctx           context.Context
	mapper        *dnsMapper
	mu            sync.Mutex
	closed        bool
	readDeadline  time.Time
	writeDeadline time.Time
	cancel        context.CancelFunc
	answers       chan []byte
	done          chan struct{}
}

func newDNSConn(ctx context.Context, m *dnsMapper) *dnsConn {
	ctx, cancel := context.WithCancel(ctx)
	return &dnsConn{ctx: ctx, cancel: cancel, mapper: m, answers: make(chan []byte, 8), done: make(chan struct{})}
}
func (c *dnsConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	closed, deadline := c.closed, c.writeDeadline
	c.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	expires := time.Now().Add(5 * time.Second)
	if !deadline.IsZero() && deadline.Before(expires) {
		expires = deadline
	}
	ctx, cancel := context.WithDeadline(c.ctx, expires)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	response, err := c.mapper.answer(ctx, p)
	if err != nil {
		return 0, err
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	select {
	case c.answers <- response:
		return len(p), nil
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-c.done:
		return 0, net.ErrClosed
	}
}
func (c *dnsConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	closed, deadline := c.closed, c.readDeadline
	c.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	var timer <-chan time.Time
	if !deadline.IsZero() {
		duration := time.Until(deadline)
		if duration <= 0 {
			return 0, osDeadline{}
		}
		timer = time.After(duration)
	}
	select {
	case response := <-c.answers:
		if len(response) > len(p) {
			return 0, io.ErrShortBuffer
		}
		return copy(p, response), nil
	case <-timer:
		return 0, osDeadline{}
	case <-c.ctx.Done():
		return 0, c.ctx.Err()
	case <-c.done:
		return 0, net.ErrClosed
	}
}
func (c *dnsConn) Close() error {
	c.mu.Lock()
	if !c.closed {
		c.closed = true
		close(c.done)
		c.cancel()
	}
	c.mu.Unlock()
	return nil
}
func (c *dnsConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IP(fakeLocal.AsSlice()), Port: 53}
}
func (c *dnsConn) RemoteAddr() net.Addr { return &net.UDPAddr{IP: net.IP(fakeDNS.AsSlice()), Port: 53} }
func (c *dnsConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline, c.writeDeadline = t, t
	c.mu.Unlock()
	return nil
}
func (c *dnsConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	return nil
}
func (c *dnsConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = t
	return nil
}

type osDeadline struct{}

func (osDeadline) Error() string   { return "i/o timeout" }
func (osDeadline) Timeout() bool   { return true }
func (osDeadline) Temporary() bool { return true }

func newDNSTCPConn(ctx context.Context, mapper *dnsMapper) net.Conn {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		stop := context.AfterFunc(ctx, func() { server.Close() })
		defer stop()
		for {
			_ = server.SetReadDeadline(time.Now().Add(2 * time.Minute))
			var size [2]byte
			if _, err := io.ReadFull(server, size[:]); err != nil {
				return
			}
			n := int(binary.BigEndian.Uint16(size[:]))
			if n < 12 {
				return
			}
			query := make([]byte, n)
			if _, err := io.ReadFull(server, query); err != nil {
				return
			}
			lookup, cancel := context.WithTimeout(ctx, 5*time.Second)
			answer, err := mapper.answer(lookup, query)
			cancel()
			if err != nil || len(answer) > 65535 {
				return
			}
			frame := make([]byte, 2+len(answer))
			binary.BigEndian.PutUint16(frame[:2], uint16(len(answer)))
			copy(frame[2:], answer)
			_ = server.SetWriteDeadline(time.Now().Add(15 * time.Second))
			if _, err := server.Write(frame); err != nil {
				return
			}
		}
	}()
	return client
}
