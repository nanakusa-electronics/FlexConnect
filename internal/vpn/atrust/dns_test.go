package atrust

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"flexconnect/internal/types"
	geektrust "github.com/ShanghaitechGeekPie/geektrust/client"
	"golang.org/x/net/dns/dnsmessage"
)

type lookupTunnel struct {
	echoTunnel
	address string
	err     error
}

func (d *lookupTunnel) LookupContextHost(context.Context, string) ([]string, error) {
	return []string{d.address}, d.err
}
func dnsQuestion(t *testing.T, name string) []byte {
	t.Helper()
	data, err := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 42, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name + "."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func dnsIPv4(t *testing.T, answer []byte) netip.Addr {
	t.Helper()
	var msg dnsmessage.Message
	if err := msg.Unpack(answer); err != nil {
		t.Fatal(err)
	}
	if msg.ID != 42 || !msg.Response || !msg.RecursionDesired || len(msg.Answers) != 1 {
		t.Fatalf("invalid DNS answer: %+v", msg)
	}
	return netip.AddrFrom4(msg.Answers[0].Body.(*dnsmessage.AResource).A)
}
func TestDNSPreservesHyphenatedDomain(t *testing.T) {
	mapper := newDNSMapper(geektrust.Info{Resources: []geektrust.Resource{{Address: "data-center.example.test"}, {Address: "10.1.0.1-10.1.0.8"}}}, nil)
	answer, err := mapper.answer(context.Background(), dnsQuestion(t, "data-center.example.test"))
	if err != nil {
		t.Fatal(err)
	}
	ip := dnsIPv4(t, answer)
	if !netip.MustParsePrefix("198.18.0.0/15").Contains(ip) || len(mapper.domains) != 1 {
		t.Fatal("domain or address range misclassified")
	}
}
func TestDNSTCPFramingAndConnectionReuse(t *testing.T) {
	mapper := newDNSMapper(geektrust.Info{Resources: []geektrust.Resource{{Address: "service.example.test"}}}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dialer := flowDialer{ctx: ctx, dns: mapper}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(fakeDNS.String(), "53"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	query := dnsQuestion(t, "service.example.test")
	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame, uint16(len(query)))
	copy(frame[2:], query)
	for range 2 {
		// A TCP read may split either the length header or the DNS payload.
		for _, part := range [][]byte{frame[:1], frame[1:3], frame[3:]} {
			if _, err := conn.Write(part); err != nil {
				t.Fatal(err)
			}
		}
		var size [2]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			t.Fatal(err)
		}
		answer := make([]byte, int(binary.BigEndian.Uint16(size[:])))
		if _, err := io.ReadFull(conn, answer); err != nil {
			t.Fatal(err)
		}
		ip := dnsIPv4(t, answer)
		if name := mapper.reserveIP(ip); name != "service.example.test" {
			t.Fatalf("mapping=%q", name)
		}
		mapper.releaseIP(ip)
	}
	cancel()
	if _, err := conn.Read(make([]byte, 2)); err == nil {
		t.Fatal("DNS stream survived cancellation")
	}
}
func TestDNSAppliesRealAddressRouteChoices(t *testing.T) {
	for _, tt := range []struct {
		name     string
		profile  types.Profile
		server   []string
		wantFake bool
	}{
		{name: "exclude", profile: types.Profile{AcceptServerRoutes: true, CustomExclude: []string{"10.0.0.0/8"}}},
		{name: "explicit routes only", profile: types.Profile{AcceptServerRoutes: false, CustomInclude: []string{"192.0.2.0/24"}}},
		{name: "local more specific include", profile: types.Profile{AcceptServerRoutes: true, CustomExclude: []string{"10.0.0.0/8"}, CustomInclude: []string{"10.1.0.0/16"}}, wantFake: true},
		{name: "server more specific include", profile: types.Profile{AcceptServerRoutes: true, CustomExclude: []string{"10.0.0.0/8"}}, server: []string{"10.1.0.0/16"}, wantFake: true},
		{name: "equal prefix exclude wins", profile: types.Profile{AcceptServerRoutes: true, CustomExclude: []string{"10.1.0.0/16"}}, server: []string{"10.1.0.0/16"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			upstream := &lookupTunnel{address: "10.1.0.2"}
			mapper := newDNSMapper(geektrust.Info{Resources: []geektrust.Resource{{Address: "service.example.test"}}}, upstream)
			mapper.policy = newRoutePolicy(tt.profile, tt.server)
			answer, err := mapper.answer(context.Background(), dnsQuestion(t, "service.example.test"))
			if err != nil {
				t.Fatal(err)
			}
			ip := dnsIPv4(t, answer)
			if got := netip.MustParsePrefix("198.18.0.0/15").Contains(ip); got != tt.wantFake {
				t.Fatalf("fake=%v want %v", got, tt.wantFake)
			}
			if !tt.wantFake && ip != netip.MustParseAddr("10.1.0.2") {
				t.Fatal("excluded address not returned for OS routing")
			}
			if got := mapper.policy.check(netip.MustParseAddr("10.1.0.2")) == nil; got != tt.wantFake {
				t.Fatal("dial-time policy disagrees with DNS")
			}
		})
	}
}
func TestDNSTransientFailureIsNotNXDomain(t *testing.T) {
	mapper := newDNSMapper(geektrust.Info{}, &lookupTunnel{err: context.DeadlineExceeded})
	answer, err := mapper.answer(context.Background(), dnsQuestion(t, "example.test"))
	if err != nil {
		t.Fatal(err)
	}
	var msg dnsmessage.Message
	if err := msg.Unpack(answer); err != nil {
		t.Fatal(err)
	}
	if msg.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("rcode=%v", msg.RCode)
	}
}
func TestDNSWriteDeadlineDoesNotChangeReadDeadline(t *testing.T) {
	mapper := newDNSMapper(geektrust.Info{Resources: []geektrust.Resource{{Address: "service.example.test"}}}, nil)
	conn := newDNSConn(context.Background(), mapper)
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write(dnsQuestion(t, "service.example.test")); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetWriteDeadline(time.Now().Add(-time.Second))
	if _, err := conn.Read(make([]byte, 512)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(dnsQuestion(t, "service.example.test")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired write: %v", err)
	}
}
