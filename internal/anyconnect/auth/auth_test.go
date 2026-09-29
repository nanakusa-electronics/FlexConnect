package auth

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"flexconnect/internal/anyconnect/base"
)

func TestCloseAfterTunnelClosesTLSConnection(t *testing.T) {
	local, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	conn := tls.Client(local, &tls.Config{})
	t.Cleanup(func() { _ = conn.Close() })
	client := &Client{Conn: conn, BufR: bufio.NewReader(conn)}
	// A tunnel worker closes TLS before the reconnect path closes the client.
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close after transport shutdown: %v", err)
	}
	if client.Conn != nil || client.BufR != nil {
		t.Fatal("Close retained transport references")
	}
	if err := client.Close(); err != nil {
		t.Fatalf("repeated Close: %v", err)
	}
}

type closeErrorConn struct {
	net.Conn
	err error
}

func (c closeErrorConn) Close() error {
	_ = c.Conn.Close()
	return c.err
}

func TestCloseClassifiesTransportError(t *testing.T) {
	unexpected := errors.New("transport cleanup failed")
	for _, tc := range []struct {
		name string
		err  error
		want error
	}{
		{name: "open connection"},
		{name: "wrapped closed connection", err: fmt.Errorf("close transport: %w", net.ErrClosed)},
		{name: "unexpected failure", err: unexpected, want: unexpected},
	} {
		t.Run(tc.name, func(t *testing.T) {
			local, peer := net.Pipe()
			t.Cleanup(func() { _ = local.Close(); _ = peer.Close() })
			client := &Client{Conn: tls.Client(closeErrorConn{Conn: local, err: tc.err}, &tls.Config{})}
			if err := client.Close(); !errors.Is(err, tc.want) {
				t.Fatalf("Close error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestRedactAuthBodyRemovesCredentials(t *testing.T) {
	body := `<config-auth><session-token>token-value</session-token><auth><password>password-value</password></auth><message>ok</message></config-auth>`
	got := redactAuthBody(body)
	for _, secret := range []string{"token-value", "password-value", "<session-token>", "<password>"} {
		if strings.Contains(got, secret) {
			t.Fatalf("redacted body still contains %q: %s", secret, got)
		}
	}
	if !strings.Contains(got, "<message>ok</message>") {
		t.Fatalf("non-sensitive response content was removed: %s", got)
	}
}

func TestConfiguredLocalAddrUsesValidatedIPv4(t *testing.T) {
	client := &Client{LocalInterface: base.Interface{Ip4: "192.0.2.10"}}
	addr, ok := client.configuredLocalAddr().(*net.TCPAddr)
	if !ok || !addr.IP.Equal(net.ParseIP("192.0.2.10")) {
		t.Fatalf("configured local address = %#v", addr)
	}

	client.LocalInterface.Ip4 = "not-an-ip"
	if client.configuredLocalAddr() != nil {
		t.Fatal("invalid configured local address was accepted")
	}
}
