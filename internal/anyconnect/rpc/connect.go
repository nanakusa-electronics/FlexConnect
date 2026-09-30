package rpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"flexconnect/internal/anyconnect/auth"
	"flexconnect/internal/anyconnect/base"
	"flexconnect/internal/anyconnect/session"
	acvpn "flexconnect/internal/anyconnect/tunnel"
	"flexconnect/internal/osnet"
	"flexconnect/internal/vpn"
)

// disconnectDrainTimeout bounds how long a disconnect waits for the tunnel
// controller to stop its packet workers before handing control back. A new
// connection reuses the same TUN device name, so a slow teardown must not
// block the control plane indefinitely.
const disconnectDrainTimeout = 15 * time.Second

// Connection owns the authentication and VPN session state for one connect
// attempt.
type Connection struct {
	Auth    *auth.Client
	Session *session.Session
}

func NewConnection(profile auth.Profile) *Connection {
	return &Connection{Auth: auth.NewClient(profile, base.Interface{}), Session: &session.Session{}}
}

func (c *Connection) Connect(ctx context.Context) error {
	if c == nil || c.Auth == nil || c.Session == nil {
		return fmt.Errorf("invalid VPN connection")
	}
	if ctx == nil {
		return fmt.Errorf("nil VPN connection context")
	}
	if err := refreshConnectionInterface(c, ctx); err != nil {
		return vpn.WrapConnectError("underlay", true, err)
	}
	if strings.Contains(c.Auth.Prof.Host, ":") {
		c.Auth.Prof.HostWithPort = c.Auth.Prof.Host
	} else {
		c.Auth.Prof.HostWithPort = c.Auth.Prof.Host + ":443"
	}
	if err := c.Auth.InitAuth(nil); err != nil {
		return vpn.WrapConnectError("tls", isTransientNetworkError(err), err)
	}
	if err := c.Auth.PasswordAuth(c.Session); err != nil {
		_ = c.Auth.Close()
		return vpn.WrapConnectError("authentication", false, err)
	}
	if err := acvpn.SetupTunnelWithClient(c.Auth, c.Session); err != nil {
		_ = c.Auth.Close()
		return vpn.WrapConnectError("tunnel", isTransientNetworkError(err), err)
	}
	return nil
}

func isTransientNetworkError(err error) bool {
	var verificationErr *tls.CertificateVerificationError
	var hostnameErr x509.HostnameError
	var authorityErr x509.UnknownAuthorityError
	var invalidErr x509.CertificateInvalidError
	if errors.As(err, &verificationErr) || errors.As(err, &hostnameErr) || errors.As(err, &authorityErr) || errors.As(err, &invalidErr) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr)
}

func (c *Connection) Disconnect(ctx context.Context) error {
	if c == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	c.Session.ActiveClose = true
	var first error
	if c.Auth != nil {
		if err := c.Auth.Close(); err != nil {
			first = err
		}
	}
	if cSess := c.Session.DrainSession(); cSess != nil {
		cSess.RecordClose("local_requested", "local", nil)
		cSess.Close()
		// The tunnel controller owns the TUN device and network manager once
		// it has started; wait for its ordered drain instead of closing the
		// manager out from under the packet workers. When no controller took
		// ownership, fall back to closing the manager directly.
		if done := cSess.TunnelDone(); done != nil {
			timer := time.NewTimer(disconnectDrainTimeout)
			defer timer.Stop()
			select {
			case <-done:
				if err := cSess.TunnelError(); err != nil && first == nil {
					first = err
				}
			case <-ctx.Done():
				if first == nil {
					first = ctx.Err()
				}
			case <-timer.C:
				base.Warn("tunnel drain timed out during disconnect")
				if first == nil {
					first = errors.New("VPN tunnel drain timed out")
				}
			}
		} else if cSess.NetworkManager != nil {
			if err := cSess.NetworkManager.Close(ctx); err != nil && first == nil {
				first = err
			}
		}
	}
	return first
}

func refreshConnectionInterface(c *Connection, ctx context.Context) error {
	info, err := osnet.GetLocalInterface(ctx)
	if err != nil {
		return err
	}
	c.Auth.LocalInterface = base.Interface{Name: info.Name, Ip4: info.IP4, Mac: info.MAC, Gateway: info.Gateway}
	return nil
}
