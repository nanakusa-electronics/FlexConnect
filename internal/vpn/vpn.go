package vpn

import (
	"context"
	"errors"
	"net"
	"time"

	"flexconnect/internal/types"
)

type ConnectError struct {
	Stage     string
	Retryable bool
	Err       error
}

func (e *ConnectError) Error() string { return e.Stage + ": " + e.Err.Error() }
func (e *ConnectError) Unwrap() error { return e.Err }

func WrapConnectError(stage string, retryable bool, err error) error {
	if err == nil {
		return nil
	}
	return &ConnectError{Stage: stage, Retryable: retryable, Err: err}
}

func IsRetryable(err error) bool {
	var connectErr *ConnectError
	return errors.As(err, &connectErr) && connectErr.Retryable
}

type Event struct {
	Type         string
	ConnectionID string
	AttemptID    string
	ProfileID    string
	OwnerID      string
	Session      *types.SessionInfo
	Err          error
	Close        *DisconnectInfo
	Network      *NetworkChange
	Component    string
}

type AuthenticationPrompt struct {
	Method    string
	ExpiresAt time.Time
}

type AuthenticationHandler func(context.Context, AuthenticationPrompt) (string, error)

type ConnectRequest struct {
	Authenticate AuthenticationHandler
	Profile      types.Profile
	Password     string
	AttemptID    string
	ConnectionID string
	OwnerID      string
}

type NetworkSnapshot struct {
	InterfaceName    string
	InterfaceIndex   int
	LocalIPv4        string
	Gateway          string
	GatewayInterface int
	RouteMetric      int
	Generation       uint64
}

type NetworkChange struct {
	Before         NetworkSnapshot
	After          NetworkSnapshot
	Reasons        []string
	RebindRequired bool
	Error          string
}

type DisconnectInfo struct {
	Code            string
	Transport       string
	Error           string
	Time            string
	TransportFaults []TransportFault
}

type TransportFault struct {
	Code      string
	Transport string
	Error     string
	Time      string
}

type Backend interface {
	Connect(context.Context, ConnectRequest) (*types.SessionInfo, error)
	Disconnect(context.Context) error
	Close(context.Context) error
	SessionInfo() *types.SessionInfo
	Traffic() *types.TrafficStats
	ReadServerConfig() map[string]any
	Events() <-chan Event
	TunnelDialer(context.Context) (TunnelDialer, error)
}

type TunnelDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
	LookupContextHost(context.Context, string) ([]string, error)
}
