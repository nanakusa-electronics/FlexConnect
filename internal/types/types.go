package types

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"time"
)

type State string

type ProfileScope string
type Provider string
type AuthMethod string

const (
	ProviderAnyConnect      Provider   = "anyconnect"
	ProviderATrust          Provider   = "atrust"
	AuthPassword            AuthMethod = "password"
	AuthECNUPasskey         AuthMethod = "ecnu_passkey"
	AuthShanghaiTechPasskey AuthMethod = "shanghaitech_passkey"
)

const (
	ProfileScopeUser    ProfileScope = "user"
	ProfileScopeMachine ProfileScope = "machine"
)

const (
	StateDisconnected State = "Disconnected"
	StateConnecting   State = "Connecting"
	StateConnected    State = "Connected"
	StateReconnecting State = "Reconnecting"
	StateError        State = "Error"
)

type RouteSpec struct {
	Destination string `json:"destination"`
	Action      string `json:"action"`
	Metric      int    `json:"metric"`
	Source      string `json:"source"`
	Enabled     bool   `json:"enabled"`
}

type Profile struct {
	ID                 string       `json:"id"`
	Provider           Provider     `json:"provider"`
	AuthMethod         AuthMethod   `json:"auth_method"`
	LoginDomain        string       `json:"login_domain,omitempty"`
	Name               string       `json:"name"`
	ServerURL          string       `json:"server_url"`
	Username           string       `json:"username"`
	SecretRef          string       `json:"-"`
	Scope              ProfileScope `json:"scope"`
	OwnerID            string       `json:"-"`
	Group              string       `json:"group"`
	AcceptServerRoutes bool         `json:"accept_server_routes"`
	AutoReconnect      *bool        `json:"auto_reconnect"`
	ApplyDNS           *bool        `json:"apply_dns"`
	CustomInclude      []string     `json:"custom_include_routes"`
	CustomExclude      []string     `json:"custom_exclude_routes"`
	DNSOverrides       []string     `json:"dns_overrides"`
	SOCKS5Enabled      bool         `json:"socks5_enabled"`
	SOCKS5Listen       string       `json:"socks5_listen"`
	MTU                int          `json:"mtu"`
	CreatedAt          string       `json:"created_at"`
	UpdatedAt          string       `json:"updated_at"`
}

type ProfileCreateRequest struct {
	Provider           Provider     `json:"provider"`
	AuthMethod         AuthMethod   `json:"auth_method"`
	LoginDomain        string       `json:"login_domain,omitempty"`
	Credential         []byte       `json:"credential,omitempty"`
	Name               string       `json:"name"`
	ServerURL          string       `json:"server_url"`
	Username           string       `json:"username"`
	Password           string       `json:"password,omitempty"`
	Group              string       `json:"group,omitempty"`
	Scope              ProfileScope `json:"scope"`
	AcceptServerRoutes *bool        `json:"accept_server_routes,omitempty"`
	AutoReconnect      *bool        `json:"auto_reconnect,omitempty"`
	ApplyDNS           *bool        `json:"apply_dns,omitempty"`
	CustomInclude      []string     `json:"custom_include_routes,omitempty"`
	CustomExclude      []string     `json:"custom_exclude_routes,omitempty"`
	DNSOverrides       []string     `json:"dns_overrides,omitempty"`
	SOCKS5Enabled      bool         `json:"socks5_enabled,omitempty"`
	SOCKS5Listen       string       `json:"socks5_listen,omitempty"`
	MTU                int          `json:"mtu,omitempty"`
}

type ProfileUpdateRequest struct {
	Provider           *Provider   `json:"provider,omitempty"`
	AuthMethod         *AuthMethod `json:"auth_method,omitempty"`
	LoginDomain        *string     `json:"login_domain,omitempty"`
	Credential         []byte      `json:"credential,omitempty"`
	Name               *string     `json:"name,omitempty"`
	ServerURL          *string     `json:"server_url,omitempty"`
	Username           *string     `json:"username,omitempty"`
	Group              *string     `json:"group,omitempty"`
	AcceptServerRoutes *bool       `json:"accept_server_routes,omitempty"`
	AutoReconnect      *bool       `json:"auto_reconnect,omitempty"`
	ApplyDNS           *bool       `json:"apply_dns,omitempty"`
	CustomInclude      []string    `json:"custom_include_routes,omitempty"`
	CustomExclude      []string    `json:"custom_exclude_routes,omitempty"`
	DNSOverrides       []string    `json:"dns_overrides,omitempty"`
	SOCKS5Enabled      *bool       `json:"socks5_enabled,omitempty"`
	SOCKS5Listen       *string     `json:"socks5_listen,omitempty"`
	MTU                *int        `json:"mtu,omitempty"`
	Password           *string     `json:"password,omitempty"`
}

type SessionInfo struct {
	ConnectionID  string        `json:"connection_id,omitempty"`
	ServerAddress string        `json:"server_address"`
	LocalAddress  string        `json:"local_address,omitempty"`
	RemoteAddress string        `json:"remote_address,omitempty"`
	Hostname      string        `json:"hostname"`
	TUNName       string        `json:"tun_name"`
	VPNAddress    string        `json:"vpn_address"`
	VPNMask       string        `json:"vpn_mask"`
	DNS           []string      `json:"dns"`
	MTU           int           `json:"mtu"`
	SplitInclude  []string      `json:"split_include"`
	SplitExclude  []string      `json:"split_exclude"`
	TLSCipher     string        `json:"tls_cipher,omitempty"`
	DTLSCipher    string        `json:"dtls_cipher,omitempty"`
	Underlay      *UnderlayInfo `json:"underlay,omitempty"`
}

type UnderlayInfo struct {
	InterfaceName    string `json:"interface_name"`
	InterfaceIndex   int    `json:"interface_index"`
	LocalIPv4        string `json:"local_ipv4"`
	Gateway          string `json:"gateway"`
	GatewayInterface int    `json:"gateway_interface"`
	RouteMetric      int    `json:"route_metric"`
	Generation       uint64 `json:"generation"`
}

type TunnelRuntime struct {
	State                 string `json:"state"`
	TLSState              string `json:"tls_state"`
	DTLSState             string `json:"dtls_state"`
	TUNReads              uint64 `json:"tun_reads"`
	TUNWrites             uint64 `json:"tun_writes"`
	TUNReadErrors         uint64 `json:"tun_read_errors"`
	TUNWriteErrors        uint64 `json:"tun_write_errors"`
	DPDSent               uint64 `json:"dpd_sent"`
	DPDResponses          uint64 `json:"dpd_responses"`
	QueueDrops            uint64 `json:"queue_drops"`
	LastNetworkChange     string `json:"last_network_change,omitempty"`
	LastNetworkChangeInfo string `json:"last_network_change_info,omitempty"`
}

type RuntimeDiagnostics struct {
	Underlay *UnderlayInfo  `json:"underlay,omitempty"`
	Tunnel   *TunnelRuntime `json:"tunnel,omitempty"`
}

type NetworkChange struct {
	Before         *UnderlayInfo `json:"before,omitempty"`
	After          *UnderlayInfo `json:"after,omitempty"`
	Reasons        []string      `json:"reasons,omitempty"`
	RebindRequired bool          `json:"rebind_required"`
	Error          string        `json:"error,omitempty"`
	Time           string        `json:"time"`
}

// ConnectionEvent is a bounded, sanitized lifecycle record for one VPN
// connection attempt or session. It is intentionally descriptive rather than
// exposing backend error values or credential-bearing data.
type ConnectionEvent struct {
	ID              string            `json:"id"`
	ConnectionID    string            `json:"connection_id,omitempty"`
	ProfileID       string            `json:"profile_id"`
	Kind            string            `json:"kind"`
	ReasonCode      string            `json:"reason_code,omitempty"`
	Transport       string            `json:"transport,omitempty"`
	Error           string            `json:"error,omitempty"`
	Attempt         int               `json:"attempt,omitempty"`
	NextRetryAt     string            `json:"next_retry_at,omitempty"`
	SessionStarted  string            `json:"session_started,omitempty"`
	SessionEnded    string            `json:"session_ended,omitempty"`
	DurationMS      int64             `json:"duration_ms,omitempty"`
	Time            string            `json:"time"`
	TransportFaults []ConnectionFault `json:"transport_faults,omitempty"`
}

type ConnectionFault struct {
	Code      string `json:"code"`
	Transport string `json:"transport"`
	Error     string `json:"error,omitempty"`
	Time      string `json:"time"`
}

type ReconnectSnapshot struct {
	Active      bool   `json:"active"`
	ProfileID   string `json:"profile_id,omitempty"`
	Attempt     int    `json:"attempt,omitempty"`
	NextRetryAt string `json:"next_retry_at,omitempty"`
	LifecycleID string `json:"lifecycle_id,omitempty"`
}

type TrafficStats struct {
	BytesSent     uint64 `json:"bytes_sent"`
	BytesReceived uint64 `json:"bytes_received"`
}

type TrafficSnapshot struct {
	Connected              bool    `json:"connected"`
	BytesSent              uint64  `json:"bytes_sent"`
	BytesReceived          uint64  `json:"bytes_received"`
	BytesSentPerSecond     float64 `json:"bytes_sent_per_second"`
	BytesReceivedPerSecond float64 `json:"bytes_received_per_second"`
	SampledAt              string  `json:"sampled_at"`
}

type Status struct {
	State              State        `json:"state"`
	CurrentProfileID   string       `json:"-"`
	SelectedProfileID  string       `json:"selected_profile_id,omitempty"`
	ConnectedProfileID string       `json:"connected_profile_id"`
	ControlMode        string       `json:"control_mode"`
	AttemptID          string       `json:"attempt_id,omitempty"`
	Operation          *Operation   `json:"operation,omitempty"`
	Session            *SessionInfo `json:"session,omitempty"`
	EffectiveRoutes    []RouteSpec  `json:"effective_routes,omitempty"`
	LastError          string       `json:"last_error,omitempty"`
	SOCKS5Enabled      bool         `json:"socks5_enabled,omitempty"`
	SOCKS5Listen       string       `json:"socks5_listen,omitempty"`
	UpdatedAt          string       `json:"updated_at"`
}

type Health struct {
	Status     string `json:"status"`
	Version    string `json:"version"`
	APIVersion string `json:"api_version"`
}

type LiveStatus struct {
	Status       string   `json:"status"`
	Version      string   `json:"version"`
	APIMajor     int      `json:"api_major"`
	Capabilities []string `json:"capabilities"`
}

type ComponentStatus struct {
	Name    string `json:"name"`
	Ready   bool   `json:"ready"`
	Message string `json:"message,omitempty"`
}

type ReadyStatus struct {
	Ready      bool              `json:"ready"`
	Components []ComponentStatus `json:"components"`
}

type OperationState string

const (
	OperationRunning   OperationState = "running"
	OperationSucceeded OperationState = "succeeded"
	OperationFailed    OperationState = "failed"
)

type Operation struct {
	ID        string         `json:"id"`
	Kind      string         `json:"kind"`
	ProfileID string         `json:"profile_id,omitempty"`
	AttemptID string         `json:"attempt_id,omitempty"`
	State     OperationState `json:"state"`
	ErrorCode string         `json:"error_code,omitempty"`
	Error     string         `json:"error,omitempty"`
	StartedAt string         `json:"started_at"`
	EndedAt   string         `json:"ended_at,omitempty"`
	OwnerID   string         `json:"-"`
}

type OperationRef struct {
	Operation Operation `json:"operation"`
}

// ProfileMutationResult represents the two valid PATCH /v3/profiles outcomes:
// a completed static update or an asynchronous active-profile transaction.
type ProfileMutationResult struct {
	Profile   *Profile
	Operation *Operation
}

type ConnectionRequest struct {
	ProfileID string `json:"profile_id"`
}

type ControlModeRequest struct {
	Mode      string `json:"mode"`
	ProfileID string `json:"profile_id,omitempty"`
}

type RouteUpdateRequest struct {
	AcceptServerRoutes *bool    `json:"accept_server_routes,omitempty"`
	CustomInclude      []string `json:"custom_include_routes,omitempty"`
	CustomExclude      []string `json:"custom_exclude_routes,omitempty"`
}

type LoginRequest struct {
	ProfileID string `json:"profile_id,omitempty"`
	Name      string `json:"name,omitempty"`
	ServerURL string `json:"server_url,omitempty"`
	Username  string `json:"username,omitempty"`
	Group     string `json:"group,omitempty"`
	Password  string `json:"password,omitempty"`
}

type LogEntry struct {
	Time    string `json:"time"`
	Level   string `json:"level"`
	Message string `json:"message"`
}

type Notify struct {
	Epoch      string           `json:"epoch"`
	Revision   uint64           `json:"revision"`
	Version    string           `json:"version"`
	Event      string           `json:"event"`
	Status     *Status          `json:"status,omitempty"`
	Traffic    *TrafficSnapshot `json:"traffic,omitempty"`
	Profile    *Profile         `json:"profile,omitempty"`
	Profiles   []Profile        `json:"profiles,omitempty"`
	Logs       []LogEntry       `json:"logs,omitempty"`
	Message    string           `json:"message,omitempty"`
	Error      string           `json:"error,omitempty"`
	Connection *ConnectionEvent `json:"connection,omitempty"`
	Network    *NetworkChange   `json:"network,omitempty"`
	Operation  *Operation       `json:"operation,omitempty"`
	Time       string           `json:"time"`
}

// UpdateAsset describes one downloadable artifact attached to a release.
type UpdateAsset struct {
	Name        string `json:"name"`
	DownloadURL string `json:"download_url"`
	Size        int64  `json:"size"`
}

// UpdateInfo is the result of an online update check against GitHub Releases.
// It is check-only: FlexConnect does not download or replace binaries.
type UpdateInfo struct {
	CurrentVersion  string        `json:"current_version"`
	LatestVersion   string        `json:"latest_version"`
	UpdateAvailable bool          `json:"update_available"`
	ReleaseURL      string        `json:"release_url,omitempty"`
	PublishedAt     string        `json:"published_at,omitempty"`
	Assets          []UpdateAsset `json:"assets,omitempty"`
	CheckedAt       string        `json:"checked_at,omitempty"`
	Disabled        bool          `json:"disabled,omitempty"`
	Error           string        `json:"error,omitempty"`
}

type Diagnostics struct {
	Version           string              `json:"version"`
	Status            Status              `json:"status"`
	CurrentProfile    *Profile            `json:"current_profile,omitempty"`
	Profiles          []Profile           `json:"profiles"`
	ServerConfig      map[string]any      `json:"server_config,omitempty"`
	Traffic           *TrafficSnapshot    `json:"traffic,omitempty"`
	Logs              []LogEntry          `json:"logs"`
	GeneratedAt       string              `json:"generated_at"`
	ConnectionHistory []ConnectionEvent   `json:"connection_history"`
	Reconnect         ReconnectSnapshot   `json:"reconnect"`
	Runtime           *RuntimeDiagnostics `json:"runtime,omitempty"`
	Health            []ComponentStatus   `json:"health"`
}

func BoolPtr(v bool) *bool {
	return &v
}

func BoolValue(v *bool, defaultValue bool) bool {
	if v == nil {
		return defaultValue
	}
	return *v
}

func NewProfile(name string) (Profile, error) {
	id, err := NewID()
	if err != nil {
		return Profile{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	return Profile{
		ID:                 id,
		Provider:           ProviderAnyConnect,
		AuthMethod:         AuthPassword,
		Name:               name,
		Scope:              ProfileScopeMachine,
		OwnerID:            "system",
		AcceptServerRoutes: true,
		AutoReconnect:      BoolPtr(false),
		ApplyDNS:           BoolPtr(true),
		SOCKS5Listen:       "127.0.0.1:1080",
		MTU:                1399,
		CreatedAt:          now,
		UpdatedAt:          now,
	}, nil
}

func NewID() (string, error) {
	return newIDFrom(rand.Reader)
}

func newIDFrom(reader io.Reader) (string, error) {
	var buf [16]byte
	if _, err := io.ReadFull(reader, buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}
