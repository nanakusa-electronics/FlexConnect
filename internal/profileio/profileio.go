package profileio

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"flexconnect/internal/types"
)

type ValidationError struct{ Err error }

func (e *ValidationError) Error() string { return e.Err.Error() }
func (e *ValidationError) Unwrap() error { return e.Err }

func NormalizeProfile(profile types.Profile) types.Profile {
	profile.ATrustCompatibility = profile.ATrustCompatibility.Clone()
	profile.Name = strings.TrimSpace(profile.Name)
	profile.Username = strings.TrimSpace(profile.Username)
	profile.Group = strings.TrimSpace(profile.Group)
	profile.LoginDomain = strings.TrimSpace(profile.LoginDomain)
	profile.ServerURL = NormalizeServerURL(profile.ServerURL)
	profile.CustomInclude = normalizeList(profile.CustomInclude)
	profile.CustomExclude = normalizeList(profile.CustomExclude)
	profile.DNSOverrides = normalizeList(profile.DNSOverrides)
	profile.SOCKS5Listen = strings.TrimSpace(profile.SOCKS5Listen)
	if profile.Name == "" {
		profile.Name = DefaultProfileName(profile.ServerURL, profile.Username)
	}
	if profile.AutoReconnect == nil {
		profile.AutoReconnect = types.BoolPtr(false)
	}
	if profile.ApplyDNS == nil {
		profile.ApplyDNS = types.BoolPtr(true)
	}
	return profile
}

func normalizeList(values []string) []string {
	if values == nil {
		return nil
	}
	out := make([]string, 0, len(values))
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func NormalizeServerURL(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if strings.Contains(v, "://") {
		return v
	}
	return "https://" + v
}

func ValidateProfile(profile types.Profile) error {
	if err := validateProfile(profile); err != nil {
		return &ValidationError{Err: err}
	}
	return nil
}

func validateProfile(profile types.Profile) error {
	switch profile.Provider {
	case types.ProviderAnyConnect:
		compatibility := profile.ATrustCompatibility
		if compatibility.ProcessIdentity != nil || compatibility.FallbackAppID != "" || len(compatibility.FallbackGateways) != 0 || compatibility.GatewayServerName != "" || compatibility.TCPToL3Fallback || compatibility.MissingGatewayGroupFallback {
			return errors.New("aTrust compatibility settings require the aTrust provider")
		}
		if profile.AuthMethod != types.AuthPassword {
			return errors.New("AnyConnect requires password authentication")
		}
	case types.ProviderATrust:
		if err := profile.ATrustCompatibility.Validate(); err != nil {
			return err
		}
		if profile.AuthMethod != types.AuthECNUPasskey && profile.AuthMethod != types.AuthShanghaiTechPasskey {
			return errors.New("aTrust requires a supported passkey authentication method")
		}
	default:
		return fmt.Errorf("unknown VPN provider %q", profile.Provider)
	}
	if err := validateText("login domain", profile.LoginDomain, false, 256); err != nil {
		return err
	}
	if err := validateText("profile name", profile.Name, true, 128); err != nil {
		return err
	}
	if err := validateText("username", profile.Username, true, 256); err != nil {
		return err
	}
	if err := validateText("group", profile.Group, false, 256); err != nil {
		return err
	}
	parsed, err := url.Parse(profile.ServerURL)
	if err != nil {
		return fmt.Errorf("invalid server URL: %w", err)
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("server URL scheme must be https")
	}
	if parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" || parsed.ForceQuery {
		return errors.New("server URL must contain only an HTTPS host, optional port, and path")
	}
	if addr, err := netip.ParseAddr(parsed.Hostname()); err == nil && !addr.Unmap().Is4() {
		return errors.New("IPv6 literal VPN server URLs are not supported")
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return fmt.Errorf("invalid server URL port %q", port)
		}
	}
	if profile.MTU < 576 || profile.MTU > 9000 {
		return fmt.Errorf("MTU must be between 576 and 9000")
	}
	if profile.Scope != types.ProfileScopeUser && profile.Scope != types.ProfileScopeMachine {
		return fmt.Errorf("invalid profile scope %q", profile.Scope)
	}
	if strings.TrimSpace(profile.OwnerID) == "" {
		return errors.New("profile owner is required")
	}
	routes := append(append([]string(nil), profile.CustomInclude...), profile.CustomExclude...)
	if len(routes) > 512 {
		return errors.New("profile route list exceeds 512 entries")
	}
	for _, value := range routes {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil {
			return fmt.Errorf("invalid route %q: %w", value, err)
		}
		if !prefix.Addr().Is4() {
			return fmt.Errorf("route %q is not IPv4", value)
		}
	}
	if len(profile.DNSOverrides) > 16 {
		return errors.New("DNS server list exceeds 16 entries")
	}
	for _, value := range profile.DNSOverrides {
		addr, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil {
			return fmt.Errorf("invalid DNS server %q: %w", value, err)
		}
		if !addr.Is4() || addr.IsUnspecified() || addr.IsMulticast() {
			return fmt.Errorf("invalid DNS server %q", value)
		}
	}
	if profile.SOCKS5Enabled {
		host, port, err := net.SplitHostPort(strings.TrimSpace(profile.SOCKS5Listen))
		if err != nil {
			return fmt.Errorf("invalid SOCKS5 listen address: %w", err)
		}
		if host == "" {
			return errors.New("SOCKS5 listen host is required")
		}
		if host != "localhost" {
			addr, err := netip.ParseAddr(host)
			if err != nil || (!addr.Is4() && !addr.Is6()) || addr.IsMulticast() {
				return fmt.Errorf("invalid SOCKS5 listen host %q", host)
			}
		}
		value, err := strconv.Atoi(port)
		if err != nil || value < 0 || value > 65535 {
			return fmt.Errorf("invalid SOCKS5 listen port %q", port)
		}
		if value == 0 && host != "localhost" {
			addr, _ := netip.ParseAddr(host)
			if !addr.IsValid() || !addr.IsLoopback() {
				return errors.New("SOCKS5 port 0 is only valid on loopback")
			}
		}
	}
	return nil
}

func validateText(field, value string, required bool, maximum int) error {
	value = strings.TrimSpace(value)
	if required && value == "" {
		return fmt.Errorf("%s is required", field)
	}
	if len(value) > maximum {
		return fmt.Errorf("%s exceeds %d bytes", field, maximum)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%s contains control characters", field)
		}
	}
	return nil
}

func DefaultProfileName(serverURL, username string) string {
	host := serverURL
	if parsed, err := url.Parse(serverURL); err == nil && parsed.Host != "" {
		host = parsed.Host
	}
	host = strings.TrimSpace(host)
	username = strings.TrimSpace(username)
	if username != "" && host != "" {
		return username + "@" + host
	}
	if host != "" {
		return host
	}
	if username != "" {
		return username
	}
	return "Profile"
}
