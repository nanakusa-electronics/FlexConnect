package types

import (
	"errors"
	"strings"
	"unicode"

	"github.com/ShanghaitechGeekPie/geektrust/compatibility"
)

// ATrustCompatibility holds the explicit deployment settings of a FlexConnect profile.
type ATrustCompatibility struct {
	ProcessIdentity             *ProcessIdentity `json:"process_identity,omitempty"`
	FallbackAppID               string           `json:"fallback_app_id,omitempty"`
	FallbackGateways            []string         `json:"fallback_gateways,omitempty"`
	GatewayServerName           string           `json:"gateway_server_name,omitempty"`
	MissingGatewayGroupFallback bool             `json:"missing_gateway_group_fallback,omitempty"`
	TCPToL3Fallback             bool             `json:"tcp_to_l3_fallback,omitempty"`
}

type ProcessIdentity struct {
	Name     string `json:"name"`
	Platform string `json:"platform"`
	Path     string `json:"path"`
}

func (c ATrustCompatibility) Clone() ATrustCompatibility {
	if c.ProcessIdentity != nil {
		identity := *c.ProcessIdentity
		c.ProcessIdentity = &identity
	}
	c.FallbackGateways = append([]string(nil), c.FallbackGateways...)
	return c
}

func (c ATrustCompatibility) Validate() error {
	name := c.GatewayServerName
	if len(name) > 253 || strings.ContainsAny(name, "/\\:@?# ") || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return errors.New("compatibility.gateway_server_name must be a TLS hostname without a port")
	}
	return c.GeekTrustOptions().Validate()
}

func (c ATrustCompatibility) GeekTrustOptions() compatibility.Options {
	// Profile settings are explicit, including when all fallbacks are disabled.
	options := compatibility.Options{
		Profile: compatibility.Generic,
		Fallbacks: &compatibility.Fallbacks{
			ApplicationID:       c.FallbackAppID,
			Gateways:            c.FallbackGateways,
			MissingGatewayGroup: c.MissingGatewayGroupFallback,
			StreamToL3:          c.TCPToL3Fallback,
		},
	}
	if p := c.ProcessIdentity; p != nil {
		options.Protocol.Process = &compatibility.ProcessMetadata{Name: p.Name, Platform: p.Platform, Path: p.Path}
	}
	return options
}
