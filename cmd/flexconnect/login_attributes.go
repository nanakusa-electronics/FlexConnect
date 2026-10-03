package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	"flexconnect/internal/profileio"
	"flexconnect/internal/types"
	"github.com/ShanghaitechGeekPie/geektrust/deployment"
)

func promptATrustAttributes(ctx context.Context, reader *bufio.Reader, out io.Writer, profile *types.Profile) error {
	mode, err := promptLoginChoice(ctx, reader, out, "Optional aTrust attributes", []string{"Keep defaults", "Configure interactively", "Import compatibility JSON"})
	if err != nil {
		return err
	}
	switch mode {
	case "Keep defaults":
		return nil
	case "Import compatibility JSON":
		path, err := promptRequiredValue(reader, out, "aTrust compatibility JSON file")
		if err != nil {
			return err
		}
		settings, err := readATrustCompatibility(strings.Trim(path, "\""))
		if err != nil {
			return err
		}
		profile.ATrustCompatibility = *settings
		return nil
	}
	network, err := promptLoginBool(ctx, reader, out, "Configure network settings", true)
	if err != nil {
		return err
	}
	if network {
		if err := promptATrustNetwork(ctx, reader, out, profile); err != nil {
			return err
		}
	}
	compatibility, err := promptLoginBool(ctx, reader, out, "Configure deployment compatibility (normally unnecessary)", false)
	if err != nil {
		return err
	}
	if compatibility {
		if err := promptATrustCompatibility(ctx, reader, out, &profile.ATrustCompatibility); err != nil {
			return err
		}
	}
	return nil
}

func promptATrustNetwork(ctx context.Context, reader *bufio.Reader, out io.Writer, profile *types.Profile) error {
	var err error
	profile.AcceptServerRoutes, err = promptLoginBool(ctx, reader, out, "Accept server routes", profile.AcceptServerRoutes)
	if err != nil {
		return err
	}
	applyDNS, err := promptLoginBool(ctx, reader, out, "Apply VPN DNS to the system", types.BoolValue(profile.ApplyDNS, true))
	if err != nil {
		return err
	}
	profile.ApplyDNS = types.BoolPtr(applyDNS)
	reconnect, err := promptLoginBool(ctx, reader, out, "Reconnect after unexpected disconnect", types.BoolValue(profile.AutoReconnect, false))
	if err != nil {
		return err
	}
	profile.AutoReconnect = types.BoolPtr(reconnect)
	include, err := promptValue(reader, out, "Additional VPN IPv4 routes (comma-separated CIDRs)", true)
	if err != nil {
		return err
	}
	profile.CustomInclude = splitCSV(include)
	exclude, err := promptValue(reader, out, "Excluded IPv4 routes (comma-separated CIDRs)", true)
	if err != nil {
		return err
	}
	profile.CustomExclude = splitCSV(exclude)
	profile.SOCKS5Enabled, err = promptLoginBool(ctx, reader, out, "Enable VPN SOCKS5 proxy", profile.SOCKS5Enabled)
	if err != nil {
		return err
	}
	if profile.SOCKS5Enabled {
		listen, err := promptValue(reader, out, "SOCKS5 listen address [default "+profile.SOCKS5Listen+"]", false)
		if err != nil {
			return err
		}
		if listen != "" {
			profile.SOCKS5Listen = listen
		}
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		value, err := promptValue(reader, out, fmt.Sprintf("MTU [576-9000, default %d]", profile.MTU), false)
		if err != nil {
			return err
		}
		if value == "" {
			break
		}
		mtu, err := strconv.Atoi(value)
		if err == nil && mtu >= 576 && mtu <= 9000 {
			profile.MTU = mtu
			break
		}
		if _, err := fmt.Fprintln(out, "Enter an MTU between 576 and 9000."); err != nil {
			return err
		}
	}
	// The daemon resolves an omitted username from the imported keystore.
	// Validate network options with a placeholder without changing that request.
	validation := *profile
	if validation.Username == "" {
		validation.Username = "keystore-user"
	}
	if err := profileio.ValidateProfile(profileio.NormalizeProfile(validation)); err != nil {
		return fmt.Errorf("invalid network settings: %w", err)
	}
	return nil
}

func promptATrustCompatibility(ctx context.Context, reader *bufio.Reader, out io.Writer, settings *types.ATrustCompatibility) error {
	var err error
	settings.FallbackAppID, err = promptValue(reader, out, "Application ID when a resource has no match", true)
	if err != nil {
		return err
	}
	gateways, err := promptValue(reader, out, "Gateways when the controller supplies none (comma-separated host:port)", true)
	if err != nil {
		return err
	}
	settings.FallbackGateways = splitCSV(gateways)
	for i := range settings.FallbackGateways {
		settings.FallbackGateways[i] = strings.TrimSpace(settings.FallbackGateways[i])
	}
	settings.GatewayServerName, err = promptValue(reader, out, "Gateway TLS certificate hostname", true)
	if err != nil {
		return err
	}
	settings.MissingGatewayGroupFallback, err = promptLoginBool(ctx, reader, out, "Use all controller gateways if the selected group has no addresses", false)
	if err != nil {
		return err
	}
	settings.TCPToL3Fallback, err = promptLoginBool(ctx, reader, out, "Try L3 when the stream transport is unsupported", false)
	if err != nil {
		return err
	}
	identity, err := promptLoginBool(ctx, reader, out, "Override process metadata sent to the gateway", false)
	if err != nil {
		return err
	}
	if identity {
		metadata := &deployment.ProcessIdentity{}
		metadata.Name, err = promptRequiredValue(reader, out, "Process name")
		if err != nil {
			return err
		}
		metadata.Platform, err = promptRequiredValue(reader, out, "Process platform")
		if err != nil {
			return err
		}
		metadata.Path, err = promptRequiredValue(reader, out, "Process path")
		if err != nil {
			return err
		}
		settings.ProcessIdentity = metadata
	}
	return settings.Validate()
}

func promptLoginBool(ctx context.Context, reader *bufio.Reader, out io.Writer, label string, fallback bool) (bool, error) {
	defaultLabel := "y/N"
	if fallback {
		defaultLabel = "Y/n"
	}
	for {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		value, err := promptValue(reader, out, label+" ["+defaultLabel+"]", false)
		if err != nil {
			return false, err
		}
		switch strings.ToLower(value) {
		case "":
			return fallback, nil
		case "y", "yes", "true", "1":
			return true, nil
		case "n", "no", "false", "0":
			return false, nil
		}
		if _, err := fmt.Fprintln(out, "Enter yes or no, or press Enter to keep the default."); err != nil {
			return false, err
		}
	}
}
