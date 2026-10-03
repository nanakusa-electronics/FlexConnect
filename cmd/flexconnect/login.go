package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"

	"flexconnect/internal/types"
)

func promptLoginProfile(ctx context.Context, in io.Reader, out io.Writer) (types.Profile, string, []byte, error) {
	reader := bufio.NewReader(in)
	provider, err := promptLoginChoice(ctx, reader, out, "VPN provider", []string{"AnyConnect", "aTrust"})
	if err != nil {
		return types.Profile{}, "", nil, err
	}
	if provider == "AnyConnect" {
		req, err := promptAnyConnectLoginRequest(ctx, reader, in, out)
		if err != nil {
			return types.Profile{}, "", nil, err
		}
		profile, err := types.NewProfile(req.Name)
		profile.Scope = types.ProfileScopeUser
		profile.ServerURL, profile.Username, profile.Group = req.ServerURL, req.Username, req.Group
		return profile, req.Password, nil, err
	}
	profile, err := types.NewProfile("")
	if err != nil {
		return types.Profile{}, "", nil, err
	}
	profile.Scope, profile.Provider = types.ProfileScopeUser, types.ProviderATrust
	auth, err := promptLoginChoice(ctx, reader, out, "Passkey authentication", []string{"ECNU Passkey", "ShanghaiTech Passkey"})
	if err != nil {
		return types.Profile{}, "", nil, err
	}
	profile.AuthMethod = types.AuthECNUPasskey
	if auth == "ShanghaiTech Passkey" {
		profile.AuthMethod = types.AuthShanghaiTechPasskey
	}
	profile.ServerURL, err = promptRequiredValue(reader, out, "Server URL")
	if err != nil {
		return types.Profile{}, "", nil, err
	}
	profile.Username, err = promptValue(reader, out, "Username (leave empty to use keystore identity)", true)
	if err != nil {
		return types.Profile{}, "", nil, err
	}
	var credential []byte
	for {
		if err := ctx.Err(); err != nil {
			return types.Profile{}, "", nil, err
		}
		path, err := promptRequiredValue(reader, out, "Passkey keystore file")
		if err != nil {
			return types.Profile{}, "", nil, err
		}
		credential, err = readKeystore(strings.Trim(path, "\""))
		if err == nil {
			break
		}
		if _, err := fmt.Fprintf(out, "Cannot read keystore: %v\n", err); err != nil {
			return types.Profile{}, "", nil, err
		}
	}
	profile.LoginDomain, err = promptValue(reader, out, "Login domain", true)
	if err != nil {
		return types.Profile{}, "", nil, err
	}
	if err := promptATrustAttributes(ctx, reader, out, &profile); err != nil {
		return types.Profile{}, "", nil, err
	}
	profile.Name, err = promptValue(reader, out, "Profile name", true)
	return profile, "", credential, err
}

func promptLoginChoice(ctx context.Context, reader *bufio.Reader, out io.Writer, label string, choices []string) (string, error) {
	for i, choice := range choices {
		if _, err := fmt.Fprintf(out, "  %d. %s\n", i+1, choice); err != nil {
			return "", err
		}
	}
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		value, err := promptValue(reader, out, label+" [default 1]", false)
		if err != nil {
			return "", err
		}
		if value == "" {
			return choices[0], nil
		}
		for i, choice := range choices {
			if value == fmt.Sprint(i+1) || strings.EqualFold(value, choice) {
				return choice, nil
			}
		}
		if _, err := fmt.Fprintln(out, "Select a listed number or name."); err != nil {
			return "", err
		}
	}
}
