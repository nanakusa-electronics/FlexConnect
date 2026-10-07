package main

import (
	"bufio"
	"context"
	"io"
	"reflect"
	"strings"
	"testing"

	"flexconnect/internal/types"
)

func atrustProfileForTest(t *testing.T) types.Profile {
	t.Helper()
	profile, err := types.NewProfile("campus")
	if err != nil {
		t.Fatal(err)
	}
	profile.Provider, profile.AuthMethod = types.ProviderATrust, types.AuthECNUPasskey
	profile.Scope, profile.ServerURL = types.ProfileScopeUser, "https://vpn.example.com"
	return profile
}

func TestATrustAttributesCanBeSkipped(t *testing.T) {
	for _, input := range []string{"\n", "2\nn\nn\n"} {
		profile := atrustProfileForTest(t)
		before := profile
		if err := promptATrustAttributes(context.Background(), bufio.NewReader(strings.NewReader(input)), io.Discard, &profile); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(profile, before) {
			t.Fatal("skipping changed profile defaults")
		}
	}
}

func TestATrustNetworkRetriesBooleanAndMTU(t *testing.T) {
	profile := atrustProfileForTest(t)
	var out strings.Builder
	input := "invalid\nno\n\n\n\n\n\nwrong\n575\n9001\n1500\n"
	if err := promptATrustNetwork(context.Background(), bufio.NewReader(strings.NewReader(input)), &out, &profile); err != nil {
		t.Fatal(err)
	}
	if profile.AcceptServerRoutes || profile.MTU != 1500 || profile.Username != "" || !types.BoolValue(profile.ApplyDNS, false) || types.BoolValue(profile.AutoReconnect, true) || profile.SOCKS5Enabled {
		t.Fatal("network choices or defaults were lost")
	}
	if !strings.Contains(out.String(), "Enter yes or no") || !strings.Contains(out.String(), "Enter an MTU") {
		t.Fatal("invalid input was not explained")
	}
}

func TestATrustNetworkRejectsInvalidRoutes(t *testing.T) {
	profile := atrustProfileForTest(t)
	input := "\n\n\nnot-a-cidr\n\n\n\n"
	if err := promptATrustNetwork(context.Background(), bufio.NewReader(strings.NewReader(input)), io.Discard, &profile); err == nil {
		t.Fatal("invalid route accepted")
	}
}

func TestATrustCompatibilityRejectsInvalidGateway(t *testing.T) {
	settings := types.ATrustCompatibility{}
	input := "\ngateway-without-port\n\n\n\n\n"
	if err := promptATrustCompatibility(context.Background(), bufio.NewReader(strings.NewReader(input)), io.Discard, &settings); err == nil {
		t.Fatal("invalid gateway accepted")
	}
}

func TestATrustAttributesRespectCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	profile := atrustProfileForTest(t)
	if err := promptATrustAttributes(ctx, bufio.NewReader(strings.NewReader("")), io.Discard, &profile); err != context.Canceled {
		t.Fatalf("error = %v", err)
	}
}
