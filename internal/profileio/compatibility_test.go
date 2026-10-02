package profileio

import (
	"flexconnect/internal/types"
	"testing"
)

func TestCompatibilityRequiresATrust(t *testing.T) {
	profile, err := types.NewProfile("test")
	if err != nil {
		t.Fatal(err)
	}
	profile.ServerURL, profile.Username, profile.OwnerID = "https://vpn.example", "user", "owner"
	profile.ATrustCompatibility.TCPToL3Fallback = true
	if err := ValidateProfile(profile); err == nil {
		t.Fatal("AnyConnect accepted aTrust options")
	}
	profile.Provider, profile.AuthMethod = types.ProviderATrust, types.AuthECNUPasskey
	if err := ValidateProfile(profile); err != nil {
		t.Fatal(err)
	}
	profile.ATrustCompatibility.FallbackGateways = []string{"gateway:0"}
	if err := ValidateProfile(profile); err == nil {
		t.Fatal("invalid compatibility reached backend")
	}
}
