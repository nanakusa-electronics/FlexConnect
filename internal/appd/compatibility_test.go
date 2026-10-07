package appd

import (
	"flexconnect/internal/types"
	"github.com/ShanghaitechGeekPie/geektrust/deployment"
	"testing"
)

func TestCompatibilityChangeRequiresReconnect(t *testing.T) {
	original := types.Profile{ATrustCompatibility: types.ATrustCompatibility{FallbackGateways: []string{"gateway:441"}, ProcessIdentity: &deployment.ProcessIdentity{Name: "app", Platform: "Windows", Path: "app.exe"}}}
	unchanged := cloneProfile(original)
	if needsReconnectForProfileUpdate(original, unchanged) {
		t.Fatal("unchanged compatibility requires reconnect")
	}
	changed := cloneProfile(original)
	changed.ATrustCompatibility.TCPToL3Fallback = true
	if !needsReconnectForProfileUpdate(original, changed) {
		t.Fatal("transport setting did not require reconnect")
	}
	if !needsReconnectForProfileUpdate(changed, original) {
		t.Fatal("disabling fallback did not require reconnect")
	}
	changed = cloneProfile(original)
	changed.ATrustCompatibility.FallbackGateways[0] = "other:441"
	changed.ATrustCompatibility.ProcessIdentity.Path = "other.exe"
	if original.ATrustCompatibility.FallbackGateways[0] != "gateway:441" || original.ATrustCompatibility.ProcessIdentity.Path != "app.exe" {
		t.Fatal("profile clone shares mutable compatibility")
	}
	if !needsReconnectForProfileUpdate(original, changed) {
		t.Fatal("identity and gateway changes did not require reconnect")
	}
}

func TestProfileUpdateReplacesCompatibility(t *testing.T) {
	profile := testProfile("atrust", false)
	profile.Provider, profile.AuthMethod = types.ProviderATrust, types.AuthECNUPasskey
	profile.Scope, profile.OwnerID = types.ProfileScopeUser, "alice"
	service := newTestService(t, newFakeBackend(), profile)
	settings := types.ATrustCompatibility{TCPToL3Fallback: true, FallbackGateways: []string{"gateway:441"}}
	updated, err := service.UpdateProfileFor(Actor{ID: "alice"}, profile.ID, types.ProfileUpdateRequest{ATrustCompatibility: &settings})
	if err != nil {
		t.Fatal(err)
	}
	settings.FallbackGateways[0] = "mutated:441"
	if !updated.ATrustCompatibility.TCPToL3Fallback || updated.ATrustCompatibility.FallbackGateways[0] != "gateway:441" {
		t.Fatal("update lost configuration or kept caller slice")
	}
	reset := types.ATrustCompatibility{}
	updated, err = service.UpdateProfileFor(Actor{ID: "alice"}, profile.ID, types.ProfileUpdateRequest{ATrustCompatibility: &reset})
	if err != nil {
		t.Fatal(err)
	}
	if updated.ATrustCompatibility.TCPToL3Fallback || len(updated.ATrustCompatibility.FallbackGateways) != 0 {
		t.Fatal("empty object did not reset compatibility")
	}
}
