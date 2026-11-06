package appd

import (
	"context"
	"testing"

	"flexconnect/internal/types"
)

func TestStartUnattended(t *testing.T) {
	for _, tc := range []struct {
		name     string
		enabled  bool
		override *bool
		scope    types.ProfileScope
		want     int
	}{
		{"disabled", false, nil, types.ProfileScopeUser, 0},
		{"user", true, nil, types.ProfileScopeUser, 1},
		{"machine", true, nil, types.ProfileScopeMachine, 1},
		{"override off", true, types.BoolPtr(false), types.ProfileScopeUser, 0},
		{"override on", false, types.BoolPtr(true), types.ProfileScopeUser, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profile := testProfile("startup", false)
			profile.Scope = tc.scope
			if tc.scope == types.ProfileScopeUser {
				profile.OwnerID = "alice"
			}
			profile.UnattendedMode = types.BoolPtr(tc.enabled)
			backend := newFakeBackend()
			service := newTestService(t, backend, profile)
			defer service.Close(context.Background())
			if err := service.StartUnattended(context.Background(), tc.override); err != nil {
				t.Fatal(err)
			}
			backend.mu.Lock()
			got := backend.connects
			backend.mu.Unlock()
			if got != tc.want {
				t.Fatalf("connects = %d, want %d", got, tc.want)
			}
			if tc.scope == types.ProfileScopeUser && tc.want == 1 {
				if err := service.authorize(Actor{ID: "bob"}, true); errorCode(err) != "daemon_in_use" {
					t.Fatalf("other user write = %v", err)
				}
			}
		})
	}
}
