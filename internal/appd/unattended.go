package appd

import (
	"context"
	"time"

	"flexconnect/internal/types"
)

// StartUnattended connects the selected profile once, using its stored credentials.
// An explicit override takes precedence over the profile setting.
func (s *Service) StartUnattended(ctx context.Context, override *bool) error {
	profile, err := s.CurrentProfile()
	if err != nil {
		if override == nil || !*override {
			return nil
		}
		return err
	}
	enabled := types.BoolValue(profile.UnattendedMode, false)
	if override != nil {
		enabled = *override
	}
	if !enabled {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if profile.Scope == types.ProfileScopeMachine {
		return s.SetControlMode(ctx, SystemActor(), types.ControlModeRequest{Mode: "machine", ProfileID: profile.ID})
	}
	return s.ConnectFor(ctx, Actor{ID: profile.OwnerID}, profile.ID)
}
