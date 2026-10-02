package appd

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"flexconnect/internal/profileio"
	"flexconnect/internal/types"
	"flexconnect/internal/vpn"
	geektrust "github.com/ShanghaitechGeekPie/geektrust/client"
)

type Actor struct {
	ID     string
	System bool
	Admin  bool
}

func SystemActor() Actor { return Actor{ID: "system", System: true, Admin: true} }

type CodedError struct {
	Code      string
	Message   string
	Retryable bool
	Cause     error
}

func (e *CodedError) Error() string { return e.Message }
func (e *CodedError) Unwrap() error { return e.Cause }

func coded(code, message string, cause error) error {
	return &CodedError{Code: code, Message: message, Cause: cause}
}

func (s *Service) authorize(actor Actor, write bool) error {
	if actor.ID == "" {
		return coded("identity_unavailable", "local client identity is unavailable", nil)
	}
	if actor.System {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if write && s.closed {
		return coded("service_closing", "daemon is shutting down", nil)
	}
	if write && s.fatalErr != nil {
		return coded("cleanup_failed", "network cleanup failed; daemon restart recovery is required", s.fatalErr)
	}
	if write && s.intent != nil {
		return coded("profile_transaction_pending", "a profile transaction requires daemon restart recovery", nil)
	}
	if write {
		for _, component := range []string{"store", "secret", "supervisor", "cleanup"} {
			if health := s.health[component]; !health.Ready {
				return coded("component_unavailable", component+" is not ready; daemon restart recovery is required", nil)
			}
		}
	}
	if write && s.controlMode == "machine" && !actor.Admin {
		return coded("machine_mode_locked", "machine mode can only be changed by an elevated administrator", nil)
	}
	if write && !actor.System && !(s.controlMode == "machine" && actor.Admin) {
		if s.activeOwnerID != "" && s.activeOwnerID != actor.ID {
			return coded("daemon_in_use", "FlexConnect is already in use by another local user", nil)
		}
	}
	return nil
}

func (s *Service) authorizeAdministrativeWrite(actor Actor) error {
	if !actor.System && !actor.Admin {
		return coded("admin_required", "operation requires an elevated administrator", nil)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return coded("service_closing", "daemon is shutting down", nil)
	}
	if s.fatalErr != nil {
		return coded("cleanup_failed", "network cleanup failed; daemon restart recovery is required", s.fatalErr)
	}
	if s.intent != nil {
		return coded("profile_transaction_pending", "a profile transaction requires daemon restart recovery", nil)
	}
	for _, component := range []string{"store", "secret", "supervisor", "cleanup"} {
		if health := s.health[component]; !health.Ready {
			return coded("component_unavailable", component+" is not ready; daemon restart recovery is required", nil)
		}
	}
	return nil
}

func actorCanAccessProfile(actor Actor, profile types.Profile) bool {
	return actor.System || actor.Admin || (profile.Scope == types.ProfileScopeUser && profile.OwnerID == actor.ID)
}

func actorCanMutateProfile(actor Actor, profile types.Profile) bool {
	if actor.System {
		return true
	}
	if profile.Scope == types.ProfileScopeMachine {
		return actor.Admin
	}
	return profile.Scope == types.ProfileScopeUser && profile.OwnerID == actor.ID
}

func publicProfile(profile types.Profile, actor Actor) types.Profile {
	profile.SecretRef = ""
	profile.OwnerID = ""
	profile.CustomInclude = append([]string(nil), profile.CustomInclude...)
	profile.CustomExclude = append([]string(nil), profile.CustomExclude...)
	profile.DNSOverrides = append([]string(nil), profile.DNSOverrides...)
	return profile
}

func (s *Service) ListProfilesFor(actor Actor) ([]types.Profile, error) {
	if err := s.authorize(actor, false); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]types.Profile, 0, len(s.profiles))
	for _, profile := range s.profiles {
		if actorCanAccessProfile(actor, profile) {
			out = append(out, publicProfile(profile, actor))
		}
	}
	return out, nil
}

func (s *Service) StatusFor(actor Actor) (types.Status, error) {
	if err := s.authorize(actor, false); err != nil {
		return types.Status{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.statusForActorLocked(actor), nil
}

func (s *Service) statusForActorLocked(actor Actor) types.Status {
	status := cloneStatus(s.status)
	if s.controlMode == "machine" {
		status.SelectedProfileID = s.machineProfileID
	} else {
		status.SelectedProfileID = s.selectedProfiles[actor.ID]
		if actor.System || actor.Admin {
			status.SelectedProfileID = s.currentID
		}
	}
	if !actor.System && !actor.Admin {
		if status.Operation != nil && status.Operation.OwnerID != actor.ID {
			status.Operation = nil
		}
		profile, err := s.findProfileLocked(status.ConnectedProfileID)
		if err != nil || !actorCanAccessProfile(actor, profile) {
			status.ConnectedProfileID = ""
			status.Session = nil
			status.EffectiveRoutes = nil
			status.SOCKS5Listen = ""
		}
	}
	return status
}

func (s *Service) TrafficFor(actor Actor) (types.TrafficSnapshot, error) {
	status, err := s.StatusFor(actor)
	if err != nil {
		return types.TrafficSnapshot{}, err
	}
	if status.ConnectedProfileID == "" && !actor.System && !actor.Admin {
		return types.TrafficSnapshot{}, nil
	}
	return s.Traffic(), nil
}

func (s *Service) LogsFor(actor Actor) ([]types.LogEntry, error) {
	if err := s.authorize(actor, false); err != nil {
		return nil, err
	}
	if !actor.System && !actor.Admin {
		return []types.LogEntry{}, nil
	}
	return s.Logs(), nil
}

func (s *Service) DiagnosticsFor(actor Actor) (types.Diagnostics, error) {
	if err := s.authorize(actor, false); err != nil {
		return types.Diagnostics{}, err
	}
	diagnostics := s.Diagnostics()
	status, err := s.StatusFor(actor)
	if err != nil {
		return types.Diagnostics{}, err
	}
	profiles, err := s.ListProfilesFor(actor)
	if err != nil {
		return types.Diagnostics{}, err
	}
	diagnostics.Status = status
	diagnostics.Profiles = profiles
	diagnostics.CurrentProfile = nil
	for i := range profiles {
		if profiles[i].ID == status.SelectedProfileID {
			profile := profiles[i]
			diagnostics.CurrentProfile = &profile
			break
		}
	}
	if !actor.System && !actor.Admin {
		diagnostics.ServerConfig = nil
		diagnostics.Logs = nil
		filtered := diagnostics.ConnectionHistory[:0]
		for _, event := range diagnostics.ConnectionHistory {
			for _, profile := range profiles {
				if event.ProfileID == profile.ID {
					filtered = append(filtered, event)
					break
				}
			}
		}
		diagnostics.ConnectionHistory = filtered
	}
	return diagnostics, nil
}

func (s *Service) ProfileIsActive(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connectedID == id || (s.status.CurrentProfileID == id && s.attemptCancel != nil)
}

func (s *Service) ConnectionActive() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connectedID != "" || s.attemptCancel != nil
}

func (s *Service) ConnectFor(ctx context.Context, actor Actor, id string) error {
	if err := s.authorize(actor, true); err != nil {
		return err
	}
	profile, err := s.profileForActor(actor, id)
	if err != nil {
		return err
	}
	s.mu.Lock()
	if !actor.System && s.activeOwnerID != "" && s.activeOwnerID != actor.ID {
		s.mu.Unlock()
		return coded("daemon_in_use", "FlexConnect is already in use by another local user", nil)
	}
	if profile.Scope == types.ProfileScopeMachine && (s.controlMode != "machine" || s.machineProfileID != profile.ID) {
		s.mu.Unlock()
		return coded("machine_mode_required", "machine profiles can only connect through machine mode", nil)
	}
	if !actor.System && s.controlMode == "user" {
		s.activeOwnerID = actor.ID
	}
	if profile.Scope == types.ProfileScopeUser && profile.OwnerID == actor.ID {
		s.selectedProfiles[actor.ID] = profile.ID
	}
	s.currentID = profile.ID
	s.status.SelectedProfileID = profile.ID
	err = s.persist()
	s.mu.Unlock()
	if err != nil {
		s.releaseIdleOwner(actor)
		return err
	}
	if err := s.Connect(ctx, profile.ID); err != nil {
		s.releaseIdleOwner(actor)
		return err
	}
	return nil
}

func (s *Service) releaseIdleOwner(actor Actor) {
	if actor.System {
		return
	}
	s.mu.Lock()
	if s.controlMode == "user" && s.activeOwnerID == actor.ID && s.connectedID == "" && s.attemptCancel == nil {
		s.activeOwnerID = ""
	}
	s.mu.Unlock()
}

func (s *Service) DisconnectFor(ctx context.Context, actor Actor) error {
	if err := s.authorize(actor, true); err != nil {
		return err
	}
	return s.Disconnect(ctx)
}

func (s *Service) CreateProfileFor(actor Actor, req types.ProfileCreateRequest) (types.Profile, error) {
	if err := s.authorize(actor, true); err != nil {
		return types.Profile{}, err
	}
	if req.Provider == "" || req.AuthMethod == "" {
		return types.Profile{}, coded("invalid_profile_provider", "provider and authentication method are required", nil)
	}
	if req.Provider == types.ProviderAnyConnect && req.Password == "" {
		return types.Profile{}, coded("invalid_profile_secret", "profile password is required", nil)
	}
	if req.Provider == types.ProviderATrust && req.Password != "" {
		return types.Profile{}, coded("invalid_profile_secret", "aTrust credentials must be imported separately", nil)
	}
	if req.Provider == types.ProviderATrust {
		if len(req.Credential) == 0 || len(req.Credential) > 1<<20 {
			return types.Profile{}, coded("invalid_profile_secret", "valid passkey credential is required", nil)
		}
		info, err := geektrust.InspectPasskey(req.Credential)
		if err != nil || !passkeyMethodMatches(req.AuthMethod, info.Kind) {
			return types.Profile{}, coded("invalid_profile_secret", "passkey credential does not match authentication method", nil)
		}
		if req.Username == "" {
			req.Username = info.Username
		}
		if req.Username != info.Username {
			return types.Profile{}, coded("invalid_profile_secret", "profile username does not match credential", nil)
		}
	} else if len(req.Credential) != 0 {
		return types.Profile{}, coded("invalid_profile_secret", "AnyConnect does not accept a passkey credential", nil)
	}
	if req.Scope == "" {
		req.Scope = types.ProfileScopeUser
	}
	if req.Scope == types.ProfileScopeMachine && !actor.Admin && !actor.System {
		return types.Profile{}, coded("admin_required", "machine profiles require an elevated administrator", nil)
	}
	profile, err := newProfile(req.Name)
	if err != nil {
		return types.Profile{}, coded("random_source_failed", "generate profile ID failed", err)
	}
	profile.ServerURL = req.ServerURL
	profile.Provider = req.Provider
	profile.AuthMethod = req.AuthMethod
	profile.LoginDomain = req.LoginDomain
	profile.ATrustCompatibility = req.ATrustCompatibility.Clone()
	profile.Username = req.Username
	profile.Group = req.Group
	profile.Scope = req.Scope
	profile.OwnerID = actor.ID
	if req.Scope == types.ProfileScopeMachine {
		profile.OwnerID = "system"
	}
	if req.AcceptServerRoutes != nil {
		profile.AcceptServerRoutes = *req.AcceptServerRoutes
	}
	profile.AutoReconnect = req.AutoReconnect
	if profile.AutoReconnect == nil {
		profile.AutoReconnect = types.BoolPtr(false)
	}
	profile.ApplyDNS = req.ApplyDNS
	if profile.ApplyDNS == nil {
		profile.ApplyDNS = types.BoolPtr(true)
	}
	profile.CustomInclude = append([]string(nil), req.CustomInclude...)
	profile.CustomExclude = append([]string(nil), req.CustomExclude...)
	profile.DNSOverrides = append([]string(nil), req.DNSOverrides...)
	profile.SOCKS5Enabled = req.SOCKS5Enabled
	profile.SOCKS5Listen = req.SOCKS5Listen
	if profile.SOCKS5Listen == "" {
		profile.SOCKS5Listen = "127.0.0.1:1080"
	}
	if req.MTU != 0 {
		profile.MTU = req.MTU
	}
	profile = profileio.NormalizeProfile(profile)
	secretValue := req.Password
	if req.Provider == types.ProviderATrust {
		secretValue = base64.StdEncoding.EncodeToString(req.Credential)
	}
	created, err := s.CreateProfile(profile, secretValue)
	if err != nil {
		return types.Profile{}, err
	}
	s.mu.Lock()
	if created.Scope == types.ProfileScopeUser {
		s.selectedProfiles[actor.ID] = created.ID
	}
	if actor.System || actor.Admin {
		s.currentID = created.ID
	}
	if err := s.persist(); err != nil {
		s.mu.Unlock()
		return types.Profile{}, err
	}
	s.mu.Unlock()
	return publicProfile(created, actor), nil
}

func passkeyMethodMatches(method types.AuthMethod, kind string) bool {
	return method == types.AuthECNUPasskey && kind == "ecnu" ||
		method == types.AuthShanghaiTechPasskey && kind == "shanghaitech"
}

func (s *Service) profileForActor(actor Actor, id string) (types.Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	profile, err := s.findProfileLocked(id)
	if err != nil {
		return types.Profile{}, coded("profile_not_found", "profile not found", err)
	}
	if !actorCanMutateProfile(actor, profile) {
		return types.Profile{}, coded("profile_not_found", "profile not found", nil)
	}
	return profile, nil
}

func (s *Service) UpdateProfileFor(actor Actor, id string, req types.ProfileUpdateRequest) (types.Profile, error) {
	if err := s.authorize(actor, true); err != nil {
		return types.Profile{}, err
	}
	if _, err := s.profileForActor(actor, id); err != nil {
		return types.Profile{}, err
	}
	if req.Password != nil && *req.Password == "" {
		return types.Profile{}, coded("invalid_profile_secret", "profile password cannot be empty", nil)
	}
	profile, _, err := s.updateProfile(id, req, false)
	return publicProfile(profile, actor), err
}

func (s *Service) UpdateActiveProfileFor(actor Actor, id string, req types.ProfileUpdateRequest) (types.Operation, error) {
	if err := s.authorize(actor, true); err != nil {
		return types.Operation{}, err
	}
	if _, err := s.profileForActor(actor, id); err != nil {
		return types.Operation{}, err
	}
	if req.Password != nil && *req.Password == "" {
		return types.Operation{}, coded("invalid_profile_secret", "profile password cannot be empty", nil)
	}
	op, err := s.newOperation(actor, "profile-update", id)
	if err != nil {
		return types.Operation{}, err
	}
	s.commandMu.Lock()
	_, _, err = s.updateProfile(id, req, false)
	if err != nil {
		s.commandMu.Unlock()
		return types.Operation{}, err
	}
	if err := s.registerAndRunOperation(op, func(ctx context.Context) error {
		return s.reconnectProfile(ctx, id, "reapplying updated profile "+id)
	}); err != nil {
		s.commandMu.Unlock()
		return types.Operation{}, err
	}
	s.commandMu.Unlock()
	return op, nil
}

func (s *Service) DeleteProfileFor(actor Actor, id string) error {
	if err := s.authorize(actor, true); err != nil {
		return err
	}
	if _, err := s.profileForActor(actor, id); err != nil {
		return err
	}
	s.mu.Lock()
	lockedMachineProfile := s.controlMode == "machine" && s.machineProfileID == id
	s.mu.Unlock()
	if lockedMachineProfile {
		return coded("machine_mode_locked", "exit machine mode before deleting its profile", nil)
	}
	return s.DeleteProfile(id)
}

func (s *Service) StartOperation(actor Actor, kind, profileID string, run func(context.Context) error) (types.Operation, error) {
	var authErr error
	if kind == "control-mode" {
		authErr = s.authorizeAdministrativeWrite(actor)
	} else {
		authErr = s.authorize(actor, true)
	}
	if authErr != nil {
		return types.Operation{}, authErr
	}
	op, err := s.newOperation(actor, kind, profileID)
	if err != nil {
		return types.Operation{}, err
	}
	if err := s.registerAndRunOperation(op, run); err != nil {
		return types.Operation{}, err
	}
	return op, nil
}

func (s *Service) newOperation(actor Actor, kind, profileID string) (types.Operation, error) {
	id, err := newID()
	if err != nil {
		return types.Operation{}, coded("random_source_failed", "generate operation ID failed", err)
	}
	attemptID, err := newID()
	if err != nil {
		return types.Operation{}, coded("random_source_failed", "generate attempt ID failed", err)
	}
	op := types.Operation{ID: id, Kind: kind, ProfileID: profileID, AttemptID: attemptID, State: types.OperationRunning, StartedAt: now(), OwnerID: actor.ID}
	return op, nil
}

func (s *Service) registerAndRunOperation(op types.Operation, run func(context.Context) error) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return coded("service_closing", "daemon is shutting down", nil)
	}
	if op.Kind == "connect" || op.Kind == "disconnect" || op.Kind == "profile-update" || op.Kind == "profile-delete" || op.Kind == "control-mode" {
		// Cancel the old transaction before this command waits for commandMu.
		// Intent is changed by the command after its profile checks succeed.
		s.invalidateReconnectLocked()
		s.reconnect = reconnectState{generation: s.reconnect.generation}
		if s.attemptCancel != nil {
			s.attemptCancel()
		}
	}
	s.operations[op.ID] = op
	s.status.Operation = cloneOperation(&op)
	s.emitLocked(types.Notify{Event: "operation", Operation: cloneOperation(&op)})
	s.mu.Unlock()
	go func() {
		s.commandMu.Lock()
		defer s.commandMu.Unlock()
		operationCtx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			select {
			case <-s.loopStop:
				cancel()
			case <-operationCtx.Done():
			}
		}()
		err := run(operationCtx)
		s.mu.Lock()
		terminal := op
		terminal.EndedAt = now()
		terminal.State = types.OperationSucceeded
		if err != nil {
			terminal.State = types.OperationFailed
			terminal.Error = sanitizeDiagnostic(err.Error())
			terminal.ErrorCode = errorCode(err)
		}
		s.emitLocked(types.Notify{Event: "operation", Operation: cloneOperation(&terminal), Error: terminal.Error})
		delete(s.operations, op.ID)
		if s.status.Operation != nil && s.status.Operation.ID == op.ID {
			s.status.Operation = nil
		}
		s.mu.Unlock()
	}()
	return nil
}

func (s *Service) OperationFor(actor Actor, id string) (types.Operation, error) {
	if err := s.authorize(actor, false); err != nil {
		return types.Operation{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	op, ok := s.operations[id]
	if !ok {
		return types.Operation{}, coded("operation_not_found", "operation not found", nil)
	}
	if !actor.System && !actor.Admin && op.OwnerID != actor.ID {
		return types.Operation{}, coded("operation_not_found", "operation not found", nil)
	}
	return op, nil
}

func errorCode(err error) string {
	var codedErr *CodedError
	if errors.As(err, &codedErr) {
		return codedErr.Code
	}
	if errors.Is(err, context.Canceled) {
		return "operation_canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "operation_timeout"
	}
	return "operation_failed"
}

func cloneOperation(op *types.Operation) *types.Operation {
	if op == nil {
		return nil
	}
	copy := *op
	return &copy
}

func (s *Service) SetControlMode(ctx context.Context, actor Actor, req types.ControlModeRequest) error {
	if !actor.System && !actor.Admin {
		return coded("admin_required", "control mode changes require an elevated administrator", nil)
	}
	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode != "user" && mode != "machine" {
		return coded("invalid_control_mode", "control mode must be user or machine", nil)
	}
	var machineProfile types.Profile
	if mode == "machine" {
		profile, err := s.profileForActor(actor, req.ProfileID)
		if err != nil {
			return err
		}
		if profile.Scope != types.ProfileScopeMachine {
			return coded("invalid_profile_scope", "machine mode requires a machine profile", nil)
		}
		machineProfile = profile
		if s.ConnectionActive() {
			if err := s.disconnect(ctx, false); err != nil {
				return fmt.Errorf("disconnect user connection before machine mode: %w", err)
			}
		}
	} else {
		if err := s.disconnect(ctx, false); err != nil {
			return fmt.Errorf("disconnect machine connection: %w", err)
		}
	}
	s.mu.Lock()
	s.controlMode = mode
	s.machineProfileID = req.ProfileID
	if mode == "user" {
		s.machineProfileID = ""
		s.activeOwnerID = ""
	}
	s.status.ControlMode = mode
	if mode == "machine" {
		s.currentID = machineProfile.ID
		s.activeOwnerID = "system"
		s.status.CurrentProfileID = machineProfile.ID
		s.status.SelectedProfileID = machineProfile.ID
	}
	err := s.persist()
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if mode == "user" {
		return nil
	}
	if err := s.Connect(ctx, machineProfile.ID); err != nil {
		if vpn.IsRetryable(err) {
			s.mu.Lock()
			manualSeq := s.disconnectSeq
			s.startReconnectLocked(machineProfile.ID, manualSeq, 1)
			s.mu.Unlock()
		}
		return err
	}
	return nil
}

func (s *Service) Ready() types.ReadyStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	components := make([]types.ComponentStatus, 0, len(s.health)+1)
	ready := !s.closed && s.intent == nil
	for _, name := range []string{"store", "secret", "supervisor", "backend", "route", "dns", "proxy", "watch", "cleanup"} {
		component := s.health[name]
		if name == "supervisor" && s.closed {
			component.Ready = false
			component.Message = "daemon is shutting down"
		}
		components = append(components, component)
		if !component.Ready {
			ready = false
		}
	}
	if s.intent != nil {
		components = append(components, types.ComponentStatus{Name: "profile-transaction", Ready: false, Message: "restart recovery required"})
	}
	if s.controlMode == "machine" && s.status.State == types.StateError {
		ready = false
		components = append(components, types.ComponentStatus{Name: "machine-connection", Ready: false, Message: sanitizeDiagnostic(s.status.LastError)})
	}
	return types.ReadyStatus{Ready: ready, Components: components}
}

func (s *Service) WatchSince(ctx context.Context, actor Actor, epoch string, since uint64) <-chan types.Notify {
	out := make(chan types.Notify, 32)
	if err := s.authorize(actor, false); err != nil {
		close(out)
		return out
	}
	s.mu.Lock()
	replay := make([]types.Notify, 0)
	needSnapshot := epoch != s.epoch || since == 0
	if !needSnapshot && len(s.eventRing) > 0 && since+1 < s.eventRing[0].Revision {
		needSnapshot = true
	}
	if !needSnapshot {
		for _, event := range s.eventRing {
			if event.Revision > since {
				replay = append(replay, s.notifyForActorLocked(actor, event))
			}
		}
	}
	if !needSnapshot && len(replay) == 0 && since < s.revision {
		needSnapshot = true
	}
	live := make(chan types.Notify, 32)
	watcherID := s.nextWatcherID
	s.nextWatcherID++
	s.watchers[watcherID] = live
	status := s.statusForActorLocked(actor)
	profiles := make([]types.Profile, 0, len(s.profiles))
	for _, profile := range s.profiles {
		if actorCanAccessProfile(actor, profile) {
			profiles = append(profiles, publicProfile(profile, actor))
		}
	}
	currentRevision := s.revision
	currentEpoch := s.epoch
	s.mu.Unlock()
	go func() {
		<-ctx.Done()
		s.mu.Lock()
		if _, ok := s.watchers[watcherID]; ok {
			delete(s.watchers, watcherID)
			close(live)
		}
		s.mu.Unlock()
	}()
	go func() {
		defer close(out)
		if needSnapshot {
			out <- types.Notify{Epoch: currentEpoch, Revision: currentRevision, Event: "snapshot", Status: &status, Profiles: profiles, Time: now()}
		} else {
			for _, event := range replay {
				out <- event
			}
		}
		for event := range live {
			s.mu.Lock()
			filtered := s.notifyForActorLocked(actor, event)
			s.mu.Unlock()
			out <- filtered
		}
	}()
	return out
}

func (s *Service) notifyForActorLocked(actor Actor, event types.Notify) types.Notify {
	copy := cloneNotify(event)
	if copy.Status != nil {
		status := s.statusForActorLocked(actor)
		copy.Status = &status
	}
	if copy.Profile != nil {
		if !actorCanAccessProfile(actor, *copy.Profile) {
			copy.Profile = nil
		} else {
			profile := publicProfile(*copy.Profile, actor)
			copy.Profile = &profile
		}
	}
	profiles := copy.Profiles[:0]
	for _, profile := range copy.Profiles {
		if actorCanAccessProfile(actor, profile) {
			profiles = append(profiles, publicProfile(profile, actor))
		}
	}
	copy.Profiles = profiles
	if !actor.System && !actor.Admin {
		copy.Logs = nil
		if copy.Connection != nil {
			profile, err := s.findProfileLocked(copy.Connection.ProfileID)
			if err != nil || !actorCanAccessProfile(actor, profile) {
				copy.Connection = nil
			}
		}
	}
	return copy
}

func cloneStatus(status types.Status) types.Status {
	copy := status
	copy.Operation = cloneOperation(status.Operation)
	if status.Session != nil {
		session := *status.Session
		session.DNS = append([]string(nil), status.Session.DNS...)
		session.SplitInclude = append([]string(nil), status.Session.SplitInclude...)
		session.SplitExclude = append([]string(nil), status.Session.SplitExclude...)
		copy.Session = &session
		if status.Session.Underlay != nil {
			underlay := *status.Session.Underlay
			session.Underlay = &underlay
		}
	}
	copy.EffectiveRoutes = append([]types.RouteSpec(nil), status.EffectiveRoutes...)
	return copy
}

func cloneNotify(event types.Notify) types.Notify {
	copy := event
	if event.Status != nil {
		status := cloneStatus(*event.Status)
		copy.Status = &status
	}
	if event.Traffic != nil {
		traffic := *event.Traffic
		copy.Traffic = &traffic
	}
	if event.Profile != nil {
		profile := cloneProfile(*event.Profile)
		copy.Profile = &profile
	}
	copy.Profiles = make([]types.Profile, len(event.Profiles))
	for i := range event.Profiles {
		copy.Profiles[i] = cloneProfile(event.Profiles[i])
	}
	copy.Logs = append([]types.LogEntry(nil), event.Logs...)
	copy.Operation = cloneOperation(event.Operation)
	if event.Connection != nil {
		connection := *event.Connection
		connection.TransportFaults = append([]types.ConnectionFault(nil), event.Connection.TransportFaults...)
		copy.Connection = &connection
	}
	if event.Network != nil {
		network := *event.Network
		network.Reasons = append([]string(nil), event.Network.Reasons...)
		if event.Network.Before != nil {
			before := *event.Network.Before
			network.Before = &before
		}
		if event.Network.After != nil {
			after := *event.Network.After
			network.After = &after
		}
		copy.Network = &network
	}
	return copy
}

func cloneProfile(profile types.Profile) types.Profile {
	profile.ATrustCompatibility = profile.ATrustCompatibility.Clone()
	profile.CustomInclude = append([]string(nil), profile.CustomInclude...)
	profile.CustomExclude = append([]string(nil), profile.CustomExclude...)
	profile.DNSOverrides = append([]string(nil), profile.DNSOverrides...)
	return profile
}
