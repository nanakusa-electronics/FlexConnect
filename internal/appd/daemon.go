package appd

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"flexconnect/internal/buildinfo"
	"flexconnect/internal/logbuf"
	"flexconnect/internal/logging"
	"flexconnect/internal/profileio"
	"flexconnect/internal/router"
	"flexconnect/internal/secret"
	"flexconnect/internal/socks5"
	storefile "flexconnect/internal/store/file"
	"flexconnect/internal/types"
	"flexconnect/internal/updater"
	"flexconnect/internal/vpn"
	geektrust "github.com/nanakusa-electronics/geektrust/client"
)

var (
	autoReconnectMinDelay = 2 * time.Second
	autoReconnectMaxDelay = 1 * time.Minute
	autoReconnectMaxTries = 3
)

var appdDebug bool
var errNoCurrentProfile = errors.New("no current profile selected")
var errConnectInProgress = errors.New("connection already in progress")
var appdLog = logging.WithComponent("appd")
var appdDebugLog = logging.WithComponent("appd")
var newID = types.NewID
var newProfile = types.NewProfile

func SetDebug(enabled bool) {
	appdDebug = enabled
}

func appdDebugf(format string, args ...any) {
	if !appdDebug {
		return
	}
	appdDebugLog.Debugf(format, args...)
}

type Store interface {
	Load() (storefile.Data, error)
	Save(storefile.Data) error
}

type Service struct {
	mu                      sync.Mutex
	commandMu               sync.Mutex
	store                   Store
	secrets                 secret.Store
	backend                 vpn.Backend
	planner                 router.Planner
	profiles                []types.Profile
	currentID               string
	connectedID             string
	status                  types.Status
	logs                    *logbuf.Buffer
	watchers                map[int]chan types.Notify
	nextWatcherID           int
	proxyServer             *socks5.Server
	disconnectSeq           uint64
	manualDisconnectSeq     uint64
	manualProfileID         string
	reconnect               reconnectState
	desiredProfileID        string
	suspended               bool
	networkOffline          bool
	traffic                 types.TrafficSnapshot
	lastTraffic             *types.TrafficStats
	lastTrafficAt           time.Time
	connectionSeq           uint64
	activeConnectionID      string
	networkConnectionID     string
	activeConnectionStarted time.Time
	connectionHistory       []types.ConnectionEvent
	lastNetworkChange       *types.NetworkChange
	updater                 updateChecker
	updateCache             types.UpdateInfo
	updateCacheAt           time.Time
	updateInterval          time.Duration
	updateNotified          bool
	selectedProfiles        map[string]string
	controlMode             string
	machineProfileID        string
	activeOwnerID           string
	operations              map[string]types.Operation
	epoch                   string
	revision                uint64
	eventRing               []types.Notify
	attemptID               string
	attemptCancel           context.CancelFunc
	closed                  bool
	loopStop                chan struct{}
	intent                  *storefile.Intent
	health                  map[string]types.ComponentStatus
	fatalErr                error
	fatalCh                 chan error
	fatalOnce               sync.Once
}

// updateChecker abstracts the online update probe so tests can inject a fake.
// It is satisfied by *updater.Checker.
type updateChecker interface {
	Check(ctx context.Context) updater.Info
}

func New(store Store, secrets secret.Store, backend vpn.Backend, planner router.Planner) (*Service, error) {
	appdLog.Printf("creating service")
	epoch, err := newID()
	if err != nil {
		return nil, fmt.Errorf("generate daemon epoch: %w", err)
	}
	s := &Service{
		store:            store,
		secrets:          secrets,
		backend:          backend,
		planner:          planner,
		logs:             logbuf.New(500),
		status:           types.Status{State: types.StateDisconnected, UpdatedAt: now()},
		watchers:         map[int]chan types.Notify{},
		selectedProfiles: map[string]string{},
		operations:       map[string]types.Operation{},
		epoch:            epoch,
		loopStop:         make(chan struct{}),
		health:           make(map[string]types.ComponentStatus),
		fatalCh:          make(chan error, 1),
	}
	for _, component := range []string{"store", "secret", "supervisor", "backend", "route", "dns", "proxy", "watch", "cleanup"} {
		s.health[component] = types.ComponentStatus{Name: component, Ready: true}
	}
	if err := s.load(); err != nil {
		appdLog.Printf("load state failed err=%v", err)
		return nil, err
	}
	appdLog.Printf("loaded service count=%d", len(s.profiles))
	appdDebugf("service initialized current=%s profile_count=%d", s.currentID, len(s.profiles))
	go s.consumeBackendEvents()
	go s.sampleTrafficLoop()
	return s, nil
}

func (s *Service) load() error {
	data, err := s.store.Load()
	if err != nil {
		s.health["store"] = types.ComponentStatus{Name: "store", Ready: false, Message: sanitizeDiagnostic(err.Error())}
		appdLog.Printf("store load failed err=%v", err)
		return err
	}
	s.health["store"] = types.ComponentStatus{Name: "store", Ready: true}
	if data.SchemaVersion != storefile.CurrentSchemaVersion {
		return fmt.Errorf("unsupported state schema version %d; FlexConnect 2.0.0 requires schema version %d and does not migrate older state", data.SchemaVersion, storefile.CurrentSchemaVersion)
	}
	appdLog.Printf("loaded state current_id=%s total_profiles=%d", data.CurrentProfileID, len(data.Profiles))
	s.profiles = data.Profiles
	s.selectedProfiles = cloneStringMap(data.SelectedProfiles)
	s.controlMode = data.ControlMode
	if s.controlMode == "" {
		return errors.New("state control_mode is required")
	}
	if s.controlMode != "user" && s.controlMode != "machine" {
		return fmt.Errorf("invalid state control_mode %q", s.controlMode)
	}
	s.machineProfileID = data.MachineProfileID
	s.intent = data.Intent
	s.currentID = data.CurrentProfileID
	for i := range s.profiles {
		if s.profiles[i].SecretRef == "" {
			return fmt.Errorf("profile %q has no secret reference", s.profiles[i].ID)
		}
		s.profiles[i] = profileio.NormalizeProfile(s.profiles[i])
		if err := profileio.ValidateProfile(s.profiles[i]); err != nil {
			return fmt.Errorf("invalid profile %q: %w", s.profiles[i].ID, err)
		}
	}
	if s.currentID != "" {
		if _, err := s.findProfileLocked(s.currentID); err != nil {
			return fmt.Errorf("state current_profile_id %q does not reference a profile", s.currentID)
		}
	}
	for owner, profileID := range s.selectedProfiles {
		if strings.TrimSpace(owner) == "" {
			return errors.New("state selected_profiles contains an empty owner")
		}
		profile, err := s.findProfileLocked(profileID)
		if err != nil {
			return fmt.Errorf("selected profile %q for owner %q does not exist", profileID, owner)
		}
		if profile.Scope != types.ProfileScopeUser || profile.OwnerID != owner {
			return fmt.Errorf("selected profile %q is not owned by %q", profileID, owner)
		}
	}
	if s.controlMode == "machine" {
		profile, err := s.findProfileLocked(s.machineProfileID)
		if err != nil || profile.Scope != types.ProfileScopeMachine {
			return errors.New("machine mode requires a valid machine_profile_id")
		}
	} else if s.machineProfileID != "" {
		return errors.New("machine_profile_id must be empty in user mode")
	}
	s.status.CurrentProfileID = s.currentID
	s.status.SelectedProfileID = s.currentID
	s.status.ControlMode = s.controlMode
	if err := s.recoverIntentLocked(); err != nil {
		return fmt.Errorf("recover profile transaction: %w", err)
	}
	appdDebugf("state loaded current=%s profile_count=%d", s.currentID, len(s.profiles))
	return nil
}

func (s *Service) persist() error {
	err := s.store.Save(storefile.Data{
		SchemaVersion:    storefile.CurrentSchemaVersion,
		Profiles:         s.profiles,
		CurrentProfileID: s.currentID,
		SelectedProfiles: cloneStringMap(s.selectedProfiles),
		ControlMode:      s.controlMode,
		MachineProfileID: s.machineProfileID,
		Intent:           s.intent,
	})
	if err != nil {
		s.health["store"] = types.ComponentStatus{Name: "store", Ready: false, Message: sanitizeDiagnostic(err.Error())}
		appdLog.Printf("failed to persist state err=%v", err)
		return err
	}
	s.health["store"] = types.ComponentStatus{Name: "store", Ready: true}
	appdLog.Printf("persisted state current_id=%s profile_count=%d", s.currentID, len(s.profiles))
	return nil
}

func (s *Service) commitProfileLocked(index int, profile *types.Profile, password, oldSecretRef string) error {
	if profile == nil {
		return errors.New("profile transaction has no profile")
	}
	if s.intent != nil {
		return errors.New("another profile transaction is pending recovery")
	}
	newSecretRef := oldSecretRef
	if password != "" {
		id, err := newID()
		if err != nil {
			return fmt.Errorf("generate secret reference: %w", err)
		}
		newSecretRef = "profile/" + profile.ID + "/" + id
	}
	if newSecretRef == "" {
		return errors.New("profile transaction has no secret reference")
	}
	profile.SecretRef = newSecretRef
	profileCopy := *profile
	s.intent = &storefile.Intent{Version: 1, Kind: "upsert", ProfileID: profile.ID, NewProfile: &profileCopy, OldSecretRef: oldSecretRef, NewSecretRef: newSecretRef}
	if err := s.persist(); err != nil {
		s.intent = nil
		return fmt.Errorf("write profile intent: %w", err)
	}
	if password != "" {
		if err := s.secrets.Put(newSecretRef, password); err != nil {
			s.health["secret"] = types.ComponentStatus{Name: "secret", Ready: false, Message: sanitizeDiagnostic(err.Error())}
			return fmt.Errorf("write new profile secret: %w", err)
		}
		s.health["secret"] = types.ComponentStatus{Name: "secret", Ready: true}
	}
	if index < 0 {
		s.profiles = append(s.profiles, profileCopy)
	} else {
		s.profiles[index] = profileCopy
	}
	if err := s.persist(); err != nil {
		return fmt.Errorf("commit profile state: %w", err)
	}
	if oldSecretRef != "" && oldSecretRef != newSecretRef {
		if err := s.secrets.Delete(oldSecretRef); err != nil {
			s.health["secret"] = types.ComponentStatus{Name: "secret", Ready: false, Message: sanitizeDiagnostic(err.Error())}
			return fmt.Errorf("delete previous profile secret: %w", err)
		}
		s.health["secret"] = types.ComponentStatus{Name: "secret", Ready: true}
	}
	completedIntent := s.intent
	s.intent = nil
	if err := s.persist(); err != nil {
		s.intent = completedIntent
		return fmt.Errorf("clear profile intent: %w", err)
	}
	return nil
}

func (s *Service) recoverIntentLocked() error {
	intent := s.intent
	if intent == nil {
		return nil
	}
	if intent.Version != 1 {
		return fmt.Errorf("unsupported intent version %d", intent.Version)
	}
	switch intent.Kind {
	case "upsert":
		if intent.NewProfile == nil || intent.NewSecretRef == "" {
			return errors.New("invalid upsert intent")
		}
		if _, err := s.secrets.Get(intent.NewSecretRef); err != nil {
			if errors.Is(err, secret.ErrNotFound) {
				s.intent = nil
				return s.persist()
			}
			return fmt.Errorf("read new secret: %w", err)
		}
		s.health["secret"] = types.ComponentStatus{Name: "secret", Ready: true}
		index := -1
		for i := range s.profiles {
			if s.profiles[i].ID == intent.ProfileID {
				index = i
				break
			}
		}
		profile := *intent.NewProfile
		if index < 0 {
			s.profiles = append(s.profiles, profile)
		} else {
			s.profiles[index] = profile
		}
		if err := s.persist(); err != nil {
			return fmt.Errorf("recover profile state: %w", err)
		}
		if intent.OldSecretRef != "" && intent.OldSecretRef != intent.NewSecretRef {
			if err := s.secrets.Delete(intent.OldSecretRef); err != nil {
				s.health["secret"] = types.ComponentStatus{Name: "secret", Ready: false, Message: sanitizeDiagnostic(err.Error())}
				return fmt.Errorf("recover old secret deletion: %w", err)
			}
			s.health["secret"] = types.ComponentStatus{Name: "secret", Ready: true}
		}
	case "delete":
		for i := range s.profiles {
			if s.profiles[i].ID == intent.ProfileID {
				s.profiles = append(s.profiles[:i], s.profiles[i+1:]...)
				break
			}
		}
		if err := s.persist(); err != nil {
			return fmt.Errorf("recover profile deletion: %w", err)
		}
		if intent.OldSecretRef != "" {
			if err := s.secrets.Delete(intent.OldSecretRef); err != nil {
				s.health["secret"] = types.ComponentStatus{Name: "secret", Ready: false, Message: sanitizeDiagnostic(err.Error())}
				return fmt.Errorf("recover deleted profile secret: %w", err)
			}
			s.health["secret"] = types.ComponentStatus{Name: "secret", Ready: true}
		}
	default:
		return fmt.Errorf("unsupported intent kind %q", intent.Kind)
	}
	completedIntent := s.intent
	s.intent = nil
	if err := s.persist(); err != nil {
		s.intent = completedIntent
		return fmt.Errorf("clear recovered intent: %w", err)
	}
	return nil
}

func cloneStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func (s *Service) Status() types.Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshConnectedStatusLocked()
	return s.status
}

func (s *Service) Traffic() types.TrafficSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.traffic
}

func (s *Service) Logs() []types.LogEntry {
	return s.logs.Snapshot()
}

func (s *Service) Diagnostics() types.Diagnostics {
	s.mu.Lock()
	defer s.mu.Unlock()

	status := cloneStatus(s.status)
	profiles := make([]types.Profile, len(s.profiles))
	for i := range s.profiles {
		profiles[i] = cloneProfile(s.profiles[i])
	}
	if status.State == types.StateConnected {
		s.refreshConnectedStatusLocked()
		status = cloneStatus(s.status)
	}
	var current *types.Profile
	for _, profile := range profiles {
		if profile.ID == s.currentID {
			cp := profile
			current = &cp
			break
		}
	}
	var runtime *types.RuntimeDiagnostics
	if provider, ok := s.backend.(interface {
		RuntimeDiagnostics() *types.RuntimeDiagnostics
	}); ok {
		runtime = cloneRuntimeDiagnostics(provider.RuntimeDiagnostics())
	}
	if runtime != nil && s.lastNetworkChange != nil {
		if runtime.Tunnel == nil {
			runtime.Tunnel = &types.TunnelRuntime{}
		}
		runtime.Tunnel.LastNetworkChange = s.lastNetworkChange.Time
		runtime.Tunnel.LastNetworkChangeInfo = strings.Join(s.lastNetworkChange.Reasons, ",")
	}
	return types.Diagnostics{
		Version:           buildinfo.Version,
		Status:            status,
		CurrentProfile:    current,
		Profiles:          profiles,
		ServerConfig:      cloneAnyMap(s.backend.ReadServerConfig()),
		Traffic:           ptrTraffic(s.traffic),
		Logs:              s.logs.Snapshot(),
		GeneratedAt:       now(),
		ConnectionHistory: cloneConnectionHistory(s.connectionHistory),
		Reconnect:         s.reconnectSnapshotLocked(),
		Runtime:           runtime,
		Health:            s.healthSnapshotLocked(),
	}
}

func cloneRuntimeDiagnostics(in *types.RuntimeDiagnostics) *types.RuntimeDiagnostics {
	if in == nil {
		return nil
	}
	out := *in
	if in.Underlay != nil {
		underlay := *in.Underlay
		out.Underlay = &underlay
	}
	if in.Tunnel != nil {
		tunnel := *in.Tunnel
		out.Tunnel = &tunnel
	}
	return &out
}

func cloneConnectionHistory(in []types.ConnectionEvent) []types.ConnectionEvent {
	out := make([]types.ConnectionEvent, len(in))
	for i := range in {
		out[i] = in[i]
		out[i].TransportFaults = append([]types.ConnectionFault(nil), in[i].TransportFaults...)
	}
	return out
}

func cloneAnyMap(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for key, value := range in {
		out[key] = cloneAny(value)
	}
	return out
}

func cloneAny(value any) any {
	switch value := value.(type) {
	case map[string]any:
		return cloneAnyMap(value)
	case []any:
		out := make([]any, len(value))
		for i := range value {
			out[i] = cloneAny(value[i])
		}
		return out
	case []string:
		return append([]string(nil), value...)
	case []types.RouteSpec:
		return append([]types.RouteSpec(nil), value...)
	default:
		return value
	}
}

func (s *Service) healthSnapshotLocked() []types.ComponentStatus {
	out := make([]types.ComponentStatus, 0, len(s.health))
	for _, name := range []string{"store", "secret", "supervisor", "backend", "route", "dns", "proxy", "watch", "cleanup"} {
		out = append(out, s.health[name])
	}
	return out
}

func (s *Service) reconnectSnapshotLocked() types.ReconnectSnapshot {
	if !s.reconnect.pending() {
		return types.ReconnectSnapshot{}
	}
	snapshot := types.ReconnectSnapshot{
		Active:    s.reconnect.timer != nil || s.reconnect.running,
		ProfileID: s.reconnect.profileID, Attempt: s.reconnect.attempt,
		LifecycleID: s.reconnect.lifecycleID,
	}
	if !s.reconnect.nextAt.IsZero() {
		snapshot.NextRetryAt = s.reconnect.nextAt.UTC().Format(time.RFC3339Nano)
	}
	return snapshot
}

func (s *Service) recordConnectionLocked(event types.ConnectionEvent) {
	s.connectionSeq++
	event.ID = fmt.Sprintf("connection-event-%d", s.connectionSeq)
	if event.Time == "" {
		event.Time = now()
	}
	event.Error = sanitizeDiagnostic(event.Error)
	if len(s.connectionHistory) >= 64 {
		s.connectionHistory = append([]types.ConnectionEvent(nil), s.connectionHistory[len(s.connectionHistory)-63:]...)
	}
	s.connectionHistory = append(s.connectionHistory, event)
	s.logs.Add("info", fmt.Sprintf("appd: connection event kind=%s profile=%s reason=%s attempt=%d", event.Kind, event.ProfileID, event.ReasonCode, event.Attempt))
	s.emitLocked(types.Notify{Event: "connection", Connection: &event, Message: event.Kind})
}

func sanitizeDiagnostic(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(value, "\r", " "), "\n", " "))
	if len(value) > 512 {
		value = value[:512]
	}
	return value
}

func (s *Service) refreshConnectedStatusLocked() {
	if session := s.backend.SessionInfo(); session != nil {
		s.status.Session = session
	}
}

func (s *Service) sampleTrafficLoop() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case t := <-ticker.C:
			s.sampleTrafficAt(t.UTC())
		case <-s.loopStop:
			return
		}
	}
}

func (s *Service) sampleTrafficAt(t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.sampleTrafficLocked(t) {
		return
	}
	s.emitLocked(types.Notify{Event: "traffic", Traffic: ptrTraffic(s.traffic)})
}

func (s *Service) sampleTrafficLocked(t time.Time) bool {
	if s.status.State != types.StateConnected {
		return s.clearTrafficLocked()
	}
	totals := s.backend.Traffic()
	if totals == nil {
		return s.clearTrafficLocked()
	}
	next := types.TrafficSnapshot{
		Connected:     true,
		BytesSent:     totals.BytesSent,
		BytesReceived: totals.BytesReceived,
		SampledAt:     t.Format(time.RFC3339),
	}
	if s.lastTraffic != nil && !s.lastTrafficAt.IsZero() {
		if seconds := t.Sub(s.lastTrafficAt).Seconds(); seconds > 0 {
			if totals.BytesSent >= s.lastTraffic.BytesSent {
				next.BytesSentPerSecond = float64(totals.BytesSent-s.lastTraffic.BytesSent) / seconds
			}
			if totals.BytesReceived >= s.lastTraffic.BytesReceived {
				next.BytesReceivedPerSecond = float64(totals.BytesReceived-s.lastTraffic.BytesReceived) / seconds
			}
		}
	}
	s.lastTraffic = &types.TrafficStats{BytesSent: totals.BytesSent, BytesReceived: totals.BytesReceived}
	s.lastTrafficAt = t
	s.traffic = next
	return true
}

func (s *Service) clearTrafficLocked() bool {
	changed := s.traffic.Connected || s.traffic.BytesSent != 0 || s.traffic.BytesReceived != 0 ||
		s.traffic.BytesSentPerSecond != 0 || s.traffic.BytesReceivedPerSecond != 0
	s.traffic = types.TrafficSnapshot{}
	s.lastTraffic = nil
	s.lastTrafficAt = time.Time{}
	return changed
}

func (s *Service) ListProfiles() []types.Profile {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]types.Profile(nil), s.profiles...)
	slices.SortFunc(out, func(a, b types.Profile) int {
		if a.Name < b.Name {
			return -1
		}
		if a.Name > b.Name {
			return 1
		}
		return 0
	})
	return out
}

func (s *Service) CurrentProfile() (types.Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.currentID == "" {
		return types.Profile{}, errNoCurrentProfile
	}
	return s.findProfileLocked(s.currentID)
}

func (s *Service) CreateProfile(profile types.Profile, password string) (types.Profile, error) {
	appdLog.Printf("create profile name=%q", profile.Name)
	s.mu.Lock()
	defer s.mu.Unlock()
	if profile.ID == "" {
		created, err := newProfile(profile.Name)
		if err != nil {
			return types.Profile{}, fmt.Errorf("generate profile ID: %w", err)
		}
		profile = created
	}
	profile = profileio.NormalizeProfile(profile)
	if err := profileio.ValidateProfile(profile); err != nil {
		return types.Profile{}, err
	}
	for _, existing := range s.profiles {
		if existing.ID == profile.ID {
			return types.Profile{}, fmt.Errorf("profile ID already exists: %s", profile.ID)
		}
	}
	profile.UpdatedAt = now()
	if profile.CreatedAt == "" {
		profile.CreatedAt = profile.UpdatedAt
	}
	if profile.SecretRef == "" {
		profile.SecretRef = "profile/" + profile.ID
	}
	if password == "" {
		return types.Profile{}, errors.New("profile credential is required")
	}
	if err := s.commitProfileLocked(-1, &profile, password, ""); err != nil {
		return types.Profile{}, err
	}
	if s.currentID == "" {
		s.currentID = profile.ID
		s.status.CurrentProfileID = profile.ID
	}
	if err := s.persist(); err != nil {
		return types.Profile{}, err
	}
	s.logs.Add("info", fmt.Sprintf("appd: profile created id=%s name=%q", profile.ID, profile.Name))
	s.emitLocked(types.Notify{Event: "profiles", Profiles: append([]types.Profile(nil), s.profiles...)})
	appdLog.Printf("profile created id=%s total=%d", profile.ID, len(s.profiles))
	return profile, nil
}

func (s *Service) UpdateProfile(id string, req types.ProfileUpdateRequest) (types.Profile, error) {
	profile, _, err := s.updateProfile(id, req, true)
	return profile, err
}

func (s *Service) updateProfile(id string, req types.ProfileUpdateRequest, applyRuntime bool) (types.Profile, bool, error) {
	appdLog.Printf("update profile start id=%s", id)
	appdDebugf("update profile request id=%s", id)
	s.mu.Lock()
	index := -1
	for i, p := range s.profiles {
		if p.ID == id {
			index = i
			break
		}
	}
	if index == -1 {
		s.mu.Unlock()
		return types.Profile{}, false, fmt.Errorf("profile not found: %s", id)
	}
	before := s.profiles[index]
	appdDebugf("update profile before id=%s name=%q accept=%v include=%d exclude=%d",
		before.ID, before.Name, before.AcceptServerRoutes, len(before.CustomInclude), len(before.CustomExclude))
	profile := before
	if req.Name != nil {
		profile.Name = *req.Name
	}
	if req.Provider != nil {
		profile.Provider = *req.Provider
	}
	if req.AuthMethod != nil {
		profile.AuthMethod = *req.AuthMethod
	}
	if req.LoginDomain != nil {
		profile.LoginDomain = *req.LoginDomain
	}
	if req.ServerURL != nil {
		profile.ServerURL = *req.ServerURL
	}
	if req.Username != nil {
		profile.Username = *req.Username
	}
	if req.Group != nil {
		profile.Group = *req.Group
	}
	if req.AcceptServerRoutes != nil {
		profile.AcceptServerRoutes = *req.AcceptServerRoutes
	}
	if req.AutoReconnect != nil {
		profile.AutoReconnect = req.AutoReconnect
	}
	if req.ApplyDNS != nil {
		profile.ApplyDNS = req.ApplyDNS
	}
	if req.CustomInclude != nil {
		profile.CustomInclude = append([]string(nil), req.CustomInclude...)
	}
	if req.CustomExclude != nil {
		profile.CustomExclude = append([]string(nil), req.CustomExclude...)
	}
	if req.DNSOverrides != nil {
		profile.DNSOverrides = append([]string(nil), req.DNSOverrides...)
	}
	if req.SOCKS5Enabled != nil {
		profile.SOCKS5Enabled = *req.SOCKS5Enabled
	}
	if req.SOCKS5Listen != nil {
		profile.SOCKS5Listen = *req.SOCKS5Listen
	}
	if req.MTU != nil {
		profile.MTU = *req.MTU
	}
	profile = profileio.NormalizeProfile(profile)
	if err := profileio.ValidateProfile(profile); err != nil {
		s.mu.Unlock()
		return types.Profile{}, false, err
	}
	profile.UpdatedAt = now()
	password := ""
	if req.Password != nil {
		password = *req.Password
	}
	if len(req.Credential) != 0 {
		info, inspectErr := geektrust.InspectPasskey(req.Credential)
		if profile.Provider != types.ProviderATrust || len(req.Credential) > 1<<20 || inspectErr != nil || !passkeyMethodMatches(profile.AuthMethod, info.Kind) || profile.Username != info.Username {
			s.mu.Unlock()
			return types.Profile{}, false, errors.New("invalid passkey credential")
		}
		password = base64.StdEncoding.EncodeToString(req.Credential)
	}
	if req.Password != nil && profile.Provider != types.ProviderAnyConnect {
		s.mu.Unlock()
		return types.Profile{}, false, errors.New("password update requires AnyConnect provider")
	}
	if req.Password != nil && len(req.Credential) != 0 {
		s.mu.Unlock()
		return types.Profile{}, false, errors.New("provide one credential type")
	}
	if (before.Provider != profile.Provider || before.AuthMethod != profile.AuthMethod) && password == "" {
		s.mu.Unlock()
		return types.Profile{}, false, errors.New("changing provider or authentication method requires a new credential")
	}
	if req.Password != nil && password == "" {
		s.mu.Unlock()
		return types.Profile{}, false, errors.New("profile password cannot be empty")
	}
	if err := s.commitProfileLocked(index, &profile, password, before.SecretRef); err != nil {
		s.mu.Unlock()
		return types.Profile{}, false, err
	}
	shouldReconnect := s.connectedID == id && needsReconnectForProfileUpdate(before, profile)
	appdDebugf("update profile result id=%s should_reconnect=%v", id, shouldReconnect)
	if s.connectedID == id && s.status.Session != nil {
		s.status.EffectiveRoutes = s.planner.Plan(s.status.Session.SplitInclude, s.status.Session.SplitExclude, profile)
		s.status.UpdatedAt = now()
		s.emitLocked(types.Notify{Event: "status", Status: ptrStatus(s.status)})
	}
	s.logs.Add("info", fmt.Sprintf("appd: profile updated id=%s name=%q", profile.ID, profile.Name))
	appdLog.Printf("update profile done id=%s reconnect=%v", id, shouldReconnect)
	s.emitLocked(types.Notify{Event: "profile", Profile: &profile})
	s.emitLocked(types.Notify{Event: "profiles", Profiles: append([]types.Profile(nil), s.profiles...)})
	s.mu.Unlock()
	if !applyRuntime {
		return profile, shouldReconnect, nil
	}
	if err := s.applyProxyProfile(profile); err != nil {
		return profile, shouldReconnect, err
	}
	if shouldReconnect {
		if err := s.reconnectProfile(context.Background(), id, "reapplying updated profile "+id); err != nil {
			return profile, shouldReconnect, err
		}
	}
	return profile, shouldReconnect, nil
}

func (s *Service) DeleteProfile(id string) error {
	appdLog.Printf("delete profile start id=%s", id)
	s.mu.Lock()
	index := -1
	for i, p := range s.profiles {
		if p.ID == id {
			index = i
			break
		}
	}
	if index == -1 {
		s.mu.Unlock()
		return fmt.Errorf("profile not found: %s", id)
	}
	wasActive := s.connectedID == id || (s.status.CurrentProfileID == id && s.attemptCancel != nil)
	s.mu.Unlock()
	if wasActive {
		if err := s.disconnect(context.Background(), false); err != nil {
			return fmt.Errorf("disconnect active profile before delete: %w", err)
		}
	}
	s.mu.Lock()
	index = -1
	for i, p := range s.profiles {
		if p.ID == id {
			index = i
			break
		}
	}
	if index == -1 {
		s.mu.Unlock()
		return fmt.Errorf("profile not found: %s", id)
	}
	if s.reconnect.profileID == id {
		s.stopReconnectLocked()
	}
	oldSecretRef := s.profiles[index].SecretRef
	s.intent = &storefile.Intent{Version: 1, Kind: "delete", ProfileID: id, OldSecretRef: oldSecretRef}
	if err := s.persist(); err != nil {
		s.intent = nil
		s.mu.Unlock()
		return err
	}
	s.profiles = append(s.profiles[:index], s.profiles[index+1:]...)
	for owner, selected := range s.selectedProfiles {
		if selected == id {
			delete(s.selectedProfiles, owner)
		}
	}
	if s.currentID == id {
		s.currentID = ""
		if len(s.profiles) == 1 {
			s.currentID = s.profiles[0].ID
		}
		s.status.CurrentProfileID = s.currentID
		s.status.SelectedProfileID = s.currentID
	}
	if err := s.persist(); err != nil {
		s.mu.Unlock()
		return err
	}
	if err := s.secrets.Delete(oldSecretRef); err != nil {
		s.health["secret"] = types.ComponentStatus{Name: "secret", Ready: false, Message: sanitizeDiagnostic(err.Error())}
		s.mu.Unlock()
		return fmt.Errorf("delete secret for profile %s: %w", id, err)
	}
	s.health["secret"] = types.ComponentStatus{Name: "secret", Ready: true}
	completedIntent := s.intent
	s.intent = nil
	if err := s.persist(); err != nil {
		s.intent = completedIntent
		s.mu.Unlock()
		return err
	}
	s.logs.Add("info", fmt.Sprintf("appd: profile deleted id=%s", id))
	appdLog.Printf("delete profile done id=%s remaining=%d", id, len(s.profiles))
	if wasActive {
		s.emitLocked(types.Notify{Event: "status", Status: ptrStatus(s.status)})
		s.emitLocked(types.Notify{Event: "traffic", Traffic: ptrTraffic(s.traffic)})
	}
	s.emitLocked(types.Notify{Event: "profiles", Profiles: append([]types.Profile(nil), s.profiles...)})
	s.mu.Unlock()
	return nil
}

func (s *Service) SwitchProfile(_ context.Context, id string) error {
	appdLog.Printf("switch profile request to=%s", id)
	s.mu.Lock()
	_, err := s.findProfileLocked(id)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	if s.currentID != id {
		s.stopReconnectLocked()
	}
	s.currentID = id
	s.status.CurrentProfileID = id
	if err := s.persist(); err != nil {
		s.mu.Unlock()
		return err
	}
	s.logs.Add("info", fmt.Sprintf("appd: switched current profile id=%s", id))
	appdLog.Printf("switch profile done current=%s", id)
	s.emitLocked(types.Notify{Event: "status", Status: ptrStatus(s.status)})
	s.mu.Unlock()
	return nil
}

func (s *Service) Connect(ctx context.Context, id string) error {
	appdDebugf("connect start profile=%s current=%s connected=%s", id, s.status.CurrentProfileID, s.connectedID)
	s.mu.Lock()
	s.stopReconnectLocked()
	profile, err := s.findProfileLocked(id)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	password, err := s.loadProfileSecret(profile)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()
	connectStart := time.Now()
	if err := s.connectPreparedProfile(ctx, profile, password, false); err != nil {
		appdLog.Printf("connect failed profile=%s err=%v", profile.ID, err)
		return err
	}
	s.mu.Lock()
	appdLog.Printf("connect success profile=%s state=%s", profile.ID, s.status.State)
	appdDebugf("connect success profile=%s duration=%s routes=%d", profile.ID, time.Since(connectStart), len(s.status.EffectiveRoutes))
	s.mu.Unlock()
	return nil
}

func (s *Service) ConnectCurrent(ctx context.Context) error {
	s.mu.Lock()
	currentID := s.currentID
	s.mu.Unlock()
	if currentID == "" {
		return errNoCurrentProfile
	}
	return s.Connect(ctx, currentID)
}

func (s *Service) Disconnect(ctx context.Context) error {
	return s.disconnect(ctx, true)
}

func (s *Service) FatalErrors() <-chan error { return s.fatalCh }

func (s *Service) failCleanup(err error) {
	if err == nil {
		return
	}
	s.mu.Lock()
	s.fatalErr = err
	s.health["cleanup"] = types.ComponentStatus{Name: "cleanup", Ready: false, Message: sanitizeDiagnostic(err.Error())}
	s.status.LastError = sanitizeDiagnostic(err.Error())
	s.status.State = types.StateError
	s.status.UpdatedAt = now()
	s.emitLocked(types.Notify{Event: "cleanup_failed", Status: ptrStatus(s.status), Error: s.status.LastError})
	s.mu.Unlock()
	s.fatalOnce.Do(func() { s.fatalCh <- err })
}

func (s *Service) Close(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.stopReconnectLocked()
	if s.attemptCancel != nil {
		s.attemptCancel()
	}
	close(s.loopStop)
	s.mu.Unlock()

	var closeErr error
	if err := s.stopProxy(); err != nil {
		closeErr = errors.Join(closeErr, fmt.Errorf("close SOCKS5 proxy: %w", err))
	}
	if err := s.backend.Close(ctx); err != nil {
		closeErr = errors.Join(closeErr, fmt.Errorf("close VPN backend: %w", err))
	}
	s.mu.Lock()
	s.attemptID = ""
	s.attemptCancel = nil
	s.connectedID = ""
	s.status.AttemptID = ""
	s.status.ConnectedProfileID = ""
	s.status.Session = nil
	s.status.EffectiveRoutes = nil
	s.status.State = types.StateDisconnected
	s.status.UpdatedAt = now()
	if closeErr != nil {
		s.health["cleanup"] = types.ComponentStatus{Name: "cleanup", Ready: false, Message: sanitizeDiagnostic(closeErr.Error())}
	} else {
		s.health["cleanup"] = types.ComponentStatus{Name: "cleanup", Ready: true}
	}
	for id, watcher := range s.watchers {
		delete(s.watchers, id)
		close(watcher)
	}
	s.mu.Unlock()
	return closeErr
}

func (s *Service) disconnect(ctx context.Context, manual bool) error {
	s.mu.Lock()
	appdDebugf("disconnect requested current_connected=%s", s.connectedID)
	active := s.connectedID != "" || s.attemptCancel != nil || s.status.State == types.StateConnecting || s.status.State == types.StateReconnecting
	cancelAttempt := s.attemptCancel
	if manual {
		s.stopReconnectLocked()
		if s.controlMode == "user" {
			s.activeOwnerID = ""
		}
	}
	if manual && s.connectedID != "" {
		s.disconnectSeq++
		s.manualDisconnectSeq = s.disconnectSeq
		s.manualProfileID = s.connectedID
	}
	if cancelAttempt != nil {
		cancelAttempt()
	}
	s.mu.Unlock()
	if err := s.stopProxy(); err != nil {
		s.failCleanup(fmt.Errorf("SOCKS5 cleanup failed: %w", err))
		return err
	}
	if !active {
		return nil
	}
	if err := s.backend.Disconnect(ctx); err != nil {
		s.failCleanup(fmt.Errorf("disconnect cleanup failed: %w", err))
		return err
	}
	s.mu.Lock()
	s.attemptID = ""
	s.attemptCancel = nil
	s.status.AttemptID = ""
	s.connectedID = ""
	s.status.State = types.StateDisconnected
	s.status.ConnectedProfileID = ""
	s.status.Session = nil
	s.status.EffectiveRoutes = nil
	s.status.LastError = ""
	if manual && s.controlMode == "user" {
		s.activeOwnerID = ""
	}
	s.clearTrafficLocked()
	s.status.UpdatedAt = now()
	s.logs.Add("info", fmt.Sprintf("appd: profile disconnected id=%s", s.status.CurrentProfileID))
	appdLog.Printf("disconnect done previous_profile=%s", s.status.CurrentProfileID)
	s.emitLocked(types.Notify{
		Event:   "status",
		Status:  ptrStatus(s.status),
		Message: "Disconnected.",
	})
	s.emitLocked(types.Notify{Event: "traffic", Traffic: ptrTraffic(s.traffic)})
	s.mu.Unlock()
	return nil
}

func (s *Service) UpdateRoutes(id string, req types.RouteUpdateRequest) (types.Profile, error) {
	appdLog.Printf("update routes start id=%s", id)
	appdDebugf("update routes request id=%s accept=%v include=%v exclude=%v", id, req.AcceptServerRoutes, req.CustomInclude, req.CustomExclude)
	s.mu.Lock()
	index := -1
	for i, p := range s.profiles {
		if p.ID == id {
			index = i
			break
		}
	}
	if index == -1 {
		s.mu.Unlock()
		return types.Profile{}, fmt.Errorf("profile not found: %s", id)
	}
	if req.AcceptServerRoutes != nil {
		s.profiles[index].AcceptServerRoutes = *req.AcceptServerRoutes
	}
	if req.CustomInclude != nil {
		s.profiles[index].CustomInclude = append([]string(nil), req.CustomInclude...)
	}
	if req.CustomExclude != nil {
		s.profiles[index].CustomExclude = append([]string(nil), req.CustomExclude...)
	}
	s.profiles[index].UpdatedAt = now()
	if err := s.persist(); err != nil {
		s.mu.Unlock()
		return types.Profile{}, err
	}
	profile := s.profiles[index]
	shouldReconnect := s.connectedID == id
	appdDebugf("update routes result id=%s should_reconnect=%v include=%d exclude=%d",
		id, shouldReconnect, len(profile.CustomInclude), len(profile.CustomExclude))
	if s.connectedID == id && s.status.Session != nil {
		s.status.EffectiveRoutes = s.planner.Plan(s.status.Session.SplitInclude, s.status.Session.SplitExclude, profile)
		s.status.UpdatedAt = now()
		s.emitLocked(types.Notify{Event: "status", Status: ptrStatus(s.status)})
	}
	s.logs.Add("info", fmt.Sprintf("appd: routes updated profile=%s include_count=%d exclude_count=%d", id, len(req.CustomInclude), len(req.CustomExclude)))
	appdLog.Printf("update routes done id=%s reconnect=%v", id, shouldReconnect)
	s.emitLocked(types.Notify{Event: "profile", Profile: &profile})
	s.mu.Unlock()
	if shouldReconnect {
		if err := s.reconnectProfile(context.Background(), id, "reapplying route changes for profile "+id); err != nil {
			return profile, err
		}
	}
	return profile, nil
}

// SetUpdater injects the online update probe and its cache interval. It is
// called once during daemon construction; a nil checker (or a zero interval)
// leaves update checks disabled.
func (s *Service) SetUpdater(c updateChecker, interval time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.updater = c
	s.updateInterval = interval
}

// UpdateCheck returns the latest online update status. Results are cached for
// the configured interval so frequent tray refreshes do not hit the network.
// When no updater is configured the check reports Disabled.
func (s *Service) UpdateCheck(ctx context.Context) (types.UpdateInfo, error) {
	s.mu.Lock()
	checker := s.updater
	interval := s.updateInterval
	cache := s.updateCache
	cacheAt := s.updateCacheAt
	s.mu.Unlock()

	if checker == nil {
		return types.UpdateInfo{CurrentVersion: buildinfo.Version, Disabled: true}, nil
	}
	if interval > 0 && !cacheAt.IsZero() && cache.CheckedAt != "" && time.Since(cacheAt) < interval {
		return cache, nil
	}

	info := checker.Check(ctx)
	result := info.ToTypes()
	// Only cache successful results so a transient network error does not
	// poison the cache for the whole interval.
	if result.Error == "" {
		s.mu.Lock()
		s.updateCache = result
		s.updateCacheAt = time.Now()
		s.updateNotified = false
		s.mu.Unlock()
	}
	return result, nil
}

func (s *Service) consumeBackendEvents() {
	appdDebugf("backend event loop started")
	for {
		var event vpn.Event
		var ok bool
		select {
		case <-s.loopStop:
			return
		case event, ok = <-s.backend.Events():
			if !ok {
				return
			}
		}
		appdLog.Printf("backend event type=%s", event.Type)
		appdDebugf("backend event type=%s err=%v session=%+v", event.Type, event.Err, event.Session)
		s.mu.Lock()
		var disconnectedProfileID string
		var scheduleAutoReconnect bool
		var manualSeq uint64
		var intentionalDisconnectEvent bool
		var networkRepairEvent bool
		switch event.Type {
		case "connected":
			// The connection attempt owns the commit. This event is observational
			// only; publishing Connected here would bypass required components.
			s.logs.Add("info", "appd: backend transport established")
		case "health":
			component := event.Component
			if component == "" {
				component = "backend"
			}
			if event.Err == nil {
				s.health[component] = types.ComponentStatus{Name: component, Ready: true}
				s.emitLocked(types.Notify{Event: "health", Message: component + " recovered"})
			} else {
				message := sanitizeDiagnostic(event.Err.Error())
				s.health[component] = types.ComponentStatus{Name: component, Ready: false, Message: message}
				s.logs.Add("error", fmt.Sprintf("appd: component unhealthy component=%s err=%q", component, message))
				s.emitLocked(types.Notify{Event: "health", Error: message, Message: component + " is unhealthy"})
			}
			s.mu.Unlock()
			continue
		case "network_change":
			s.handleNetworkChangeLocked(event)
			s.mu.Unlock()
			continue
		case "disconnected":
			if event.ConnectionID != "" && event.ConnectionID != s.activeConnectionID {
				appdLog.Printf("ignoring stale backend disconnect connection=%s active=%s", event.ConnectionID, s.activeConnectionID)
				s.mu.Unlock()
				continue
			}
			disconnectedProfileID = s.connectedID
			if disconnectedProfileID == "" && s.manualProfileID != "" {
				disconnectedProfileID = s.manualProfileID
			}
			networkRepairEvent = s.reconnect.repair && s.reconnect.connectionID != "" && event.ConnectionID == s.reconnect.connectionID
			autoProfile, autoProfileFound := s.profileAutoReconnect(disconnectedProfileID)
			manual := disconnectedProfileID != "" && disconnectedProfileID == s.manualProfileID && s.manualDisconnectSeq == s.disconnectSeq
			localRequested := event.Close != nil && event.Close.Code == "local_requested"
			intentionalDisconnectEvent = manual || localRequested
			if manual {
				s.manualProfileID = ""
				s.manualDisconnectSeq = 0
			}
			// A planned teardown belongs to the same lifecycle as its replacement.
			if !intentionalDisconnectEvent && !networkRepairEvent && s.currentID == disconnectedProfileID &&
				autoProfileFound && s.autoReconnectEnabledLocked(autoProfile) &&
				!s.reconnect.pending() && s.desiredProfileID == disconnectedProfileID && retryableDisconnectEvent(event) {
				manualSeq = s.disconnectSeq
				scheduleAutoReconnect = true
			}
			if !networkRepairEvent && (intentionalDisconnectEvent || !retryableDisconnectEvent(event)) {
				s.stopReconnectLocked()
			} else if !networkRepairEvent && !scheduleAutoReconnect && !s.reconnect.pending() {
				s.desiredProfileID = ""
			}
			connectionID := s.activeConnectionID
			s.connectedID = ""
			s.status.State = types.StateDisconnected
			if networkRepairEvent {
				s.status.State = types.StateReconnecting
			}
			s.status.ConnectedProfileID = ""
			s.status.Session = nil
			s.status.EffectiveRoutes = nil
			s.status.SOCKS5Enabled = false
			s.status.SOCKS5Listen = ""
			s.clearTrafficLocked()
			s.logs.Add("info", fmt.Sprintf("appd: backend event=disconnected intentional=%t network_repair=%t", intentionalDisconnectEvent, networkRepairEvent))
			reasonCode, transport, closeError := "unknown_close", "", ""
			var transportFaults []types.ConnectionFault
			if event.Close != nil {
				reasonCode, transport, closeError = event.Close.Code, event.Close.Transport, event.Close.Error
				for _, fault := range event.Close.TransportFaults {
					transportFaults = append(transportFaults, types.ConnectionFault{Code: fault.Code, Transport: fault.Transport, Error: fault.Error, Time: fault.Time})
				}
			}
			if event.Err != nil && closeError == "" {
				reasonCode = "backend_error"
				closeError = event.Err.Error()
			}
			if intentionalDisconnectEvent {
				reasonCode, transport, closeError = "local_requested", "local", ""
			}
			if networkRepairEvent {
				reasonCode, transport, closeError = "underlay_changed", "network", ""
			}
			ended := time.Now().UTC()
			eventRecord := types.ConnectionEvent{ConnectionID: connectionID, ProfileID: disconnectedProfileID, Kind: "connection_lost", ReasonCode: reasonCode, Transport: transport, Error: closeError, SessionEnded: ended.Format(time.RFC3339Nano), TransportFaults: transportFaults}
			if !s.activeConnectionStarted.IsZero() {
				eventRecord.SessionStarted = s.activeConnectionStarted.Format(time.RFC3339Nano)
				eventRecord.DurationMS = ended.Sub(s.activeConnectionStarted).Milliseconds()
			}
			if networkRepairEvent {
				eventRecord.Kind = "network_reconnect"
			} else if intentionalDisconnectEvent {
				eventRecord.Kind = "disconnected"
			}
			s.recordConnectionLocked(eventRecord)
			s.activeConnectionID = ""
			s.activeConnectionStarted = time.Time{}
		}
		message := ""
		switch event.Type {
		case "connected":
			message = "Backend connection established."
		case "disconnected":
			message = "Backend disconnected."
			if networkRepairEvent {
				message = "Network path changed; reconnecting."
			}
		}
		if event.Err != nil {
			appdLog.Printf("backend event error: %v", event.Err)
			s.status.State = types.StateError
			s.status.LastError = event.Err.Error()
			s.logs.Add("error", fmt.Sprintf("appd: backend error err=%q", event.Err.Error()))
			message = "Backend error: " + event.Err.Error()
		}
		if event.Type == "disconnected" && event.Err == nil && event.Close != nil && event.Close.Error != "" && !intentionalDisconnectEvent && !networkRepairEvent {
			s.status.State = types.StateError
			s.status.LastError = sanitizeDiagnostic(event.Close.Error)
			message = "VPN connection lost: " + s.status.LastError
		}
		if event.Type == "disconnected" && event.Close != nil && event.Close.Code != "" && !intentionalDisconnectEvent && !networkRepairEvent && event.Close.Error == "" {
			message = "VPN connection lost (" + event.Close.Code + ")."
		}
		s.status.UpdatedAt = now()
		s.emitLocked(types.Notify{
			Event:   "status",
			Status:  ptrStatus(s.status),
			Error:   s.status.LastError,
			Message: message,
		})
		if event.Type == "connected" || event.Type == "disconnected" {
			s.emitLocked(types.Notify{Event: "traffic", Traffic: ptrTraffic(s.traffic)})
		}
		if event.Type == "disconnected" && s.controlMode == "user" && !scheduleAutoReconnect && !networkRepairEvent && !s.reconnect.pending() {
			s.activeOwnerID = ""
		}
		if scheduleAutoReconnect {
			s.startReconnectLocked(disconnectedProfileID, manualSeq, 1)
		}
		s.mu.Unlock()
	}
}

func retryableDisconnectEvent(event vpn.Event) bool {
	if event.Err != nil {
		return vpn.IsRetryable(event.Err)
	}
	if event.Close == nil {
		return false
	}
	switch event.Close.Code {
	case "tls_read_error", "tls_read_timeout", "tls_write_error", "tls_write_timeout", "tls_deadline_error", "underlay_snapshot_failed":
		return true
	default:
		return false
	}
}

func (s *Service) profileAutoReconnect(profileID string) (types.Profile, bool) {
	if profileID == "" {
		return types.Profile{}, false
	}
	for _, profile := range s.profiles {
		if profile.ID == profileID {
			return profile, true
		}
	}
	return types.Profile{}, false
}

func (s *Service) autoReconnectEnabledLocked(profile types.Profile) bool {
	return (s.controlMode == "machine" && s.machineProfileID == profile.ID) || types.BoolValue(profile.AutoReconnect, false)
}

func networkChangeFromBackend(change *vpn.NetworkChange) *types.NetworkChange {
	if change == nil {
		return nil
	}
	return &types.NetworkChange{
		Before: networkSnapshotInfo(change.Before), After: networkSnapshotInfo(change.After),
		Reasons: append([]string(nil), change.Reasons...), RebindRequired: change.RebindRequired,
		Error: sanitizeDiagnostic(change.Error), Time: now(),
	}
}

func networkSnapshotInfo(snapshot vpn.NetworkSnapshot) *types.UnderlayInfo {
	if snapshot.InterfaceName == "" && snapshot.LocalIPv4 == "" && snapshot.Gateway == "" {
		return nil
	}
	return &types.UnderlayInfo{
		InterfaceName: snapshot.InterfaceName, InterfaceIndex: snapshot.InterfaceIndex,
		LocalIPv4: snapshot.LocalIPv4, Gateway: snapshot.Gateway,
		GatewayInterface: snapshot.GatewayInterface, RouteMetric: snapshot.RouteMetric,
		Generation: snapshot.Generation,
	}
}

func (s *Service) findProfileLocked(id string) (types.Profile, error) {
	for _, p := range s.profiles {
		if p.ID == id {
			return p, nil
		}
	}
	return types.Profile{}, fmt.Errorf("profile not found: %s", id)
}

func (s *Service) emitLocked(notify types.Notify) {
	notify.Version = buildinfo.Version
	notify.Time = now()
	s.revision++
	notify.Epoch = s.epoch
	notify.Revision = s.revision
	notify = cloneNotify(notify)
	s.eventRing = append(s.eventRing, notify)
	if len(s.eventRing) > 1024 {
		s.eventRing = append([]types.Notify(nil), s.eventRing[len(s.eventRing)-1024:]...)
	}
	appdDebugf("emit notify event=%s watchers=%d", notify.Event, len(s.watchers))
	for id, ch := range s.watchers {
		select {
		case ch <- cloneNotify(notify):
		default:
			appdDebugf("closing slow watch client id=%d event=%s", id, notify.Event)
			delete(s.watchers, id)
			close(ch)
		}
	}
}

func ptrStatus(status types.Status) *types.Status {
	copy := cloneStatus(status)
	return &copy
}

func ptrTraffic(traffic types.TrafficSnapshot) *types.TrafficSnapshot {
	copy := traffic
	return &copy
}

func (s *Service) reconnectProfile(ctx context.Context, id, reason string) error {
	appdDebugf("reconnect profile id=%s reason=%s", id, reason)
	s.logs.Add("info", fmt.Sprintf("appd: reconnect reason=%q", reason))
	if err := s.disconnect(ctx, false); err != nil {
		return err
	}
	return s.Connect(ctx, id)
}

func needsReconnectForProfileUpdate(before, after types.Profile) bool {
	if before.Provider != after.Provider || before.AuthMethod != after.AuthMethod || before.LoginDomain != after.LoginDomain ||
		before.ServerURL != after.ServerURL ||
		before.Username != after.Username ||
		before.Group != after.Group ||
		before.AcceptServerRoutes != after.AcceptServerRoutes ||
		types.BoolValue(before.AutoReconnect, false) != types.BoolValue(after.AutoReconnect, false) ||
		types.BoolValue(before.ApplyDNS, true) != types.BoolValue(after.ApplyDNS, true) ||
		before.MTU != after.MTU {
		return true
	}
	if !slices.Equal(before.CustomInclude, after.CustomInclude) ||
		!slices.Equal(before.CustomExclude, after.CustomExclude) ||
		!slices.Equal(before.DNSOverrides, after.DNSOverrides) {
		return true
	}
	return false
}

func (s *Service) prepareLoginProfileLocked(req types.LoginRequest) (types.Profile, string, error) {
	var (
		profile  types.Profile
		password string
		index    = -1
	)
	if req.ProfileID != "" {
		for i, p := range s.profiles {
			if p.ID == req.ProfileID {
				index = i
				profile = p
				break
			}
		}
		if index == -1 {
			return types.Profile{}, "", fmt.Errorf("profile not found: %s", req.ProfileID)
		}
	} else {
		created, err := newProfile(req.Name)
		if err != nil {
			return types.Profile{}, "", fmt.Errorf("generate profile ID: %w", err)
		}
		profile = created
		profile.SecretRef = "profile/" + profile.ID
	}

	if req.Name != "" {
		profile.Name = req.Name
	}
	if req.ServerURL != "" {
		profile.ServerURL = req.ServerURL
	}
	if req.Username != "" {
		profile.Username = req.Username
	}
	if req.Group != "" {
		profile.Group = req.Group
	}
	if profile.Provider != types.ProviderAnyConnect {
		return types.Profile{}, "", errors.New("login supports AnyConnect profiles only; use profile add with a keystore for aTrust")
	}
	profile = profileio.NormalizeProfile(profile)
	if profile.Name == "" {
		profile.Name = profileio.DefaultProfileName(profile.ServerURL, profile.Username)
	}
	if profile.SecretRef == "" {
		profile.SecretRef = "profile/" + profile.ID
	}
	profile.UpdatedAt = now()
	if profile.CreatedAt == "" {
		profile.CreatedAt = profile.UpdatedAt
	}
	if req.Password != "" {
		password = req.Password
		if err := s.secrets.Put(profile.SecretRef, req.Password); err != nil {
			return types.Profile{}, "", err
		}
	} else {
		var err error
		password, err = s.loadProfileSecret(profile)
		if err != nil {
			return types.Profile{}, "", err
		}
	}

	if index >= 0 {
		s.profiles[index] = profile
	} else {
		s.profiles = append(s.profiles, profile)
	}
	s.currentID = profile.ID
	s.status.CurrentProfileID = profile.ID
	return profile, password, nil
}

func (s *Service) connectPreparedProfile(ctx context.Context, profile types.Profile, password string, allowReconnectState bool) error {
	if err := validateProfileForConnect(profile); err != nil {
		return err
	}
	if profile.SecretRef != "" && password == "" {
		var err error
		password, err = s.loadProfileSecret(profile)
		if err != nil {
			return err
		}
	}

	s.mu.Lock()
	if s.status.State == types.StateConnecting || s.status.State == types.StateReconnecting {
		if !s.connectAllowedFromStateLocked(profile.ID, allowReconnectState) && s.status.CurrentProfileID == profile.ID {
			appdLog.Printf("connect ignored profile=%s reason=already_connecting", profile.ID)
			s.mu.Unlock()
			return nil
		}
		if !s.connectAllowedFromStateLocked(profile.ID, allowReconnectState) {
			s.mu.Unlock()
			return errConnectInProgress
		}
	}
	if s.status.State == types.StateConnected && s.connectedID == profile.ID {
		s.desiredProfileID = profile.ID
		appdLog.Printf("connect ignored profile=%s reason=already_connected", profile.ID)
		s.mu.Unlock()
		return nil
	}
	alreadyConnected := s.connectedID
	s.mu.Unlock()
	if alreadyConnected != "" && alreadyConnected != profile.ID {
		if err := s.disconnect(ctx, false); err != nil {
			return err
		}
	}

	s.mu.Lock()
	if s.status.State == types.StateConnecting || s.status.State == types.StateReconnecting {
		if !s.connectAllowedFromStateLocked(profile.ID, allowReconnectState) && s.status.CurrentProfileID == profile.ID {
			appdLog.Printf("connect ignored profile=%s reason=already_connecting", profile.ID)
			s.mu.Unlock()
			return nil
		}
		if !s.connectAllowedFromStateLocked(profile.ID, allowReconnectState) {
			s.mu.Unlock()
			return errConnectInProgress
		}
	}
	if s.status.State == types.StateConnected && s.connectedID == profile.ID {
		s.desiredProfileID = profile.ID
		appdLog.Printf("connect ignored profile=%s reason=already_connected", profile.ID)
		s.mu.Unlock()
		return nil
	}
	attemptID, err := newID()
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("generate connection attempt ID: %w", err)
	}
	connectionID, err := newID()
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("generate connection ID: %w", err)
	}
	attemptCtx, cancelAttempt := context.WithCancel(ctx)
	if allowReconnectState {
		s.status.State = types.StateReconnecting
	} else {
		s.status.State = types.StateConnecting
	}
	s.currentID = profile.ID
	s.status.CurrentProfileID = profile.ID
	s.status.ConnectedProfileID = ""
	s.attemptID = attemptID
	s.attemptCancel = cancelAttempt
	s.status.AttemptID = attemptID
	s.status.LastError = ""
	s.clearTrafficLocked()
	s.status.UpdatedAt = now()
	s.logs.Add("info", fmt.Sprintf("appd: connecting id=%s", profile.ID))
	s.emitLocked(types.Notify{
		Event:   "status",
		Status:  ptrStatus(s.status),
		Message: "Connecting to profile " + profile.ID,
	})
	s.mu.Unlock()

	session, err := s.backend.Connect(attemptCtx, vpn.ConnectRequest{Profile: profile, Password: password, AttemptID: attemptID, ConnectionID: connectionID, OwnerID: profile.OwnerID})
	if err != nil {
		s.mu.Lock()
		if s.attemptID != attemptID {
			s.mu.Unlock()
			cancelAttempt()
			return context.Canceled
		}
		s.attemptID = ""
		s.attemptCancel = nil
		s.status.AttemptID = ""
		s.status.State = types.StateError
		if errors.Is(err, context.Canceled) || errors.Is(attemptCtx.Err(), context.Canceled) {
			s.status.State = types.StateDisconnected
			s.status.LastError = ""
		} else {
			s.status.LastError = sanitizeDiagnostic(err.Error())
		}
		s.status.UpdatedAt = now()
		s.logs.Add("error", fmt.Sprintf("appd: connect failed id=%s err=%q", profile.ID, err.Error()))
		s.recordConnectionLocked(types.ConnectionEvent{ProfileID: profile.ID, Kind: "connect_failed", ReasonCode: "connect_error", Error: err.Error()})
		s.emitLocked(types.Notify{
			Event:   "status",
			Status:  ptrStatus(s.status),
			Error:   err.Error(),
			Message: "Failed to connect profile " + profile.ID + ": " + err.Error(),
		})
		s.mu.Unlock()
		cancelAttempt()
		return err
	}
	if session == nil {
		err = errors.New("VPN backend returned an empty session")
	} else if profile.SOCKS5Enabled {
		var dialer socks5.TunnelDialer
		dialer, err = s.backend.TunnelDialer(attemptCtx)
		if err == nil {
			err = s.startProxy(profile.ID, profile.SOCKS5Listen, dialer)
		}
	} else {
		err = s.stopProxy()
	}
	if err != nil {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		cleanupErr := s.backend.Disconnect(cleanupCtx)
		cleanupCancel()
		s.mu.Lock()
		if s.attemptID == attemptID {
			s.attemptID = ""
			s.attemptCancel = nil
			s.status.AttemptID = ""
			s.status.State = types.StateError
			s.status.LastError = sanitizeDiagnostic(err.Error())
			if cleanupErr != nil {
				s.status.LastError = sanitizeDiagnostic(fmt.Sprintf("%v; cleanup failed: %v", err, cleanupErr))
			}
			s.status.UpdatedAt = now()
			s.recordConnectionLocked(types.ConnectionEvent{ProfileID: profile.ID, Kind: "connect_failed", ReasonCode: "required_component_failed", Error: s.status.LastError})
			s.emitLocked(types.Notify{Event: "status", Status: ptrStatus(s.status), Error: s.status.LastError, Message: "Connection setup failed."})
		}
		s.mu.Unlock()
		cancelAttempt()
		if cleanupErr != nil {
			s.failCleanup(fmt.Errorf("connection rollback cleanup failed: %w", cleanupErr))
			return fmt.Errorf("connection setup failed: %w; cleanup failed: %v", err, cleanupErr)
		}
		return err
	}

	s.mu.Lock()
	if s.attemptID != attemptID || attemptCtx.Err() != nil {
		s.mu.Unlock()
		cancelAttempt()
		return context.Canceled
	}
	s.attemptID = ""
	s.attemptCancel = nil
	s.status.AttemptID = ""
	s.connectedID = profile.ID
	s.desiredProfileID = profile.ID
	s.manualProfileID = ""
	s.manualDisconnectSeq = 0
	s.status.State = types.StateConnected
	s.status.ConnectedProfileID = profile.ID
	s.status.Session = session
	s.activeConnectionID = session.ConnectionID
	if s.activeConnectionID == "" {
		s.activeConnectionID = fmt.Sprintf("connection-%d", s.connectionSeq+1)
	}
	s.networkConnectionID = s.activeConnectionID
	s.networkOffline = false
	s.activeConnectionStarted = time.Now().UTC()
	s.status.EffectiveRoutes = s.planner.Plan(session.SplitInclude, session.SplitExclude, profile)
	s.status.UpdatedAt = now()
	s.sampleTrafficLocked(time.Now().UTC())
	s.logs.Add("info", fmt.Sprintf("appd: connected profile=%s", profile.ID))
	connectionKind := "connected"
	if allowReconnectState {
		connectionKind = "reconnected"
	}
	s.recordConnectionLocked(types.ConnectionEvent{ConnectionID: s.activeConnectionID, ProfileID: profile.ID, Kind: connectionKind, Attempt: s.reconnect.attempt})
	s.emitLocked(types.Notify{
		Event:   "status",
		Status:  ptrStatus(s.status),
		Message: "Connected to profile " + profile.ID,
	})
	s.emitLocked(types.Notify{Event: "traffic", Traffic: ptrTraffic(s.traffic)})
	s.mu.Unlock()
	cancelAttempt()
	return nil
}

func (s *Service) loadProfileSecret(profile types.Profile) (string, error) {
	if profile.SecretRef == "" {
		return "", fmt.Errorf("profile %s has no secret reference", profile.ID)
	}
	password, err := s.secrets.Get(profile.SecretRef)
	if err != nil {
		return "", fmt.Errorf("load secret for profile %s: %w", profile.ID, err)
	}
	if password == "" {
		return "", fmt.Errorf("secret for profile %s is empty", profile.ID)
	}
	return password, nil
}

func (s *Service) connectAllowedFromStateLocked(profileID string, allowReconnectState bool) bool {
	return allowReconnectState && s.status.State == types.StateReconnecting && s.status.CurrentProfileID == profileID
}

func validateProfileForConnect(profile types.Profile) error {
	if err := profileio.ValidateProfile(profile); err != nil {
		return err
	}
	if profile.Username == "" {
		return errors.New("profile username is required")
	}
	return nil
}

func (s *Service) applyProxyProfile(profile types.Profile) error {
	appdLog.Printf("apply proxy for profile=%s enabled=%v addr=%q", profile.ID, profile.SOCKS5Enabled, profile.SOCKS5Listen)
	s.mu.Lock()
	connected := s.connectedID == profile.ID && s.status.State == types.StateConnected
	s.mu.Unlock()
	if !connected {
		return s.stopProxy()
	}
	if !profile.SOCKS5Enabled {
		return s.stopProxy()
	}
	dialer, err := s.backend.TunnelDialer(context.Background())
	if err != nil {
		_ = s.stopProxy()
		s.recordProxyError(fmt.Errorf("SOCKS5 VPN dialer unavailable: %w", err))
		return err
	}
	return s.startProxy(profile.ID, profile.SOCKS5Listen, dialer)
}

func (s *Service) startProxy(profileID, listenAddr string, dialer socks5.TunnelDialer) error {
	if dialer == nil {
		return errors.New("SOCKS5 requires a VPN tunnel dialer")
	}
	if listenAddr == "" {
		listenAddr = "127.0.0.1:1080"
	}
	appdLog.Printf("start proxy addr=%s", listenAddr)
	s.mu.Lock()
	if s.proxyServer != nil && s.status.SOCKS5Enabled && s.status.SOCKS5Listen == listenAddr {
		s.mu.Unlock()
		return nil
	}
	oldProxy := s.proxyServer
	s.proxyServer = nil
	s.status.SOCKS5Enabled = false
	s.status.SOCKS5Listen = ""
	s.mu.Unlock()

	if oldProxy != nil {
		if err := oldProxy.Close(); err != nil {
			return fmt.Errorf("replace SOCKS5 listener: %w", err)
		}
	}
	server, err := socks5.Listen(listenAddr, dialer)
	if err != nil {
		s.mu.Lock()
		s.health["proxy"] = types.ComponentStatus{Name: "proxy", Ready: false, Message: sanitizeDiagnostic(err.Error())}
		s.logs.Add("error", fmt.Sprintf("appd: start socks5 proxy failed err=%q", err.Error()))
		appdLog.Printf("start proxy failed addr=%s err=%v", listenAddr, err)
		s.status.LastError = err.Error()
		s.status.UpdatedAt = now()
		s.emitLocked(types.Notify{Event: "status", Status: ptrStatus(s.status), Error: err.Error()})
		s.mu.Unlock()
		return err
	}
	s.mu.Lock()
	s.proxyServer = server
	s.health["proxy"] = types.ComponentStatus{Name: "proxy", Ready: true}
	s.status.SOCKS5Enabled = true
	s.status.SOCKS5Listen = server.Addr()
	s.status.UpdatedAt = now()
	s.logs.Add("info", fmt.Sprintf("appd: socks5 proxy started addr=%s", server.Addr()))
	appdLog.Printf("start proxy success listen=%s", server.Addr())
	s.emitLocked(types.Notify{Event: "status", Status: ptrStatus(s.status), Message: "SOCKS5 proxy started"})
	s.mu.Unlock()
	go s.monitorProxy(server, profileID)
	return nil
}

func (s *Service) monitorProxy(server *socks5.Server, profileID string) {
	err, ok := <-server.Errors()
	if !ok || err == nil {
		return
	}
	s.commandMu.Lock()
	defer s.commandMu.Unlock()
	s.mu.Lock()
	active := s.proxyServer == server && s.currentID == profileID && profileID != "" && (s.connectedID == profileID || s.attemptCancel != nil)
	s.mu.Unlock()
	if !active {
		return
	}
	s.recordProxyError(err)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if closeErr := s.disconnect(ctx, false); closeErr != nil {
		s.recordProxyError(fmt.Errorf("SOCKS5 failure cleanup: %w", closeErr))
	}
}

func (s *Service) recordProxyError(err error) {
	if err == nil {
		return
	}
	s.mu.Lock()
	s.health["proxy"] = types.ComponentStatus{Name: "proxy", Ready: false, Message: sanitizeDiagnostic(err.Error())}
	s.status.LastError = err.Error()
	s.status.UpdatedAt = now()
	s.logs.Add("error", fmt.Sprintf("appd: socks5 proxy unavailable err=%q", err.Error()))
	s.emitLocked(types.Notify{Event: "status", Status: ptrStatus(s.status), Error: err.Error()})
	s.mu.Unlock()
}

func (s *Service) stopProxy() error {
	s.mu.Lock()
	server := s.proxyServer
	if server == nil && !s.status.SOCKS5Enabled && s.status.SOCKS5Listen == "" {
		s.mu.Unlock()
		return nil
	}
	s.proxyServer = nil
	wasEnabled := s.status.SOCKS5Enabled
	oldAddr := s.status.SOCKS5Listen
	s.status.SOCKS5Enabled = false
	s.status.SOCKS5Listen = ""
	s.status.UpdatedAt = now()
	if wasEnabled {
		s.logs.Add("info", fmt.Sprintf("appd: socks5 proxy stopped addr=%s", oldAddr))
		appdLog.Printf("stop proxy done addr=%s", oldAddr)
		s.emitLocked(types.Notify{Event: "status", Status: ptrStatus(s.status), Message: "SOCKS5 proxy stopped"})
	}
	s.mu.Unlock()
	if server != nil {
		if err := server.Close(); err != nil {
			return err
		}
	}
	s.mu.Lock()
	s.health["proxy"] = types.ComponentStatus{Name: "proxy", Ready: true}
	s.mu.Unlock()
	return nil
}

func now() string {
	return time.Now().UTC().Format(time.RFC3339)
}
