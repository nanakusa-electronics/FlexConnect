package appd

import (
	"context"
	"errors"
	"fmt"
	"time"

	"flexconnect/internal/types"
	"flexconnect/internal/vpn"
)

// reconnectState is the sole owner of automatic connection replacement. All
// fields are protected by Service.mu; commandMu serializes backend transactions.
// desiredProfileID expresses user intent independently of transport state.
type reconnectState struct {
	timer        *time.Timer
	profileID    string
	attempt      int
	manualSeq    uint64
	generation   uint64
	nextAt       time.Time
	lifecycleID  string
	waitingID    string
	running      bool
	cancel       context.CancelFunc
	repair       bool
	connectionID string
}

func (r *reconnectState) pending() bool { return r.timer != nil || r.running || r.waitingID != "" }

func (s *Service) reconnectPausedLocked() bool {
	return s.suspended || s.networkOffline
}

// invalidateReconnectLocked cancels work before a new generation can start.
// It preserves connection intent and the reason for replacement.
func (s *Service) invalidateReconnectLocked() {
	r := &s.reconnect
	if r.timer != nil {
		r.timer.Stop()
	}
	if r.cancel != nil {
		r.cancel()
	}
	r.timer, r.cancel = nil, nil
	r.running = false
	r.nextAt = time.Time{}
	r.generation++
}

func (s *Service) stopReconnectLocked() {
	s.invalidateReconnectLocked()
	s.reconnect = reconnectState{generation: s.reconnect.generation}
	s.desiredProfileID = ""
}

func (s *Service) startReconnectLocked(profileID string, manualSeq uint64, attempt int) {
	profile, ok := s.profileAutoReconnect(profileID)
	if !ok || s.closed || s.fatalErr != nil || s.desiredProfileID != profileID ||
		s.currentID != profileID || s.disconnectSeq != manualSeq ||
		(!s.reconnect.repair && !s.autoReconnectEnabledLocked(profile)) {
		return
	}
	if attempt < 1 {
		attempt = 1
	}
	s.invalidateReconnectLocked()
	r := &s.reconnect
	r.profileID, r.manualSeq, r.attempt = profileID, manualSeq, attempt
	r.waitingID = ""
	if r.lifecycleID == "" {
		r.lifecycleID = fmt.Sprintf("reconnect-%d", s.connectionSeq+1)
	}
	if s.reconnectPausedLocked() {
		r.waitingID = profileID
		s.recordConnectionLocked(types.ConnectionEvent{ConnectionID: r.lifecycleID, ProfileID: profileID, Kind: "reconnect_paused", Attempt: attempt})
		return
	}
	delay := reconnectDelay(attempt)
	if r.repair && attempt == 1 {
		delay = 0
	}
	generation := r.generation
	r.nextAt = time.Now().UTC().Add(delay)
	r.timer = time.AfterFunc(delay, func() {
		s.runScheduledReconnect(profileID, manualSeq, attempt, generation)
	})
	s.recordConnectionLocked(types.ConnectionEvent{
		ConnectionID: r.lifecycleID, ProfileID: profileID, Kind: "reconnect_scheduled",
		Attempt: attempt, NextRetryAt: r.nextAt.Format(time.RFC3339Nano),
	})
}

func (s *Service) runScheduledReconnect(profileID string, manualSeq uint64, attempt int, generation uint64) {
	s.commandMu.Lock()
	defer s.commandMu.Unlock()
	s.mu.Lock()
	r := &s.reconnect
	if r.generation != generation || r.profileID != profileID || s.desiredProfileID != profileID ||
		s.closed || s.fatalErr != nil || s.reconnectPausedLocked() || s.disconnectSeq != manualSeq {
		s.mu.Unlock()
		return
	}
	profile, ok := s.profileAutoReconnect(profileID)
	if !ok || s.currentID != profileID || (!r.repair && !s.autoReconnectEnabledLocked(profile)) {
		s.stopReconnectLocked()
		s.mu.Unlock()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	r.timer, r.nextAt, r.running, r.cancel = nil, time.Time{}, true, cancel
	if r.repair && s.connectedID != "" {
		r.connectionID = s.activeConnectionID
	}
	s.status.State = types.StateReconnecting
	s.status.LastError = ""
	s.status.UpdatedAt = now()
	s.recordConnectionLocked(types.ConnectionEvent{ConnectionID: r.lifecycleID, ProfileID: profileID, Kind: "reconnect_attempt", Attempt: attempt})
	s.emitLocked(types.Notify{Event: "status", Status: ptrStatus(s.status), Message: "Reconnecting profile " + profileID})
	s.mu.Unlock()

	// Cleanup must finish before replacement. A pause cancels dialing, not
	// the ordered drain of a TUN and its routes.
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
	err := s.disconnect(cleanupCtx, false)
	cleanupCancel()
	if err == nil {
		err = ctx.Err()
	}
	if err == nil {
		var password string
		password, err = s.loadProfileSecret(profile)
		if err == nil {
			err = s.connectPreparedProfile(ctx, profile, password, true)
		}
	}
	if errors.Is(err, context.DeadlineExceeded) && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		err = vpn.WrapConnectError("timeout", true, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reconnect.generation != generation {
		return // Pause, manual command or newer path owns the next transaction.
	}
	s.reconnect.running, s.reconnect.cancel = false, nil
	if err == nil {
		if s.reconnect.repair {
			s.recordConnectionLocked(types.ConnectionEvent{ConnectionID: s.activeConnectionID, ProfileID: profileID, Kind: "network_reconnected", ReasonCode: "underlay_changed", Transport: "network"})
		}
		s.invalidateReconnectLocked()
		s.reconnect = reconnectState{generation: s.reconnect.generation}
		return
	}
	s.recordConnectionLocked(types.ConnectionEvent{ConnectionID: s.reconnect.lifecycleID, ProfileID: profileID, Kind: "reconnect_failed", ReasonCode: "connect_failed", Error: sanitizeDiagnostic(err.Error()), Attempt: attempt})
	s.retryReconnectLocked(profileID, manualSeq, attempt, err)
}

func (s *Service) retryReconnectLocked(profileID string, manualSeq uint64, attempt int, err error) {
	profile, ok := s.profileAutoReconnect(profileID)
	retryable := vpn.IsRetryable(err) && s.fatalErr == nil && ok && s.autoReconnectEnabledLocked(profile)
	if retryable && attempt < autoReconnectMaxTries {
		s.startReconnectLocked(profileID, manualSeq, attempt+1)
		return
	}
	message := sanitizeDiagnostic(err.Error())
	s.status.State, s.status.LastError, s.status.UpdatedAt = types.StateError, message, now()
	s.recordConnectionLocked(types.ConnectionEvent{
		ConnectionID: s.reconnect.lifecycleID, ProfileID: profileID, Kind: "reconnect_exhausted",
		ReasonCode: reconnectFailureCode(err), Error: message, Attempt: attempt,
	})
	s.invalidateReconnectLocked()
	s.reconnect.repair = false
	s.reconnect.connectionID = ""
	if retryable {
		// Retain intent, but wait for a new network or wake event. There is no
		// periodic retry after exhaustion on the same environment.
		s.reconnect.waitingID = profileID
	} else {
		s.stopReconnectLocked()
		if s.controlMode == "user" {
			s.activeOwnerID = ""
		}
	}
	s.emitLocked(types.Notify{Event: "status", Status: ptrStatus(s.status), Error: message,
		Message: fmt.Sprintf("Automatic reconnect stopped after %d failed attempts: %s", attempt, message)})
}

func (s *Service) handleNetworkChangeLocked(event vpn.Event) {
	if event.Network == nil ||
		(event.ConnectionID != "" && event.ConnectionID != s.networkConnectionID) {
		return
	}
	s.networkOffline = event.Network.Error != ""
	if s.desiredProfileID == "" || (event.ProfileID != "" && event.ProfileID != s.desiredProfileID) {
		return
	}
	s.lastNetworkChange = networkChangeFromBackend(event.Network)
	s.recordConnectionLocked(types.ConnectionEvent{ConnectionID: s.activeConnectionID, ProfileID: s.desiredProfileID,
		Kind: "network_change", ReasonCode: "underlay_changed", Transport: "network", Error: s.lastNetworkChange.Error})
	s.emitLocked(types.Notify{Event: "network", Network: s.lastNetworkChange, Status: ptrStatus(s.status), Message: "Network path changed."})
	if s.reconnectPausedLocked() {
		s.pauseReconnectLocked()
		return
	}
	if event.Network.RebindRequired || s.reconnect.waitingID != "" {
		s.requestReplacementLocked()
	}
}

func (s *Service) requestReplacementLocked() {
	profile, ok := s.profileAutoReconnect(s.desiredProfileID)
	if !ok || s.closed || s.fatalErr != nil || s.currentID != profile.ID {
		return
	}
	if s.connectedID != "" {
		s.reconnect.repair = true
	}
	if !s.reconnect.repair && !s.autoReconnectEnabledLocked(profile) {
		return
	}
	s.startReconnectLocked(profile.ID, s.disconnectSeq, 1)
}

func (s *Service) pauseReconnectLocked() {
	if s.connectedID != "" {
		s.reconnect.repair = true
	}
	s.invalidateReconnectLocked()
	if s.attemptCancel != nil {
		s.attemptCancel()
	}
	if s.desiredProfileID != "" {
		s.reconnect.waitingID = s.desiredProfileID
		s.reconnect.profileID = s.desiredProfileID
		s.recordConnectionLocked(types.ConnectionEvent{ConnectionID: s.reconnect.lifecycleID,
			ProfileID: s.desiredProfileID, Kind: "reconnect_paused", Attempt: s.reconnect.attempt})
		s.emitLocked(types.Notify{Event: "status", Status: ptrStatus(s.status), Message: "Reconnect paused until the system and network are available."})
	}
}

// SetSuspended pauses transport attempts without discarding connection intent.
// A wake (or unlock following exhausted retries) starts one new bounded cycle.
func (s *Service) SetSuspended(suspended bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	wasSuspended := s.suspended
	s.suspended = suspended
	if suspended {
		if !wasSuspended {
			s.pauseReconnectLocked()
		}
		return
	}
	if !s.networkOffline && (wasSuspended || s.reconnect.waitingID != "") && !s.reconnect.running && s.reconnect.timer == nil {
		s.requestReplacementLocked()
	}
}

func reconnectFailureCode(err error) string {
	if vpn.IsRetryable(err) {
		return "retry_limit_reached"
	}
	return "non_retryable_error"
}

func reconnectDelay(attempt int) time.Duration {
	delay := autoReconnectMinDelay
	for i := 1; i < attempt; i++ {
		delay *= 2
		if delay >= autoReconnectMaxDelay {
			return autoReconnectMaxDelay
		}
	}
	return delay
}
