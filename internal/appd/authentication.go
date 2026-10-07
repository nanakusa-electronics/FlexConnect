package appd

import (
	"context"
	"time"

	"flexconnect/internal/types"
	"flexconnect/internal/vpn"
)

type pendingAuthentication struct {
	challenge types.AuthenticationChallenge
	attemptID string
	ctx       context.Context
	response  chan string
	submitted bool
}

func (s *Service) authenticationCurrentLocked(p *pendingAuthentication) bool {
	if p == nil || s.closed || p.ctx.Err() != nil || !time.Now().Before(p.challenge.ExpiresAt) {
		return false
	}
	return (p.attemptID != "" && s.attemptID == p.attemptID) || (s.activeConnectionID == p.challenge.ConnectionID && s.status.State == types.StateConnected)
}

func (s *Service) authenticationForLocked(actor Actor) *types.AuthenticationChallenge {
	p := s.authentication
	if !s.authenticationCurrentLocked(p) || p.submitted {
		return nil
	}
	profile, err := s.findProfileLocked(p.challenge.ProfileID)
	if err != nil || !actorCanAccessProfile(actor, profile) {
		return nil
	}
	return cloneAuthentication(&p.challenge)
}

func (s *Service) AuthenticationFor(actor Actor) (*types.AuthenticationChallenge, error) {
	if err := s.authorize(actor, false); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.authenticationForLocked(actor), nil
}

func (s *Service) RespondAuthenticationFor(actor Actor, id, response string) error {
	if err := s.authorize(actor, true); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	challenge := s.authenticationForLocked(actor)
	if challenge == nil || challenge.ID != id {
		return coded("authentication_not_found", "authentication request is no longer available", nil)
	}
	// SMS is the only supported challenge. Never reflect rejected input into an error.
	if len(response) == 0 || len(response) > 32 {
		return coded("invalid_authentication_response", "enter the SMS verification code", nil)
	}
	for _, c := range response {
		if c < '0' || c > '9' {
			return coded("invalid_authentication_response", "enter the SMS verification code", nil)
		}
	}
	s.authentication.submitted = true
	s.authentication.response <- response
	return nil
}

func (s *Service) requestAuthentication(ctx context.Context, profileID, attemptID, connectionID string, prompt vpn.AuthenticationPrompt) (string, error) {
	if prompt.Method != "sms" {
		return "", coded("unsupported_authentication", "authentication method is not supported", nil)
	}
	expires := time.Now().Add(time.Minute)
	if !prompt.ExpiresAt.IsZero() && prompt.ExpiresAt.Before(expires) {
		expires = prompt.ExpiresAt
	}
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	ctx, cancel := context.WithDeadline(ctx, expires)
	defer cancel()
	id, err := newID()
	if err != nil {
		return "", coded("random_source_failed", "generate authentication ID failed", err)
	}
	pending := &pendingAuthentication{
		challenge: types.AuthenticationChallenge{ID: id, ProfileID: profileID, ConnectionID: connectionID, Method: prompt.Method, ExpiresAt: expires},
		attemptID: attemptID, ctx: ctx, response: make(chan string, 1),
	}
	s.mu.Lock()
	if !s.authenticationCurrentLocked(pending) {
		s.mu.Unlock()
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", context.Canceled
	}
	if s.authentication != nil {
		s.mu.Unlock()
		return "", coded("authentication_in_progress", "an authentication request is already pending", nil)
	}
	s.authentication = pending
	s.emitLocked(types.Notify{Event: "authentication", Authentication: cloneAuthentication(&pending.challenge)})
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.authentication == pending {
			s.authentication = nil
			s.emitLocked(types.Notify{Event: "authentication"})
		}
	}()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-s.loopStop:
		return "", context.Canceled
	case response := <-pending.response:
		s.mu.Lock()
		current := s.authenticationCurrentLocked(pending)
		s.mu.Unlock()
		if !current {
			return "", context.Canceled
		}
		return response, nil
	}
}

func cloneAuthentication(challenge *types.AuthenticationChallenge) *types.AuthenticationChallenge {
	if challenge == nil {
		return nil
	}
	copy := *challenge
	return &copy
}
