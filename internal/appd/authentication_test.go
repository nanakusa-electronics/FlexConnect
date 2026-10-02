package appd

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"flexconnect/internal/types"
	"flexconnect/internal/vpn"
)

type authenticatingBackend struct {
	*fakeBackend
	prompt vpn.AuthenticationPrompt
	answer chan string
}

func (b *authenticatingBackend) Connect(ctx context.Context, req vpn.ConnectRequest) (*types.SessionInfo, error) {
	answer, err := req.Authenticate(ctx, b.prompt)
	if err != nil {
		return nil, err
	}
	b.answer <- answer
	return &types.SessionInfo{ConnectionID: req.ConnectionID, ServerAddress: "vpn.example.test", VPNAddress: "10.0.0.2"}, nil
}

func startAuthenticatingService(t *testing.T, expires time.Time) (*Service, context.CancelFunc, <-chan error) {
	t.Helper()
	profile := testProfile("alice-profile", false)
	profile.Scope, profile.OwnerID = types.ProfileScopeUser, "alice"
	backend := &authenticatingBackend{fakeBackend: newFakeBackend(), prompt: vpn.AuthenticationPrompt{Method: "sms", ExpiresAt: expires}, answer: make(chan string, 1)}
	service := newTestService(t, backend, profile)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- service.ConnectFor(ctx, Actor{ID: "alice"}, profile.ID) }()
	t.Cleanup(func() { cancel(); _ = service.Close(context.Background()) })
	return service, cancel, result
}

func awaitAuthentication(t *testing.T, s *Service) *types.AuthenticationChallenge {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for event := range s.WatchSince(ctx, Actor{ID: "alice"}, "", 0) {
		if event.Authentication != nil {
			return event.Authentication
		}
	}
	t.Fatal("authentication event not received")
	return nil
}

func TestAuthenticationOwnerSubmissionAndReplay(t *testing.T) {
	s, _, result := startAuthenticatingService(t, time.Now().Add(time.Minute))
	challenge := awaitAuthentication(t, s)
	if challenge.Method != "sms" || challenge.ConnectionID == "" {
		t.Fatalf("invalid challenge: %+v", challenge)
	}
	if other, err := s.AuthenticationFor(Actor{ID: "bob"}); err != nil || other != nil {
		t.Fatalf("other user's challenge: %+v %v", other, err)
	}
	if err := s.RespondAuthenticationFor(Actor{ID: "bob"}, challenge.ID, "123456"); err == nil {
		t.Fatal("cross-user response accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	event := <-s.WatchSince(ctx, Actor{ID: "bob"}, "", 0)
	if event.Authentication != nil {
		t.Fatal("challenge leaked in snapshot")
	}
	s.mu.Lock()
	for _, event := range s.eventRing {
		if s.notifyForActorLocked(Actor{ID: "bob"}, event).Authentication != nil {
			t.Error("challenge leaked in replay")
		}
	}
	s.mu.Unlock()
	if err := s.RespondAuthenticationFor(Actor{ID: "alice"}, "wrong-id", "123456"); errorCode(err) != "authentication_not_found" {
		t.Fatalf("wrong ID error: %v", err)
	}
	if err := s.RespondAuthenticationFor(Actor{ID: "alice"}, challenge.ID, "secret-value"); err == nil || strings.Contains(err.Error(), "secret-value") {
		t.Fatal("invalid response accepted or echoed")
	}
	if err := s.RespondAuthenticationFor(Actor{ID: "alice"}, challenge.ID, "123456"); err != nil {
		t.Fatal(err)
	}
	if err := s.RespondAuthenticationFor(Actor{ID: "alice"}, challenge.ID, "123456"); errorCode(err) != "authentication_not_found" {
		t.Fatalf("duplicate response: %v", err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("connect did not finish")
	}
	if challenge, err := s.AuthenticationFor(Actor{ID: "alice"}); err != nil || challenge != nil {
		t.Fatalf("challenge retained: %+v %v", challenge, err)
	}
	backend := s.backend.(*authenticatingBackend)
	if answer := <-backend.answer; answer != "123456" {
		t.Fatal("answer not delivered")
	}
	s.mu.Lock()
	data, _ := json.Marshal(s.eventRing)
	for _, event := range s.eventRing {
		if s.notifyForActorLocked(Actor{ID: "alice"}, event).Authentication != nil {
			t.Error("completed challenge replayed")
		}
	}
	s.mu.Unlock()
	if strings.Contains(string(data), "123456") {
		t.Fatal("answer leaked in events")
	}
}

func TestAuthenticationCancellationAndExpiry(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "expiry"}[expired], func(t *testing.T) {
			expires := time.Now().Add(time.Minute)
			if expired {
				expires = time.Now().Add(150 * time.Millisecond)
			}
			s, cancel, result := startAuthenticatingService(t, expires)
			challenge := awaitAuthentication(t, s)
			if !expired {
				cancel()
			}
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("connect error: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("authentication did not stop")
			}
			if err := s.RespondAuthenticationFor(Actor{ID: "alice"}, challenge.ID, "123456"); errorCode(err) != "authentication_not_found" {
				t.Fatalf("stale response: %v", err)
			}
		})
	}
}

func TestUnsupportedAuthenticationDoesNotPrompt(t *testing.T) {
	s := newTestService(t, newFakeBackend(), testProfile("p", false))
	defer s.Close(context.Background())
	_, err := s.requestAuthentication(context.Background(), "p", "attempt", "connection", vpn.AuthenticationPrompt{Method: "unknown"})
	if errorCode(err) != "unsupported_authentication" || vpn.IsRetryable(err) {
		t.Fatalf("unsupported error: %v", err)
	}
}

func TestAuthenticationStopsOnDaemonShutdown(t *testing.T) {
	s, _, result := startAuthenticatingService(t, time.Now().Add(time.Minute))
	_ = awaitAuthentication(t, s)
	if err := s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("shutdown error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("authentication survived shutdown")
	}
}
