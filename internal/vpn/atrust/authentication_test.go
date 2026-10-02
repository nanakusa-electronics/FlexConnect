package atrust

import (
	"context"
	"errors"
	"flexconnect/internal/vpn"
	"github.com/ShanghaitechGeekPie/geektrust/auth"
	"testing"
	"time"
)

func TestAuthenticationAdapter(t *testing.T) {
	if authenticationHandler(nil) != nil {
		t.Fatal("missing callback should remain nil")
	}
	expires := time.Now().Add(time.Minute)
	called := false
	handler := authenticationHandler(func(ctx context.Context, prompt vpn.AuthenticationPrompt) (string, error) {
		called = true
		if prompt.Method != "sms" || !prompt.ExpiresAt.Equal(expires) {
			t.Fatalf("prompt: %+v", prompt)
		}
		return "123456", ctx.Err()
	})
	if _, err := handler(context.Background(), auth.Challenge{Method: "unknown"}); !errors.Is(err, auth.ErrUnsupported) || called || vpn.IsRetryable(err) {
		t.Fatalf("unsupported: %v called=%v", err, called)
	}
	answer, err := handler(context.Background(), auth.Challenge{Method: "auth/sms", ExpiresAt: expires})
	if err != nil || answer != "123456" || !called {
		t.Fatalf("answer not delivered: %v", err)
	}
}
