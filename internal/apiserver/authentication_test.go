package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"flexconnect/client/local"
	"flexconnect/internal/appd"
	"flexconnect/internal/types"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type authenticationDaemon struct {
	fakeDaemon
	response string
	actor    appd.Actor
}

func (d *authenticationDaemon) AuthenticationFor(actor appd.Actor) (*types.AuthenticationChallenge, error) {
	d.actor = actor
	return &types.AuthenticationChallenge{ID: "challenge", Method: "sms", ExpiresAt: time.Now().Add(time.Minute)}, nil
}
func (d *authenticationDaemon) RespondAuthenticationFor(actor appd.Actor, id, response string) error {
	if id != "challenge" {
		return &appd.CodedError{Code: "authentication_not_found", Message: "authentication request is no longer available"}
	}
	d.actor, d.response = actor, response
	return nil
}

type handlerTransport struct{ handler http.Handler }

func (h handlerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req.WithContext(WithActor(req.Context(), appd.Actor{ID: "alice"})))
	return rec.Result(), nil
}

func TestAuthenticationLocalClientRoundTrip(t *testing.T) {
	daemon := &authenticationDaemon{}
	client := &local.Client{Transport: handlerTransport{New(daemon).Handler()}}
	challenge, err := client.Authentication(context.Background())
	if err != nil || challenge == nil || challenge.ID != "challenge" {
		t.Fatalf("challenge: %+v %v", challenge, err)
	}
	if err := client.RespondAuthentication(context.Background(), challenge.ID, "123456"); err != nil {
		t.Fatal(err)
	}
	if daemon.actor.ID != "alice" || daemon.response != "123456" {
		t.Fatal("actor or response not forwarded")
	}
	if err := client.RespondAuthentication(context.Background(), "stale", "123456"); err == nil {
		t.Fatal("stale response accepted")
	}
}

func TestAuthenticationMalformedBodyDoesNotEchoInput(t *testing.T) {
	for _, body := range []string{`{"response":123456}`, `{"secret-value":"123456"}`, `{"response":"123456"} {}`, strings.Repeat("1", 1025)} {
		req := request(http.MethodPost, "/v3/authentication/challenge")
		req.Body = io.NopCloser(bytes.NewBufferString(body))
		rec := httptest.NewRecorder()
		New(&authenticationDaemon{}).Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status: %d", rec.Code)
		}
		if strings.Contains(rec.Body.String(), "123456") || strings.Contains(rec.Body.String(), "secret-value") {
			t.Fatal("input echoed in error")
		}
		var envelope errorEnvelope
		if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
			t.Fatal(err)
		}
		if envelope.Error.Code != "invalid_authentication_response" {
			t.Fatalf("error code: %s", envelope.Error.Code)
		}
	}
}
