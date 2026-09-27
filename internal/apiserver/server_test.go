package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"flexconnect/internal/appd"
	"flexconnect/internal/buildinfo"
	"flexconnect/internal/ipc"
	"flexconnect/internal/profileio"
	"flexconnect/internal/types"
)

type fakeDaemon struct{}

func (fakeDaemon) StatusFor(appd.Actor) (types.Status, error) {
	return types.Status{State: types.StateDisconnected}, nil
}

type validationDaemon struct{ fakeDaemon }

func (validationDaemon) CreateProfileFor(appd.Actor, types.ProfileCreateRequest) (types.Profile, error) {
	return types.Profile{}, &profileio.ValidationError{Err: io.ErrUnexpectedEOF}
}

func TestValidationErrorUsesStructured422(t *testing.T) {
	req := request(http.MethodPost, "/v3/profiles")
	req.Body = io.NopCloser(bytes.NewBufferString(`{"name":"bad"}`))
	rec := httptest.NewRecorder()
	New(validationDaemon{}).Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var envelope errorEnvelope
	if err := json.NewDecoder(rec.Body).Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Error.Code != "invalid_profile" || envelope.Error.RequestID == "" {
		t.Fatalf("error = %+v", envelope.Error)
	}
}
func (fakeDaemon) TrafficFor(appd.Actor) (types.TrafficSnapshot, error) {
	return types.TrafficSnapshot{SampledAt: "2026-08-29T00:00:00Z"}, nil
}
func (fakeDaemon) LogsFor(appd.Actor) ([]types.LogEntry, error) { return nil, nil }
func (fakeDaemon) DiagnosticsFor(appd.Actor) (types.Diagnostics, error) {
	return types.Diagnostics{}, nil
}
func (fakeDaemon) ListProfilesFor(appd.Actor) ([]types.Profile, error) { return nil, nil }
func (fakeDaemon) CreateProfileFor(appd.Actor, types.ProfileCreateRequest) (types.Profile, error) {
	return types.Profile{ID: "created"}, nil
}
func (fakeDaemon) UpdateProfileFor(appd.Actor, string, types.ProfileUpdateRequest) (types.Profile, error) {
	return types.Profile{ID: "updated"}, nil
}
func (fakeDaemon) UpdateActiveProfileFor(appd.Actor, string, types.ProfileUpdateRequest) (types.Operation, error) {
	return types.Operation{ID: "op", Kind: "profile-update", State: types.OperationRunning}, nil
}
func (fakeDaemon) DeleteProfileFor(appd.Actor, string) error            { return nil }
func (fakeDaemon) ProfileIsActive(string) bool                          { return false }
func (fakeDaemon) ConnectionActive() bool                               { return false }
func (fakeDaemon) ConnectFor(context.Context, appd.Actor, string) error { return nil }
func (fakeDaemon) DisconnectFor(context.Context, appd.Actor) error      { return nil }
func (fakeDaemon) SetControlMode(context.Context, appd.Actor, types.ControlModeRequest) error {
	return nil
}
func (fakeDaemon) StartOperation(_ appd.Actor, kind, profileID string, _ func(context.Context) error) (types.Operation, error) {
	return types.Operation{ID: "op", Kind: kind, ProfileID: profileID, State: types.OperationRunning}, nil
}
func (fakeDaemon) OperationFor(appd.Actor, string) (types.Operation, error) {
	return types.Operation{ID: "op", State: types.OperationRunning}, nil
}
func (fakeDaemon) Ready() types.ReadyStatus { return types.ReadyStatus{Ready: true} }
func (fakeDaemon) WatchSince(context.Context, appd.Actor, string, uint64) <-chan types.Notify {
	ch := make(chan types.Notify)
	close(ch)
	return ch
}
func (fakeDaemon) UpdateCheck(context.Context) (types.UpdateInfo, error) {
	return types.UpdateInfo{CurrentVersion: buildinfo.Version}, nil
}

func request(method, path string) *http.Request {
	req := httptest.NewRequest(method, "http://"+ipc.LocalAPIHost+path, nil)
	return req.WithContext(WithActor(req.Context(), appd.SystemActor()))
}

func TestLiveReturnsVersionAndCapabilities(t *testing.T) {
	rec := httptest.NewRecorder()
	New(fakeDaemon{}).Handler().ServeHTTP(rec, request(http.MethodGet, "/v3/live"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var got types.LiveStatus
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Version != buildinfo.Version || got.APIMajor != 3 {
		t.Fatalf("live = %+v", got)
	}
	want := map[string]bool{"watch-replay": false, "structured-errors": false}
	for _, capability := range got.Capabilities {
		if _, ok := want[capability]; ok {
			want[capability] = true
		}
	}
	for capability, found := range want {
		if !found {
			t.Fatalf("missing capability %s", capability)
		}
	}
}

func TestV1IsRemovedWithStructuredError(t *testing.T) {
	rec := httptest.NewRecorder()
	New(fakeDaemon{}).Handler().ServeHTTP(rec, request(http.MethodGet, "/v1/status"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rec.Code)
	}
	var got errorEnvelope
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Error.Code != "endpoint_not_found" || got.Error.RequestID == "" {
		t.Fatalf("error = %+v", got.Error)
	}
}

func TestRejectsInvalidHostAndOrigin(t *testing.T) {
	for name, mutate := range map[string]func(*http.Request){
		"host":   func(r *http.Request) { r.Host = "evil.example" },
		"origin": func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") },
	} {
		t.Run(name, func(t *testing.T) {
			req := request(http.MethodGet, "/v3/status")
			mutate(req)
			rec := httptest.NewRecorder()
			New(fakeDaemon{}).Handler().ServeHTTP(rec, req)
			if rec.Code < 400 {
				t.Fatalf("status = %d", rec.Code)
			}
		})
	}
}

func TestRequestBodyIsBoundedAndStructured(t *testing.T) {
	body := bytes.NewReader(bytes.Repeat([]byte("x"), maxRequestBodyBytes+1))
	req := httptest.NewRequest(http.MethodPost, "http://"+ipc.LocalAPIHost+"/v3/profiles", body)
	req = req.WithContext(WithActor(req.Context(), appd.SystemActor()))
	rec := httptest.NewRecorder()
	New(fakeDaemon{}).Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Fatalf("content-type = %q", got)
	}
}

func TestConnectionIsAsynchronous(t *testing.T) {
	req := request(http.MethodPut, "/v3/connection")
	req.Body = http.NoBody
	req.Header.Set("Content-Type", "application/json")
	req = req.Clone(req.Context())
	req.Body = io.NopCloser(bytes.NewBufferString(`{"profile_id":"p1"}`))
	rec := httptest.NewRecorder()
	New(fakeDaemon{}).Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
}
