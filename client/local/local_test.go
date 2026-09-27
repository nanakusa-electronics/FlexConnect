package local

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"flexconnect/internal/types"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestUpdateProfileReturnsAsyncOperation(t *testing.T) {
	client := &Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodPatch || req.URL.EscapedPath() != "/v3/profiles/profile-1" {
			t.Fatalf("request = %s %s", req.Method, req.URL.EscapedPath())
		}
		return &http.Response{
			StatusCode: http.StatusAccepted,
			Body:       io.NopCloser(strings.NewReader(`{"operation":{"id":"op-1","kind":"profile-update","state":"running","started_at":"now"}}`)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})}

	result, err := client.UpdateProfile(context.Background(), "profile-1", types.ProfileUpdateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Profile != nil || result.Operation == nil || result.Operation.ID != "op-1" {
		t.Fatalf("result = %+v", result)
	}
}

func TestHealthRejectsIncompatibleAPI(t *testing.T) {
	client := &Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"status":"ok","version":"2.0.0","api_version":"2"}`)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})}

	_, err := client.Health(context.Background())
	var incompatible *IncompatibleAPIError
	if !errors.As(err, &incompatible) {
		t.Fatalf("Health error = %v, want IncompatibleAPIError", err)
	}
}

func TestReadyDecodesComponentReasonsFrom503(t *testing.T) {
	client := &Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/v3/ready" {
			t.Fatalf("path = %s", req.URL.Path)
		}
		return &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Body:       io.NopCloser(strings.NewReader(`{"ready":false,"components":[{"name":"machine-connection","ready":false,"message":"authentication failed"}]}`)),
			Header:     make(http.Header), Request: req,
		}, nil
	})}
	ready, err := client.Ready(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ready.Ready || len(ready.Components) != 1 || ready.Components[0].Name != "machine-connection" {
		t.Fatalf("ready = %+v", ready)
	}
}

func TestSetControlModeUsesV2Endpoint(t *testing.T) {
	client := &Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodPut || req.URL.Path != "/v3/control-mode" {
			t.Fatalf("request = %s %s", req.Method, req.URL.Path)
		}
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), `"mode":"user"`) {
			t.Fatalf("body = %s", body)
		}
		return &http.Response{StatusCode: http.StatusAccepted, Body: io.NopCloser(strings.NewReader(`{"operation":{"id":"op-1"}}`)), Header: make(http.Header), Request: req}, nil
	})}
	operation, err := client.SetControlMode(context.Background(), "user", "")
	if err != nil {
		t.Fatal(err)
	}
	if operation.ID != "op-1" {
		t.Fatalf("operation = %+v", operation)
	}
}
