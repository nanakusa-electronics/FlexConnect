package main

import (
	"context"
	"encoding/json"
	"flexconnect/client/local"
	"flexconnect/internal/types"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestAuthenticationInputOutsideRequestDeadline(t *testing.T) {
	in, writer := io.Pipe()
	defer in.Close()
	previousIn, previousOut := cliIn, cliOut
	var out strings.Builder
	cliIn, cliOut = in, &out
	defer func() { cliIn, cliOut = previousIn, previousOut }()
	submitted := false
	client := &local.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Context().Err() != nil {
			t.Fatal("request context expired")
		}
		status, body := http.StatusOK, ""
		if req.Method == http.MethodGet {
			data, _ := json.Marshal(types.AuthenticationChallenge{ID: "challenge", Method: "sms", ExpiresAt: time.Now().Add(time.Minute)})
			body = string(data)
			go func() {
				time.Sleep(50 * time.Millisecond)
				_, _ = io.WriteString(writer, "123456\n")
				_ = writer.Close()
			}()
		} else {
			if req.URL.Path != "/v3/authentication/challenge" {
				t.Fatalf("submit path: %s", req.URL.Path)
			}
			var response types.AuthenticationResponse
			if err := json.NewDecoder(req.Body).Decode(&response); err != nil {
				t.Fatal(err)
			}
			if response.Response != "123456" {
				t.Fatal("wrong code")
			}
			submitted = true
			status = http.StatusNoContent
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header), Request: req}, nil
	})}
	if err := runAuthentication(context.Background(), client, []string{"respond", "--response-stdin"}, 20*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if !submitted || strings.Contains(out.String(), "123456") {
		t.Fatal("missing submission or leaked code")
	}
}

func TestAuthenticationRejectsCodeArgument(t *testing.T) {
	err := runAuthentication(context.Background(), &local.Client{}, []string{"respond", "123456"}, time.Second)
	if err == nil || strings.Contains(err.Error(), "123456") {
		t.Fatal("code argument accepted or echoed")
	}
}
