package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"flexconnect/client/local"
	"flexconnect/internal/loginprobe"
	"flexconnect/internal/netcheck"
	"flexconnect/internal/types"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func stubLoginProbes(t *testing.T, groups []string, verifyResults []error) *[]loginprobe.Options {
	t.Helper()
	previousFetch, previousVerify := loginFetchGroups, loginVerify
	loginFetchGroups = func(ctx context.Context, serverURL string) ([]string, error) {
		return groups, nil
	}
	var seen []loginprobe.Options
	loginVerify = func(ctx context.Context, opts loginprobe.Options) error {
		seen = append(seen, opts)
		if len(verifyResults) == 0 {
			return nil
		}
		err := verifyResults[0]
		verifyResults = verifyResults[1:]
		return err
	}
	t.Cleanup(func() {
		loginFetchGroups, loginVerify = previousFetch, previousVerify
	})
	return &seen
}

func TestInteractiveLoginStartsTimeoutAfterInput(t *testing.T) {
	stubLoginProbes(t, []string{"engineering", "sales"}, nil)
	inputReader, inputWriter := io.Pipe()
	defer inputReader.Close()

	var paths []string
	client := &local.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		paths = append(paths, req.URL.Path)

		status := http.StatusOK
		body := "{}"
		if req.URL.Path == "/v3/live" {
			body = `{"status":"ok","version":"2.0.0-dev","api_major":3,"capabilities":["authentication","component-health","machine-mode","operations","profile-scope","vpn-providers","structured-errors","watch-replay"]}`
		} else if req.URL.Path == "/v3/ready" {
			body = `{"ready":true,"components":[]}`
		} else if req.URL.Path == "/v3/profiles" && req.Method == http.MethodPost {
			status = http.StatusCreated
			body = `{"id":"created","name":"corp","scope":"user"}`
		} else if req.URL.Path == "/v3/profiles" {
			body = "[]"
		}
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})}

	go func() {
		time.Sleep(40 * time.Millisecond)
		_, _ = io.WriteString(inputWriter, "https://vpn.example.com\n1\nalice\npassword\ncorp\n")
		_ = inputWriter.Close()
	}()

	var output strings.Builder
	previousOut := cliOut
	cliOut = &output
	defer func() { cliOut = previousOut }()
	if err := runInteractiveLogin(context.Background(), client, inputReader, &output, 20*time.Millisecond); err != nil {
		t.Fatalf("interactive login failed after slow input: %v", err)
	}

	want := []string{"/v3/profiles", "/v3/status", "/v3/profiles"}
	if strings.Join(paths, ",") != strings.Join(want, ",") {
		t.Fatalf("request paths = %v, want %v", paths, want)
	}
}

func TestRunChecksDaemonBeforeInteractiveLogin(t *testing.T) {
	stubLoginProbes(t, []string{"engineering"}, nil)
	inputReader, inputWriter := io.Pipe()
	defer inputReader.Close()

	var paths []string
	client := &local.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		paths = append(paths, req.URL.Path)
		status := http.StatusOK
		body := "{}"
		if req.URL.Path == "/v3/live" {
			body = `{"status":"ok","version":"2.0.0-dev","api_major":3,"capabilities":["authentication","component-health","machine-mode","operations","profile-scope","vpn-providers","structured-errors","watch-replay"]}`
		} else if req.URL.Path == "/v3/ready" {
			body = `{"ready":true,"components":[]}`
		} else if req.URL.Path == "/v3/profiles" && req.Method == http.MethodPost {
			status = http.StatusCreated
			body = `{"id":"created","name":"corp","scope":"user"}`
		} else if req.URL.Path == "/v3/profiles" {
			body = "[]"
		}
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})}

	go func() {
		_, _ = io.WriteString(inputWriter, "https://vpn.example.com\n1\nalice\npassword\ncorp\n")
		_ = inputWriter.Close()
	}()

	previousIn, previousOut := cliIn, cliOut
	var output strings.Builder
	cliIn, cliOut = inputReader, &output
	defer func() { cliIn, cliOut = previousIn, previousOut }()
	if err := run(context.Background(), client, []string{"login"}); err != nil {
		t.Fatalf("run interactive login: %v", err)
	}

	want := []string{"/v3/live", "/v3/ready", "/v3/profiles", "/v3/status", "/v3/profiles"}
	if strings.Join(paths, ",") != strings.Join(want, ",") {
		t.Fatalf("request paths = %v, want %v", paths, want)
	}
}

func TestInteractiveLoginVerifiesBeforeSavingProfile(t *testing.T) {
	seen := stubLoginProbes(t, []string{"engineering", "sales"}, nil)
	var output strings.Builder
	req, err := promptLoginRequest(context.Background(),
		strings.NewReader("https://vpn.example.com\nengineering\nalice\nhunter2\ncorp\n"), &output)
	if err != nil {
		t.Fatalf("promptLoginRequest: %v", err)
	}
	if req != (types.LoginRequest{
		Name: "corp", ServerURL: "https://vpn.example.com",
		Username: "alice", Group: "engineering", Password: "hunter2",
	}) {
		t.Fatalf("login request = %+v", req)
	}
	if len(*seen) != 1 {
		t.Fatalf("verification calls = %d, want 1", len(*seen))
	}
	if got := (*seen)[0]; got.Group != "engineering" || got.Username != "alice" || got.Password != "hunter2" {
		t.Fatalf("verification options = %+v", got)
	}
	for _, want := range []string{
		"Connection test succeeded. Available user groups:",
		"1. engineering",
		"2. sales",
		"Verifying login...",
		"Login verified; saving profile",
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("output %q missing %q", output.String(), want)
		}
	}
}

func TestInteractiveLoginRetriesFailedVerification(t *testing.T) {
	rejected := errors.New("Authentication failed")
	seen := stubLoginProbes(t, []string{"engineering", "sales"}, []error{rejected})
	var output strings.Builder
	req, err := promptLoginRequest(context.Background(),
		strings.NewReader("https://vpn.example.com\n2\nalice\nbadpass\n1\nalice\ngoodpass\ncorp\n"), &output)
	if err != nil {
		t.Fatalf("promptLoginRequest: %v", err)
	}
	if req.Group != "engineering" || req.Username != "alice" || req.Password != "goodpass" {
		t.Fatalf("login request = %+v", req)
	}
	if len(*seen) != 2 {
		t.Fatalf("verification calls = %d, want 2", len(*seen))
	}
	if (*seen)[0].Password != "badpass" || (*seen)[0].Group != "sales" {
		t.Fatalf("first verification = %+v", (*seen)[0])
	}
	if !strings.Contains(output.String(), "Login verification failed: Authentication failed") {
		t.Fatalf("output %q missing failure message", output.String())
	}
	if !strings.Contains(output.String(), "Re-enter the VPN group, username, and password") {
		t.Fatalf("output %q missing re-entry prompt", output.String())
	}
}

func TestInteractiveLoginRetriesServerConnectionTest(t *testing.T) {
	previousFetch, previousVerify := loginFetchGroups, loginVerify
	defer func() { loginFetchGroups, loginVerify = previousFetch, previousVerify }()
	calls := 0
	loginFetchGroups = func(ctx context.Context, serverURL string) ([]string, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("dial tcp: connection refused")
		}
		return []string{"engineering"}, nil
	}
	loginVerify = func(ctx context.Context, opts loginprobe.Options) error { return nil }

	var output strings.Builder
	req, err := promptLoginRequest(context.Background(),
		strings.NewReader("https://typo.example.com\nhttps://vpn.example.com\n\nalice\npassword\n\n"), &output)
	if err != nil {
		t.Fatalf("promptLoginRequest: %v", err)
	}
	if req.ServerURL != "https://vpn.example.com" || req.Group != "engineering" {
		t.Fatalf("login request = %+v", req)
	}
	if !strings.Contains(output.String(), "Connection test failed: dial tcp: connection refused") {
		t.Fatalf("output %q missing connection failure", output.String())
	}
}

func TestPromptGroupSelection(t *testing.T) {
	tests := []struct {
		name   string
		groups []string
		input  string
		want   string
		output []string
	}{
		{name: "index selection", groups: []string{"engineering", "sales"}, input: "2\n", want: "sales"},
		{name: "name selection", groups: []string{"engineering", "sales"}, input: "engineering\n", want: "engineering"},
		{name: "default first group", groups: []string{"engineering", "sales"}, input: "\n", want: "engineering"},
		{
			name:   "unknown group re-prompts",
			groups: []string{"engineering", "sales"},
			input:  "bogus\nsales\n",
			want:   "sales",
			output: []string{`Unknown group "bogus"; choose one of: engineering, sales`},
		},
		{name: "free text without advertised groups", groups: nil, input: "mygroup\n", want: "mygroup"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := bufio.NewReader(strings.NewReader(test.input))
			var output strings.Builder
			got, err := promptGroupSelection(reader, &output, test.groups)
			if err != nil {
				t.Fatalf("promptGroupSelection: %v", err)
			}
			if got != test.want {
				t.Fatalf("group = %q, want %q", got, test.want)
			}
			for _, want := range test.output {
				if !strings.Contains(output.String(), want) {
					t.Fatalf("output %q missing %q", output.String(), want)
				}
			}
		})
	}
}

func TestCommandNeedsDaemon(t *testing.T) {
	tests := []struct {
		args []string
		want bool
	}{
		{args: []string{"status"}, want: true},
		{args: []string{"login"}, want: true},
		{args: []string{"watch"}, want: true},
		{args: []string{"netcheck"}, want: false},
		{args: []string{"status", "--help"}, want: false},
		{args: []string{"profile", "add", "--help"}, want: false},
		{args: []string{"profile"}, want: false},
		{args: []string{"profile", "list"}, want: true},
		{args: []string{"help", "status"}, want: false},
		{args: []string{"unknown"}, want: false},
	}
	for _, test := range tests {
		if got := commandNeedsDaemon(test.args); got != test.want {
			t.Errorf("commandNeedsDaemon(%v) = %v, want %v", test.args, got, test.want)
		}
	}
}

func TestRunStopsWhenDaemonConnectivityCheckFails(t *testing.T) {
	requestCount := 0
	client := &local.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requestCount++
		return &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Body:       io.NopCloser(strings.NewReader("daemon unavailable\n")),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})}

	err := run(context.Background(), client, []string{"status"})
	if err == nil || !strings.Contains(err.Error(), "cannot connect to flexconnectd: daemon unavailable") {
		t.Fatalf("run error = %v", err)
	}
	if requestCount != 1 {
		t.Fatalf("request count = %d, want only the connectivity check", requestCount)
	}
}

func TestReadSecretInputFromStdin(t *testing.T) {
	got, provided, err := readSecretInput("", true, strings.NewReader("test password\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !provided || got != "test password" {
		t.Fatalf("secret = %q provided=%v", got, provided)
	}
}

func TestReadSecretInputRejectsAmbiguousAndOversizedSources(t *testing.T) {
	if _, _, err := readSecretInput("password", true, strings.NewReader("ignored")); err == nil {
		t.Fatal("combined password sources succeeded")
	}
	oversized := strings.NewReader(strings.Repeat("x", maxSecretInputBytes+1))
	if _, _, err := readSecretInput("", true, oversized); err == nil {
		t.Fatal("oversized password input succeeded")
	}
}

func TestFormatTrafficSnapshotText(t *testing.T) {
	got := formatTrafficSnapshot(types.TrafficSnapshot{
		Connected:              true,
		BytesSent:              1024,
		BytesReceived:          2048,
		BytesSentPerSecond:     512,
		BytesReceivedPerSecond: 1536,
		SampledAt:              "2026-06-27T00:00:00Z",
	})

	for _, want := range []string{
		"Connected: true",
		"Traffic Sent: 1024 B",
		"Traffic Received: 2048 B",
		"Speed Sent: 512 B/s",
		"Speed Received: 1536 B/s",
		"Sampled: 2026-06-27T00:00:00Z",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in:\n%s", want, got)
		}
	}
}

func TestFormatNetcheckResultTextIncludesSocketsAndSpeed(t *testing.T) {
	got := formatNetcheckResult(netcheck.Result{
		Mode: "CSTP", Endpoint: "vpn.example.test", LocalInterface: "Ethernet",
		LocalIPv4: "192.0.2.10", Gateway: "192.0.2.1", AuthLocalAddress: "192.0.2.10:50000",
		AuthRemoteAddress: "198.51.100.10:443", CSTPStatus: "200 OK", VPNAddress: "172.20.130.149",
		MTU: 1399, Transport: "dtls", ObservationDuration: 2 * time.Second, DPDSent: 1,
		Speedtest: &netcheck.SpeedtestResult{TargetHost: "speed.example.test", Bytes: 1024, Duration: time.Second, MiBPS: 0.01, Transport: "dtls"},
	})
	for _, want := range []string{
		"Auth Socket: 192.0.2.10:50000 -> 198.51.100.10:443",
		"CSTP: 200 OK vpn_ip=172.20.130.149 mtu=1399",
		"Speedtest: target=speed.example.test transport=dtls",
		"0.01 MiB/s",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in:\n%s", want, got)
		}
	}
}
