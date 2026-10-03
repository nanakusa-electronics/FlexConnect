package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"flexconnect/client/local"
	"flexconnect/internal/types"
)

func TestInteractiveATrustLoginImportsCredential(t *testing.T) {
	for _, auth := range []string{"ecnu_passkey", "shanghaitech_passkey"} {
		t.Run(auth, func(t *testing.T) {
			seen := stubLoginProbes(t, nil, nil)
			dir := t.TempDir()
			path := filepath.Join(dir, "passkey fixture.json")
			credential := []byte(`{"test":"credential payload"}`)
			if err := os.WriteFile(path, credential, 0o600); err != nil {
				t.Fatal(err)
			}
			compatibility := filepath.Join(dir, "compatibility.json")
			if err := os.WriteFile(compatibility, []byte(`{"tcp_to_l3_fallback":true}`), 0o600); err != nil {
				t.Fatal(err)
			}
			var payload types.ProfileCreateRequest
			posts := 0
			client := &local.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				body, status := `{}`, http.StatusOK
				if req.Method == http.MethodPost && req.URL.Path == "/v3/profiles" {
					posts++
					if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
						t.Fatal(err)
					}
					body, status = `{"id":"created","name":"campus","scope":"user"}`, http.StatusCreated
				} else if req.URL.Path == "/v3/profiles" {
					body = `[]`
				}
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header), Request: req}, nil
			})}
			choice := "ECNU Passkey"
			if auth == "shanghaitech_passkey" {
				choice = "ShanghaiTech Passkey"
			}
			input := strings.NewReader("atrust\n" + choice + "\nhttps://vpn.example.com\n\n\"" + path + "\"\ncampus-domain\n" + compatibility + "\ncampus\n")
			var output strings.Builder
			oldOut := cliOut
			cliOut = &output
			defer func() { cliOut = oldOut }()
			if err := runInteractiveLogin(context.Background(), client, input, &output, time.Second); err != nil {
				t.Fatal(err)
			}
			if posts != 1 || payload.Provider != types.ProviderATrust || payload.AuthMethod != types.AuthMethod(auth) || string(payload.Credential) != string(credential) || payload.Password != "" || payload.Scope != types.ProfileScopeUser || payload.Username != "" || payload.Name != "campus" || payload.ServerURL != "https://vpn.example.com" || payload.LoginDomain != "campus-domain" || !payload.ATrustCompatibility.TCPToL3Fallback {
				t.Fatal("wizard did not submit the selected provider, credential, or settings")
			}
			if len(*seen) != 0 || strings.Contains(output.String(), "Verifying login") || strings.Contains(output.String(), string(credential)) {
				t.Fatal("aTrust wizard probed AnyConnect or exposed credential data")
			}
			if _, err := os.Stat(path); err != nil {
				t.Fatal("source keystore was removed")
			}
			if !strings.Contains(output.String(), "Do not use the source keystore concurrently") {
				t.Fatal("credential import warning missing")
			}
		})
	}
}

func TestATrustWizardRetriesUnreadableKeystore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credential.json")
	if err := os.WriteFile(path, []byte(`{"test":"credential"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	in := strings.NewReader("invalid\n2\ninvalid\n2\nhttps://vpn.example.com\nalice\n" + filepath.Join(dir, "missing") + "\n" + path + "\n\n\ncorp\n")
	profile, password, credential, err := promptLoginProfile(context.Background(), in, &out)
	if err != nil {
		t.Fatal(err)
	}
	if profile.AuthMethod != types.AuthShanghaiTechPasskey || profile.Username != "alice" || password != "" || len(credential) == 0 || !strings.Contains(out.String(), "Cannot read keystore") {
		t.Fatal("retry did not retain wizard choices")
	}
}

func TestLoginWizardCancellationAndIncompleteInput(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, _, err := promptLoginProfile(ctx, strings.NewReader(""), io.Discard); err != context.Canceled {
		t.Fatalf("error = %v", err)
	}
	if _, _, _, err := promptLoginProfile(context.Background(), strings.NewReader("2\n"), io.Discard); err == nil {
		t.Fatal("incomplete wizard accepted")
	}
}
