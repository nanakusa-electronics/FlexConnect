package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadATrustCompatibility(t *testing.T) {
	for _, tc := range []struct {
		body            string
		valid, fallback bool
	}{
		{`{}`, true, false},
		{`{"tcp_to_l3_fallback":true,"fallback_gateways":["[2001:db8::1]:441"]}`, true, true},
		{`{"tcp_to_l3_fallback":false}`, true, false},
		{`{"tcp_to_l3_fallbak":true}`, false, false},
		{`{"fallback_gateways":["gateway:0"]}`, false, false},
		{`{"process_identity":{"name":"x"}}`, false, false},
		{`null`, false, false},
		{`{} {}`, false, false},
	} {
		t.Run(tc.body, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "compatibility.json")
			if err := os.WriteFile(path, []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			settings, err := readATrustCompatibility(path)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
			if tc.valid && settings.TCPToL3Fallback != tc.fallback {
				t.Fatal("switch lost")
			}
		})
	}
}
