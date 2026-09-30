//go:build windows

package main

import (
	"testing"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

func TestResumesWindowsSession(t *testing.T) {
	for _, tc := range []struct {
		request svc.ChangeRequest
		want    bool
	}{
		{svc.ChangeRequest{Cmd: svc.SessionChange, EventType: windows.WTS_SESSION_UNLOCK}, true},
		{svc.ChangeRequest{Cmd: svc.PowerEvent, EventType: powerResumeAutomatic}, true},
		{svc.ChangeRequest{Cmd: svc.PowerEvent, EventType: powerResumeSuspend}, true},
		{svc.ChangeRequest{Cmd: svc.SessionChange, EventType: windows.WTS_SESSION_LOCK}, false},
		{svc.ChangeRequest{Cmd: svc.PowerEvent, EventType: 4}, false},
	} {
		if got := resumesWindowsSession(tc.request); got != tc.want {
			t.Fatalf("resumesWindowsSession(%v) = %t, want %t", tc.request, got, tc.want)
		}
	}
}
