//go:build windows

package main

import (
	"testing"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

func TestWindowsPowerState(t *testing.T) {
	for _, tc := range []struct {
		request   svc.ChangeRequest
		suspended bool
		want      bool
	}{
		{svc.ChangeRequest{Cmd: svc.SessionChange, EventType: windows.WTS_SESSION_UNLOCK}, false, true},
		{svc.ChangeRequest{Cmd: svc.PowerEvent, EventType: powerResumeAutomatic}, false, true},
		{svc.ChangeRequest{Cmd: svc.PowerEvent, EventType: powerResumeSuspend}, false, true},
		{svc.ChangeRequest{Cmd: svc.SessionChange, EventType: windows.WTS_SESSION_LOCK}, false, false},
		{svc.ChangeRequest{Cmd: svc.PowerEvent, EventType: powerSuspend}, true, true},
	} {
		if suspended, got := windowsPowerState(tc.request); got != tc.want || suspended != tc.suspended {
			t.Fatalf("windowsPowerState(%v) valid = %t, want %t", tc.request, got, tc.want)
		}
	}
}
