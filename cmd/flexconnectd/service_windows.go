//go:build windows

package main

import (
	"context"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

const windowsServiceName = "FlexConnect"

const (
	powerSuspend         = 0x04
	powerResumeAutomatic = 0x12
	powerResumeSuspend   = 0x07
)

func isWindowsService() bool {
	ok, err := svc.IsWindowsService()
	if err != nil {
		return false
	}
	return ok
}

func runWindowsService(opts daemonOptions) error {
	return svc.Run(windowsServiceName, &daemonService{opts: opts})
}

type daemonService struct {
	opts daemonOptions
}

func (s *daemonService) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const accepts = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPowerEvent | svc.AcceptSessionChange

	changes <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runErrCh := make(chan error, 1)
	readyCh := make(chan error, 1)
	powerCh := make(chan bool, 1)
	go func() {
		runErrCh <- runDaemonReadyWithPowerEvents(ctx, s.opts, readyCh, powerCh)
	}()

	select {
	case err := <-readyCh:
		if err != nil {
			cancel()
			return false, uint32(windows.ERROR_SERVICE_SPECIFIC_ERROR)
		}
	case err := <-runErrCh:
		if err != nil {
			return false, uint32(windows.ERROR_SERVICE_SPECIFIC_ERROR)
		}
		return false, windows.NO_ERROR
	}

	changes <- svc.Status{State: svc.Running, Accepts: accepts}

	stopping := false
	for {
		select {
		case err := <-runErrCh:
			if err != nil {
				return false, uint32(windows.ERROR_SERVICE_SPECIFIC_ERROR)
			}
			return false, windows.NO_ERROR
		case req := <-requests:
			switch req.Cmd {
			case svc.Stop, svc.Shutdown:
				if !stopping {
					stopping = true
					changes <- svc.Status{State: svc.StopPending}
					cancel()
				}
			case svc.Interrogate:
				changes <- req.CurrentStatus
			case svc.PowerEvent, svc.SessionChange:
				if suspended, ok := windowsPowerState(req); ok {
					// Keep the latest power state when notifications arrive in a burst.
					select {
					case <-powerCh:
					default:
					}
					powerCh <- suspended
				}
			}
		}
	}
}

func windowsPowerState(req svc.ChangeRequest) (suspended, ok bool) {
	if req.Cmd == svc.PowerEvent && req.EventType == powerSuspend {
		return true, true
	}
	if req.Cmd == svc.SessionChange && req.EventType == windows.WTS_SESSION_UNLOCK ||
		req.Cmd == svc.PowerEvent && (req.EventType == powerResumeAutomatic || req.EventType == powerResumeSuspend) {
		return false, true
	}
	return false, false
}
