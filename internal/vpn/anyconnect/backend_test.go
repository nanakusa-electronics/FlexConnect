package anyconnect

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	acRPC "flexconnect/internal/anyconnect/rpc"
	acSession "flexconnect/internal/anyconnect/session"
	"flexconnect/internal/osnet"
	"flexconnect/internal/types"
	"flexconnect/internal/vpn"
)

type fakeMonitor struct {
	mu      sync.Mutex
	closed  bool
	changes chan osnet.UnderlayChange
}

func (m *fakeMonitor) Snapshot(context.Context) (osnet.UnderlaySnapshot, error) {
	return osnet.UnderlaySnapshot{}, nil
}

func (m *fakeMonitor) Changes(context.Context) <-chan osnet.UnderlayChange {
	return m.changes
}

func (m *fakeMonitor) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *fakeMonitor) isClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

type monitorRecorder struct {
	mu       sync.Mutex
	monitors []*fakeMonitor
}

func (r *monitorRecorder) factory() func(context.Context, osnet.MonitorOptions) (osnet.Monitor, error) {
	return func(context.Context, osnet.MonitorOptions) (osnet.Monitor, error) {
		monitor := &fakeMonitor{changes: make(chan osnet.UnderlayChange, 4)}
		r.mu.Lock()
		r.monitors = append(r.monitors, monitor)
		r.mu.Unlock()
		return monitor, nil
	}
}

func (r *monitorRecorder) all() []*fakeMonitor {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*fakeMonitor(nil), r.monitors...)
}

func newTestBackend() (*Backend, *monitorRecorder) {
	recorder := &monitorRecorder{}
	backend := &Backend{
		events:     make(chan vpn.Event, 32),
		newMonitor: recorder.factory(),
	}
	return backend, recorder
}

func typesProfileStub() types.Profile {
	return types.Profile{ServerURL: "https://vpn.example.test", Username: "tester"}
}

func newMonitorTestSession(t *testing.T) *acSession.ConnSession {
	t.Helper()
	connection := acRPC.NewConnection(buildAuthProfile(typesProfileStub(), "ignored"))
	cSess := connection.Session.NewConnSession(&http.Header{})
	cSess.TunName = "FlexConnect"
	t.Cleanup(cSess.Close)
	return cSess
}

func monitorRequest(connectionID string) vpn.ConnectRequest {
	profile := typesProfileStub()
	profile.ID = "profile-1"
	return vpn.ConnectRequest{Profile: profile, AttemptID: "attempt-1", ConnectionID: connectionID, OwnerID: "owner-1"}
}

func TestStartUnderlayMonitorReplacesStaleMonitor(t *testing.T) {
	backend, recorder := newTestBackend()
	first := newMonitorTestSession(t)
	if err := backend.startUnderlayMonitor(first, "vpn-1", monitorRequest("vpn-1")); err != nil {
		t.Fatalf("first startUnderlayMonitor: %v", err)
	}
	backend.stopMonitorFor("vpn-x")
	if monitors := recorder.all(); len(monitors) != 1 || monitors[0].isClosed() {
		t.Fatal("stopMonitorFor with a different connection ID must not release the monitor")
	}

	second := newMonitorTestSession(t)
	if err := backend.startUnderlayMonitor(second, "vpn-2", monitorRequest("vpn-2")); err != nil {
		t.Fatalf("second startUnderlayMonitor: %v", err)
	}
	monitors := recorder.all()
	if len(monitors) != 2 {
		t.Fatalf("created %d monitors, want 2", len(monitors))
	}
	if !monitors[0].isClosed() {
		t.Fatal("stale monitor was not closed when replaced")
	}
	if monitors[1].isClosed() {
		t.Fatal("replacement monitor must stay active")
	}
	backend.stopUnderlayMonitor()
	if !monitors[1].isClosed() {
		t.Fatal("stopUnderlayMonitor did not close the active monitor")
	}
}

func TestMonitorCloseKeepsNetworkObserverAfterSessionEnd(t *testing.T) {
	backend, recorder := newTestBackend()
	connection := acRPC.NewConnection(buildAuthProfile(typesProfileStub(), "ignored"))
	cSess := connection.Session.NewConnSession(&http.Header{})
	cSess.TunName = "FlexConnect"
	if err := backend.startUnderlayMonitor(cSess, "vpn-1", monitorRequest("vpn-1")); err != nil {
		t.Fatalf("startUnderlayMonitor: %v", err)
	}
	go backend.monitorClose(cSess, "vpn-1", monitorRequest("vpn-1"))

	// The session ends without Backend.Disconnect ever running, for example
	// because the server dropped the tunnel.
	cSess.Close()

	select {
	case event := <-backend.events:
		if event.Type != "disconnected" {
			t.Fatalf("event type = %s, want disconnected", event.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("monitorClose did not emit the disconnect event")
	}
	monitors := recorder.all()
	if len(monitors) != 1 || monitors[0].isClosed() {
		t.Fatal("network observer must remain active after the session ended")
	}

	// Reconnect after the unexpected drop: this used to fail with
	// "underlay monitor already active".
	second := newMonitorTestSession(t)
	if err := backend.startUnderlayMonitor(second, "vpn-2", monitorRequest("vpn-2")); err != nil {
		t.Fatalf("reconnect startUnderlayMonitor: %v", err)
	}
	if monitors := recorder.all(); len(monitors) != 2 {
		t.Fatalf("created %d monitors after reconnect, want 2", len(monitors))
	}
	backend.stopUnderlayMonitor()
}

func TestMonitorCloseDoesNotReleaseReplacementMonitor(t *testing.T) {
	backend, recorder := newTestBackend()
	connection := acRPC.NewConnection(buildAuthProfile(typesProfileStub(), "ignored"))
	oldSession := connection.Session.NewConnSession(&http.Header{})
	oldSession.TunName = "FlexConnect"
	if err := backend.startUnderlayMonitor(oldSession, "vpn-1", monitorRequest("vpn-1")); err != nil {
		t.Fatalf("startUnderlayMonitor: %v", err)
	}

	// A replacement connection takes over before the old teardown runs.
	backend.stopUnderlayMonitor()
	newSession := newMonitorTestSession(t)
	if err := backend.startUnderlayMonitor(newSession, "vpn-2", monitorRequest("vpn-2")); err != nil {
		t.Fatalf("replacement startUnderlayMonitor: %v", err)
	}
	go backend.monitorClose(oldSession, "vpn-1", monitorRequest("vpn-1"))
	oldSession.Close()

	select {
	case <-backend.events:
	case <-time.After(2 * time.Second):
		t.Fatal("monitorClose did not emit the disconnect event")
	}
	monitors := recorder.all()
	if len(monitors) != 2 {
		t.Fatalf("created %d monitors, want 2", len(monitors))
	}
	if monitors[1].isClosed() {
		t.Fatal("delayed teardown of the old session closed the replacement monitor")
	}
	backend.stopUnderlayMonitor()
}

func TestNetworkObserverSurvivesDisconnectAndReportsRecovery(t *testing.T) {
	backend, recorder := newTestBackend()
	cSess := newMonitorTestSession(t)
	if err := backend.startUnderlayMonitor(cSess, "vpn-1", monitorRequest("vpn-1")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close(context.Background()) })
	monitor := recorder.all()[0]
	if err := backend.Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, reason := range []string{"snapshot_error", "network_recovered"} {
		monitor.changes <- osnet.UnderlayChange{Reasons: []string{reason}, RebindRequired: true}
		select {
		case event := <-backend.events:
			if event.Type != "network_change" || event.ConnectionID != "vpn-1" || event.Network.Reasons[0] != reason {
				t.Fatalf("network event = %+v", event)
			}
		case <-time.After(time.Second):
			t.Fatalf("network observer missed %s after disconnect", reason)
		}
	}
	if err := backend.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !monitor.isClosed() {
		t.Fatal("backend shutdown did not close network observer")
	}
}
