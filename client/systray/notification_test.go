package systray

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"flexconnect/internal/types"
)

type recordingNotifier struct {
	calls  []string
	alerts []string
}

func (n *recordingNotifier) Send(title, body string) error {
	n.calls = append(n.calls, title+"|"+body)
	return nil
}

func (n *recordingNotifier) Alert(title, body string) error {
	n.alerts = append(n.alerts, title+"|"+body)
	return nil
}

func TestConnectionNotificationsDeduplicateLifecycleKind(t *testing.T) {
	recorder := &recordingNotifier{}
	menu := &Menu{rebuildCh: make(chan struct{}, 1), notifier: recorder}
	event := types.ConnectionEvent{ID: "event-1", ConnectionID: "reconnect-1", Kind: "reconnect_scheduled", Attempt: 1}
	menu.handleNotify(types.Notify{Connection: &event}, func() {})
	menu.handleNotify(types.Notify{Connection: &event}, func() {})
	if len(recorder.calls) != 1 {
		t.Fatalf("notification calls = %d, want 1", len(recorder.calls))
	}
}

func TestTrayErrorsAlertAndDeduplicate(t *testing.T) {
	recorder := &recordingNotifier{}
	menu := &Menu{notifier: recorder}
	err := fmt.Errorf("daemon unavailable")
	menu.reportError("daemon unavailable", err)
	menu.reportError("daemon unavailable", err)
	if len(recorder.alerts) != 1 {
		t.Fatalf("alert calls = %d, want 1", len(recorder.alerts))
	}
	if !strings.Contains(recorder.alerts[0], "daemon unavailable") {
		t.Fatalf("alert = %q, want operation and error", recorder.alerts[0])
	}
}

func TestConnectionNotificationKinds(t *testing.T) {
	recorder := &recordingNotifier{}
	menu := &Menu{rebuildCh: make(chan struct{}, 1), notifier: recorder}
	for _, kind := range []string{"connection_lost", "reconnect_scheduled", "reconnected", "reconnect_failed", "reconnect_exhausted"} {
		event := types.ConnectionEvent{ID: kind, ConnectionID: kind, Kind: kind, ReasonCode: "tls_read_error", Attempt: 2}
		menu.handleNotify(types.Notify{Connection: &event}, func() {})
	}
	if len(recorder.calls) != 5 {
		t.Fatalf("notification calls = %d, want 5", len(recorder.calls))
	}
}

func TestAuthenticationNotificationDeduplicatesAndIgnoresExpired(t *testing.T) {
	recorder := &recordingNotifier{}
	menu := &Menu{notifier: recorder}
	challenge := types.AuthenticationChallenge{ID: "challenge", Method: "sms", ExpiresAt: timeNow().Add(time.Minute)}
	menu.handleNotify(types.Notify{Event: "authentication", Authentication: &challenge}, func() {})
	menu.handleNotify(types.Notify{Event: "snapshot", Authentication: &challenge}, func() {})
	challenge.ID = "expired"
	challenge.ExpiresAt = timeNow().Add(-time.Second)
	menu.handleNotify(types.Notify{Authentication: &challenge}, func() {})
	if len(recorder.calls) != 1 || !strings.Contains(recorder.calls[0], "flexconnect auth respond") {
		t.Fatalf("notifications: %v", recorder.calls)
	}
}
