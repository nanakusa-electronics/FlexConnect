package rpc

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"flexconnect/internal/anyconnect/auth"
	"flexconnect/internal/anyconnect/session"
	"flexconnect/internal/osnet"
)

type fakeManager struct {
	mu     sync.Mutex
	closed int
}

func TestDisconnectAfterTransportClosed(t *testing.T) {
	cleanupErr := errors.New("route cleanup failed")
	for _, tc := range []struct {
		name string
		err  error
	}{
		{name: "successful cleanup"},
		{name: "failed tunnel cleanup", err: cleanupErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			local, peer := net.Pipe()
			t.Cleanup(func() { _ = peer.Close() })
			conn := tls.Client(local, &tls.Config{})
			t.Cleanup(func() { _ = conn.Close() })
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			sess := &session.Session{}
			cSess := sess.NewConnSession(&http.Header{})
			done := make(chan struct{})
			cSess.SetTunnelDone(done)
			cSess.SetTunnelError(tc.err)
			close(done)
			connection := &Connection{Auth: &auth.Client{Conn: conn}, Session: sess}
			if err := connection.Disconnect(context.Background()); !errors.Is(err, tc.err) {
				t.Fatalf("Disconnect error = %v, want %v", err, tc.err)
			}
			select {
			case <-cSess.CloseChan:
			default:
				t.Fatal("Disconnect did not close the session")
			}
		})
	}
}

func TestTransientNetworkErrorIncludesInterruptedTLSHandshake(t *testing.T) {
	for _, err := range []error{io.EOF, io.ErrUnexpectedEOF} {
		if !isTransientNetworkError(err) {
			t.Fatalf("%v should be retryable after an interrupted TLS handshake", err)
		}
	}
}

func TestDisconnectReturnsTunnelCleanupFailure(t *testing.T) {
	sess := &session.Session{}
	cSess := sess.NewConnSession(&http.Header{})
	done := make(chan struct{})
	cSess.SetTunnelDone(done)
	cleanupErr := errors.New("route cleanup failed")
	cSess.SetTunnelError(cleanupErr)
	close(done)
	connection := &Connection{Session: sess}
	if err := connection.Disconnect(context.Background()); !errors.Is(err, cleanupErr) {
		t.Fatalf("Disconnect error = %v", err)
	}
}

func (m *fakeManager) Up(context.Context) error { return nil }
func (m *fakeManager) Set(context.Context, *osnet.Config) error {
	return nil
}
func (m *fakeManager) SetDynamicRoutes(context.Context, osnet.DynamicRoutes) error {
	return nil
}
func (m *fakeManager) Close(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed++
	return nil
}

func (m *fakeManager) closeCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

func TestDisconnectWithoutSessionIsNoop(t *testing.T) {
	connection := &Connection{Session: &session.Session{}}
	if err := connection.Disconnect(context.Background()); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	var nilConnection *Connection
	if err := nilConnection.Disconnect(context.Background()); err != nil {
		t.Fatalf("nil Disconnect: %v", err)
	}
}

func TestDisconnectClosesManagerWhenControllerNeverStarted(t *testing.T) {
	sess := &session.Session{}
	cSess := sess.NewConnSession(&http.Header{})
	manager := &fakeManager{}
	cSess.NetworkManager = manager

	connection := &Connection{Session: sess}
	if err := connection.Disconnect(context.Background()); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	select {
	case <-cSess.CloseChan:
	default:
		t.Fatal("session close channel was not signaled")
	}
	if manager.closeCount() != 1 {
		t.Fatalf("manager closed %d times, want 1", manager.closeCount())
	}
	if info := cSess.CloseInfo(); info.Code != "local_requested" || info.Transport != "local" {
		t.Fatalf("close info = %+v", info)
	}
}

func TestDisconnectWaitsForOwnedTunnelDrain(t *testing.T) {
	sess := &session.Session{}
	cSess := sess.NewConnSession(&http.Header{})
	manager := &fakeManager{}
	cSess.NetworkManager = manager

	done := make(chan struct{})
	cSess.SetTunnelDone(done)
	go func() {
		time.Sleep(150 * time.Millisecond)
		close(done)
	}()

	connection := &Connection{Session: sess}
	start := time.Now()
	if err := connection.Disconnect(context.Background()); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Fatalf("Disconnect returned before the tunnel drained (%v)", elapsed)
	}
	// The tunnel controller owns the manager once it has started; the RPC
	// disconnect must not close it a second time.
	if manager.closeCount() != 0 {
		t.Fatalf("manager closed %d times, want 0 while controller owns teardown", manager.closeCount())
	}
}
