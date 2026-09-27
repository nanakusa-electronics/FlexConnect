package atrust

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"flexconnect/internal/secret"
	geektrust "github.com/nanakusa-electronics/geektrust/client"
)

func TestGatewayPinStorePersistsAndRejectsChange(t *testing.T) {
	base := secret.NewMemoryStore()
	first := &gatewayPinStore{secrets: base, ref: "profile-one"}
	second := &gatewayPinStore{secrets: base, ref: "profile-one"}
	ctx := context.Background()
	pin := bytes.Repeat([]byte{0x29}, 32)
	if err := first.SavePin(ctx, "192.0.2.1:441", pin); err != nil {
		t.Fatal(err)
	}
	got, err := second.LoadPin(ctx, "192.0.2.1:441")
	if err != nil || !bytes.Equal(got, pin) {
		t.Fatalf("reloaded pin mismatch: %v", err)
	}
	if err := second.SavePin(ctx, "192.0.2.1:441", bytes.Repeat([]byte{0x30}, 32)); err == nil {
		t.Fatal("changed gateway key accepted")
	}
	other := &gatewayPinStore{secrets: base, ref: "profile-two"}
	got, err = other.LoadPin(ctx, "192.0.2.1:441")
	if err != nil || len(got) != 0 {
		t.Fatalf("pin escaped profile boundary: %v", err)
	}
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := first.SavePin(ctx, "192.0.2.2:441", pin); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled save: %v", err)
	}
}

func TestFakeIPRecyclesOnlyExpiredInactiveLease(t *testing.T) {
	m := newDNSMapper(geektrust.Info{}, nil)
	first, err := m.allocate("first.example.test")
	if err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	m.next = 131066
	m.leases[first] = time.Now().Add(-time.Second)
	m.active[first] = 1
	m.mu.Unlock()
	if _, err := m.allocate("second.example.test"); err == nil {
		t.Fatal("active Fake-IP recycled")
	}
	m.releaseIP(first)
	second, err := m.allocate("second.example.test")
	if err != nil || second != first {
		t.Fatalf("expired Fake-IP not recycled: %v", err)
	}
	if got := m.reserveIP(second); got != "second.example.test" {
		t.Fatalf("recycled mapping = %q", got)
	}
	m.releaseIP(second)
}
