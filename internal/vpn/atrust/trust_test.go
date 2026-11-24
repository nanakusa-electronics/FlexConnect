package atrust

import (
	"context"
	"errors"
	"testing"
	"time"

	"flexconnect/internal/secret"
	geektrust "github.com/ShanghaitechGeekPie/geektrust/client"
)

func TestGatewayPinStorePersistsAndRejectsChange(t *testing.T) {
	base := secret.NewMemoryStore()
	first := &gatewayPinStore{secrets: base, ref: "profile-one"}
	second := &gatewayPinStore{secrets: base, ref: "profile-one"}
	ctx := context.Background()
	identity := geektrust.GatewayIdentity{Address: "192.0.2.1:441"}
	pin, changed := [32]byte{0x29}, [32]byte{0x30}
	if ok, err := first.CheckOrEnroll(ctx, identity, pin); err != nil || !ok {
		t.Fatalf("enroll pin: %v, %v", ok, err)
	}
	if ok, err := second.CheckOrEnroll(ctx, identity, pin); err != nil || !ok {
		t.Fatalf("reloaded pin mismatch: %v, %v", ok, err)
	}
	if ok, err := second.CheckOrEnroll(ctx, identity, changed); err != nil || ok {
		t.Fatalf("changed gateway key: %v, %v", ok, err)
	}
	other := &gatewayPinStore{secrets: base, ref: "profile-two"}
	if ok, err := other.CheckOrEnroll(ctx, identity, changed); err != nil || !ok {
		t.Fatalf("pin escaped profile boundary: %v, %v", ok, err)
	}
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := first.CheckOrEnroll(ctx, geektrust.GatewayIdentity{Address: "192.0.2.2:441"}, pin); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled save: %v", err)
	}
}

func TestFakeIPRecyclesOnlyExpiredInactiveLease(t *testing.T) {
	m := newDNSMapper(geektrust.SessionInfo{}, nil)
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
