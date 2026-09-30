package vpn

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"flexconnect/internal/anyconnect/proto"
	"flexconnect/internal/anyconnect/session"
)

func TestTransportEncodingGrowsExactCapacityPackets(t *testing.T) {
	for _, tls := range []bool{false, true} {
		for _, size := range []int{60, 1399, 9000} {
			packet := bytes.Repeat([]byte{0x45}, size)
			pl := &proto.Payload{Data: append([]byte(nil), packet...)}
			pl.Data = pl.Data[:size:size]
			frame, err := encodeTransportPayload(pl, tls)
			if err != nil {
				t.Fatal(err)
			}
			header := 1
			if tls {
				header = 8
				if int(binary.BigEndian.Uint16(frame[4:6])) != size {
					t.Fatal("invalid CSTP length")
				}
			}
			if !bytes.Equal(frame[header:], packet) {
				t.Fatal("packet changed during framing")
			}
		}
	}
}

func TestTransportEncodingDoesNotMutateSharedDPD(t *testing.T) {
	for _, tls := range []bool{false, true} {
		data := []byte{9, 8, 7}
		pl := &proto.Payload{Type: 3, Data: data}
		for i := 0; i < 3; i++ {
			frame, err := encodeTransportPayload(pl, tls)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(pl.Data, []byte{9, 8, 7}) || pl.Type != 3 {
				t.Fatal("shared DPD payload mutated")
			}
			index := 0
			if tls {
				index = 6
			}
			if frame[index] != 3 {
				t.Fatal("wrong control type")
			}
		}
	}
}

func TestTransportEncodingRejectsInvalidData(t *testing.T) {
	for _, pl := range []*proto.Payload{nil, {Data: nil}, {Data: make([]byte, maxCSTPPayloadSize+1)}} {
		for _, tls := range []bool{false, true} {
			if _, err := encodeTransportPayload(pl, tls); err == nil {
				t.Fatal("invalid data accepted")
			}
		}
	}
}

func TestSessionCloseUnblocksTransportRead(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	closed := make(chan struct{})
	stop := watchSessionClose(closed, left)
	defer stop()
	done := make(chan error, 1)
	go func() { _, err := left.Read(make([]byte, 1)); done <- err }()
	close(closed)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("read succeeded after closure")
		}
	case <-time.After(time.Second):
		t.Fatal("transport read did not unblock")
	}
}

func TestStoppedSessionWatcherLeavesTransportOpen(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	closed := make(chan struct{})
	stop := watchSessionClose(closed, left)
	stop()
	// Cancellation alone should not close a transport managed by its caller.
	done := make(chan error, 1)
	go func() { _, err := right.Write([]byte{1}); done <- err }()
	if err := left.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(left, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestDTLSSetupPreservesTUNFailureAndBoundsWait(t *testing.T) {
	cSess := (&session.Session{}).NewConnSession(&http.Header{})
	cSess.RecordClose("tun_write_error", "tun", errors.New("device failed"))
	cSess.Close()
	cSess.SignalDTLSSetup() // Both channels ready: the terminal reason wins.
	for i := 0; i < 10; i++ {
		err := waitDTLSSetup(cSess, time.Second)
		if err == nil || !strings.Contains(err.Error(), "tun_write_error") || !strings.Contains(err.Error(), "device failed") {
			t.Fatalf("lost close reason: %v", err)
		}
	}
	cSess = (&session.Session{}).NewConnSession(&http.Header{})
	defer cSess.Close()
	if err := waitDTLSSetup(cSess, time.Millisecond); err == nil {
		t.Fatal("unbounded setup wait")
	}
	cSess.SignalDTLSSetup()
	if err := waitDTLSSetup(cSess, time.Second); err == nil {
		t.Fatal("failed DTLS setup accepted")
	}
	cSess.DtlsConnected.Store(true)
	if err := waitDTLSSetup(cSess, time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestLosingUserTunnelDoesNotRemoveWinner(t *testing.T) {
	cSess := (&session.Session{}).NewConnSession(&http.Header{})
	defer cSess.Close()
	winner := &userTunnel{cSess: cSess}
	loser := &userTunnel{cSess: cSess}
	userTunnels.Store(cSess, winner)
	defer userTunnels.Delete(cSess)
	if err := loser.Close(); err != nil {
		t.Fatal(err)
	}
	if got, ok := userTunnels.Load(cSess); !ok || got != winner {
		t.Fatal("loser removed active tunnel")
	}
}

func TestUserTunnelStopsWithItsSession(t *testing.T) {
	cSess := (&session.Session{}).NewConnSession(&http.Header{})
	cSess.VPNAddress = "192.0.2.10"
	cSess.MTU = 1399
	tunnel, err := SessionTunnelDialer(t.Context(), cSess)
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.(*userTunnel).Close()
	cSess.Close()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, ok := userTunnels.Load(cSess); !ok {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if _, ok := userTunnels.Load(cSess); ok {
		t.Fatal("user tunnel survived session shutdown")
	}
	if _, err := SessionTunnelDialer(t.Context(), cSess); err == nil {
		t.Fatal("created a tunnel for a closed session")
	}
}
