package vpn

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"flexconnect/internal/anyconnect/proto"
	"flexconnect/internal/anyconnect/session"
)

type offloadTestDevice struct {
	*testTUNDevice
	read  func([][]byte, []int, int) (int, error)
	write func([][]byte, int) (int, error)
}

func (d *offloadTestDevice) BatchSize() int { return 2 }
func (d *offloadTestDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	return d.read(bufs, sizes, offset)
}
func (d *offloadTestDevice) Write(bufs [][]byte, offset int) (int, error) {
	return d.write(bufs, offset)
}

func TestTunWriteReservesOffloadHeader(t *testing.T) {
	cSess := (&session.Session{}).NewConnSession(&http.Header{})
	defer cSess.Close()
	packet := []byte{0x45, 0, 0, 20, 1, 2, 3, 4}
	written := make(chan []byte, 1)
	dev := &offloadTestDevice{testTUNDevice: newTestTUNDevice()}
	dev.write = func(bufs [][]byte, offset int) (int, error) {
		if offset < 10 || offset >= len(bufs[0]) {
			return 0, errors.New("invalid offset")
		}
		written <- append([]byte(nil), bufs[0][offset:]...)
		return 1, nil
	}
	cSess.PayloadIn <- &proto.Payload{Data: packet}
	done := make(chan struct{})
	go func() { payloadInToTun(dev, cSess); close(done) }()
	select {
	case got := <-written:
		if !bytes.Equal(got, packet) {
			t.Fatalf("packet corrupted: %x", got)
		}
	case <-cSess.CloseChan:
		t.Fatalf("write failed: %+v", cSess.CloseInfo())
	case <-time.After(2 * time.Second):
		t.Fatal("write timed out")
	}
	cSess.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not stop")
	}
}

func TestTunReadForwardsEveryOffloadSegment(t *testing.T) {
	cSess := (&session.Session{}).NewConnSession(&http.Header{})
	defer cSess.Close()
	packets := [][]byte{{0x45, 1, 2, 3}, {0x45, 4, 5, 6, 7}}
	reads := 0
	dev := &offloadTestDevice{testTUNDevice: newTestTUNDevice()}
	dev.read = func(bufs [][]byte, sizes []int, offset int) (int, error) {
		reads++
		if reads > 1 {
			<-cSess.CloseChan
			return 0, io.EOF
		}
		if len(bufs) < 2 || len(sizes) < 2 {
			return 0, errors.New("insufficient segment buffers")
		}
		if offset < 10 {
			return 0, errors.New("invalid offset")
		}
		for i, packet := range packets {
			copy(bufs[i][offset:], packet)
			sizes[i] = len(packet)
		}
		return 2, nil
	}
	done := make(chan struct{})
	go func() { tunToPayloadOut(dev, cSess); close(done) }()
	for _, want := range packets {
		select {
		case pl := <-cSess.PayloadOutTLS:
			if !bytes.Equal(pl.Data, want) {
				t.Fatalf("packet corrupted: %x", pl.Data)
			}
			putPayloadBuffer(pl)
		case <-time.After(2 * time.Second):
			t.Fatal("segment not forwarded")
		}
	}
	cSess.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not stop")
	}
	if cSess.Stat.TUNReads.Load() != 2 {
		t.Fatalf("read count = %d", cSess.Stat.TUNReads.Load())
	}
}
