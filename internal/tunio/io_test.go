package tunio

import (
	"bytes"
	"errors"
	"github.com/tailscale/wireguard-go/tun"
	"testing"
)

type device struct {
	tun.Device
	read  func([][]byte, []int, int) (int, error)
	write func([][]byte, int) (int, error)
}

func (*device) BatchSize() int { return 2 }
func (d *device) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	return d.read(bufs, sizes, offset)
}
func (d *device) Write(bufs [][]byte, offset int) (int, error) { return d.write(bufs, offset) }

func TestNativeBatchReadAndValidation(t *testing.T) {
	d := &device{read: func(bufs [][]byte, sizes []int, offset int) (int, error) {
		if len(bufs) != 2 || len(sizes) != 2 || offset < 10 {
			t.Fatal("native TUN contract violated")
		}
		copy(bufs[0][offset:], []byte{0x45, 1})
		sizes[0] = 2
		copy(bufs[1][offset:], []byte{0x45, 2, 3})
		sizes[1] = 3
		return 2, nil
	}}
	reader := NewReader(d, 1500)
	packets, err := reader.Read()
	if err != nil || len(packets) != 2 || !bytes.Equal(packets[1], []byte{0x45, 2, 3}) {
		t.Fatalf("batch lost: %v", err)
	}
	for _, bad := range []struct{ count, size int }{{3, 1}, {-1, 1}, {1, -1}, {1, 1501}, {1, 0}} {
		d.read = func(_ [][]byte, sizes []int, _ int) (int, error) { sizes[0] = bad.size; return bad.count, nil }
		if _, err := reader.Read(); !errors.Is(err, ErrInvalidRead) {
			t.Fatalf("invalid batch accepted: %+v", bad)
		}
	}
}

func TestNativeWriteAcceptsPlatformCountsAndKeepsPacket(t *testing.T) {
	packet := []byte{0x45, 1, 2}
	for _, count := range []int{1, len(packet), len(packet) + 10} {
		d := &device{write: func(bufs [][]byte, offset int) (int, error) {
			if offset < 10 || !bytes.Equal(bufs[0][offset:], packet) {
				t.Fatal("missing headroom or damaged packet")
			}
			bufs[0][offset] = 0
			return count, nil
		}}
		if err := Write(d, packet); err != nil {
			t.Fatal(err)
		}
		if packet[0] != 0x45 {
			t.Fatal("caller packet mutated")
		}
	}
}
