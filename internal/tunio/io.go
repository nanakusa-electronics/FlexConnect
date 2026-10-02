// Package tunio implements native TUN packet I/O shared by VPN providers.
package tunio

import (
	"errors"
	"fmt"
	"github.com/tailscale/wireguard-go/tun"
)

// PacketOffset reserves Linux virtio-net (10 bytes) and Darwin (4 bytes) headers.
const PacketOffset = 16

var ErrInvalidRead = errors.New("invalid TUN read")

// Reader owns reusable segment buffers. Packets are valid until the next Read.
// A Reader must have exactly one reader goroutine.
type Reader struct {
	dev     tun.Device
	buffers [][]byte
	sizes   []int
	packets [][]byte
}

func NewReader(dev tun.Device, maxPacket int) *Reader {
	batch := max(dev.BatchSize(), 1)
	r := &Reader{dev: dev, buffers: make([][]byte, batch), sizes: make([]int, batch), packets: make([][]byte, batch)}
	for i := range r.buffers {
		r.buffers[i] = make([]byte, PacketOffset+maxPacket)
	}
	return r
}

func (r *Reader) Read() ([][]byte, error) {
	clear(r.sizes)
	n, err := r.dev.Read(r.buffers, r.sizes, PacketOffset)
	if err != nil {
		return nil, err
	}
	if n < 0 || n > len(r.buffers) {
		return nil, fmt.Errorf("%w: count=%d", ErrInvalidRead, n)
	}
	for i := 0; i < n; i++ {
		size := r.sizes[i]
		if size <= 0 || size > len(r.buffers[i])-PacketOffset {
			return nil, fmt.Errorf("%w: packet=%d size=%d", ErrInvalidRead, i, size)
		}
		r.packets[i] = r.buffers[i][PacketOffset : PacketOffset+size]
	}
	return r.packets[:n], nil
}

// Write preserves the input packet and provides headroom for native offload.
// Native Write counts vary by platform; its error determines success.
// The caller serializes concurrent device writes.
func Write(dev tun.Device, packet []byte) error {
	data := make([]byte, PacketOffset+len(packet))
	copy(data[PacketOffset:], packet)
	_, err := dev.Write([][]byte{data}, PacketOffset)
	return err
}
