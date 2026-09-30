package vpn

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"flexconnect/internal/anyconnect/proto"
)

const transportWriteTimeout = 20 * time.Second

// watchSessionClose unblocks network I/O when the session closes. The returned
// stop function also terminates the watcher when its transport exits first.
func watchSessionClose(closed <-chan struct{}, conn io.Closer) func() {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		select {
		case <-closed:
			_ = conn.Close()
		case <-ctx.Done():
		}
	}()
	return cancel
}

func encodeTransportPayload(pl *proto.Payload, tls bool) ([]byte, error) {
	if pl == nil {
		return nil, errors.New("nil transport payload")
	}
	headerSize := 1
	if tls {
		headerSize = 8
	}
	if pl.Type != 0 {
		header := make([]byte, headerSize)
		if tls {
			copy(header, proto.Header)
			header[6] = pl.Type
		} else {
			header[0] = pl.Type
		}
		return header, nil // do not mutate shared keepalive/DPD payloads
	}
	n := len(pl.Data)
	if n == 0 || n > maxCSTPPayloadSize {
		return nil, errors.New("invalid transport packet length")
	}
	// append grows an exact-capacity packet instead of panicking on reslicing.
	pl.Data = append(pl.Data, make([]byte, headerSize)...)
	copy(pl.Data[headerSize:], pl.Data[:n])
	if tls {
		copy(pl.Data[:headerSize], proto.Header)
		binary.BigEndian.PutUint16(pl.Data[4:6], uint16(n))
	} else {
		pl.Data[0] = 0
	}
	return pl.Data, nil
}
