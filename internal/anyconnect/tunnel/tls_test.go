package vpn

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"flexconnect/internal/anyconnect/proto"
)

func TestReadCSTPFrameHandlesFragmentedAndConcatenatedStream(t *testing.T) {
	first := testCSTPFrame(0x00, []byte{1, 2, 3, 4})
	second := testCSTPFrame(0x04, nil)
	reader := &chunkReader{data: append(first, second...), max: 3}
	pl := getPayloadBuffer()
	defer putPayloadBuffer(pl)

	typ, wireBytes, err := readCSTPFrame(reader, pl)
	if err != nil {
		t.Fatalf("read first frame: %v", err)
	}
	if typ != 0x00 || wireBytes != len(first) || !bytes.Equal(pl.Data, []byte{1, 2, 3, 4}) {
		t.Fatalf("first frame = type 0x%02x bytes %d payload %v", typ, wireBytes, pl.Data)
	}

	// Reuse the owned buffer without returning it to the shared pool twice.
	pl.Data = pl.Data[:cap(pl.Data)]
	typ, wireBytes, err = readCSTPFrame(reader, pl)
	if err != nil {
		t.Fatalf("read second frame: %v", err)
	}
	if typ != 0x04 || wireBytes != len(second) || len(pl.Data) != 0 {
		t.Fatalf("second frame = type 0x%02x bytes %d payload %v", typ, wireBytes, pl.Data)
	}
}

func TestReadCSTPFrameRejectsInvalidAndTruncatedFrames(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "invalid header", data: []byte("BAD!\x00\x00\x00\x00")},
		{name: "truncated header", data: []byte("STF")},
		{name: "truncated payload", data: append(testCSTPFrame(0x00, []byte{1, 2, 3})[:8], []byte{1}...)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pl := getPayloadBuffer()
			defer putPayloadBuffer(pl)
			if _, _, err := readCSTPFrame(bytes.NewReader(test.data), pl); err == nil {
				t.Fatal("invalid frame was accepted")
			}
		})
	}
}

func testCSTPFrame(frameType byte, payload []byte) []byte {
	header := append([]byte(nil), proto.Header...)
	header[6] = frameType
	binary.BigEndian.PutUint16(header[4:6], uint16(len(payload)))
	return append(header, payload...)
}

type chunkReader struct {
	data []byte
	max  int
}

func (r *chunkReader) Read(dst []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := len(dst)
	if n > r.max {
		n = r.max
	}
	if n > len(r.data) {
		n = len(r.data)
	}
	copy(dst[:n], r.data[:n])
	r.data = r.data[n:]
	return n, nil
}
