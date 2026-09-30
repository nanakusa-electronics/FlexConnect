package vpn

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"flexconnect/internal/anyconnect/base"
	"flexconnect/internal/anyconnect/proto"
	"flexconnect/internal/anyconnect/session"
)

// 复用已有的 tls.Conn 和对应的 bufR
func tlsChannel(conn *tls.Conn, bufR *bufio.Reader, cSess *session.ConnSession, resp *http.Response) {
	defer func() {
		base.Info("tls channel exit")
		cSess.SetTLSState("Closed")
		_ = conn.Close()
		resp.Body.Close()
		cSess.Close()
	}()
	stopWatcher := watchSessionClose(cSess.CloseChan, conn)
	defer stopWatcher()
	cSess.SetTLSState("Ready")
	base.Info("start tls channel", "peer", conn.RemoteAddr().String())
	dead := time.Duration(session.EffectiveDPD(cSess.TLSDpdTime)+5) * time.Second

	go payloadOutTLSToServer(conn, cSess)

	// Step 21 serverToPayloadIn
	// 读取服务器返回的数据，调整格式，放入 cSess.PayloadIn
	for {
		// 重置超时限制
		if cSess.ResetTLSReadDead.Load() {
			if err := conn.SetReadDeadline(time.Now().Add(dead)); err != nil {
				cSess.RecordClose("tls_deadline_error", "tls", err)
				base.Error("set tls read deadline failed:", err)
				return
			}
			cSess.ResetTLSReadDead.Store(false)
		}

		pl := getPayloadBuffer(cSess.MTU) // 从池子申请一块内存，存放去除头部的数据包到 PayloadIn，在 payloadInToTun 中释放
		frameType, wireBytes, err := readCSTPFrame(bufR, pl)
		if err != nil {
			putPayloadBuffer(pl)
			code := "tls_read_error"
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				code = "tls_read_timeout"
			}
			cSess.RecordClose(code, "tls", err)
			base.Error("tls server to payloadIn error:", err)
			return
		}

		// https://datatracker.ietf.org/doc/html/draft-mavrogiannopoulos-openconnect-03#section-2.2
		base.Debug("tls receive frame", "type", frameType, "len", wireBytes)
		pl.Type = frameType
		switch frameType {
		case 0x00: // DATA
			select {
			case cSess.PayloadIn <- pl:
			case <-cSess.CloseChan:
				putPayloadBuffer(pl)
				return
			}
		case 0x04, 0x07: // DPD-RESP / KEEPALIVE
			base.Debug("tls receive DPD-RESP")
			if frameType == 0x04 {
				cSess.Stat.DPDResponses.Inc()
			}
			putPayloadBuffer(pl)
		case 0x03: // DPD-REQ
			pl.Type = 0x04
			pl.Data = pl.Data[:0]
			select {
			case cSess.PayloadOutTLS <- pl:
			case <-cSess.CloseChan:
				putPayloadBuffer(pl)
				return
			}
		case 0x05: // DISCONNECT
			putPayloadBuffer(pl)
			cSess.RecordClose("server_disconnect", "tls", nil)
			return
		case 0x09: // TERMINATE
			putPayloadBuffer(pl)
			cSess.RecordClose("server_terminate", "tls", nil)
			return
		default:
			putPayloadBuffer(pl)
			err = fmt.Errorf("unsupported CSTP frame type 0x%02x", frameType)
			cSess.RecordClose("tls_protocol_error", "tls", err)
			base.Error("tls server sent unsupported frame:", err)
			return
		}
		cSess.Stat.BytesReceived.Add(uint64(wireBytes))
	}
}

const maxCSTPPayloadSize = 64*1024 - 1

func readCSTPFrame(reader io.Reader, pl *proto.Payload) (frameType byte, wireBytes int, err error) {
	if pl == nil {
		return 0, 0, errors.New("nil CSTP payload")
	}
	var header [8]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return 0, 0, err
	}
	if !bytes.Equal(header[:4], proto.Header[:4]) || header[7] != proto.Header[7] {
		return 0, 0, fmt.Errorf("invalid CSTP header %x", header)
	}
	payloadSize := int(binary.BigEndian.Uint16(header[4:6]))
	if payloadSize > maxCSTPPayloadSize {
		return 0, 0, fmt.Errorf("CSTP payload exceeds %d bytes: %d", maxCSTPPayloadSize, payloadSize)
	}
	if payloadSize > cap(pl.Data) {
		pl.Data = make([]byte, payloadSize)
	} else {
		pl.Data = pl.Data[:payloadSize]
	}
	if _, err := io.ReadFull(reader, pl.Data); err != nil {
		return 0, 0, err
	}
	return header[6], len(header) + payloadSize, nil
}

// payloadOutTLSToServer Step 4
func payloadOutTLSToServer(conn *tls.Conn, cSess *session.ConnSession) {
	defer func() {
		base.Info("tls payloadOut to server exit")
		_ = conn.Close()
		cSess.Close()
	}()
	base.Info("start tls payload out worker")

	var (
		err       error
		bytesSent int
		pl        *proto.Payload
	)

	for {
		select {
		case pl = <-cSess.PayloadOutTLS:
		case <-cSess.CloseChan:
			return
		}
		if pl == nil {
			err := errors.New("nil TLS payload")
			cSess.RecordClose("tls_payload_invalid", "tls", err)
			cSess.Close()
			return
		}

		frame, encodeErr := encodeTransportPayload(pl, true)
		err = encodeErr
		if err == nil {
			err = conn.SetWriteDeadline(time.Now().Add(transportWriteTimeout))
		}
		if err == nil {
			bytesSent, err = conn.Write(frame)
			if err == nil && bytesSent != len(frame) {
				err = io.ErrShortWrite
			}
		}
		if err != nil {
			putPayloadBuffer(pl)
			code := "tls_write_error"
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				code = "tls_write_timeout"
			}
			cSess.RecordClose(code, "tls", err)
			base.Error("tls payloadOut to server error:", err)
			return
		}
		cSess.Stat.BytesSent.Add(uint64(bytesSent))

		// 释放由 tunToPayloadOut 申请的内存
		putPayloadBuffer(pl)
	}
}
