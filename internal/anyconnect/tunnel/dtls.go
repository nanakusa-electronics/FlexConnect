package vpn

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strconv"
	"time"

	"flexconnect/internal/anyconnect/base"
	"flexconnect/internal/anyconnect/proto"
	"flexconnect/internal/anyconnect/session"
	"github.com/pion/dtls/v3"
)

// 新建 dtls.Conn
func dtlsChannel(cSess *session.ConnSession) {
	var (
		conn          *dtls.Conn
		dSess         *session.DtlsSession
		err           error
		bytesReceived int
		dead          = time.Duration(session.EffectiveDPD(cSess.DTLSDpdTime)+5) * time.Second
	)
	base.Info("start dtls channel", "server", cSess.ServerAddress)
	cSess.SetDTLSState("Starting")
	defer func() {
		base.Info("dtls channel exit")
		if conn != nil {
			_ = conn.Close()
		}
		if dSess != nil {
			dSess.Close()
		}
		if cSess.LifecycleState == nil || cSess.LifecycleState.Load() != "Closed" {
			cSess.SetDTLSState("Degraded")
		} else {
			cSess.SetDTLSState("Closed")
		}
		cSess.SignalDTLSSetup()
	}()

	port, err := strconv.Atoi(cSess.DTLSPort)
	if err != nil || port < 1 || port > 65535 {
		if err == nil {
			err = errors.New("DTLS port is outside the valid range")
		}
		cSess.RecordTransportFault("dtls_config_error", "dtls", err)
		return
	}
	addr := &net.UDPAddr{IP: net.ParseIP(cSess.ServerAddress), Port: port}
	if addr.IP == nil {
		err = errors.New("invalid DTLS server address")
		cSess.RecordTransportFault("dtls_config_error", "dtls", err)
		return
	}

	id, err := hex.DecodeString(cSess.DTLSId)
	if err != nil || len(id) == 0 {
		if err == nil {
			err = errors.New("missing DTLS session ID")
		}
		cSess.RecordTransportFault("dtls_config_error", "dtls", err)
		return
	}

	config := &dtls.Config{
		ServerName:           cSess.TLSServerName,
		ExtendedMasterSecret: dtls.DisableExtendedMasterSecret,
		CipherSuites: func() []dtls.CipherSuiteID {
			switch cSess.DTLSCipherSuite {
			case "ECDHE-ECDSA-AES128-GCM-SHA256":
				return []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
			case "ECDHE-RSA-AES128-GCM-SHA256":
				return []dtls.CipherSuiteID{dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}
			case "ECDHE-ECDSA-AES256-GCM-SHA384":
				return []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384}
			case "ECDHE-RSA-AES256-GCM-SHA384":
				return []dtls.CipherSuiteID{dtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384}
			default:
				return []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
			}
		}(),
		SessionStore: &SessionStore{dtls.Session{ID: id, Secret: cSess.Sess.PreMasterSecret}},
		// PSK: func(hint []byte) ([]byte, error) {
		//     // return []byte{0xAB, 0xC1, 0x23}, nil
		//     return id, nil
		// },
		// PSKIdentityHint: id,
	}

	conn, err = dtls.Dial("udp4", addr, config)
	// https://github.com/pion/dtls/pull/649
	if err != nil {
		cSess.RecordTransportFault("dtls_dial_error", "dtls", err)
		base.Error(err)
		return
	}
	stopWatcher := watchSessionClose(cSess.CloseChan, conn)
	defer stopWatcher()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err = conn.HandshakeContext(ctx); err != nil {
		cSess.RecordTransportFault("dtls_handshake_error", "dtls", err)
		base.Error(err)
		return
	}
	dSess = cSess.DSess
	select {
	case <-cSess.CloseChan:
		return
	default:
	}
	base.Info("dtls handshake done")

	cSess.DtlsConnected.Store(true)
	cSess.SetDTLSState("Ready")
	cSess.SignalDTLSSetup()

	// rewrite cSess.DTLSCipherSuite
	state, success := conn.ConnectionState()
	if success {
		cSess.DTLSCipherSuite = dtls.CipherSuiteName(state.CipherSuiteID)
	} else {
		cSess.DTLSCipherSuite = ""
	}

	base.Info("dtls channel negotiation succeeded")

	go payloadOutDTLSToServer(conn, dSess, cSess)

	// Step 21 serverToPayloadIn
	// 读取服务器返回的数据，调整格式，放入 cSess.PayloadIn，不再用子协程是为了能够退出 dtlsChannel 协程
	for {
		// 重置超时限制
		if cSess.ResetDTLSReadDead.Load() {
			_ = conn.SetReadDeadline(time.Now().Add(dead))
			cSess.ResetDTLSReadDead.Store(false)
		}

		pl := getPayloadBuffer(cSess.MTU)       // 从池子申请一块内存，存放去除头部的数据包到 PayloadIn，在 payloadInToTun 中释放
		bytesReceived, err = conn.Read(pl.Data) // 服务器没有数据返回时，会阻塞
		if err != nil {
			putPayloadBuffer(pl)
			code := "dtls_read_error"
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				code = "dtls_read_timeout"
			}
			cSess.RecordTransportFault(code, "dtls", err)
			base.Error("dtls server to payloadIn error:", err)
			return
		}
		if bytesReceived <= 0 || bytesReceived > len(pl.Data) {
			putPayloadBuffer(pl)
			err = errors.New("DTLS returned an invalid packet length")
			cSess.RecordTransportFault("dtls_read_invalid", "dtls", err)
			return
		}
		base.Debug("dtls receive frame", "type", pl.Data[0], "len", bytesReceived)

		// base.Debug("dtls server to payloadIn")
		// https://datatracker.ietf.org/doc/html/draft-mavrogiannopoulos-openconnect-02#section-2.3
		// UDP 数据包的头部只有 1 字节
		switch pl.Data[0] {
		case 0x07: // KEEPALIVE
			// base.Debug("dtls receive KEEPALIVE")
			putPayloadBuffer(pl)
		case 0x05: // DISCONNECT
			putPayloadBuffer(pl)
			cSess.RecordTransportFault("server_disconnect", "dtls", nil)
			return
		case 0x03: // DPD-REQ
			// base.Debug("dtls receive DPD-REQ")
			pl.Type = 0x04
			select {
			case cSess.PayloadOutDTLS <- pl:
			case <-dSess.CloseChan:
				putPayloadBuffer(pl)
				return
			}
		case 0x04:
			base.Debug("dtls receive DPD-RESP")
			cSess.Stat.DPDResponses.Inc()
			putPayloadBuffer(pl)
		case 0x00: // DATA
			pl.Data = append(pl.Data[:0], pl.Data[1:bytesReceived]...)
			select {
			case cSess.PayloadIn <- pl:
			case <-dSess.CloseChan:
				putPayloadBuffer(pl)
				return
			}
		default:
			putPayloadBuffer(pl)
			err = errors.New("unsupported DTLS frame type")
			cSess.RecordTransportFault("dtls_protocol_error", "dtls", err)
			return
		}
		cSess.Stat.BytesReceived.Add(uint64(bytesReceived))
	}
}

// payloadOutDTLSToServer Step 4
func payloadOutDTLSToServer(conn *dtls.Conn, dSess *session.DtlsSession, cSess *session.ConnSession) {
	defer func() {
		base.Info("dtls payloadOut to server exit")
		_ = conn.Close()
		dSess.Close()
	}()
	base.Info("start dtls payload out worker")

	var (
		err       error
		bytesSent int
		pl        *proto.Payload
	)

	for {
		select {
		case pl = <-cSess.PayloadOutDTLS:
		case <-dSess.CloseChan:
			return
		}
		if pl == nil {
			err := errors.New("nil DTLS payload")
			cSess.RecordTransportFault("dtls_payload_invalid", "dtls", err)
			return
		}

		frame, encodeErr := encodeTransportPayload(pl, false)
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
			code := "dtls_write_error"
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				code = "dtls_write_timeout"
			}
			cSess.RecordTransportFault(code, "dtls", err)
			base.Error("dtls payloadOut to server error:", err)
			return
		}
		cSess.Stat.BytesSent.Add(uint64(bytesSent))

		// 释放由 tunToPayloadOut 申请的内存
		putPayloadBuffer(pl)
	}
}

type SessionStore struct {
	sess dtls.Session
}

func (store *SessionStore) Set([]byte, dtls.Session) error {
	return nil
}

func (store *SessionStore) Get([]byte) (dtls.Session, error) {
	return store.sess, nil
}

func (store *SessionStore) Del([]byte) error {
	return nil
}
