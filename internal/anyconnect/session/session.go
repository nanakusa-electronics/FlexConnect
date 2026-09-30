package session

import (
	"encoding/xml"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"flexconnect/internal/anyconnect/base"
	"flexconnect/internal/anyconnect/proto"
	"flexconnect/internal/anyconnect/utils"
	"flexconnect/internal/osnet"
	"go.uber.org/atomic"
)

type Session struct {
	SessionToken    string
	PreMasterSecret []byte

	ActiveClose  bool
	CloseChan    chan struct{} // 用于通知所有 UI，ConnSession 已关闭
	CSess        *ConnSession
	drainMu      sync.Mutex
	drainSession *ConnSession
}

// DrainSession retains the transport's cleanup owner after Close clears CSess.
// Its tunnel controller can still be draining packet workers and OS state.
func (sess *Session) DrainSession() *ConnSession {
	sess.drainMu.Lock()
	defer sess.drainMu.Unlock()
	return sess.drainSession
}

type stat struct {
	// be sure to use the double type when parsing
	BytesSent      *atomic.Uint64 `json:"bytesSent"`
	BytesReceived  *atomic.Uint64 `json:"bytesReceived"`
	TUNReads       *atomic.Uint64 `json:"tunReads"`
	TUNWrites      *atomic.Uint64 `json:"tunWrites"`
	TUNReadErrors  *atomic.Uint64 `json:"tunReadErrors"`
	TUNWriteErrors *atomic.Uint64 `json:"tunWriteErrors"`
	DPDSent        *atomic.Uint64 `json:"dpdSent"`
	DPDResponses   *atomic.Uint64 `json:"dpdResponses"`
	QueueDrops     *atomic.Uint64 `json:"queueDrops"`
}

// ConnSession used for both TLS and DTLS
type ConnSession struct {
	Sess         *Session `json:"-"`
	ConnectionID string

	ServerAddress            string
	TLSServerName            string
	LocalAddress             string
	LocalSocketAddress       string
	RemoteSocketAddress      string
	Hostname                 string
	TunName                  string
	VPNAddress               string // The IPv4 address of the client
	VPNMask                  string // IPv4 netmask
	DNS                      []string
	MTU                      int
	SplitInclude             []string
	SplitExclude             []string
	UseDefaultRouteWhenEmpty bool

	DynamicSplitTunneling       bool
	DynamicSplitIncludeDomains  []string
	DynamicSplitIncludeResolved sync.Map // https://github.com/golang/go/issues/31136
	DynamicSplitExcludeDomains  []string
	DynamicSplitExcludeResolved sync.Map

	NetworkManager osnet.Manager          `json:"-"`
	Underlay       osnet.UnderlaySnapshot `json:"-"`

	TLSCipherSuite    string
	TLSDpdTime        int // https://datatracker.ietf.org/doc/html/rfc3706
	TLSKeepaliveTime  int
	DTLSPort          string
	DTLSDpdTime       int
	DTLSKeepaliveTime int
	DTLSId            string `json:"-"` // used by the server to associate the DTLS channel with the CSTP channel
	DTLSCipherSuite   string
	Stat              *stat

	closeOnce           sync.Once           `json:"-"`
	CloseChan           chan struct{}       `json:"-"`
	PayloadIn           chan *proto.Payload `json:"-"`
	PayloadOutTLS       chan *proto.Payload `json:"-"`
	PayloadOutDTLS      chan *proto.Payload `json:"-"`
	DynamicRoutePackets chan []byte         `json:"-"`
	NetworkErrors       chan error          `json:"-"`

	DtlsConnected *atomic.Bool
	DtlsSetupChan chan struct{} `json:"-"`
	DSess         *DtlsSession  `json:"-"`
	dtlsSetupOnce sync.Once     `json:"-"`

	ResetTLSReadDead  *atomic.Bool   `json:"-"`
	ResetDTLSReadDead *atomic.Bool   `json:"-"`
	LifecycleState    *atomic.String `json:"-"`
	TLSState          *atomic.String `json:"-"`
	DTLSState         *atomic.String `json:"-"`

	closeInfoMu     sync.Mutex
	closeInfo       CloseInfo
	closeInfoSet    bool
	transportFaults []TransportFault
	closeHookMu     sync.Mutex
	closeHook       func()
	tunnelDone      chan struct{}
	tunnelErrMu     sync.Mutex
	tunnelErr       error
}

func (cSess *ConnSession) SetTunnelError(err error) {
	if cSess == nil {
		return
	}
	cSess.tunnelErrMu.Lock()
	cSess.tunnelErr = err
	cSess.tunnelErrMu.Unlock()
}

func (cSess *ConnSession) TunnelError() error {
	if cSess == nil {
		return nil
	}
	cSess.tunnelErrMu.Lock()
	defer cSess.tunnelErrMu.Unlock()
	return cSess.tunnelErr
}

// defaultDPDSeconds substitutes for a dead-peer interval the server did not
// advertise. A zero interval must not collapse the transport read deadline to
// a few seconds and drop idle sessions.
const defaultDPDSeconds = 30

// EffectiveDPD normalizes the server-advertised dead-peer detection interval
// so transport read deadlines stay meaningful when a header is missing.
func EffectiveDPD(advertised int) int {
	if advertised <= 0 {
		return defaultDPDSeconds
	}
	return advertised
}

type TransportFault struct {
	Code      string
	Transport string
	Error     string
	Time      string
}

type CloseInfo struct {
	Code            string
	Transport       string
	Error           string
	Time            string
	TransportFaults []TransportFault
}

type RuntimeStats struct {
	BytesSent      uint64
	BytesReceived  uint64
	TUNReads       uint64
	TUNWrites      uint64
	TUNReadErrors  uint64
	TUNWriteErrors uint64
	DPDSent        uint64
	DPDResponses   uint64
	QueueDrops     uint64
}

type DtlsSession struct {
	closeOnce sync.Once
	CloseChan chan struct{}
	owner     *ConnSession
}

func (sess *Session) NewConnSession(header *http.Header) *ConnSession {
	cSess := &ConnSession{
		Sess: sess,
		Stat: &stat{
			BytesSent:      atomic.NewUint64(0),
			BytesReceived:  atomic.NewUint64(0),
			TUNReads:       atomic.NewUint64(0),
			TUNWrites:      atomic.NewUint64(0),
			TUNReadErrors:  atomic.NewUint64(0),
			TUNWriteErrors: atomic.NewUint64(0),
			DPDSent:        atomic.NewUint64(0),
			DPDResponses:   atomic.NewUint64(0),
			QueueDrops:     atomic.NewUint64(0),
		},
		closeOnce:           sync.Once{},
		CloseChan:           make(chan struct{}),
		DtlsSetupChan:       make(chan struct{}),
		PayloadIn:           make(chan *proto.Payload, 64),
		PayloadOutTLS:       make(chan *proto.Payload, 64),
		PayloadOutDTLS:      make(chan *proto.Payload, 64),
		DynamicRoutePackets: make(chan []byte, 64),
		NetworkErrors:       make(chan error, 8),
		DtlsConnected:       atomic.NewBool(false),
		ResetTLSReadDead:    atomic.NewBool(true),
		ResetDTLSReadDead:   atomic.NewBool(true),
		LifecycleState:      atomic.NewString("Created"),
		TLSState:            atomic.NewString("Starting"),
		DTLSState:           atomic.NewString("Disabled"),
		DSess: &DtlsSession{
			closeOnce: sync.Once{},
			CloseChan: make(chan struct{}),
		},
	}
	cSess.DSess.owner = cSess
	sess.drainMu.Lock()
	sess.drainSession = cSess
	sess.drainMu.Unlock()
	sess.CSess = cSess

	sess.ActiveClose = false
	sess.CloseChan = make(chan struct{})

	cSess.VPNAddress = header.Get("X-CSTP-Address")
	cSess.VPNMask = header.Get("X-CSTP-Netmask")
	cSess.MTU, _ = strconv.Atoi(header.Get("X-CSTP-MTU"))
	cSess.DNS = header.Values("X-CSTP-DNS")
	// 如果服务器下发空字符串，字符串数组不会为 nil，会导致解析ip时报错
	cSess.SplitInclude = header.Values("X-CSTP-Split-Include")
	cSess.SplitExclude = header.Values("X-CSTP-Split-Exclude")
	cSess.UseDefaultRouteWhenEmpty = len(cSess.SplitInclude) == 0
	// debug with https://ip.900cha.com/
	// cSess.SplitExclude = append(cSess.SplitExclude, "47.243.165.103/255.255.255.255")

	cSess.TLSDpdTime, _ = strconv.Atoi(header.Get("X-CSTP-DPD"))
	cSess.TLSKeepaliveTime, _ = strconv.Atoi(header.Get("X-CSTP-Keepalive"))
	// https://datatracker.ietf.org/doc/html/draft-mavrogiannopoulos-openconnect-02#section-2.1.5.1
	cSess.DTLSId = header.Get("X-DTLS-Session-ID")
	if cSess.DTLSId == "" {
		// 兼容最新 ocserv
		cSess.DTLSId = header.Get("X-DTLS-App-ID")
	}
	base.Info("new conn session params", "vpnAddress", cSess.VPNAddress, "mtu", cSess.MTU, "dtlsPort", cSess.DTLSPort, "serverAddress", header.Get("X-CSTP-Server"))
	cSess.DTLSPort = header.Get("X-DTLS-Port")
	cSess.DTLSDpdTime, _ = strconv.Atoi(header.Get("X-DTLS-DPD"))
	cSess.DTLSKeepaliveTime, _ = strconv.Atoi(header.Get("X-DTLS-Keepalive"))
	if base.Cfg.NoDTLS {
		cSess.DTLSCipherSuite = "Unknown"
	} else {
		cSess.DTLSCipherSuite = header.Get("X-DTLS12-CipherSuite") // 连接前后格式不同
	}

	postAuth := header.Get("X-CSTP-Post-Auth-XML")
	if postAuth != "" {
		dtd := proto.DTD{}
		err := xml.Unmarshal([]byte(postAuth), &dtd)
		if err != nil {
			base.Warn("parse post-auth xml failed:", err)
		}
		if err == nil {
			if dtd.Config.Opaque.CustomAttr.DynamicSplitIncludeDomains != "" {
				cSess.DynamicSplitIncludeDomains = strings.Split(dtd.Config.Opaque.CustomAttr.DynamicSplitIncludeDomains, ",")
				cSess.DynamicSplitTunneling = true
			}
			if dtd.Config.Opaque.CustomAttr.DynamicSplitExcludeDomains != "" {
				// 字符串最后多一个逗号，导致数组最后一个元素为 ""，不排除配置错误其它元素也为空的可能，go 没有直接删除容器元素的方法，这里不处理
				cSess.DynamicSplitExcludeDomains = strings.Split(dtd.Config.Opaque.CustomAttr.DynamicSplitExcludeDomains, ",")
				cSess.DynamicSplitTunneling = true
			}

		}
	}

	return cSess
}

func (cSess *ConnSession) DPDTimer() {
	go func() {
		defer func() {
			base.Info("dead peer detection timer exit")
		}()
		base.Info("dead peer detection timer start", "tls", cSess.TLSDpdTime, "dtls", cSess.DTLSDpdTime)
		base.Debug("TLSDpdTime:", cSess.TLSDpdTime, "TLSKeepaliveTime", cSess.TLSKeepaliveTime,
			"DTLSDpdTime", cSess.DTLSDpdTime, "DTLSKeepaliveTime", cSess.DTLSKeepaliveTime)
		// 简化处理，最小15秒检测一次,至少5秒冗余
		dpdTime := utils.Min(cSess.TLSDpdTime, cSess.DTLSDpdTime) - 5
		if dpdTime < 10 {
			dpdTime = 10
		}
		ticker := time.NewTicker(time.Duration(dpdTime) * time.Second)

		tlsDpd := proto.Payload{
			Type: 0x03,
			Data: make([]byte, 0, 8),
		}
		dtlsDpd := proto.Payload{
			Type: 0x03,
			Data: make([]byte, 0, 1),
		}

		for {
			select {
			case <-ticker.C:
				// base.Debug("dead peer detection")
				base.Debug("send DPD", "tls", true)
				select {
				case cSess.PayloadOutTLS <- &tlsDpd:
					cSess.Stat.DPDSent.Inc()
				default:
					cSess.Stat.QueueDrops.Inc()
				}
				if cSess.DtlsConnected.Load() {
					select {
					case cSess.PayloadOutDTLS <- &dtlsDpd:
						cSess.Stat.DPDSent.Inc()
					default:
						cSess.Stat.QueueDrops.Inc()
					}
				}
			case <-cSess.CloseChan:
				ticker.Stop()
				return
			}
		}
	}()
}

func (cSess *ConnSession) ReadDeadTimer() {
	go func() {
		defer func() {
			base.Info("read dead timer exit")
		}()
		base.Info("read-dead timer start", "interval", "4s")
		// 避免每次 for 循环都重置读超时的时间
		// 这里是绝对时间，至于链接本身，服务器没有数据时 conn.Read 会阻塞，有数据时会不断判断
		ticker := time.NewTicker(4 * time.Second)
		for range ticker.C {
			select {
			case <-cSess.CloseChan:
				ticker.Stop()
				return
			default:
				cSess.ResetTLSReadDead.Store(true)
				cSess.ResetDTLSReadDead.Store(true)
			}
		}
	}()
}

// RecordTransportFault preserves the first few low-level failures for
// diagnostics without making a DTLS degradation look like a full session loss.
func (cSess *ConnSession) RecordTransportFault(code, transport string, err error) {
	if cSess == nil {
		return
	}
	cSess.closeInfoMu.Lock()
	defer cSess.closeInfoMu.Unlock()
	if len(cSess.transportFaults) >= 8 {
		return
	}
	cSess.transportFaults = append(cSess.transportFaults, TransportFault{
		Code: code, Transport: transport, Error: diagnosticError(err),
		Time: time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func (cSess *ConnSession) RecordClose(code, transport string, err error) {
	if cSess == nil {
		return
	}
	cSess.closeInfoMu.Lock()
	defer cSess.closeInfoMu.Unlock()
	if cSess.closeInfoSet {
		return
	}
	if cSess.Sess != nil && cSess.Sess.ActiveClose {
		code = "local_requested"
		transport = "local"
		err = nil
	}
	if code == "" {
		code = "unknown_close"
	}
	cSess.closeInfo = CloseInfo{
		Code: code, Transport: transport, Error: diagnosticError(err),
		Time:            time.Now().UTC().Format(time.RFC3339Nano),
		TransportFaults: append([]TransportFault(nil), cSess.transportFaults...),
	}
	cSess.closeInfoSet = true
}

func (cSess *ConnSession) CloseInfo() CloseInfo {
	if cSess == nil {
		return CloseInfo{Code: "unknown_close", Error: "session unavailable"}
	}
	cSess.closeInfoMu.Lock()
	defer cSess.closeInfoMu.Unlock()
	if !cSess.closeInfoSet {
		return CloseInfo{Code: "unknown_close", Time: time.Now().UTC().Format(time.RFC3339Nano)}
	}
	info := cSess.closeInfo
	info.TransportFaults = append([]TransportFault(nil), cSess.transportFaults...)
	return info
}

func diagnosticError(err error) string {
	if err == nil {
		return ""
	}
	message := err.Error()
	if len(message) > 512 {
		message = message[:512]
	}
	return message
}

func (cSess *ConnSession) Close() {
	cSess.closeOnce.Do(func() {
		cSess.SetLifecycleState("Draining")
		cSess.RecordClose("", "", nil)
		base.Info("conn session close")
		if cSess.DtlsConnected.Load() {
			cSess.DSess.Close()
		}
		close(cSess.CloseChan)
		// A reconnect can create a new ConnSession before all goroutines from
		// the previous session have returned. Do not let a stale session clear
		// or signal the replacement session through the process-global fields.
		if cSess.Sess != nil && cSess.Sess.CSess == cSess {
			cSess.Sess.CSess = nil
			close(cSess.Sess.CloseChan)
		}
		cSess.SetLifecycleState("Closed")
		cSess.closeHookMu.Lock()
		hook := cSess.closeHook
		cSess.closeHookMu.Unlock()
		if hook != nil {
			hook()
		}
	})
}

// SetTunnelDone registers the channel the tunnel controller closes after all
// packet workers have drained. Disconnect paths wait on it so a replacement
// connection never races the previous teardown.
func (cSess *ConnSession) SetTunnelDone(done chan struct{}) {
	if cSess == nil || done == nil {
		return
	}
	cSess.closeHookMu.Lock()
	cSess.tunnelDone = done
	cSess.closeHookMu.Unlock()
}

// TunnelDone returns the tunnel controller drain channel, or nil when no
// controller owns the TUN device for this session.
func (cSess *ConnSession) TunnelDone() <-chan struct{} {
	if cSess == nil {
		return nil
	}
	cSess.closeHookMu.Lock()
	defer cSess.closeHookMu.Unlock()
	return cSess.tunnelDone
}

func (cSess *ConnSession) SetCloseHook(hook func()) {
	if cSess == nil {
		return
	}
	cSess.closeHookMu.Lock()
	select {
	case <-cSess.CloseChan:
		cSess.closeHookMu.Unlock()
		if hook != nil {
			hook()
		}
		return
	default:
	}
	cSess.closeHook = hook
	cSess.closeHookMu.Unlock()
}

func (cSess *ConnSession) SetLifecycleState(state string) {
	if cSess == nil || cSess.LifecycleState == nil || state == "" {
		return
	}
	cSess.LifecycleState.Store(state)
}

func (cSess *ConnSession) SetTLSState(state string) {
	if cSess == nil || cSess.TLSState == nil || state == "" {
		return
	}
	cSess.TLSState.Store(state)
}

func (cSess *ConnSession) SetDTLSState(state string) {
	if cSess == nil || cSess.DTLSState == nil || state == "" {
		return
	}
	cSess.DTLSState.Store(state)
}

func (cSess *ConnSession) SignalDTLSSetup() {
	if cSess == nil || cSess.DtlsSetupChan == nil {
		return
	}
	cSess.dtlsSetupOnce.Do(func() { close(cSess.DtlsSetupChan) })
}

func (cSess *ConnSession) RuntimeStats() RuntimeStats {
	if cSess == nil || cSess.Stat == nil {
		return RuntimeStats{}
	}
	return RuntimeStats{
		BytesSent:      cSess.Stat.BytesSent.Load(),
		BytesReceived:  cSess.Stat.BytesReceived.Load(),
		TUNReads:       cSess.Stat.TUNReads.Load(),
		TUNWrites:      cSess.Stat.TUNWrites.Load(),
		TUNReadErrors:  cSess.Stat.TUNReadErrors.Load(),
		TUNWriteErrors: cSess.Stat.TUNWriteErrors.Load(),
		DPDSent:        cSess.Stat.DPDSent.Load(),
		DPDResponses:   cSess.Stat.DPDResponses.Load(),
		QueueDrops:     cSess.Stat.QueueDrops.Load(),
	}
}

func (dSess *DtlsSession) Close() {
	dSess.closeOnce.Do(func() {
		base.Info("dtls session close")
		close(dSess.CloseChan)
		if dSess.owner != nil {
			dSess.owner.DtlsConnected.Store(false)
			dSess.owner.DTLSCipherSuite = ""
		}
	})
}
