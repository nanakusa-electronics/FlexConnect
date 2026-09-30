package vpn

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"flexconnect/internal/anyconnect/auth"
	"flexconnect/internal/anyconnect/base"
	"flexconnect/internal/anyconnect/session"
	"flexconnect/internal/anyconnect/utils"
	"flexconnect/internal/osnet"
	"flexconnect/internal/router"
)

func initTunnel(client *auth.Client, sess *session.Session) (map[string]string, error) {
	requestedMTU := client.Prof.MTU
	if requestedMTU <= 0 {
		requestedMTU = defaultMTU
	}
	headers := map[string]string{
		"X-CSTP-VPNAddress-Type": "IPv4",
		"X-CSTP-MTU":             strconv.Itoa(requestedMTU),
		"X-CSTP-Base-MTU":        strconv.Itoa(requestedMTU),
	}
	// https://datatracker.ietf.org/doc/html/draft-mavrogiannopoulos-openconnect-03#section-2.1.3
	headers["Cookie"] = "webvpn=" + sess.SessionToken // 无论什么服务端都需要通过 Cookie 发送 Session
	headers["X-CSTP-Local-VPNAddress-IP4"] = client.LocalInterface.Ip4

	// Secondary UDP channel setup: https://datatracker.ietf.org/doc/html/draft-mavrogiannopoulos-openconnect-02#section-2.1.5.1
	// worker-vpn.c WSPCONFIG(ws)->udp_port != 0 && req->master_secret_set != 0 否则 disabling UDP (DTLS) connection
	// 如果开启 dtls_psk（默认开启，见配置说明） 且 CipherSuite 包含 PSK-NEGOTIATE（仅限ocserv），worker-http.c 自动设置 req->master_secret_set = 1
	// 此时无需手动设置 Secret，会自动协商建立 dtls 链接，AnyConnect 客户端不支持
	masterSecret, err := utils.MakeMasterSecret()
	if err != nil {
		return nil, fmt.Errorf("generate DTLS master secret: %w", err)
	}
	sess.PreMasterSecret = masterSecret
	headers["X-DTLS-Master-Secret"] = hex.EncodeToString(sess.PreMasterSecret) // Hex-encoded pre-master secret used in DTLS negotiation.

	// https://gitlab.com/openconnect/ocserv/-/blob/master/src/worker-http.c#L150
	// https://github.com/openconnect/openconnect/blob/master/gnutls-dtls.c#L75
	headers["X-DTLS12-CipherSuite"] = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:AES128-GCM-SHA256"
	return headers, nil
}

// SetupTunnelWithClient establishes a tunnel using only the supplied
// connection-owned authentication and session state.
func SetupTunnelWithClient(client *auth.Client, sess *session.Session) error {
	if client == nil || client.Conn == nil || client.BufR == nil {
		return fmt.Errorf("authentication client is not connected")
	}
	if sess == nil {
		return fmt.Errorf("nil VPN session")
	}
	headers, err := initTunnel(client, sess)
	if err != nil {
		return err
	}
	base.Info("start tunnel negotiation", "server", client.Prof.HostWithPort)

	// https://github.com/golang/go/commit/da6c168378b4c1deb2a731356f1f438e4723b8a7
	// https://github.com/golang/go/issues/17227#issuecomment-341855744
	req, err := http.NewRequest("CONNECT", client.Prof.Scheme+client.Prof.HostWithPort+"/CSCOSSLC/tunnel", nil)
	if err != nil {
		return err
	}
	utils.SetCommonHeader(req)
	for k, v := range headers {
		// req.Header.Set 会将首字母大写，其它小写
		req.Header[k] = []string{v}
	}

	// 发送 CONNECT 请求
	err = req.Write(client.Conn)
	if err != nil {
		_ = client.Close()
		base.Error("write tunnel request failed:", err)
		return err
	}
	var resp *http.Response
	// resp.Body closed when tlsChannel exit
	resp, err = http.ReadResponse(client.BufR, req)
	if err != nil {
		_ = client.Close()
		base.Error("read tunnel response failed:", err)
		return err
	}
	base.Info("tunnel response status", resp.Status)

	if resp.StatusCode != http.StatusOK {
		_ = client.Close()
		base.Warn("tunnel negotiation failed", resp.Status)
		return fmt.Errorf("tunnel negotiation failed %s", resp.Status)
	}
	// 协商成功，读取服务端返回的配置
	// https://datatracker.ietf.org/doc/html/draft-mavrogiannopoulos-openconnect-03#section-2.1.3

	// 提前判断是否调试模式，避免不必要的转换，http.ReadResponse.Header 将首字母大写，其余小写，即使服务端调试时正常
	if base.Cfg.LogLevel == "Debug" {
		headers := make([]byte, 0)
		buf := bytes.NewBuffer(headers)
		// http.ReadResponse: Keys in the map are canonicalized (see CanonicalHeaderKey).
		// https://ron-liu.medium.com/what-canonical-http-header-mean-in-golang-2e97f854316d
		_ = resp.Header.Write(buf)
		base.Debug(buf.String())
	}

	cSess := sess.NewConnSession(&resp.Header)
	cSess.TLSServerName, err = tlsServerName(client.Prof.HostWithPort)
	if err != nil {
		_ = client.Close()
		return err
	}
	mtu, err := effectiveMTU(cSess.MTU, client.Prof.MTU)
	if err != nil {
		_ = client.Close()
		cSess.RecordClose("invalid_mtu", "tls", err)
		cSess.Close()
		return err
	}
	cSess.MTU = mtu
	serverAddress, _, err := net.SplitHostPort(client.Conn.RemoteAddr().String())
	if err != nil {
		_ = client.Close()
		cSess.Close()
		return fmt.Errorf("parse VPN server socket: %w", err)
	}
	cSess.ServerAddress = serverAddress
	cSess.LocalSocketAddress = client.Conn.LocalAddr().String()
	cSess.RemoteSocketAddress = client.Conn.RemoteAddr().String()
	cSess.Hostname = client.Prof.Host
	cSess.TLSCipherSuite = tls.CipherSuiteName(client.Conn.ConnectionState().CipherSuite)
	base.Info("tls session created", "serverAddress", cSess.ServerAddress, "cipher", cSess.TLSCipherSuite)
	applyProfileOverridesWithProfile(cSess, &client.Prof)

	dev, err := setupTun(cSess)
	if err != nil {
		_ = client.Close()
		cSess.Close()
		base.Error("setup tun failed:", err)
		return err
	}
	base.Info("tun created", "name", cSess.TunName, "mtu", cSess.MTU, "dtlsPort", cSess.DTLSPort)
	underlay, err := osnet.GetUnderlaySnapshot(context.Background(), cSess.TunName)
	if err != nil {
		_ = client.Close()
		if cSess.NetworkManager != nil {
			_ = cSess.NetworkManager.Close(context.Background())
		}
		_ = dev.Close()
		cSess.RecordClose("underlay_snapshot_failed", "network", err)
		cSess.Close()
		return err
	}
	cSess.Underlay = underlay
	cSess.LocalAddress = underlay.LocalIPv4.String()
	base.Info("underlay selected", "interface", underlay.InterfaceName, "local", underlay.LocalIPv4.String(), "gateway", underlay.Gateway.String(), "metric", underlay.RouteMetric)

	netCfg, err := buildOSNetConfig(cSess)
	if err != nil {
		_ = client.Close()
		if cSess.NetworkManager != nil {
			_ = cSess.NetworkManager.Close(context.Background())
		}
		_ = dev.Close()
		cSess.RecordClose("net_config_build_failed", "network", err)
		cSess.Close()
		base.Error("build network config failed:", err)
		return err
	}
	err = cSess.NetworkManager.Set(context.Background(), netCfg)
	if err != nil {
		_ = client.Close()
		if cSess.NetworkManager != nil {
			_ = cSess.NetworkManager.Close(context.Background())
		}
		_ = dev.Close()
		cSess.RecordClose("net_config_apply_failed", "network", err)
		cSess.Close()
		base.Error("set network config failed:", err)
		return err
	}
	if _, err := startTun(dev, cSess); err != nil {
		_ = client.Close()
		_ = cSess.NetworkManager.Close(context.Background())
		_ = dev.Close()
		cSess.RecordClose("tun_start_failed", "tun", err)
		cSess.Close()
		return err
	}
	base.Info("tls channel negotiation succeeded", "remote", cSess.ServerAddress, "port", client.Prof.HostWithPort)

	// 只有网卡和路由设置成功才会进行下一步
	// https://datatracker.ietf.org/doc/html/draft-mavrogiannopoulos-openconnect-03#section-2.1.4
	go tlsChannel(client.Conn, client.BufR, cSess, resp)

	if !base.Cfg.NoDTLS && cSess.DTLSPort != "" {
		base.Info("start dtls channel", "address", cSess.ServerAddress, "port", cSess.DTLSPort)
		// https://datatracker.ietf.org/doc/html/draft-mavrogiannopoulos-openconnect-03#section-2.1.5
		go dtlsChannel(cSess)
		if err := waitDTLSSetup(cSess, 25*time.Second); err != nil {
			return err
		}
	}

	cSess.DPDTimer()
	cSess.ReadDeadTimer()

	return nil
}

func tlsServerName(hostPort string) (string, error) {
	host, _, err := net.SplitHostPort(strings.TrimSpace(hostPort))
	if err != nil {
		return "", fmt.Errorf("invalid VPN server address %q: %w", hostPort, err)
	}
	if host == "" {
		return "", fmt.Errorf("VPN server hostname is empty")
	}
	return host, nil
}

func applyProfileOverridesWithProfile(cSess *session.ConnSession, profile *auth.Profile) {
	serverInclude := cSess.SplitInclude
	serverExclude := cSess.SplitExclude
	if profile == nil {
		return
	}
	if !profile.AcceptServerRoutes {
		serverInclude = nil
		serverExclude = nil
		cSess.DynamicSplitTunneling = false
		cSess.DynamicSplitIncludeDomains = nil
		cSess.DynamicSplitExcludeDomains = nil
		cSess.UseDefaultRouteWhenEmpty = false
	}
	merged := router.MergeRouteLists(serverInclude, serverExclude, profile.CustomInclude, profile.CustomExclude)
	cSess.SplitInclude = merged.Include
	cSess.SplitExclude = merged.Exclude
	if !profile.ApplyDNS {
		cSess.DNS = nil
		return
	}
	if len(profile.DNSOverrides) > 0 {
		cSess.DNS = append([]string{}, profile.DNSOverrides...)
	}
	if len(cSess.SplitInclude) == 0 {
		cSess.UseDefaultRouteWhenEmpty = profile.AcceptServerRoutes
	} else {
		cSess.UseDefaultRouteWhenEmpty = false
	}
}

const defaultMTU = 1399

func effectiveMTU(serverMTU, profileMTU int) (int, error) {
	if profileMTU <= 0 {
		profileMTU = defaultMTU
	}
	if profileMTU < 576 || profileMTU > 9000 {
		return 0, fmt.Errorf("invalid profile MTU %d", profileMTU)
	}
	if serverMTU <= 0 {
		return profileMTU, nil
	}
	if serverMTU < 576 || serverMTU > 9000 {
		return 0, fmt.Errorf("invalid server MTU %d", serverMTU)
	}
	if serverMTU < profileMTU {
		return serverMTU, nil
	}
	return profileMTU, nil
}

func sessionSetupCloseError(cSess *session.ConnSession, stage string) error {
	info := cSess.CloseInfo()
	if info.Error != "" {
		return fmt.Errorf("VPN session closed during %s (%s/%s): %s", stage, info.Transport, info.Code, info.Error)
	}
	return fmt.Errorf("VPN session closed during %s (%s/%s)", stage, info.Transport, info.Code)
}

func waitDTLSSetup(cSess *session.ConnSession, timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-cSess.DtlsSetupChan:
		select {
		case <-cSess.CloseChan:
			return sessionSetupCloseError(cSess, "DTLS negotiation")
		default:
		}
		if !cSess.DtlsConnected.Load() {
			return errors.New("DTLS was offered but negotiation failed")
		}
		return nil
	case <-cSess.CloseChan:
		return sessionSetupCloseError(cSess, "DTLS negotiation")
	case <-timer.C:
		select {
		case <-cSess.CloseChan:
			return sessionSetupCloseError(cSess, "DTLS negotiation")
		default:
		}
		return errors.New("DTLS negotiation timed out")
	}
}
