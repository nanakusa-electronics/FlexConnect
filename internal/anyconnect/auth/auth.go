package auth

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"text/template"
	"time"

	"flexconnect/internal/anyconnect/base"
	"flexconnect/internal/anyconnect/proto"
	"flexconnect/internal/anyconnect/session"
	"flexconnect/internal/anyconnect/utils"
	"github.com/elastic/go-sysinfo"
)

// Profile contains the per-connection authentication and tunnel parameters.
type Profile struct {
	Host      string `json:"host"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	Group     string `json:"group"`
	SecretKey string `json:"secret"`

	AcceptServerRoutes bool     `json:"accept_server_routes"`
	ApplyDNS           bool     `json:"apply_dns"`
	CustomInclude      []string `json:"custom_include_routes"`
	CustomExclude      []string `json:"custom_exclude_routes"`
	DNSOverrides       []string `json:"dns_overrides"`
	MTU                int      `json:"mtu"`

	Initialized bool
	AppVersion  string // for report to server in xml
	GroupAccess string

	HostWithPort string
	Scheme       string
	AuthPath     string

	MacAddress  string
	TunnelGroup string
	GroupAlias  string
	ConfigHash  string

	ComputerName    string
	DeviceType      string
	PlatformVersion string
	UniqueId        string
}

// Client owns one authentication transaction. A Client must not be shared by
// concurrent connection attempts.
type Client struct {
	Prof           Profile
	Conn           *tls.Conn
	BufR           *bufio.Reader
	WebVpnCookie   string
	LocalInterface base.Interface
	serverGroups   []string
}

func NewClient(profile Profile, local base.Interface) *Client {
	defaults := newDefaultProfile()
	if profile.Scheme == "" {
		profile.Scheme = defaults.Scheme
	}
	if profile.DeviceType == "" {
		profile.DeviceType = defaults.DeviceType
	}
	if profile.PlatformVersion == "" {
		profile.PlatformVersion = defaults.PlatformVersion
	}
	if profile.ComputerName == "" {
		profile.ComputerName = defaults.ComputerName
	}
	if profile.UniqueId == "" {
		profile.UniqueId = defaults.UniqueId
	}
	return &Client{Prof: profile, LocalInterface: local}
}

func newDefaultProfile() Profile {
	profile := Profile{
		Scheme:             "https://",
		AcceptServerRoutes: true,
		ApplyDNS:           true,
		DeviceType:         runtime.GOOS,
	}
	if runtime.GOARCH == "amd64" {
		profile.DeviceType += "-64"
	}
	if runtime.GOOS == "windows" {
		profile.DeviceType = "win"
	}
	host, err := sysinfo.Host()
	if err != nil {
		base.Warn("collect host metadata failed:", err)
		return profile
	}
	info := host.Info()
	profile.ComputerName = info.Hostname
	profile.UniqueId = info.UniqueID
	profile.PlatformVersion = strings.Split(info.OS.Version, " ")[0]
	return profile
}

func (c *Client) Close() error {
	if c == nil || c.Conn == nil {
		return nil
	}
	err := c.Conn.Close()
	c.Conn = nil
	c.BufR = nil
	// Tunnel workers also close this connection when the transport fails.
	// Reconnect cleanup must not treat an already closed socket as a failure.
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// ServerGroups returns the user groups advertised by the server login form
// during the most recent InitAuth call. The result is empty when the server
// does not expose a group list.
func (c *Client) ServerGroups() []string {
	return append([]string(nil), c.serverGroups...)
}

const (
	tplInit = iota
	tplAuthReply
	maxAuthResponseBytes = 4 << 20
)

func (c *Client) configuredLocalAddr() net.Addr {
	ip := net.ParseIP(strings.TrimSpace(c.LocalInterface.Ip4)).To4()
	if ip == nil {
		return nil
	}
	return &net.TCPAddr{IP: ip}
}

func (c *Client) InitAuth(localAddr net.Addr) error {
	if c == nil {
		return errors.New("nil auth client")
	}
	if localAddr == nil {
		localAddr = c.configuredLocalAddr()
	}
	base.Info("init auth with server", c.Prof.HostWithPort)
	c.WebVpnCookie = ""
	serverName, err := tlsServerName(c.Prof.HostWithPort)
	if err != nil {
		return err
	}
	config := tls.Config{
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
	}
	dialer := &net.Dialer{Timeout: 6 * time.Second, LocalAddr: localAddr}
	conn, err := tls.DialWithDialer(dialer, "tcp4", c.Prof.HostWithPort, &config)
	if err != nil {
		base.Error("auth tcp connect failed:", err)
		return err
	}
	c.Conn = conn
	c.BufR = bufio.NewReader(conn)
	base.Info("auth tcp connection established", "local", conn.LocalAddr().String(), "remote", conn.RemoteAddr().String())

	dtd := new(proto.DTD)
	c.Prof.AppVersion = base.Cfg.AgentVersion
	c.Prof.MacAddress = c.LocalInterface.Mac
	if err := c.tplPost(tplInit, "", dtd); err != nil {
		base.Error("init auth request failed:", err)
		return err
	}
	if dtd.Type == "" {
		return errors.New("vpn server returned an unrecognized authentication response")
	}
	c.Prof.AuthPath = dtd.Auth.Form.Action
	if c.Prof.AuthPath == "" {
		c.Prof.AuthPath = "/"
	}
	c.Prof.TunnelGroup = dtd.Opaque.TunnelGroup
	c.Prof.GroupAlias = dtd.Opaque.GroupAlias
	c.Prof.ConfigHash = dtd.Opaque.ConfigHash
	c.serverGroups = append([]string(nil), dtd.Auth.Form.Groups...)
	if len(dtd.Auth.Form.Groups) != 0 && !utils.InArray(dtd.Auth.Form.Groups, c.Prof.Group) {
		return fmt.Errorf("available user groups are: %s", strings.Join(dtd.Auth.Form.Groups, " "))
	}
	c.Prof.Initialized = true
	base.Info("auth initialization completed", "authPath", c.Prof.AuthPath, "tunnelGroup", c.Prof.TunnelGroup, "groupAlias", c.Prof.GroupAlias)
	return nil
}

// PasswordAuth completes authentication and stores the resulting token in the
// supplied connection session.
func (c *Client) PasswordAuth(sess *session.Session) error {
	if c == nil || sess == nil {
		return errors.New("nil authentication session")
	}
	base.Info("start password auth")
	dtd := new(proto.DTD)
	err := c.tplPost(tplAuthReply, c.Prof.AuthPath, dtd)
	if err != nil {
		base.Error("password auth first step failed:", err)
		return err
	}
	base.Info("password auth response", "step", 1, "type", dtd.Type)
	if dtd.Type == "auth-request" && dtd.Auth.Error.Value == "" {
		dtd = new(proto.DTD)
		err = c.tplPost(tplAuthReply, c.Prof.AuthPath, dtd)
		if err != nil {
			base.Error("password auth second step failed:", err)
			return err
		}
		base.Info("password auth response", "step", 2, "type", dtd.Type)
	}
	if dtd.Type == "auth-request" {
		if dtd.Auth.Error.Value != "" {
			return fmt.Errorf("%s", formatAuthError(dtd.Auth.Error))
		}
		return errors.New(dtd.Auth.Message)
	}
	sess.SessionToken = dtd.SessionToken
	if c.WebVpnCookie != "" {
		sess.SessionToken = c.WebVpnCookie
		base.Info("using webvpn session token from cookie")
	}
	base.Info("password auth completed")
	base.Debug("session token received", "length", len(sess.SessionToken))
	return nil
}

// tplPost renders and sends one authentication request for this Client.
func (c *Client) tplPost(typ int, path string, dtd *proto.DTD) error {
	if c == nil || c.Conn == nil || c.BufR == nil {
		return errors.New("authentication connection is not initialized")
	}
	tplBuffer := new(bytes.Buffer)
	tplName := "tplInit"
	templateName := "init"
	templateText := templateInit
	if typ != tplInit {
		tplName = "tplAuthReply"
		templateName = "auth_reply"
		templateText = templateAuthReply
	}
	t, err := template.New(templateName).Parse(templateText)
	if err != nil {
		return err
	}
	if err := t.Execute(tplBuffer, c.Prof); err != nil {
		return err
	}
	base.Info("send auth template", "type", tplName, "path", path, "length", tplBuffer.Len())
	if base.Cfg.LogLevel == "Debug" {
		post := tplBuffer.String()
		if typ == tplAuthReply {
			post = utils.RemoveBetween(post, "<auth>", "</auth>")
		}
		base.Debug(post)
	}
	url := fmt.Sprintf("%s%s%s", c.Prof.Scheme, c.Prof.HostWithPort, path)
	if c.Prof.SecretKey != "" {
		url += "?" + c.Prof.SecretKey
	}
	req, err := http.NewRequest("POST", url, tplBuffer)
	if err != nil {
		return err
	}
	utils.SetCommonHeader(req)
	for k, v := range map[string]string{
		"X-Transcend-Version": "1",
		"X-Aggregate-Auth":    "1",
	} {
		req.Header[k] = []string{v}
	}
	if err := req.Write(c.Conn); err != nil {
		_ = c.Close()
		base.Error("write auth request failed:", err)
		return err
	}
	resp, err := http.ReadResponse(c.BufR, req)
	if err != nil {
		_ = c.Close()
		base.Error("read auth response failed:", err)
		return err
	}
	defer resp.Body.Close()
	body, err := readAuthResponse(resp.Body)
	if err != nil {
		_ = c.Close()
		base.Error("read auth body failed:", err)
		return err
	}
	base.Info("auth response received", "status", resp.StatusCode, "bodyLen", len(body))
	if base.Cfg.LogLevel == "Debug" {
		base.Debug(redactAuthBody(string(body)))
	}
	if resp.StatusCode != http.StatusOK {
		_ = c.Close()
		base.Warn("auth failed with status", resp.Status)
		return fmt.Errorf("auth error %s", resp.Status)
	}
	if err := xml.Unmarshal(body, dtd); err != nil {
		base.Error("unmarshal auth body failed:", err)
		return err
	}
	if dtd.Error.Value != "" {
		return fmt.Errorf("vpn server error: %s", formatAuthError(dtd.Error))
	}
	if dtd.Auth.Error.Value != "" {
		return fmt.Errorf("vpn auth error: %s", formatAuthError(dtd.Auth.Error))
	}
	if dtd.Type == "complete" && dtd.SessionToken == "" {
		for _, cookie := range resp.Cookies() {
			if cookie.Name == "webvpn" {
				c.WebVpnCookie = cookie.Value
				break
			}
		}
	}
	return nil
}

func readAuthResponse(body io.Reader) ([]byte, error) {
	value, err := io.ReadAll(io.LimitReader(body, maxAuthResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read authentication response: %w", err)
	}
	if len(value) > maxAuthResponseBytes {
		return nil, fmt.Errorf("authentication response exceeds %d bytes", maxAuthResponseBytes)
	}
	return value, nil
}

func tlsServerName(hostPort string) (string, error) {
	host, _, err := net.SplitHostPort(strings.TrimSpace(hostPort))
	if err != nil {
		return "", fmt.Errorf("invalid VPN server address %q: %w", hostPort, err)
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "", errors.New("VPN server hostname is empty")
	}
	return host, nil
}

func redactAuthBody(body string) string {
	body = utils.RemoveBetween(body, "<session-token>", "</session-token>")
	body = utils.RemoveBetween(body, "<password>", "</password>")
	return body
}

func formatAuthError(err proto.AuthError) string {
	message := strings.TrimSpace(err.Value)
	if message == "" {
		message = "authentication failed"
	}
	if err.Param1 != "" && strings.Contains(message, "%") {
		return fmt.Sprintf(message, err.Param1)
	}
	if err.Param1 != "" {
		return message + " " + err.Param1
	}
	return message
}

var templateInit = `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="init">
    <version who="vpn">{{.AppVersion}}</version>
    <device-id>{{.DeviceType}}</device-id>
    <group-access>{{.GroupAccess}}</group-access>{{if .Group}}
    <group-select>{{.Group}}</group-select>{{end}}
</config-auth>`

// https://datatracker.ietf.org/doc/html/draft-mavrogiannopoulos-openconnect-03#section-2.1.2.2
var templateAuthReply = `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-reply">
    <version who="vpn">{{.AppVersion}}</version>
    <device-id>{{.DeviceType}}</device-id>
    <opaque is-for="sg">
        <tunnel-group>{{.TunnelGroup}}</tunnel-group>
        <group-alias>{{.GroupAlias}}</group-alias>
        <config-hash>{{.ConfigHash}}</config-hash>
    </opaque>
    <mac-address-list>
        <mac-address public-interface="true">{{.MacAddress}}</mac-address>
    </mac-address-list>
    <auth>
        <username>{{.Username}}</username>
        <password>{{.Password}}</password>
    </auth>
    <group-select>{{.Group}}</group-select>
</config-auth>`
