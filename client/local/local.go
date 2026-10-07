package local

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"flexconnect/internal/buildinfo"
	"flexconnect/internal/ipc"
	"flexconnect/internal/logging"
	"flexconnect/internal/types"
)

var (
	debugEnabled bool
	debugLogger  = logging.WithComponent("flexconnect-local")
)

func SetDebug(enabled bool) {
	debugEnabled = enabled
}

func localDebug(v ...interface{}) {
	if !debugEnabled {
		return
	}
	debugLogger.Debug(strings.TrimSpace(fmt.Sprintln(v...)))
}

type Client struct {
	Socket    string
	Transport http.RoundTripper
	Dial      func(context.Context, string) (net.Conn, error)

	once sync.Once
	hc   *http.Client
}

type IncompatibleAPIError struct {
	ClientVersion string
	DaemonVersion string
}

type APIError struct {
	StatusCode int
	Code       string
	Message    string
	RequestID  string
	Retryable  bool
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("local API returned HTTP %d", e.StatusCode)
	}
	return e.Message
}

func (e *IncompatibleAPIError) Error() string {
	return fmt.Sprintf("local API version mismatch: client=%s daemon=%s", e.ClientVersion, e.DaemonVersion)
}

func (c *Client) socket() string {
	if c.Socket != "" {
		return c.Socket
	}
	return ipc.DefaultSocketPath()
}

func (c *Client) dialer() func(context.Context, string) (net.Conn, error) {
	if c.Dial != nil {
		return c.Dial
	}
	return func(ctx context.Context, _ string) (net.Conn, error) {
		return ipc.DialContext(ctx, c.socket())
	}
}

func (c *Client) httpClient() *http.Client {
	c.once.Do(func() {
		transport := c.Transport
		if transport == nil {
			transport = &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return c.dialer()(ctx, c.socket())
				},
			}
		}
		c.hc = &http.Client{Transport: transport}
	})
	return c.hc
}

func (c *Client) do(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	localDebug("HTTP request", method, path)
	req, err := http.NewRequestWithContext(ctx, method, "http://"+ipc.LocalAPIHost+path, body)
	if err != nil {
		localDebug("HTTP request create failed", err)
		return nil, err
	}
	start := time.Now()
	res, err := c.httpClient().Do(req)
	elapsed := time.Since(start)
	if err != nil {
		localDebug("HTTP request failed", method, path, "elapsed", elapsed, "err", err)
		return nil, err
	}
	localDebug("HTTP response", method, path, "status", res.StatusCode, "elapsed", elapsed)
	return res, nil
}

func (c *Client) Status(ctx context.Context) (*types.Status, error) {
	var out types.Status
	return &out, c.getJSON(ctx, "/v3/status", &out)
}

func (c *Client) Health(ctx context.Context) (*types.Health, error) {
	live, err := c.Live(ctx)
	if err != nil {
		return nil, err
	}
	ready, err := c.Ready(ctx)
	if err != nil {
		return nil, err
	}
	if !ready.Ready {
		return nil, &NotReadyError{Status: *ready}
	}
	return &types.Health{Status: "ok", Version: live.Version, APIVersion: strconv.Itoa(live.APIMajor)}, nil
}

type NotReadyError struct{ Status types.ReadyStatus }

func (e *NotReadyError) Error() string {
	problems := make([]string, 0, len(e.Status.Components))
	for _, component := range e.Status.Components {
		if !component.Ready {
			message := component.Name
			if component.Message != "" {
				message += ": " + component.Message
			}
			problems = append(problems, message)
		}
	}
	if len(problems) == 0 {
		return "flexconnectd is not ready"
	}
	return "flexconnectd is not ready: " + strings.Join(problems, "; ")
}

func (c *Client) Live(ctx context.Context) (*types.LiveStatus, error) {
	var live types.LiveStatus
	if err := c.getJSON(ctx, "/v3/live", &live); err != nil {
		return nil, err
	}
	if live.APIMajor != buildinfo.LocalAPIMajor {
		return nil, &IncompatibleAPIError{ClientVersion: buildinfo.LocalAPIVersion, DaemonVersion: strconv.Itoa(live.APIMajor)}
	}
	capabilities := make(map[string]bool, len(live.Capabilities))
	for _, capability := range live.Capabilities {
		capabilities[capability] = true
	}
	for _, required := range buildinfo.LocalAPICapabilities {
		if !capabilities[required] {
			return nil, fmt.Errorf("local API is missing required capability %q", required)
		}
	}
	return &live, nil
}

func (c *Client) Ready(ctx context.Context) (*types.ReadyStatus, error) {
	var ready types.ReadyStatus
	res, err := c.do(ctx, http.MethodGet, "/v3/ready", nil)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusServiceUnavailable {
		return nil, responseError(res)
	}
	if err := json.NewDecoder(res.Body).Decode(&ready); err != nil {
		return nil, err
	}
	return &ready, nil
}

func (c *Client) Profiles(ctx context.Context) ([]types.Profile, error) {
	var out []types.Profile
	return out, c.getJSON(ctx, "/v3/profiles", &out)
}

func (c *Client) CurrentProfile(ctx context.Context) (*types.Profile, error) {
	status, err := c.Status(ctx)
	if err != nil {
		return nil, err
	}
	profiles, err := c.Profiles(ctx)
	if err != nil {
		return nil, err
	}
	for i := range profiles {
		if profiles[i].ID == status.SelectedProfileID {
			return &profiles[i], nil
		}
	}
	return nil, &APIError{StatusCode: http.StatusNotFound, Code: "profile_not_found", Message: "selected profile not found"}
}

func (c *Client) CreateProfile(ctx context.Context, profile types.Profile, password string) (*types.Profile, error) {
	return c.CreateProfileWithCredential(ctx, profile, password, nil)
}

func (c *Client) CreateProfileWithCredential(ctx context.Context, profile types.Profile, password string, credential []byte) (*types.Profile, error) {
	payload := types.ProfileCreateRequest{ATrustCompatibility: profile.ATrustCompatibility.Clone(), Provider: profile.Provider, AuthMethod: profile.AuthMethod, LoginDomain: profile.LoginDomain, Credential: credential, Name: profile.Name, ServerURL: profile.ServerURL, Username: profile.Username, Password: password, Group: profile.Group, Scope: profile.Scope, AcceptServerRoutes: &profile.AcceptServerRoutes, AutoReconnect: profile.AutoReconnect, ApplyDNS: profile.ApplyDNS, CustomInclude: profile.CustomInclude, CustomExclude: profile.CustomExclude, DNSOverrides: profile.DNSOverrides, SOCKS5Enabled: profile.SOCKS5Enabled, SOCKS5Listen: profile.SOCKS5Listen, MTU: profile.MTU}
	var out types.Profile
	return &out, c.sendJSON(ctx, http.MethodPost, "/v3/profiles", payload, &out, http.StatusCreated)
}

func (c *Client) UpdateProfile(ctx context.Context, id string, req types.ProfileUpdateRequest) (types.ProfileMutationResult, error) {
	path := "/v3/profiles/" + url.PathEscape(id)
	res, err := c.sendRequest(ctx, http.MethodPatch, path, req)
	if err != nil {
		return types.ProfileMutationResult{}, err
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusOK:
		var profile types.Profile
		if err := json.NewDecoder(res.Body).Decode(&profile); err != nil {
			return types.ProfileMutationResult{}, err
		}
		return types.ProfileMutationResult{Profile: &profile}, nil
	case http.StatusAccepted:
		var ref types.OperationRef
		if err := json.NewDecoder(res.Body).Decode(&ref); err != nil {
			return types.ProfileMutationResult{}, err
		}
		return types.ProfileMutationResult{Operation: &ref.Operation}, nil
	default:
		return types.ProfileMutationResult{}, responseError(res)
	}
}

func (c *Client) SwitchProfile(ctx context.Context, id string) error {
	return c.Connect(ctx, id)
}

func (c *Client) DeleteProfile(ctx context.Context, id string) error {
	return c.expectStatus(ctx, http.MethodDelete, "/v3/profiles/"+url.PathEscape(id), nil, http.StatusNoContent, http.StatusAccepted)
}

func (c *Client) Login(ctx context.Context, req types.LoginRequest) error {
	if req.ProfileID != "" {
		_, err := c.UpdateProfile(ctx, req.ProfileID, types.ProfileUpdateRequest{Name: stringPtrNonEmpty(req.Name), ServerURL: stringPtrNonEmpty(req.ServerURL), Username: stringPtrNonEmpty(req.Username), Group: stringPtrNonEmpty(req.Group), Password: stringPtrNonEmpty(req.Password)})
		return err
	}
	profile, err := types.NewProfile(req.Name)
	if err != nil {
		return err
	}
	profile.ServerURL, profile.Username, profile.Group, profile.Scope = req.ServerURL, req.Username, req.Group, types.ProfileScopeUser
	_, err = c.CreateProfile(ctx, profile, req.Password)
	return err
}

func stringPtrNonEmpty(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func (c *Client) Connect(ctx context.Context, id string) error {
	if id == "" {
		return c.ConnectCurrent(ctx)
	}
	return c.expectStatusJSON(ctx, http.MethodPut, "/v3/connection", types.ConnectionRequest{ProfileID: id}, http.StatusAccepted)
}

func (c *Client) ConnectCurrent(ctx context.Context) error {
	profile, err := c.CurrentProfile(ctx)
	if err != nil {
		return err
	}
	return c.Connect(ctx, profile.ID)
}

func (c *Client) Disconnect(ctx context.Context) error {
	return c.expectStatus(ctx, http.MethodDelete, "/v3/connection", nil, http.StatusNoContent, http.StatusAccepted)
}

func (c *Client) SetControlMode(ctx context.Context, mode, profileID string) (*types.Operation, error) {
	var ref types.OperationRef
	if err := c.sendJSON(ctx, http.MethodPut, "/v3/control-mode", types.ControlModeRequest{Mode: mode, ProfileID: profileID}, &ref, http.StatusAccepted); err != nil {
		return nil, err
	}
	return &ref.Operation, nil
}

func (c *Client) UpdateRoutes(ctx context.Context, id string, req types.RouteUpdateRequest) (*types.Profile, error) {
	var out types.Profile
	update := types.ProfileUpdateRequest{AcceptServerRoutes: req.AcceptServerRoutes, CustomInclude: req.CustomInclude, CustomExclude: req.CustomExclude}
	return &out, c.sendJSON(ctx, http.MethodPatch, "/v3/profiles/"+url.PathEscape(id), update, &out, http.StatusOK)
}

func (c *Client) Logs(ctx context.Context) ([]types.LogEntry, error) {
	var out []types.LogEntry
	return out, c.getJSON(ctx, "/v3/logs", &out)
}

func (c *Client) Diagnostics(ctx context.Context) (*types.Diagnostics, error) {
	var out types.Diagnostics
	return &out, c.getJSON(ctx, "/v3/diagnostics", &out)
}

func (c *Client) Traffic(ctx context.Context) (*types.TrafficSnapshot, error) {
	var out types.TrafficSnapshot
	return &out, c.getJSON(ctx, "/v3/traffic", &out)
}

func (c *Client) UpdateCheck(ctx context.Context) (*types.UpdateInfo, error) {
	var out types.UpdateInfo
	return &out, c.getJSON(ctx, "/v3/update/check", &out)
}

func (c *Client) DiagnosticsText(ctx context.Context) (string, error) {
	diag, err := c.Diagnostics(ctx)
	if err != nil {
		return "", err
	}
	data, err := json.MarshalIndent(diag, "", "  ")
	if err != nil {
		return "", fmt.Errorf("format diagnostics: %w", err)
	}
	return string(data), nil
}

func (c *Client) Watch(ctx context.Context) (*Watcher, error) {
	return c.WatchSince(ctx, "", 0)
}

func (c *Client) WatchSince(ctx context.Context, epoch string, since uint64) (*Watcher, error) {
	path := "/v3/watch?since=" + strconv.FormatUint(since, 10)
	if epoch != "" {
		path += "&epoch=" + url.QueryEscape(epoch)
	}
	localDebug("GET", path)
	res, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		defer res.Body.Close()
		err := responseError(res)
		localDebug(path, "unexpected status", res.StatusCode, err)
		return nil, err
	}
	localDebug(path, "started")
	return &Watcher{ctx: ctx, res: res, dec: json.NewDecoder(res.Body)}, nil
}

func (c *Client) getJSON(ctx context.Context, path string, out any) error {
	localDebug("GET", path)
	res, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		err := responseError(res)
		localDebug("GET", path, "unexpected status", res.StatusCode, "err", err)
		return err
	}
	localDebug("GET", path, "ok")
	return json.NewDecoder(res.Body).Decode(out)
}

func (c *Client) sendJSON(ctx context.Context, method, path string, in, out any, want int) error {
	localDebug(method, path)
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		localDebug(method, path, "payload_bytes", len(b))
		body = strings.NewReader(string(b))
	}
	res, err := c.do(ctx, method, path, body)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != want {
		err := responseError(res)
		localDebug(method, path, "unexpected status", res.StatusCode, "err", err)
		return err
	}
	if out == nil {
		return nil
	}
	localDebug(method, path, "ok")
	return json.NewDecoder(res.Body).Decode(out)
}

func (c *Client) sendRequest(ctx context.Context, method, path string, in any) (*http.Response, error) {
	b, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	localDebug(method, path, "payload_bytes", len(b))
	return c.do(ctx, method, path, strings.NewReader(string(b)))
}

func (c *Client) expectNoContent(ctx context.Context, method, path string, body io.Reader) error {
	localDebug(method, path)
	res, err := c.do(ctx, method, path, body)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		err := responseError(res)
		localDebug(method, path, "unexpected status", res.StatusCode, "err", err)
		return err
	}
	localDebug(method, path, "ok")
	return nil
}

func (c *Client) expectStatus(ctx context.Context, method, path string, body io.Reader, allowed ...int) error {
	res, err := c.do(ctx, method, path, body)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	for _, status := range allowed {
		if res.StatusCode == status {
			return nil
		}
	}
	return responseError(res)
}

func (c *Client) expectStatusJSON(ctx context.Context, method, path string, in any, allowed ...int) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return c.expectStatus(ctx, method, path, strings.NewReader(string(b)), allowed...)
}

func responseError(res *http.Response) error {
	const maxErrorBytes = 64 * 1024
	all, err := io.ReadAll(io.LimitReader(res.Body, maxErrorBytes+1))
	if err != nil {
		return fmt.Errorf("read local API error response: %w", err)
	}
	message := strings.TrimSpace(string(all))
	if len(all) > maxErrorBytes {
		message = strings.TrimSpace(string(all[:maxErrorBytes])) + "..."
	}
	if message == "" {
		message = http.StatusText(res.StatusCode)
	}
	var envelope struct {
		Error struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			RequestID string `json:"request_id"`
			Retryable bool   `json:"retryable"`
		} `json:"error"`
	}
	if json.Unmarshal(all, &envelope) == nil && envelope.Error.Code != "" {
		return &APIError{StatusCode: res.StatusCode, Code: envelope.Error.Code, Message: envelope.Error.Message, RequestID: envelope.Error.RequestID, Retryable: envelope.Error.Retryable}
	}
	return &APIError{StatusCode: res.StatusCode, Message: message}
}

func (c *Client) expectNoContentJSON(ctx context.Context, method, path string, in any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return c.expectNoContent(ctx, method, path, strings.NewReader(string(b)))
}

type Watcher struct {
	ctx context.Context
	res *http.Response
	dec *json.Decoder
}

func (w *Watcher) Next() (types.Notify, error) {
	localDebug("watch next")
	var out types.Notify
	if err := w.dec.Decode(&out); err != nil {
		if w.ctx.Err() != nil {
			return types.Notify{}, w.ctx.Err()
		}
		localDebug("watch decode error", err)
		return types.Notify{}, err
	}
	localDebug("watch event", out.Event)
	return out, nil
}

func (w *Watcher) Close() error {
	return w.res.Body.Close()
}
