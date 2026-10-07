package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"

	"flexconnect/internal/appd"
	"flexconnect/internal/buildinfo"
	"flexconnect/internal/ipc"
	"flexconnect/internal/logging"
	"flexconnect/internal/profileio"
	"flexconnect/internal/types"
)

var apiserverLog = logging.WithComponent("apiserver")

const maxRequestBodyBytes = 1 << 20

type requestIDContextKey struct{}
type actorContextKey struct{}

type Daemon interface {
	AuthenticationFor(appd.Actor) (*types.AuthenticationChallenge, error)
	RespondAuthenticationFor(appd.Actor, string, string) error
	StatusFor(appd.Actor) (types.Status, error)
	TrafficFor(appd.Actor) (types.TrafficSnapshot, error)
	LogsFor(appd.Actor) ([]types.LogEntry, error)
	DiagnosticsFor(appd.Actor) (types.Diagnostics, error)
	ListProfilesFor(appd.Actor) ([]types.Profile, error)
	CreateProfileFor(appd.Actor, types.ProfileCreateRequest) (types.Profile, error)
	UpdateProfileFor(appd.Actor, string, types.ProfileUpdateRequest) (types.Profile, error)
	UpdateActiveProfileFor(appd.Actor, string, types.ProfileUpdateRequest) (types.Operation, error)
	DeleteProfileFor(appd.Actor, string) error
	ProfileIsActive(string) bool
	ConnectionActive() bool
	ConnectFor(context.Context, appd.Actor, string) error
	DisconnectFor(context.Context, appd.Actor) error
	SetControlMode(context.Context, appd.Actor, types.ControlModeRequest) error
	StartOperation(appd.Actor, string, string, func(context.Context) error) (types.Operation, error)
	OperationFor(appd.Actor, string) (types.Operation, error)
	Ready() types.ReadyStatus
	WatchSince(context.Context, appd.Actor, string, uint64) <-chan types.Notify
	UpdateCheck(context.Context) (types.UpdateInfo, error)
}

type Server struct {
	daemon Daemon
	mux    *http.ServeMux
	nextID atomic.Uint64
}

func WithActor(ctx context.Context, actor appd.Actor) context.Context {
	return context.WithValue(ctx, actorContextKey{}, actor)
}

func New(daemon Daemon) *Server {
	s := &Server{daemon: daemon, mux: http.NewServeMux()}
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := strconv.FormatUint(s.nextID.Add(1), 10)
		w.Header().Set("X-FlexConnect-Request-ID", requestID)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		r = r.WithContext(context.WithValue(r.Context(), requestIDContextKey{}, requestID))
		if r.Host != ipc.LocalAPIHost {
			s.writeError(w, r, http.StatusBadRequest, "invalid_host", "invalid Local API host", false)
			return
		}
		if !allowedBrowserSource(r.Header.Get("Origin")) || !allowedBrowserSource(r.Header.Get("Referer")) {
			s.writeError(w, r, http.StatusForbidden, "browser_source_rejected", "browser source is not allowed", false)
			return
		}
		if r.ContentLength > maxRequestBodyBytes {
			s.writeError(w, r, http.StatusRequestEntityTooLarge, "request_too_large", "request body exceeds the Local API limit", false)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		s.mux.ServeHTTP(w, r)
	})
}

func allowedBrowserSource(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return true
	}
	u, err := url.Parse(value)
	return err == nil && u.Scheme == "http" && u.Host == ipc.LocalAPIHost
}

func (s *Server) routes() {
	s.mux.HandleFunc("/v3/live", s.handleLive)
	s.mux.HandleFunc("/v3/ready", s.handleReady)
	s.mux.HandleFunc("/v3/status", s.handleStatus)
	s.mux.HandleFunc("/v3/profiles", s.handleProfiles)
	s.mux.HandleFunc("/v3/profiles/", s.handleProfile)
	s.mux.HandleFunc("/v3/authentication", s.handleAuthentication)
	s.mux.HandleFunc("/v3/authentication/", s.handleAuthenticationResponse)
	s.mux.HandleFunc("/v3/connection", s.handleConnection)
	s.mux.HandleFunc("/v3/control-mode", s.handleControlMode)
	s.mux.HandleFunc("/v3/operations/", s.handleOperation)
	s.mux.HandleFunc("/v3/watch", s.handleWatch)
	s.mux.HandleFunc("/v3/logs", s.handleLogs)
	s.mux.HandleFunc("/v3/traffic", s.handleTraffic)
	s.mux.HandleFunc("/v3/diagnostics", s.handleDiagnostics)
	s.mux.HandleFunc("/v3/update/check", s.handleUpdateCheck)
	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.writeError(w, r, http.StatusNotFound, "endpoint_not_found", "Local API endpoint not found", false)
	})
}

func (s *Server) actor(r *http.Request) (appd.Actor, error) {
	actor, ok := r.Context().Value(actorContextKey{}).(appd.Actor)
	if !ok || actor.ID == "" {
		return appd.Actor{}, &appd.CodedError{Code: "identity_unavailable", Message: "local client identity is unavailable"}
	}
	return actor, nil
}

func (s *Server) requireMethod(w http.ResponseWriter, r *http.Request, methods ...string) bool {
	for _, method := range methods {
		if r.Method == method {
			return true
		}
	}
	s.writeError(w, r, http.StatusBadRequest, "method_not_allowed", "method not allowed", false)
	return false
}

func (s *Server) handleLive(w http.ResponseWriter, r *http.Request) {
	if !s.requireMethod(w, r, http.MethodGet) {
		return
	}
	s.writeJSON(w, http.StatusOK, types.LiveStatus{Status: "ok", Version: buildinfo.Version, APIMajor: buildinfo.LocalAPIMajor, Capabilities: append([]string(nil), buildinfo.LocalAPICapabilities...)})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if !s.requireMethod(w, r, http.MethodGet) {
		return
	}
	ready := s.daemon.Ready()
	status := http.StatusOK
	if !ready.Ready {
		status = http.StatusServiceUnavailable
	}
	s.writeJSON(w, status, ready)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if !s.requireMethod(w, r, http.MethodGet) {
		return
	}
	actor, err := s.actor(r)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	value, err := s.daemon.StatusFor(actor)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, value)
}

func (s *Server) handleProfiles(w http.ResponseWriter, r *http.Request) {
	actor, err := s.actor(r)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	switch r.Method {
	case http.MethodGet:
		profiles, err := s.daemon.ListProfilesFor(actor)
		if err != nil {
			s.handleError(w, r, err)
			return
		}
		s.writeJSON(w, http.StatusOK, profiles)
	case http.MethodPost:
		var req types.ProfileCreateRequest
		if err := decodeJSON(r, &req); err != nil {
			s.handleDecodeError(w, r, err)
			return
		}
		profile, err := s.daemon.CreateProfileFor(actor, req)
		if err != nil {
			s.handleError(w, r, err)
			return
		}
		s.writeJSON(w, http.StatusCreated, profile)
	default:
		s.writeError(w, r, http.StatusBadRequest, "method_not_allowed", "method not allowed", false)
	}
}

func pathID(path, prefix string) (string, error) {
	raw := strings.TrimPrefix(path, prefix)
	if raw == "" || strings.Contains(raw, "/") {
		return "", errors.New("invalid resource ID")
	}
	id, err := url.PathUnescape(raw)
	if err != nil || id == "" || strings.ContainsAny(id, "/\\") {
		return "", errors.New("invalid resource ID")
	}
	return id, nil
}

func (s *Server) handleProfile(w http.ResponseWriter, r *http.Request) {
	actor, err := s.actor(r)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	id, err := pathID(r.URL.EscapedPath(), "/v3/profiles/")
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, "invalid_profile_id", err.Error(), false)
		return
	}
	switch r.Method {
	case http.MethodPatch:
		var req types.ProfileUpdateRequest
		if err := decodeJSON(r, &req); err != nil {
			s.handleDecodeError(w, r, err)
			return
		}
		if s.daemon.ProfileIsActive(id) {
			op, err := s.daemon.UpdateActiveProfileFor(actor, id, req)
			if err != nil {
				s.handleError(w, r, err)
				return
			}
			s.writeJSON(w, http.StatusAccepted, types.OperationRef{Operation: op})
			return
		}
		profile, err := s.daemon.UpdateProfileFor(actor, id, req)
		if err != nil {
			s.handleError(w, r, err)
			return
		}
		s.writeJSON(w, http.StatusOK, profile)
	case http.MethodDelete:
		if s.daemon.ProfileIsActive(id) {
			op, err := s.daemon.StartOperation(actor, "profile-delete", id, func(context.Context) error {
				return s.daemon.DeleteProfileFor(actor, id)
			})
			if err != nil {
				s.handleError(w, r, err)
				return
			}
			s.writeJSON(w, http.StatusAccepted, types.OperationRef{Operation: op})
			return
		}
		if err := s.daemon.DeleteProfileFor(actor, id); err != nil {
			s.handleError(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		s.writeError(w, r, http.StatusBadRequest, "method_not_allowed", "method not allowed", false)
	}
}

func (s *Server) handleConnection(w http.ResponseWriter, r *http.Request) {
	actor, err := s.actor(r)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	switch r.Method {
	case http.MethodPut:
		var req types.ConnectionRequest
		if err := decodeJSON(r, &req); err != nil {
			s.handleDecodeError(w, r, err)
			return
		}
		if strings.TrimSpace(req.ProfileID) == "" {
			s.writeError(w, r, http.StatusUnprocessableEntity, "profile_id_required", "profile_id is required", false)
			return
		}
		op, err := s.daemon.StartOperation(actor, "connect", req.ProfileID, func(ctx context.Context) error {
			return s.daemon.ConnectFor(ctx, actor, req.ProfileID)
		})
		if err != nil {
			s.handleError(w, r, err)
			return
		}
		s.writeJSON(w, http.StatusAccepted, types.OperationRef{Operation: op})
	case http.MethodDelete:
		if !s.daemon.ConnectionActive() {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		op, err := s.daemon.StartOperation(actor, "disconnect", "", func(ctx context.Context) error {
			return s.daemon.DisconnectFor(ctx, actor)
		})
		if err != nil {
			s.handleError(w, r, err)
			return
		}
		s.writeJSON(w, http.StatusAccepted, types.OperationRef{Operation: op})
	default:
		s.writeError(w, r, http.StatusBadRequest, "method_not_allowed", "method not allowed", false)
	}
}

func (s *Server) handleControlMode(w http.ResponseWriter, r *http.Request) {
	if !s.requireMethod(w, r, http.MethodPut) {
		return
	}
	actor, err := s.actor(r)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	var req types.ControlModeRequest
	if err := decodeJSON(r, &req); err != nil {
		s.handleDecodeError(w, r, err)
		return
	}
	op, err := s.daemon.StartOperation(actor, "control-mode", req.ProfileID, func(ctx context.Context) error {
		return s.daemon.SetControlMode(ctx, actor, req)
	})
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusAccepted, types.OperationRef{Operation: op})
}

func (s *Server) handleOperation(w http.ResponseWriter, r *http.Request) {
	if !s.requireMethod(w, r, http.MethodGet) {
		return
	}
	actor, err := s.actor(r)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	id, err := pathID(r.URL.EscapedPath(), "/v3/operations/")
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, "invalid_operation_id", err.Error(), false)
		return
	}
	op, err := s.daemon.OperationFor(actor, id)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, types.OperationRef{Operation: op})
}

func (s *Server) handleWatch(w http.ResponseWriter, r *http.Request) {
	if !s.requireMethod(w, r, http.MethodGet) {
		return
	}
	actor, err := s.actor(r)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	since := uint64(0)
	if raw := r.URL.Query().Get("since"); raw != "" {
		since, err = strconv.ParseUint(raw, 10, 64)
		if err != nil {
			s.writeError(w, r, http.StatusBadRequest, "invalid_revision", "since must be an unsigned integer", false)
			return
		}
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		s.writeError(w, r, http.StatusInternalServerError, "streaming_unsupported", "streaming is unsupported", false)
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	for notify := range s.daemon.WatchSince(r.Context(), actor, r.URL.Query().Get("epoch"), since) {
		if err := enc.Encode(notify); err != nil {
			return
		}
		flusher.Flush()
	}
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	if !s.requireMethod(w, r, http.MethodGet) {
		return
	}
	actor, err := s.actor(r)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	value, err := s.daemon.LogsFor(actor)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, value)
}

func (s *Server) handleTraffic(w http.ResponseWriter, r *http.Request) {
	if !s.requireMethod(w, r, http.MethodGet) {
		return
	}
	actor, err := s.actor(r)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	value, err := s.daemon.TrafficFor(actor)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, value)
}

func (s *Server) handleDiagnostics(w http.ResponseWriter, r *http.Request) {
	if !s.requireMethod(w, r, http.MethodGet) {
		return
	}
	actor, err := s.actor(r)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	value, err := s.daemon.DiagnosticsFor(actor)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, value)
}

func (s *Server) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	if !s.requireMethod(w, r, http.MethodGet) {
		return
	}
	value, err := s.daemon.UpdateCheck(r.Context())
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, value)
}

type errorEnvelope struct {
	Error struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
		Retryable bool   `json:"retryable"`
	} `json:"error"`
}

func (s *Server) handleDecodeError(w http.ResponseWriter, r *http.Request, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		s.writeError(w, r, http.StatusRequestEntityTooLarge, "request_too_large", "request body exceeds the Local API limit", false)
		return
	}
	s.writeError(w, r, http.StatusBadRequest, "invalid_json", "request body is not valid for this endpoint", false)
}

func (s *Server) handleError(w http.ResponseWriter, r *http.Request, err error) {
	status, code, retryable := http.StatusInternalServerError, "internal_error", false
	message := "internal Local API error"
	var coded *appd.CodedError
	if errors.As(err, &coded) {
		code, message, retryable = coded.Code, coded.Message, coded.Retryable
		switch code {
		case "identity_unavailable":
			status = http.StatusUnauthorized
		case "admin_required", "machine_mode_locked":
			status = http.StatusForbidden
		case "profile_not_found", "operation_not_found":
			status = http.StatusNotFound
		case "daemon_in_use":
			status = http.StatusConflict
		case "service_closing", "cleanup_failed", "profile_transaction_pending", "component_unavailable":
			status = http.StatusServiceUnavailable
		case "authentication_not_found":
			status = http.StatusNotFound
		case "random_source_failed":
			status = http.StatusInternalServerError
		default:
			status = http.StatusUnprocessableEntity
		}
	} else {
		var validation *profileio.ValidationError
		if errors.As(err, &validation) {
			status, code, message = http.StatusUnprocessableEntity, "invalid_profile", validation.Error()
		}
	}
	if errors.Is(err, context.Canceled) {
		status, code, message = http.StatusConflict, "operation_canceled", "operation was canceled"
	} else if errors.Is(err, context.DeadlineExceeded) {
		status, code, message, retryable = http.StatusGatewayTimeout, "operation_timeout", "operation timed out", true
	}
	s.writeError(w, r, status, code, message, retryable)
}

func (s *Server) writeError(w http.ResponseWriter, r *http.Request, status int, code, message string, retryable bool) {
	var envelope errorEnvelope
	envelope.Error.Code = code
	envelope.Error.Message = message
	envelope.Error.RequestID, _ = r.Context().Value(requestIDContextKey{}).(string)
	envelope.Error.Retryable = retryable
	s.writeJSON(w, status, envelope)
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		apiserverLog.Printf("response encode failed err=%v", err)
	}
}

func decodeJSON(r *http.Request, out any) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("request body must contain exactly one JSON value")
		}
		return fmt.Errorf("invalid trailing JSON data: %w", err)
	}
	return nil
}
