package apiserver

import (
	"flexconnect/internal/types"
	"net/http"
)

func (s *Server) handleAuthentication(w http.ResponseWriter, r *http.Request) {
	if !s.requireMethod(w, r, http.MethodGet) {
		return
	}
	actor, err := s.actor(r)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	challenge, err := s.daemon.AuthenticationFor(actor)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	s.writeJSON(w, http.StatusOK, challenge)
}

func (s *Server) handleAuthenticationResponse(w http.ResponseWriter, r *http.Request) {
	if !s.requireMethod(w, r, http.MethodPost) {
		return
	}
	actor, err := s.actor(r)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	id, err := pathID(r.URL.EscapedPath(), "/v3/authentication/")
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, "invalid_authentication_id", "invalid authentication request ID", false)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	var response types.AuthenticationResponse
	if err := decodeJSON(r, &response); err != nil {
		// JSON decoder errors may quote input; this endpoint must never echo secrets.
		s.writeError(w, r, http.StatusBadRequest, "invalid_authentication_response", "invalid authentication response", false)
		return
	}
	if err := s.daemon.RespondAuthenticationFor(actor, id, response.Response); err != nil {
		s.handleError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
