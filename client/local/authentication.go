package local

import (
	"context"
	"flexconnect/internal/types"
	"net/http"
	"net/url"
)

func (c *Client) Authentication(ctx context.Context) (*types.AuthenticationChallenge, error) {
	var challenge *types.AuthenticationChallenge
	err := c.getJSON(ctx, "/v3/authentication", &challenge)
	return challenge, err
}

func (c *Client) RespondAuthentication(ctx context.Context, id, response string) error {
	return c.expectStatusJSON(ctx, http.MethodPost, "/v3/authentication/"+url.PathEscape(id), types.AuthenticationResponse{Response: response}, http.StatusNoContent)
}
