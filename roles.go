package rbac

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

func (c *Client) ListRoles(ctx context.Context, identity string, username string) (RoleList, error) {
	// Build request to RBAC service
	url := c.BaseURL + "/roles/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %w", err)
	}

	q := req.URL.Query()
	if username != "" {
		q.Add("username", username)
	}
	q.Add("limit", paginationLimit)
	req.URL.RawQuery = q.Encode()

	// Add X-RH-Identity header for authenticating the current principal
	req.Header.Set(identityHeader, identity)

	var roles RoleList
	err = c.listParsed(req, &roles)
	if err != nil {
		return nil, fmt.Errorf("failed to list roles: %w", err)
	}

	return roles, nil
}

func (c *Client) CreateRole(ctx context.Context, input *RoleInput, identity string) (*Role, error) {
	body, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("error encoding role input: %v", err)
	}

	url := c.BaseURL + "/roles/"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create http request for rbac POST /roles/: %v", err)
	}
	// TODO: add header for psk
	req.Header.Set(identityHeader, identity)
	req.Header.Set("Content-Type", "application/json")

	var role Role
	err = c.postParsed(req, &role)
	if err != nil {
		return nil, fmt.Errorf("failed to create role: %v", err)
	}

	return &role, nil
}

func (c *Client) DeleteRole(ctx context.Context, roleId string, identity string) error {
	url := c.BaseURL + "/roles/" + roleId + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create http request for rbac DELETE /roles/: %v", err)
	}
	// TODO: add header for psk
	req.Header.Set(identityHeader, identity)

	err = c.delete(req)
	if err != nil {
		return fmt.Errorf("failed to create role: %v", err)
	}

	return nil
}
