package rbac

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

func (c *Client) ListGroups(ctx context.Context, identity string, username string) (GroupList, error) {
	// Build request to RBAC service
	url := c.BaseURL + "/groups/"
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

	var groups GroupList
	err = c.listParsed(req, &groups)
	if err != nil {
		return nil, fmt.Errorf("failed to list groups: %w", err)
	}

	return groups, nil
}

func (c *Client) CreateGroup(ctx context.Context, input *GroupInput, identity string) (*Group, error) {
	body, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("error encoding group input: %v", err)
	}

	url := c.BaseURL + "/groups/"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create http request for rbac POST /groups/: %v", err)
	}
	// TODO: add header for psk
	req.Header.Set(identityHeader, identity)
	req.Header.Set("Content-Type", "application/json")

	var group Group
	err = c.postParsed(req, &group)
	if err != nil {
		return nil, fmt.Errorf("failed to create group: %v", err)
	}

	return &group, nil
}

func (c *Client) DeleteGroup(ctx context.Context, groupId string, identity string) error {
	url := c.BaseURL + "/groups/" + groupId + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create http request for rbac DELETE /groups/: %v", err)
	}
	// TODO: add header for psk
	req.Header.Set(identityHeader, identity)

	err = c.delete(req)
	if err != nil {
		return fmt.Errorf("failed to delete group: %v", err)
	}

	return nil
}

func (c *Client) AddUserToGroup(ctx context.Context, groupId string, input *AddUserToGroupInput, identity string) (*GroupWithPrincipalAndRoles, error) {
	body, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("error encoding group input: %v", err)
	}

	url := c.BaseURL + "/groups/" + groupId + "/principals/"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create http request for rbac POST /groups/:uuid/principals/: %v", err)
	}
	// TODO: add header for psk
	req.Header.Set(identityHeader, identity)
	req.Header.Set("Content-Type", "application/json")

	var group GroupWithPrincipalAndRoles
	err = c.postParsed(req, &group)
	if err != nil {
		return nil, fmt.Errorf("failed to add user to group: %v", err)
	}

	return &group, nil
}

func (c *Client) AddRoleToGroup(ctx context.Context, groupId string, input *AddRoleToGroupInput, identity string) ([]Role, error) {
	body, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("error encoding group input: %v", err)
	}

	url := c.BaseURL + "/groups/" + groupId + "/roles/"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create http request for rbac POST /groups/:uuid/roles/: %v", err)
	}
	// TODO: add header for psk
	req.Header.Set(identityHeader, identity)
	req.Header.Set("Content-Type", "application/json")

	roles := make([]Role, 0)
	out := PaginatedBody{
		Data: &roles,
	}
	err = c.postParsed(req, &out)
	if err != nil {
		return nil, fmt.Errorf("failed to add user to group: %v", err)
	}

	return roles, nil
}
