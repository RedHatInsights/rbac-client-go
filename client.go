package rbac

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

// TODO: support auto-paginating body
const paginationLimit = "100"

// Client is used for making requests to the RBAC service
type Client struct {
	HTTPClient  *http.Client
	BaseURL     string
	Application string
}

// NewClient returns a Client given an application
func NewClient(baseURL, application string) Client {
	return Client{
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		BaseURL:     baseURL,
		Application: application,
	}
}

func (c *Client) listParsed(r *http.Request, data interface{}) error {
	// Perform request and check status
	resp, err := c.do(r)
	if err != nil {
		return fmt.Errorf("request to RBAC service failed: %w", err)
	}

	defer resp.Body.Close()

	rawBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received non-OK status code: %d, body: %s", resp.StatusCode, rawBody)
	}

	// pagination on list requests.
	body := PaginatedBody{
		Data: &data,
	}

	// Unmarshal JSON from good response
	err = json.Unmarshal(rawBody, &body)
	if err != nil {
		return fmt.Errorf("failed to parse response body: %w", err)
	}
	return nil
}

func (c *Client) getParsed(r *http.Request, data interface{}) error {
	// Perform request and check status
	resp, err := c.do(r)
	if err != nil {
		return fmt.Errorf("request to RBAC service failed: %w", err)
	}

	defer resp.Body.Close()

	rawBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received non-OK status code: %d, body: %s", resp.StatusCode, rawBody)
	}

	// Unmarshal JSON from good response
	err = json.Unmarshal(rawBody, &data)
	if err != nil {
		return fmt.Errorf("failed to parse response body: %w", err)
	}
	return nil
}

func (c *Client) postParsed(r *http.Request, data interface{}) error {
	// Perform request and check status
	resp, err := c.do(r)
	if err != nil {
		return fmt.Errorf("request to RBAC service failed: %w", err)
	}

	defer resp.Body.Close()

	rawBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	// accept either a 201 or a 200, a 200 is returned when adding a user to a group.
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received non-OK status code: %d, body: %s", resp.StatusCode, rawBody)
	}

	// Unmarshal JSON from good response
	err = json.Unmarshal(rawBody, &data)
	if err != nil {
		return fmt.Errorf("failed to parse response body: %w", err)
	}
	return nil
}

func (c *Client) delete(r *http.Request) error {
	// Perform request and check status
	resp, err := c.do(r)
	if err != nil {
		return fmt.Errorf("request to RBAC service failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("received non-OK status code: %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) do(r *http.Request) (*http.Response, error) {
	if c.HTTPClient == nil {
		return nil, errors.New("HTTPClient cannot be nil")
	}
	return c.HTTPClient.Do(r)
}
