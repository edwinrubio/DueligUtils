package testhelpers

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
)

// TestClient is an HTTP client that injects JWT and standard headers.
type TestClient struct {
	BaseURL    string
	JWT        string
	ServiceKey string
	HTTP       *http.Client
}

// NewTestClient creates a TestClient with default http.Client.
func NewTestClient(baseURL, jwt string) *TestClient {
	return &TestClient{BaseURL: baseURL, JWT: jwt, HTTP: &http.Client{}}
}

func (c *TestClient) Post(path string, body interface{}) (*http.Response, error) {
	return c.do("POST", path, body)
}

func (c *TestClient) Get(path string) (*http.Response, error) {
	return c.do("GET", path, nil)
}

func (c *TestClient) Put(path string, body interface{}) (*http.Response, error) {
	return c.do("PUT", path, body)
}

func (c *TestClient) Delete(path string) (*http.Response, error) {
	return c.do("DELETE", path, nil)
}

func (c *TestClient) do(method, path string, body interface{}) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, c.BaseURL+path, bodyReader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Client-Type", "android") // bypasses CSRF middleware
	if c.JWT != "" {
		req.Header.Set("Authorization", "Bearer "+c.JWT)
	}
	if c.ServiceKey != "" {
		req.Header.Set("X-Service-Key", c.ServiceKey)
	}
	return c.HTTP.Do(req)
}
