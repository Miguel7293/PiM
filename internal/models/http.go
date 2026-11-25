package models

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

// HTTPModel posts {"prompt":"..."} and expects {"response":"..."}.
// Provider-specific APIs require an endpoint implementing this contract.
type HTTPModel struct {
	endpoint string
	keyEnv   string
	client   *http.Client
}

// NewHTTPModel configures an endpoint and the name of its bearer-token environment
// variable. An empty keyEnv allows unauthenticated local endpoints.
func NewHTTPModel(endpoint, keyEnv string) (*HTTPModel, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return nil, fmt.Errorf("configure HTTP model: invalid HTTP endpoint")
	}
	return &HTTPModel{
		endpoint: endpoint,
		keyEnv:   keyEnv,
		client: &http.Client{
			Timeout: 60 * time.Second,
			// Credentials and prompts must stay at the configured endpoint.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func (m *HTTPModel) Complete(ctx context.Context, prompt string) (string, error) {
	if m == nil || m.client == nil {
		return "", fmt.Errorf("complete HTTP model: unconfigured model")
	}
	key := ""
	if m.keyEnv != "" {
		key = os.Getenv(m.keyEnv)
		if key == "" {
			return "", fmt.Errorf("complete HTTP model: API key environment variable is empty")
		}
	}
	data, err := json.Marshal(struct {
		Prompt string `json:"prompt"`
	}{prompt})
	if err != nil {
		return "", fmt.Errorf("encode model prompt: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.endpoint, bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("complete HTTP model: cannot create request")
	}
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := m.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("complete HTTP model: %w", ctx.Err())
		}
		// Transport errors may contain credentials or sensitive endpoint details.
		return "", fmt.Errorf("complete HTTP model: request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("complete HTTP model: HTTP status %d", resp.StatusCode)
	}
	const maxResponseBytes = 4 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return "", fmt.Errorf("complete HTTP model: cannot read response")
	}
	if len(body) > maxResponseBytes {
		return "", fmt.Errorf("complete HTTP model: response exceeds size limit")
	}
	var result struct {
		Response *string `json:"response"`
	}
	if err := json.Unmarshal(body, &result); err != nil || result.Response == nil {
		return "", fmt.Errorf("complete HTTP model: invalid response JSON")
	}
	return *result.Response, nil
}

var _ Model = (*HTTPModel)(nil)
