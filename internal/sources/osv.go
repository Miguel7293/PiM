// Package sources downloads structured vulnerability data during explicit ingestion.
// Assessment-time queries must use store.Store.Lookup instead.
package sources

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Miguel7293/PiM-/internal/store"
)

const OSVQueryURL = "https://api.osv.dev/v1/query"

// OSVClient's zero value uses the public OSV endpoint and a bounded HTTP timeout.
type OSVClient struct {
	HTTPClient *http.Client
	QueryURL   string
}

// Fetch sends package identity and version to OSV. Use only for explicit mirror
// preparation with an approved catalog, never as an offline lookup fallback.
func (c OSVClient) Fetch(ctx context.Context, pkg store.Package, version string) ([]store.Vuln, error) {
	if err := pkg.Validate(version); err != nil {
		return nil, fmt.Errorf("query OSV: %w", err)
	}
	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	endpoint := c.QueryURL
	if endpoint == "" {
		endpoint = OSVQueryURL
	}
	query := struct {
		Package   store.Package `json:"package"`
		Version   string        `json:"version"`
		PageToken string        `json:"page_token,omitempty"`
	}{Package: pkg, Version: version}
	result := []store.Vuln{}
	seen := map[string]bool{}
	for {
		body, err := json.Marshal(query)
		if err != nil {
			return nil, fmt.Errorf("encode OSV query: %w", err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("create OSV request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("request OSV: %w", err)
		}
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, (32<<20)+1))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("query OSV: HTTP %d", resp.StatusCode)
		}
		if readErr != nil {
			return nil, fmt.Errorf("read OSV response: %w", readErr)
		}
		if len(data) > 32<<20 {
			return nil, fmt.Errorf("read OSV response: exceeds 32 MiB")
		}
		var page struct {
			Vulns []store.Vuln `json:"vulns"`
			Next  string       `json:"next_page_token"`
		}
		if err := json.Unmarshal(data, &page); err != nil {
			return nil, fmt.Errorf("decode OSV response: %w", err)
		}
		for _, v := range page.Vulns {
			if v.ID == "" {
				return nil, fmt.Errorf("decode OSV response: empty vulnerability ID")
			}
		}
		result = append(result, page.Vulns...)
		if page.Next == "" {
			return result, nil
		}
		if seen[page.Next] {
			return nil, fmt.Errorf("query OSV: repeated page token")
		}
		seen[page.Next] = true
		query.PageToken = page.Next
	}
}

// Refresh explicitly fetches all pages before replacing a mirrored result.
// A failed download leaves the previously stored result intact.
func (c OSVClient) Refresh(ctx context.Context, dst store.Store, pkg store.Package, version string) error {
	vulns, err := c.Fetch(ctx, pkg, version)
	if err != nil {
		return err
	}
	if err := dst.Put(pkg, version, vulns); err != nil {
		return fmt.Errorf("refresh OSV mirror: %w", err)
	}
	return nil
}
