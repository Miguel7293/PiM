// Package sources downloads vulnerability data only during explicit ingestion.
package sources

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Miguel7293/PiM-/internal/store"
)

const OSVBulkURL = "https://osv-vulnerabilities.storage.googleapis.com"

// OSVBulk's zero value uses bounded downloads from the public ecosystem archive.
// Limits set to zero use defaults; negative limits are rejected.
type OSVBulk struct {
	HTTPClient       *http.Client
	BaseURL          string
	MaxDownloadBytes int64
	MaxEntryBytes    int64
	MaxEntries       int
}

type BulkStore interface {
	ReplaceOSV(context.Context, string, func(func(store.Vuln) error) error) error
}

// Ingest downloads an entire ecosystem without sending client dependencies.
func (c OSVBulk) Ingest(ctx context.Context, dst BulkStore, ecosystem string) error {
	if ecosystem != "Go" && ecosystem != "npm" {
		return fmt.Errorf("unsupported ecosystem %q", ecosystem)
	}
	if c.MaxDownloadBytes < 0 || c.MaxEntryBytes < 0 || c.MaxEntries < 0 {
		return fmt.Errorf("OSV limits must be nonnegative")
	}
	if c.MaxDownloadBytes == 0 {
		c.MaxDownloadBytes = 1 << 30
	}
	if c.MaxEntryBytes == 0 {
		c.MaxEntryBytes = 16 << 20
	}
	if c.MaxEntries == 0 {
		c.MaxEntries = 1000000
	}
	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Minute}
	}
	base := c.BaseURL
	if base == "" {
		base = OSVBulkURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/"+ecosystem+"/all.zip", nil)
	if err != nil {
		return fmt.Errorf("create OSV request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download OSV archive: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download OSV archive: HTTP %d", resp.StatusCode)
	}
	tmp, err := os.CreateTemp("", "pim-osv-*.zip")
	if err != nil {
		return fmt.Errorf("create OSV temporary archive: %w", err)
	}
	defer func() { tmp.Close(); os.Remove(tmp.Name()) }()
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, c.MaxDownloadBytes))
	if err != nil {
		return fmt.Errorf("download OSV archive: %w", err)
	}
	var extra [1]byte
	more, err := io.ReadFull(resp.Body, extra[:])
	if more != 0 {
		return fmt.Errorf("OSV download exceeds size limit")
	}
	if err != io.EOF {
		return fmt.Errorf("finish OSV download: %w", err)
	}
	archive, err := zip.NewReader(tmp, n)
	if err != nil {
		return fmt.Errorf("open OSV archive: %w", err)
	}
	if len(archive.File) > c.MaxEntries {
		return fmt.Errorf("OSV archive exceeds entry count limit")
	}
	return dst.ReplaceOSV(ctx, ecosystem, func(emit func(store.Vuln) error) error {
		for _, entry := range archive.File {
			if err := ctx.Err(); err != nil {
				return err
			}
			if entry.FileInfo().IsDir() {
				continue
			}
			if entry.UncompressedSize64 > uint64(c.MaxEntryBytes) {
				return fmt.Errorf("OSV entry exceeds size limit")
			}
			reader, err := entry.Open()
			if err != nil {
				return fmt.Errorf("open OSV entry: %w", err)
			}
			data, readErr := io.ReadAll(io.LimitReader(reader, c.MaxEntryBytes))
			more, endErr := io.ReadFull(reader, extra[:])
			reader.Close()
			if readErr != nil {
				return fmt.Errorf("read OSV entry: %w", readErr)
			}
			if more != 0 {
				return fmt.Errorf("OSV entry exceeds size limit")
			}
			if endErr != io.EOF {
				return fmt.Errorf("finish OSV entry: %w", endErr)
			}
			var v store.Vuln
			if err := json.Unmarshal(data, &v); err != nil {
				return fmt.Errorf("decode OSV entry: %w", err)
			}
			if err := emit(v); err != nil {
				return err
			}
		}
		return nil
	})
}
