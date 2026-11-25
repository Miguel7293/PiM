package sources

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/Miguel7293/PiM-/internal/store"
)

const record = `{"id":"test","affected":[{"package":{"ecosystem":"Go","name":"demo"},"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"}]}]}]}`

func archiveFixture(t *testing.T, records ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for i, r := range records {
		f, err := w.Create(fmt.Sprintf("%d.json", i))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write([]byte(r)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
func TestBulkIngest(t *testing.T) {
	body := archiveFixture(t, record)
	status := 200
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "GET" || r.URL.Path != "/Go/all.zip" || r.URL.RawQuery != "" || r.ContentLength > 0 {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
		}
		w.WriteHeader(status)
		w.Write(body)
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "mirror.db")
	dst, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { dst.Close() }()
	client := OSVBulk{BaseURL: server.URL, HTTPClient: server.Client()}
	if err = client.Ingest(context.Background(), dst, "Go"); err != nil {
		t.Fatal(err)
	}
	if err = dst.Close(); err != nil {
		t.Fatal(err)
	}
	dst, err = store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	pkg := store.Package{Ecosystem: "Go", Name: "demo"}
	for _, tc := range []struct {
		name            string
		body            []byte
		status          int
		download, entry int64
		entries         int
	}{
		{"http", nil, 503, 0, 0, 0},
		{"corrupt", []byte("bad zip"), 200, 0, 0, 0},
		{"download", archiveFixture(t, record), 200, 10, 0, 0},
		{"entry", archiveFixture(t, record), 200, 0, 10, 0},
		{"count", archiveFixture(t, record, record), 200, 0, 0, 1},
		{"late JSON", archiveFixture(t, record, "{"), 200, 0, 0, 0},
		{"late ID", archiveFixture(t, record, "{}"), 200, 0, 0, 0},
		{"duplicate", archiveFixture(t, record, record), 200, 0, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, status = tc.body, tc.status
			c := client
			c.MaxDownloadBytes = tc.download
			c.MaxEntryBytes = tc.entry
			c.MaxEntries = tc.entries
			if err := c.Ingest(context.Background(), dst, "Go"); err == nil {
				t.Fatal("expected failure")
			}
			got, err := dst.Lookup(pkg, "v1.5.0")
			if err != nil || len(got) != 1 || got[0].ID != "test" {
				t.Fatalf("lost snapshot: %v %v", got, err)
			}
		})
	}
	before := calls
	for _, version := range []string{"0.9.0", "2.0.0"} {
		got, err := dst.Lookup(pkg, version)
		if err != nil || got == nil || len(got) != 0 {
			t.Fatalf("lookup: %v %v", got, err)
		}
	}
	if calls != before {
		t.Fatal("lookup used HTTP")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = client.Ingest(ctx, dst, "Go"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err = client.Ingest(context.Background(), dst, "PyPI"); err == nil {
		t.Fatal("unsupported ecosystem accepted")
	}
	invalid := client
	invalid.MaxEntries = -1
	if err = invalid.Ingest(context.Background(), dst, "Go"); err == nil {
		t.Fatal("invalid limit accepted")
	}
	body, status = archiveFixture(t), 200
	if err = client.Ingest(context.Background(), dst, "Go"); err != nil {
		t.Fatal(err)
	}
	got, err := dst.Lookup(pkg, "1.5.0")
	if err != nil || got == nil || len(got) != 0 {
		t.Fatalf("empty snapshot: %v %v", got, err)
	}
}
