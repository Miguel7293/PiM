package sources

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Miguel7293/PiM-/internal/store"
)

func TestRefreshAndOfflineLookup(t *testing.T) {
	fixture, err := os.ReadFile("testdata/osv-query.json")
	if err != nil {
		t.Fatal(err)
	}
	pkg := store.Package{Ecosystem: "npm", Name: "@example/demo"}
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			t.Error("invalid request headers")
		}
		var query struct {
			Package store.Package
			Version string
			Token   string `json:"page_token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&query); err != nil {
			t.Error(err)
		}
		if query.Package != pkg || query.Version != "1.0.0" {
			t.Errorf("unexpected query: %+v", query)
		}
		if calls == 1 {
			if query.Token != "" {
				t.Error("unexpected initial token")
			}
			w.Write(fixture)
		} else {
			if query.Token != "page-2" {
				t.Error("missing pagination token")
			}
			w.Write([]byte(`{"vulns":[{"id":"OSV-test-0002"}]}`))
		}
	}))
	t.Cleanup(server.Close)
	dir := filepath.Join(t.TempDir(), "pim.db")
	dst, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	client := OSVClient{HTTPClient: server.Client(), QueryURL: server.URL}
	if err := client.Refresh(context.Background(), dst, pkg, "1.0.0"); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("got %d requests", calls)
	}
	server.Close()
	if err := dst.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	want := []store.Vuln{{ID: "GHSA-test-0001", Aliases: []string{"CVE-2026-0001"}, Summary: "Synthetic fixture vulnerability"}, {ID: "OSV-test-0002"}}
	got, err := reopened.Lookup(pkg, "1.0.0")
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("lookup = %+v, %v", got, err)
	}
	if _, err := reopened.Lookup(pkg, "2.0.0"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("miss = %v", err)
	}
}

func TestFetchFailuresPreserveMirror(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"http", `{}`, 503},
		{"json", `{`, 200},
		{"missing ID", `{"vulns":[{}]}`, 200},
		{"repeated token", `{"next_page_token":"same"}`, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status); w.Write([]byte(tc.body)) }))
			defer server.Close()
			dst, err := store.Open(filepath.Join(t.TempDir(), "pim.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer dst.Close()
			pkg := store.Package{Ecosystem: "Go", Name: "example.org/demo"}
			if err := dst.Put(pkg, "v1", []store.Vuln{{ID: "old"}}); err != nil {
				t.Fatal(err)
			}
			client := OSVClient{HTTPClient: server.Client(), QueryURL: server.URL}
			if err := client.Refresh(context.Background(), dst, pkg, "v1"); err == nil {
				t.Fatal("expected error")
			}
			got, err := dst.Lookup(pkg, "v1")
			if err != nil || len(got) != 1 || got[0].ID != "old" {
				t.Fatalf("old entry lost: %v, %v", got, err)
			}
		})
	}
}

func TestFetchEmptyAndCanceled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{}`)) }))
	defer server.Close()
	client := OSVClient{HTTPClient: server.Client(), QueryURL: server.URL}
	pkg := store.Package{Ecosystem: "npm", Name: "demo"}
	got, err := client.Fetch(context.Background(), pkg, "1")
	if err != nil || len(got) != 0 {
		t.Fatalf("empty response = %v, %v", got, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Fetch(ctx, pkg, "1"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled = %v", err)
	}
	if _, err := client.Fetch(context.Background(), store.Package{}, ""); err == nil {
		t.Fatal("expected validation error")
	}
}
