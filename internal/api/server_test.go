package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestNewServerAddress(t *testing.T) {
	for _, tt := range []struct {
		name string
		addr string
		want string
	}{
		{name: "default", want: "127.0.0.1:8787"},
		{name: "port only", addr: ":9090", want: "127.0.0.1:9090"},
		{name: "configured", addr: "127.0.0.1:9000", want: "127.0.0.1:9000"},
		{name: "IPv6 loopback", addr: "[::1]:9000", want: "[::1]:9000"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := NewServer(tt.addr)
			if server.Addr != tt.want {
				t.Fatalf("Addr = %q, want %q", server.Addr, tt.want)
			}
		})
	}
}

func TestNewServerAddressFromEnvironment(t *testing.T) {
	t.Setenv("PIM_ADDR", "127.0.0.1:9091")
	server := NewServer(os.Getenv("PIM_ADDR"))
	if server.Addr != "127.0.0.1:9091" {
		t.Fatalf("Addr = %q, want configured environment address", server.Addr)
	}
}

func TestHealthz(t *testing.T) {
	server := httptest.NewServer(NewServer("").Handler)
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read health response: %v", err)
	}
	if string(body) != `{"status":"ok"}` {
		t.Errorf("body = %q, want health status JSON", body)
	}
}

func TestServerRouting(t *testing.T) {
	for _, tt := range []struct {
		method string
		path   string
		want   int
	}{
		{http.MethodPost, "/healthz", http.StatusMethodNotAllowed},
		{http.MethodGet, "/missing", http.StatusNotFound},
		{http.MethodGet, "/healthz/extra", http.StatusNotFound},
	} {
		t.Run(tt.method+tt.path, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			NewServer("").Handler.ServeHTTP(recorder, httptest.NewRequest(tt.method, tt.path, nil))
			if recorder.Code != tt.want {
				t.Errorf("status = %d, want %d", recorder.Code, tt.want)
			}
		})
	}
}
