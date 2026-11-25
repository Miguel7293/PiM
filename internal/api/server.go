package api

import (
	"net"
	"net/http"
	"time"
)

// NewServer constructs an HTTP server ready to start with ListenAndServe.
// An empty addr defaults to 127.0.0.1:8787; a port without a host also
// binds to loopback. Callers may pass os.Getenv("PIM_ADDR") as addr.
func NewServer(addr string) *http.Server {
	if addr == "" {
		addr = "127.0.0.1:8787"
	} else if host, port, err := net.SplitHostPort(addr); err == nil && host == "" {
		addr = net.JoinHostPort("127.0.0.1", port)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
}
