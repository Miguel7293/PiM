package models

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPModelComplete(t *testing.T) {
	for _, authenticated := range []bool{false, true} {
		t.Run(map[bool]string{false: "local", true: "authenticated"}[authenticated], func(t *testing.T) {
			keyEnv, authorization := "", ""
			if authenticated {
				keyEnv, authorization = "PIM_TEST_MODEL_KEY", "Bearer test-token"
				t.Setenv(keyEnv, "test-token")
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Authorization") != authorization {
					t.Error("unexpected request method or headers")
				}
				var payload struct {
					Prompt string `json:"prompt"`
				}
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.Prompt != "hello\n世界" {
					t.Errorf("unexpected prompt: %q, %v", payload.Prompt, err)
				}
				_, _ = w.Write([]byte(`{"response":"completion"}`))
			}))
			defer server.Close()
			model, err := NewHTTPModel(server.URL, keyEnv)
			if err != nil {
				t.Fatal(err)
			}
			got, err := model.Complete(context.Background(), "hello\n世界")
			if err != nil || got != "completion" {
				t.Fatalf("Complete() = %q, %v", got, err)
			}
		})
	}
}

func TestHTTPModelResponses(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		body    string
		wantErr string
	}{
		{"empty completion", 200, `{"response":""}`, ""},
		{"status", 401, "secret-token", "HTTP status 401"},
		{"malformed", 200, "secret-token", "invalid response JSON"},
		{"missing", 200, `{}`, "invalid response JSON"},
		{"null", 200, `{"response":null}`, "invalid response JSON"},
		{"wrong type", 200, `{"response":123}`, "invalid response JSON"},
		{"oversized", 200, strings.Repeat("x", (4<<20)+1), "size limit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			model, err := NewHTTPModel(server.URL, "")
			if err != nil {
				t.Fatal(err)
			}
			got, err := model.Complete(context.Background(), "prompt")
			if tc.wantErr == "" {
				if err != nil || got != "" {
					t.Fatalf("Complete() = %q, %v", got, err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErr) || strings.Contains(err.Error(), "secret-token") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestHTTPModelInvalidConfiguration(t *testing.T) {
	for _, endpoint := range []string{"", "/relative", "ftp://example.com", "http://", "http://user:secret@example.com", "://"} {
		if _, err := NewHTTPModel(endpoint, ""); err == nil {
			t.Errorf("accepted endpoint %q", endpoint)
		}
	}
	for _, model := range []*HTTPModel{nil, {}} {
		if _, err := model.Complete(context.Background(), "prompt"); err == nil {
			t.Error("accepted unconfigured model")
		}
	}
}

func TestHTTPModelMissingKeyAndCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("unexpected request") }))
	defer server.Close()
	t.Setenv("PIM_TEST_MODEL_KEY", "")
	model, err := NewHTTPModel(server.URL, "PIM_TEST_MODEL_KEY")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := model.Complete(context.Background(), "prompt"); err == nil {
		t.Error("accepted missing key")
	}
	t.Setenv("PIM_TEST_MODEL_KEY", "test-token")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := model.Complete(ctx, "prompt"); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}

func TestHTTPModelDoesNotFollowRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("followed redirect") }))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	model, err := NewHTTPModel(server.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := model.Complete(context.Background(), "prompt"); err == nil || !strings.Contains(err.Error(), "307") {
		t.Fatalf("expected redirect status, got %v", err)
	}
}
