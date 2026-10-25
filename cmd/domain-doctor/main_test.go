package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFormatVersion(t *testing.T) {
	version = "v0.1.0"
	commit = "abcdef123456"
	date = "2026-10-25T19:00:00Z"

	out := formatVersion()
	if !strings.Contains(out, "domain-doctor 0.1.0") {
		t.Fatalf("expected version string to contain 'domain-doctor 0.1.0', got: %s", out)
	}
	if !strings.Contains(out, "commit: abcdef123456") {
		t.Fatalf("expected commit string, got: %s", out)
	}
	if !strings.Contains(out, "Licensed under the MIT licence.") {
		t.Fatalf("expected license notice, got: %s", out)
	}
}

func TestHealthzEndpoint(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","app":"domain-doctor"}`))
	})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got: %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"status":"ok"`) {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
}
